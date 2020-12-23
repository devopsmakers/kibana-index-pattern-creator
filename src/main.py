#!/usr/bin/python3

import os
import sys
import json
import requests
import urllib3
import logging

from pythonjsonlogger import jsonlogger


urllib3.disable_warnings()


def setup_logging(log_level):
    logger = logging.getLogger(__name__)
    logger.setLevel(log_level)
    logHandler = logging.StreamHandler(sys.stdout)
    formatter = jsonlogger.JsonFormatter(
        fmt='%(asctime)s | %(levelname)s | %(name)s | %(message)s'
    )
    logHandler.setFormatter(formatter)
    logger.addHandler(logHandler)


def get_indices_from_elasticsearch(elasticsearch_url, index_prefix):
    '''
    Given an elasticsearch URL and an index prefix, returns a list of indices or
    False on error.
    '''
    try:
        indices_resp = requests.get(
            elasticsearch_url + "/_cat/indices?format=json", verify=False)

        if indices_resp.status_code == 200:
            indices_data = indices_resp.json()
            index_list = [index['index'] for index in indices_data if index['index'].startswith(index_prefix)]
            logger.info('Found {} indexes matching prefix: "{}" in elasticsearch'.format(len(index_list), index_prefix))
            return index_list

        logger.critical('Failed to fetch index list from elasticsearch with status: {} {}'.format(indices_resp.status_code, indices_resp.text))
        sys.exit(1)

    except Exception as e:
        logger.exception('Failed to fetch index list from elasticsearch')
        sys.exit(1)


def get_kibana_patterns(indices, exact_patterns, last_pattern_character):
    '''
    Given a list of elasticsearch indexes, returns a list of patterns to create
    in Kibana based on whether the user wants to match indexes exactly
    '''
    if exact_patterns:
        logger.info('Returning {} exact index pattern matches for kibana'.format(len(indices)))
        return indices

    logger.debug('Creating index patterns with last character match of "{}"'.format(last_pattern_character))
    index_patterns = []
    for index in indices:
        index_lastchar_idx = index.rfind(last_pattern_character)

        if index_lastchar_idx != -1:
            index_pattern = index[:index_lastchar_idx] + last_pattern_character + '*'
            index_patterns.append(index_pattern)

    index_patterns = list(dict.fromkeys(index_patterns))  # Deduplicate the list of patterns

    logger.info('Found {} index pattern matches for kibana'.format(len(index_patterns)))

    return index_patterns


def create_index_patterns(kibana_url, patterns, saved_index_pattern_names):
    '''
    Create patterns in kibana for each of our given patterns
    '''
    headers = {'kbn-xsrf': 'true'}

    skipped = 0
    created = 0
    failed = 0

    for pattern in patterns:
        if pattern in saved_index_pattern_names:
            logger.debug('Skipping index pattern: {}'.format(pattern))
            skipped += 1
        else:
            logger.debug('Creating index pattern: {}'.format(pattern))

            payload = {
                "attributes": {
                    "title": pattern,
                    "timeFieldName": "@timestamp"
                }
            }

            try:
                index_create_resp = requests.post(
                    kibana_url + '/api/saved_objects/index-pattern',
                    json=payload,
                    headers=headers,
                    verify=False)

                if (index_create_resp.status_code) == 200:
                    created += 1
                else:
                    failed += 1
                    logger.warning('Failed to post index pattern: {} to Kibana with status: {} {}'.format(pattern, index_create_resp.status_code, index_create_resp.text))

            except Exception as e:
                logger.exception('Failed to post index pattern to kibana')
                sys.exit(1)

    logger.info('Created: {}, and skipped: {} index patterns with {} failures'.format(created, skipped, failed))


def get_saved_index_patterns(kibana_url):
    '''
    Returns the existing saved index pattern objects
    '''
    headers = {'kbn-xsrf': 'true'}

    try:
        existing_patterns_resp = requests.get(
            kibana_url + '/api/saved_objects/_find?fields=title&fields=type&per_page=10000&type=index-pattern',
            headers=headers,
            verify=False)

        if existing_patterns_resp.status_code == 200:
            existing_patterns_data = existing_patterns_resp.json()
            return existing_patterns_data['saved_objects']

        logger.critical('Failed to get index patterns from kibana with status: {} {}'.format(existing_patterns_resp.status_code, existing_patterns_resp.text))
        sys.exit(1)

    except Exception as e:
        logger.exception('Failed to get saved index patterns from kibana')
        sys.exit(1)


def refresh_field_list(kibana_url, saved_index_patterns):
    '''
    Given a list of (all) saved index pattern objects, update the field lists on them
    '''
    headers = {'kbn-xsrf': 'true'}

    updated = 0
    failed = 0

    for saved_pattern in saved_index_patterns:

        pattern = saved_pattern['attributes']['title']
        pattern_id = saved_pattern['id']

        logger.debug('Getting fields for: {}'.format(pattern))
        try:
            index_fields_resp = requests.get(
                kibana_url +
                '/api/index_patterns/_fields_for_wildcard?pattern=' +
                pattern +
                '&meta_fields=_source&meta_fields=_id&meta_fields=_type&meta_fields=_index&meta_fields=_score',
                headers=headers,
                verify=False)

            if index_fields_resp.status_code == 200:
                index_fields_data = index_fields_resp.json()
            else:
                logger.warning('Failed to get field list from kibana for pattern: {}'.format(pattern))
                failed += 1
                continue

        except Exception as e:
            logger.exception('Failed to get field list from kibana for pattern: {}'.format(pattern))
            sys.exit(1)


        payload = {
            'attributes': {
                'title': pattern,
                'timeFieldName': '@timestamp',
                'fields': json.dumps(index_fields_data['fields'])  # fields attribute is a stringified JSON list
            }
        }

        logger.debug('Putting new field mappings for pattern: {} with id: {}'.format(pattern, pattern_id))
        try:
            pattern_update_resp = requests.put(
                kibana_url + '/api/saved_objects/index-pattern/' + pattern_id,
                json=payload,
                headers=headers,
                verify=False)

            if pattern_update_resp.status_code == 200:
                updated +=1
            else:
                logger.warning('Failed to put field list to kibana for pattern: {}'.format(pattern))
                failed += 1
                continue

        except Exception as e:
            logger.exception('Failed to put field list to kibana for pattern: {}'.format(pattern))
            sys.exit(1)

    logger.info('Updated field lists on all {} index patterns with {} failures'.format(updated, failed))


if __name__ == "__main__":
    # Configure JSON logging
    log_level = os.getenv('LOG_LEVEL', 'INFO')
    setup_logging(log_level)
    logger = logging.getLogger(__name__)

    # URL that this script can access Kibana
    kibana_url = os.getenv('KIBANA_URL', 'http://kibana:5601/').rstrip('/')

    # URL that this script can access elasticsearch at
    elasticsearch_url = os.getenv(
        'ELASTICSEARCH_URL',
        'http://elasticsearch:9200/').rstrip('/')

    # A prefix can be set to match indexes returned by elasticsearch
    index_prefix = os.getenv('INDEX_PREFIX', 'logstash-')

    # Should we create exact index patters? We probably want wildcard patterns
    # by default
    exact_patterns = os.getenv('EXACT_MATCHES', False)

    # What is the last instance of a character I want my pattern to be based on?
    # usually "-" for log related indexes
    last_pattern_character = os.getenv('LAST_CHARACTER', '-')

    # Should we refresh field lists on all saved patterns?
    refresh_fields = os.getenv('REFRESH_FIELDS', False)

    # A list of all indexes in Elasticsearch that match the given prefix
    indices = get_indices_from_elasticsearch(elasticsearch_url, index_prefix)

    # A list of patterns based on the given index names and configuration
    patterns = get_kibana_patterns(indices, exact_patterns, last_pattern_character)

    # We should fetch the current saved index patterns for Kibana, they are used
    # to filter out existing indexes and to update field mappings.
    saved_index_patterns = get_saved_index_patterns(kibana_url)
    saved_index_pattern_names = [
        saved_index_pattern['attributes']['title'] for saved_index_pattern in saved_index_patterns]

    create_index_patterns(kibana_url, patterns, saved_index_pattern_names)

    if bool(refresh_fields):
        refresh_field_list(kibana_url, saved_index_patterns)

    logger.info('Done')
