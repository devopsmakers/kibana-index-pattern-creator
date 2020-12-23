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
    logHandler = logging.StreamHandler()
    formatter = jsonlogger.JsonFormatter(
        fmt='%(asctime)s | %(levelname)s | %(name)s | %(message)s'
    )
    logHandler.setFormatter(formatter)
    logger.addHandler(logHandler)


def get_elasticsearch_indices(elasticsearch_url, index_prefix):
    '''
    Given an elasticsearch URL and an index prefix, returns a list of indices or
    False on error.
    '''
    try:
        index_data = requests.get(
            elasticsearch_url + "/_cat/indices?format=json", verify=False).json()

        if isinstance(index_data, list):
            index_list = [index['index'] for index in index_data if index['index'].startswith(index_prefix)]
            logger.info('Found {} indexes matching prefix: {}'.format(len(index_list), index_prefix))
            return index_list

        logger.critical('Failed to fetch index list from elasticsearch', extra=index_data)
        return False
    except Exception as e:
        logger.exception('Failed to fetch index list from elasticsearch')
        return False


def get_kibana_patterns(indices, exact_patterns, last_pattern_character):
    '''
    Given a list of elasticsearch indexes, returns a list of patterns to create
    in Kibana based on whether the user wants to match indexes exactly.
    Examples:
       input: (['fluentd-bosun-docs-2020.12.13', 'fluentd-bosun-docs-2020.12.14'], false, '-')
       returns ['fluentd-bosun-docs-*']

       input: (['fluentd-bosun-docs-2020.12.13'], true, '-')
       returns ['fluentd-bosun-docs-2020.12.13']
    '''
    indices.sort()

    if exact_patterns:
        logger.info('Returning {} exact index pattern matches for Kibana'.format(len(indices)))
        return indices

    logger.info('Creating index patterns with last character match of "{}"'.format(last_pattern_character))
    index_patterns = []
    for index in indices:
        index_lastchar_idx = index.rfind(last_pattern_character)
        if index_lastchar_idx != -1:
            index_pattern = index[:index_lastchar_idx] + last_pattern_character + '*'
            index_patterns.append(index_pattern)

    index_patterns = list(dict.fromkeys(index_patterns))

    logger.info('Returning {} index pattern matches for Kibana'.format(len(index_patterns)))

    return index_patterns


def create_index_patterns(kibana_url, patterns, saved_index_pattern_names):
    '''
    Create patterns in Kibana for each of our given patterns
    '''
    headers = {'kbn-xsrf': 'true'}

    created = 0
    failed = 0

    for pattern in patterns:
        if pattern in saved_index_pattern_names:
            logger.info('Skipping index pattern: {}'.format(pattern))
        else:
            logger.info('Creating index pattern: {}'.format(pattern))

            payload = {
                "attributes": {
                    "title": pattern,
                    "timeFieldName": "@timestamp"
                }
            }

            res = requests.post(
                kibana_url + '/api/saved_objects/index-pattern',
                json=payload,
                headers=headers,
                verify=False)

            if (res.status_code) == 200:
                created += 1
            else:
                failed += 1

    logger.info('Created: {} index patterns with {} failures'.format(created, failed))


def get_saved_index_patterns(kibana_url):
    '''
    Returns the existing saved index pattern objects
    '''
    headers = {'kbn-xsrf': 'true'}

    existing_patterns_data = requests.get(
        kibana_url + '/api/saved_objects/_find?fields=title&fields=type&per_page=10000&type=index-pattern',
        headers=headers,
        verify=False).json()

    return existing_patterns_data['saved_objects']


def refresh_field_list(kibana_url, saved_index_patterns):
    '''
    Given a list of saved index pattern objects, update the field lists on them
    '''
    headers = {'kbn-xsrf': 'true'}

    for saved_pattern in saved_index_patterns:

        pattern = saved_pattern['attributes']['title']
        pattern_id = saved_pattern['id']

        logger.info('Getting fields for: {}'.format(pattern))
        index_fields_data = requests.get(
            kibana_url +
            '/api/index_patterns/_fields_for_wildcard?pattern=' +
            pattern +
            '&meta_fields=_source&meta_fields=_id&meta_fields=_type&meta_fields=_index&meta_fields=_score',
            headers=headers,
            verify=False).json()

        payload = {
            'attributes': {
                'title': pattern,
                'timeFieldName': '@timestamp',
                'fields': json.dumps(index_fields_data['fields'])  # fields attribute is a stringified JSON list
            }
        }
        logger.info('Putting new field mappings for pattern: {} with id: {}'.format(pattern, pattern_id))
        requests.put(
            kibana_url + '/api/saved_objects/index-pattern/' + pattern_id,
            json=payload,
            headers=headers,
            verify=False)


if __name__ == "__main__":
    # Configure JSON logging
    setup_logging('INFO')
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
    indices = get_elasticsearch_indices(elasticsearch_url, index_prefix)

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
