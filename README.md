# kibana-index-pattern-creator
A python script and Docker image for creating index patterns and refreshing fields.

## Background
If you're like me, you send your logs into elasticsearch, you realised that shipping logs into a big old `logstash-YYYY.MM.DD` bucket is probably not great and split your logs into different indexes.

Index names might be based on an applications name, Kubernetes namespace, log type, or something completely exotic. You probably found out that you should keep a common prefix like `logstash-` or `fluentd-` to make curator index management jobs easier by applying basic operations to all logs starting with the prefix.

You probably get a bit annoyed when a new namespace, app, or other index turns up and you have to go into Kibana and create a new index pattern for it, you also get annoyed at indexes field lists getting out of date too... That is the annoyance that this script will rid you of.

## Tell me more...
The script: `src/main.py` gets a list of all indexes in Elasticsearch that start with a user specified prefix. It then creates a Kibana index pattern for each one (if it doesn't already exist). It can be run with an environment variable set to refresh the fields on **all** index patterns in Kibana.

## Mmmkay, how do I do that?
The script is configured solely by environment variables. It's designed to be run as a `CronJob` in Kubernetes, but can be run anywhere.

| Variable | Description | Default | Example |
| -------- | ----------- | ------- | ------- |
| `LOG_LEVEL` | Sets the log level for the script | `INFO` | `DEBUG` |
| `KIBANA_URL` | The URL that the script can find Kibana at | `http://kibana:5601` | `http://notadmin:aPassword@kibana.dev.example.com` |
| `ELASTICSEARCH_URL` | The URL that the script can find Elasticsearch at | `http://elasticsearch:9200` | `https://notadmin:aPassword@elasticsearch.logging.svc.cluster.local:9200` |
| `INDEX_PREFIX` | The prefix that the script should filter Elasticsearch indexes on | `logstash-` | `fluentd-` |
| `EXACT_MATCHES` | Set this to create exact (not wildcard) index patterns | `False` | `yes` |
| `LAST_CHARACTER` | The last character that should come before the `*` | `-` | `_` |
| `REFRESH_FIELDS` | Whether to refresh the field lists of all index patterns in Kibana | `False` | `yes` |
| `DRY_RUN` | Set this to prevent creating or updating index patterns | `False` | `yes` |

### Running the script locally
If your Elasticsearch and Kibana are in Kubernetes, you can run this script locally using the something like telepresence.io and the service URLs within the cluster.

```bash
# Setup a venv
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the script
LOG_LEVEL=DEBUG \
KIBANA_URL=http://localhost:5601 \
ELASTICSEARCH_URL=http://localhost:9200 \
# Other settings
python3 src/main.py

# To refresh field lists on all index patterns in Kibana
LOG_LEVEL=DEBUG \
KIBANA_URL=http://localhost:5601 \
ELASTICSEARCH_URL=http://localhost:9200 \
REFRESH_FIELDS=yes \
# Other settings
python3 src/main.py
```
