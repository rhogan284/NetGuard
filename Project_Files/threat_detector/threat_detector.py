import json
import re
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
import os
import logging
import yaml
import time
import uuid
from elasticsearch import Elasticsearch, helpers
from elasticsearch.helpers import bulk

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

log_dir = '/mnt/logs'
os.makedirs(log_dir, exist_ok=True)

threat_logger = logging.getLogger('threat_logger')
threat_logger.setLevel(logging.WARNING)
file_handler = logging.FileHandler(os.path.join(log_dir, 'detected_threats.log'))
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
threat_logger.addHandler(file_handler)

threat_logger.propagate = False

class ThreatDetector:
    def __init__(self, config_path='config.yaml'):
        self.config = self.load_config(config_path)
        self.es = self.connect_to_elasticsearch()
        self.compiled_rules = self.compile_rules()
        self.request_timestamps = defaultdict(lambda: deque(maxlen=self.config['ddos']['max_requests']))
        self.last_processed_timestamp = datetime.now(timezone.utc)

    @staticmethod
    def load_config(config_path):
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)

    @staticmethod
    def connect_to_elasticsearch():
        es_host = os.environ.get('ELASTICSEARCH_HOST', 'elasticsearch')
        es_port = os.environ.get('ELASTICSEARCH_PORT', '9200')
        es = Elasticsearch([f"http://{es_host}:{es_port}"])
        es.info()
        logger.info("Successfully connected to Elasticsearch")
        return es

    def compile_rules(self):
        return {
            threat_type: [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
            for threat_type, patterns in self.config['detection_rules'].items()
        }

    def detect_threats(self, log_entry):
        threats = set()
        url = log_entry.get('url', '')
        method = log_entry.get('method', '')
        request_body = json.dumps(log_entry.get('request_body', {}))
        headers = json.dumps(log_entry.get('request_headers', {}))
        client_ip = log_entry.get('client_ip', '')
        timestamp = datetime.now(timezone.utc)

        content_to_check = f"{url} {request_body} {headers}"

        for threat_type, patterns in self.compiled_rules.items():
            if threat_type != "ddos" and any(pattern.search(content_to_check) for pattern in patterns):
                threats.add(threat_type)

        if method == 'POST' and '/login' in url:
            threats.add('potential_brute_force')

        if '/exec' in url and 'cmd' in url:
            threats.add('command_injection')

        # DDoS detection
        self.request_timestamps[client_ip].append(timestamp)

        self.request_timestamps[client_ip] = deque(
            filter(lambda ts: timestamp - ts <= timedelta(seconds=self.config['ddos']['time_window']),
                   self.request_timestamps[client_ip]),
            maxlen=self.config['ddos']['max_requests']
        )

        if len(self.request_timestamps[client_ip]) > self.config['ddos']['threshold']:
            threats.add('ddos')
        elif len(self.request_timestamps[client_ip]) > 1:
            threats.add('potential_ddos')

        return list(threats)

    def process_logs_stream(self):
        while True:
            query = {
                "query": {
                    "range": {
                        "@timestamp": {
                            "gt": self.last_processed_timestamp.isoformat()
                        }
                    }
                },
                "sort": [
                    {"@timestamp": "asc"}
                ]
            }

            logger.info(f"Querying for logs after {self.last_processed_timestamp.isoformat()}")

            for log in helpers.scan(self.es, query=query, index=self.config['indices']['source']):
                log_entry = log['_source']
                log_timestamp = datetime.fromisoformat(log_entry['@timestamp'].replace('Z', '+00:00'))

                if log_timestamp > self.last_processed_timestamp:
                    threats = self.detect_threats(log_entry)
                    if threats:
                        self.process_threat(log_entry, threats)
                    else:
                        self.process_normal_log(log_entry)

                    self.last_processed_timestamp = log_timestamp

            logger.info(f"Processed logs up to {self.last_processed_timestamp.isoformat()}")
            time.sleep(self.config['processing']['poll_interval'])

    def process_threat(self, log_entry, threats):
        log_entry['detected_threats'] = threats
        self.es.index(index=self.config['indices']['threat'], body=log_entry)

    def process_normal_log(self, log_entry):
        self.es.index(index=self.config['indices']['normal'], body=log_entry)

    def run(self):
        logger.info(f"Starting threat detector. Processing logs from {self.last_processed_timestamp.isoformat()}")
        self.process_logs_stream()


if __name__ == "__main__":
    detector = ThreatDetector()
    detector.run()
