import json
import logging
import yaml
import time
from datetime import datetime, timedelta, timezone
from elasticsearch import Elasticsearch, helpers
import redis
import sys

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.StreamHandler(sys.stderr),
                        logging.FileHandler("/mnt/logs/threat_responder.log")
                    ])
logger = logging.getLogger(__name__)

class ThreatResponder:
    def __init__(self, config_path='responder_config.yaml'):
        logger.info("Initializing ThreatResponder")
        self.config = self.load_config(config_path)
        self.es = self.connect_to_elasticsearch()
        self.redis = self.connect_to_redis()
        self.BLOCKED_IPS_KEY = f"{self.config['redis']['key_prefix']}blocked_ips"
        self.last_processed_timestamp = datetime.now(timezone.utc)

    @staticmethod
    def load_config(config_path):
        logger.info(f"Loading config from {config_path}")
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        logger.info("Config loaded successfully")
        return config

    def connect_to_elasticsearch(self):
        es_host = self.config['elasticsearch']['host']
        es_port = self.config['elasticsearch']['port']
        es = Elasticsearch([f"http://{es_host}:{es_port}"])
        es.info()
        logger.info("Successfully connected to Elasticsearch")
        return es

    def connect_to_redis(self):
        redis_url = self.config['redis']['url']
        logger.info(f"Connecting to Redis at {redis_url}")
        return redis.Redis.from_url(redis_url, decode_responses=True)

    def process_threats_stream(self):
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

            logger.info(f"Querying for threats after {self.last_processed_timestamp.isoformat()}")

            for threat in helpers.scan(self.es, query=query, index=self.config['indices']['threat']):
                threat_entry = threat['_source']
                threat_timestamp = datetime.fromisoformat(threat_entry['@timestamp'].replace('Z', '+00:00'))

                if threat_timestamp > self.last_processed_timestamp:
                    self.execute_response(threat_entry.get('detected_threats', []), threat_entry)
                    self.last_processed_timestamp = threat_timestamp

            logger.info(f"Processed threats up to {self.last_processed_timestamp.isoformat()}")
            time.sleep(self.config['processing']['poll_interval'])

    def execute_response(self, detected_threats, threat_entry):
        logger.info(f"Executing response for threats: {detected_threats}")
        client_ip = threat_entry.get('client_ip', 'unknown')

        for threat_type in detected_threats:
            if threat_type in self.config['response_actions']:
                action = self.config['response_actions'][threat_type]
                logger.info(f"Action for {threat_type}: {action}")

                if action == "block_ip":
                    self.block_ip(client_ip)
                elif action == "rate_limit":
                    self.rate_limit_ip(client_ip)
                elif action == "log":
                    self.log_threat(threat_type, client_ip)
                else:
                    logger.warning(f"Unknown action type for threat: {threat_type}")
            else:
                logger.warning(f"No response action defined for threat type: {threat_type}")

    def block_ip(self, ip):
        try:
            if not self.redis.sismember(self.BLOCKED_IPS_KEY, ip):
                self.redis.sadd(self.BLOCKED_IPS_KEY, ip)
                self.redis.expire(self.BLOCKED_IPS_KEY, self.config['redis']['expiration_time'])
                logger.info(f"Blocked IP: {ip} for {self.config['redis']['expiration_time']} seconds")
            else:
                logger.info(f"IP: {ip} is already blocked")
        except redis.exceptions.RedisError as e:
            logger.error(f"Error blocking IP: {e}")

    def rate_limit_ip(self, ip):
        logger.info(f"Rate limiting IP: {ip}")
        key = f"{self.config['redis']['key_prefix']}rate:{ip}"
        current = int(self.redis.get(key) or 0)
        if current == 0:
            self.redis.set(key, 1, ex=self.config['rate_limit']['window_size'])
        elif current < self.config['rate_limit']['max_requests']:
            self.redis.incr(key)
        else:
            self.block_ip(ip)
            logger.info(f"Rate limit exceeded for IP: {ip}. Blocking.")

    def log_threat(self, threat_type, ip):
        logger.info(f"Logging threat: {threat_type} from IP: {ip}")
        with open(self.config['logging']['file'], "a") as f:
            f.write(f"{datetime.now().isoformat()},{threat_type},{ip}\n")

    def run(self):
        logger.info(f"Starting threat responder. Processing threats from {self.last_processed_timestamp.isoformat()}")
        while True:
            try:
                self.process_threats_stream()
            except Exception as e:
                logger.error(f"An error occurred: {str(e)}")
                logger.info("Attempting to reconnect to Elasticsearch...")
                self.es = self.connect_to_elasticsearch()
                time.sleep(self.config['processing']['error_retry_interval'])


if __name__ == "__main__":
    responder = ThreatResponder()
    responder.run()