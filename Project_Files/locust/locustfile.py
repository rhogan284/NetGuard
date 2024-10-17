import random
import json
import logging
import time
import uuid
import os
from locust import HttpUser, task, between, events
from locust.contrib.fasthttp import FastHttpUser
from datetime import datetime
import gevent
import yaml

config_path = "/mnt/locust/locust_config.yaml"
with open(config_path, "r") as config_file:
    config = yaml.safe_load(config_file)

logging_config_path = "/mnt/locust/logging_config.yaml"
with open(logging_config_path, 'rt') as f:
    logging_config = yaml.safe_load(f.read())
    logging.config.dictConfig(logging_config)

json_logger = logging.getLogger('json_logger')
user_stats_logger = logging.getLogger('normal_user_stats')

class DynamicWebsiteUser(FastHttpUser):
    wait_time = between(config['normal_users']['wait_time_min'], config['normal_users']['wait_time_max'])
    host = config['host']
    instances = []

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__class__.instances.append(self)
        self.is_active = False
        self.last_active_time = time.time()
        self.activation_cooldown = random.uniform(config['lifecycle']['min_cooldown'], config['lifecycle']['max_cooldown'])
        self.randomise_user()

    def randomise_user(self):
        self.user_id = str(uuid.uuid4())
        self.session_id = str(uuid.uuid4())
        self.client_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        self.username = random.choice([
            'applebee',
            'ofgirl',
            'bigbuffmen',
            'alphagamer101',
            'donaldtrump'
        ])
        self.password = random.choice([
            'password',
            '123456',
            'admin',
            'qwerty',
            'letmein'
        ])
        self.user_agent = random.choice([
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36'
        ])
        self.geolocation = random.choice([
            {"country": "United States", "city": "New York", "timezone": "America/New_York"},
            {"country": "United Kingdom", "city": "London", "timezone": "Europe/London"},
            {"country": "Japan", "city": "Tokyo", "timezone": "Asia/Tokyo"},
            {"country": "Australia", "city": "Sydney", "timezone": "Australia/Sydney"},
            {"country": "Germany", "city": "Berlin", "timezone": "Europe/Berlin"}
        ])

    def on_start(self):
        self.is_active = True
        self.last_active_time = time.time()

    def on_stop(self):
        self.__class__.instances.remove(self)

    @task(10)
    def index_page(self):
        if not self.is_active:
            return
        self._log_request("GET", "/", None)

    @task(5)
    def view_product(self):
        if not self.is_active:
            return
        product_id = random.randint(1, 10)
        self._log_request("GET", f"/products/{product_id}", None)

    @task(2)
    def add_to_cart(self):
        if not self.is_active:
            return
        product_id = random.randint(1, 10)
        self._log_request("POST", "/cart", {"product_id": product_id, "quantity": 1})

    @task(2)
    def view_cart(self):
        if not self.is_active:
            return
        self._log_request("GET", "/cart", None)

    @task(1)
    def checkout(self):
        if not self.is_active:
            return
        self._log_request("POST", "/checkout", {"payment_method": "credit_card"})

    @task(1)
    def login(self):
        if not self.is_active:
            return
        self._log_request("POST", "/login", {"username": self.username, "password": self.password})

    @task(2)
    def search(self):
        if not self.is_active:
            return
        search_terms = ["laptop", "phone", "book", "shirt", "headphones"]
        query = random.choice(search_terms)
        self._log_request("GET", f"/search?q={query}", None)

    def _log_request(self, method, path, data):
        log_id = str(uuid.uuid4())
        start_time = time.time()
        try:
            if method == "GET":
                response = self.client.get(path)
            elif method == "POST":
                response = self.client.post(path, json=data)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            self._log_response(log_id, method, path, response, start_time, data)
        except Exception as e:
            self._log_exception(log_id, method, path, e, start_time, data)

    def _log_response(self, log_id, method, path, response, start_time, data):
        log_entry = {
            "log_id": log_id,
            "@timestamp": datetime.utcnow().isoformat(),
            "client_ip": self.client_ip,
            "method": method,
            "url": f"{self.host}{path}",
            "status_code": response.status_code,
            "response_time_ms": int((time.time() - start_time) * 1000),
            "bytes_sent": len(response.request.body) if response.request.body else 0,
            "bytes_received": len(response.content),
            "user_agent": self.user_agent,
            "referer": random.choice([None, "https://www.google.com", "https://www.bing.com"]),
            "request_headers": dict(response.request.headers),
            "response_headers": dict(response.headers),
            "geo": self.geolocation,
            "request_body": data if data else None
        }
        json_logger.info(json.dumps(log_entry))

    def _log_exception(self, log_id, method, path, exception, start_time, data):
        log_entry = {
            "log_id": log_id,
            "@timestamp": datetime.utcnow().isoformat(),
            "client_ip": self.client_ip,
            "method": method,
            "url": f"{self.host}{path}",
            "status_code": 500,
            "response_time_ms": int((time.time() - start_time) * 1000),
            "exception": str(exception),
            "user_agent": self.user_agent,
            "referer": random.choice([None, "https://www.google.com", "https://www.bing.com", "https://example.com"]),
            "geo": self.geolocation,
            "request_body": data if data else None
        }
        json_logger.info(json.dumps(log_entry))


def manage_user_lifecycle(environment):
    for user_instance in DynamicWebsiteUser.instances:
        current_time = time.time()
        if user_instance.is_active:
            if random.random() < config['lifecycle']['deactivation_chance']:
                user_instance.is_active = False
                user_instance.last_active_time = current_time
                user_instance.activation_cooldown = random.uniform(config['lifecycle']['min_cooldown'], config['lifecycle']['max_cooldown'])
                logging.info(f"User {user_instance.user_id} deactivated")
        elif current_time - user_instance.last_active_time > user_instance.activation_cooldown:
            if random.random() < config['lifecycle']['activation_chance']:
                user_instance.is_active = True
                user_instance.last_active_time = current_time
                logging.info(f"User {user_instance.user_id} activated")

def log_user_stats(environment):
    active_users = sum(1 for user in DynamicWebsiteUser.instances if user.is_active)
    inactive_users = len(DynamicWebsiteUser.instances) - active_users
    log_message = f"Normal User Statistics: Active: {active_users}, Inactive: {inactive_users}"
    user_stats_logger.info(log_message)

@events.init.add_listener
def on_locust_init(environment, **kwargs):
    gevent.spawn(periodic_tasks, environment)

def periodic_tasks(environment):
    while True:
        manage_user_lifecycle(environment)
        log_user_stats(environment)
        gevent.sleep(config['lifecycle']['check_interval'])