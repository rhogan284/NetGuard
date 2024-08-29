import random
import json
import logging
import time
import uuid
from locust import HttpUser, task, between
from locust.contrib.fasthttp import FastHttpUser
from datetime import datetime

json_logger = logging.getLogger('json_logger')
json_logger.setLevel(logging.INFO)
json_handler = logging.FileHandler('/mnt/logs/threat_locust_json.log')
json_handler.setFormatter(logging.Formatter('%(message)s'))
json_logger.addHandler(json_handler)

class MaliciousUser(FastHttpUser):
    wait_time = between(1, 10)

    def on_start(self):
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

    @task(2)
    def sql_injection_attempt(self):
        payloads = [
            "' OR '1'='1",
            "' UNION SELECT username, password FROM users--",
            "admin'--",
            "1; DROP TABLE users--",
            "' OR 1=1--",
        ]
        payload = random.choice(payloads)
        self._log_request("GET", f"/products?id={payload}", None, "sql_injection")

    @task(2)
    def xss_attempt(self):
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
        ]
        payload = random.choice(payloads)
        self._log_request("POST", "/search", {"q": payload}, "xss")

    @task(3)
    def brute_force_login(self):
        usernames = ['admin', 'root', 'user', 'test', 'guest']
        passwords = ['password', '123456', 'admin', 'qwerty', 'letmein']
        username = random.choice(usernames)
        password = random.choice(passwords)
        self._log_request("POST", "/login", {"username": username, "password": password}, "brute_force")

    @task(1)
    def path_traversal_attempt(self):
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/hosts",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
        ]
        payload = random.choice(payloads)
        self._log_request("GET", f"/static/{payload}", None, "path_traversal")

    @task(1)
    def command_injection_attempt(self):
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
    def ddos_simulation(self):
        endpoints = ['/', '/products', '/cart', '/checkout', '/search']
        for _ in range(random.randint(5, 15)):
            endpoint = random.choice(endpoints)
            self._log_request("GET", endpoint, None, "ddos")

    def _log_request(self, method, path, data, threat_type):
        log_id = str(uuid.uuid4())
        start_time = time.time()
        try:
            if method == "GET":
                response = self.client.get(path)
            elif method == "POST":
                response = self.client.post(path, json=data)
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
            "request_headers": dict(response.request.headers),
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