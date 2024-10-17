# NetGuard

NetGuard is a comprehensive e-commerce platform simulation with integrated logging, monitoring, threat detection, and automated response capabilities. It leverages the ELK (Elasticsearch, Logstash, Kibana) stack for log management and analysis, and includes both normal user traffic simulation and potential security threat simulations.

## Project Structure

```
.
├── db/
│   └── init.sql
├── interface/
│   ├── templates/
│   │   ├── dashboard.html
│   │   ├── error.html
│   │   └── login.html
│   └── interface.py
├── locust/
│   ├── Dockerfile.locust
│   ├── locust_config.yaml
│   ├── locustfile.py
│   ├── logging_config.yaml
│   └── threat_locustfile.py
├── logstash/
│   ├── logstash.conf
│   └── logstash.yaml
├── threat_detector/
│   ├── detector_config.yaml
│   ├── Dockerfile.detector
│   ├── Dockerfile.responder
│   ├── requirements.txt
│   ├── responder_config.yaml
│   ├── threat_detector.py
│   └── threat_responder.py
├── web/
│   ├── app.py
│   ├── Dockerfile
│   └── requirements.txt
└── docker-compose.yml
```

## Components

1. **Web Application**: A Flask-based e-commerce API simulating basic operations.
2. **Database**: PostgreSQL database storing product information.
3. **Redis**: Used for caching and managing blocked IP addresses.
4. **Load Testing**: Two Locust instances simulating normal user traffic and potential security threats.
5. **ELK Stack**: 
   - Elasticsearch for storing and indexing logs
   - Logstash for log processing and ingestion
   - Kibana for log visualization and analysis
6. **Threat Detector**: A Python-based service that analyzes logs in real-time to detect potential security threats.
7. **Threat Responder**: A Python-based service that automatically responds to detected threats.
8. **Interface**: A Flask-based web interface for viewing the Kibana dashboard and managing the system.

## Setup and Running

1. Ensure you have Docker and Docker Compose installed on your system.

2. Clone this repository:
   ```
   git clone <repository-url>
   cd <repository-directory>
   ```

3. Start the services:
   ```
   docker compose up --build
   ```

4. Access the components:
   - Web API: http://localhost:5002
   - Kibana: http://localhost:5601
   - Locust (normal traffic): http://localhost:8089
   - Locust (threat simulation): Running in headless mode
   - Interface: http://localhost:5000 (assuming the interface runs on port 5000)

## Usage

1. **Web Application**: 
   - The Flask app provides basic e-commerce endpoints like product listing, cart management, and checkout.

2. **Load Testing**:
   - Normal traffic simulation: Use the Locust web interface at http://localhost:8089 to start and manage load tests.
   - Threat simulation: This runs automatically in headless mode, simulating various types of attacks.

3. **Log Analysis**:
   - Access Kibana at http://localhost:5601
   - Set up index patterns for "locust-logs-*", "threat-logs", and "normal-logs"
   - Create visualizations and dashboards to analyze the simulated traffic and potential security threats

4. **Threat Detection**:
   - The threat detector service continuously analyzes logs from Elasticsearch
   - Detected threats are logged to `/mnt/logs/detected_threats.log` and indexed in Elasticsearch
   - Configure detection rules and thresholds in `threat_detector/detector_config.yaml`

5. **Threat Response**:
   - The threat responder service automatically takes action based on detected threats
   - Actions include blocking IPs, rate limiting, and logging
   - Configure response actions in `threat_detector/responder_config.yaml`

6. **Interface**:
   - Access the web interface at http://localhost:5000
   - Log in using the credentials specified in the `interface.py` file
   - View the Kibana dashboard and manage system settings

## Monitoring and Logging

- All logs are centralized in Elasticsearch
- Kibana provides real-time visualizations and dashboards
- The Threat Detector continuously monitors for suspicious activities
- The Threat Responder takes automated actions to mitigate detected threats
- The Interface provides a user-friendly way to view and manage the system

## Customisation

- Modify `threat_detector/detector_config.yaml` to adjust threat detection rules and thresholds
- Update `threat_detector/responder_config.yaml` to customize automated response actions
- Edit `locust/threat_locustfile.py` to simulate different types of attacks
- Customize the interface by modifying the templates in `interface/templates/`