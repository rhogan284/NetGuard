# NetGuard

NetGuard is a comprehensive e-commerce platform simulation with integrated logging, monitoring, threat detection, and automated response capabilities. It leverages the ELK (Elasticsearch, Logstash, Kibana) stack for log management and analysis, and includes both normal user traffic simulation and potential security threat simulations.

## Project Structure

```
.
├── db/
├── interface/
├── locust/
├── logstash/
├── threat_detector/
├── web/
└── docker-compose.yml
```

## Components

1. **Web Application**: A Flask-based e-commerce API simulating basic operations, including product management, cart operations, and user authentication.
2. **Database**: PostgreSQL database storing product and user information with secure password storage.
3. **Redis**: Used for caching, managing blocked IP addresses, and rate limiting.
4. **Load Testing**: 
   - Normal traffic Locust instance with configurable user behavior patterns
   - Threat simulation Locust instance with various attack patterns including SQL injection, XSS, path traversal, and DDoS
5. **ELK Stack**: 
   - Elasticsearch for storing and indexing logs
   - Logstash for log processing with separate normal and threat log streams
   - Kibana for log visualization and analysis with preconfigured dashboards
6. **Threat Detector**: Real-time log analysis with configurable detection rules for various attack patterns.
7. **Threat Responder**: Automated response system with configurable actions including IP blocking, rate limiting, and threat logging.
8. **Interface**: A comprehensive web interface featuring:
   - User authentication and registration
   - Real-time monitoring dashboard
   - Configuration management for all components
   - Detailed log viewing and filtering
   - Threat analysis and response monitoring

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
   - Interface: http://localhost:5123

## Usage

1. **Web Application**: 
   - RESTful API endpoints for product listing, cart management, and checkout
   - User authentication and session management
   - Rate limiting and IP blocking protection

2. **Load Testing**:
   - Normal traffic simulation with configurable user counts and behavior patterns
   - Comprehensive threat simulation including:
     - SQL injection attempts
     - Cross-site scripting (XSS)
     - Path traversal attacks
     - Command injection
     - Brute force attempts
     - Web scraping
     - DDoS attacks

3. **Log Analysis**:
   - Access Kibana at http://localhost:5601
   - Preconfigured index patterns for different log types
   - Real-time log streaming and analysis
   - Advanced search and filtering capabilities
   - Custom visualization options

4. **Threat Detection**:
   - Pattern-based threat detection using regular expressions
   - Rate-based attack detection (DDoS, brute force)
   - Configurable detection rules and thresholds
   - Real-time threat analysis and logging

5. **Threat Response**:
   - Automated response actions based on threat type
   - IP blocking with configurable duration
   - Rate limiting with adjustable thresholds
   - Detailed threat logging and analysis
   - Redis-based blocked IP management

6. **Interface**:
   - Secure user authentication and registration
   - Real-time monitoring dashboard
   - Detailed log viewing with filtering and search
   - Configuration management for all components
   - System health monitoring

## Monitoring and Logging

- Centralized logging in Elasticsearch with separate indices for normal and threat logs
- Real-time log processing through Logstash
- Comprehensive Kibana dashboards for system monitoring
- Detailed threat detection and response logging
- User-friendly interface for log analysis and system management

## Customisation

- Modify `threat_detector/detector_config.yaml` to adjust threat detection rules and thresholds
- Update `threat_detector/responder_config.yaml` to customize automated response actions
- Edit `locust/locust_config.yaml` to adjust load testing parameters
- Customize attack patterns in `locust/payloads/` directory
- Modify interface templates in `interface/templates/` for UI customization
- Adjust logging configuration in `logstash/logstash.conf` and `logging_config.yaml`