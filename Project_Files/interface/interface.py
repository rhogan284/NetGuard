import glob
import json
import os
import time
import urllib.parse
from collections import defaultdict
from datetime import datetime, timedelta
from functools import wraps

import docker
import psycopg2
import psycopg2.extras
import yaml
from elasticsearch import Elasticsearch
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify

app = Flask(__name__, template_folder="templates")
app.secret_key = 'your_secret_key'

users = {
    'admin': 'password123'
}

docker_client = docker.DockerClient(base_url='unix://var/run/docker.sock')
es = Elasticsearch([{'host': 'elasticsearch', 'port': 9200}])


def load_config(file_path):
    with open(file_path, 'r') as f:
        return yaml.safe_load(f)


def save_config(file_path, config):
    with open(file_path, 'w') as f:
        yaml.dump(config, f)


def restart_container(container_name):
    try:
        container = docker_client.containers.get(container_name)
        app.logger.info(f"Restarting container: {container.name} (ID: {container.id})")
        container.restart()
        for i in range(30):
            container.reload()
            if container.status == 'running':
                app.logger.info(
                    f"Container {container_name} successfully restarted. Current status: {container.status}")
                return True
            time.sleep(1)

    except docker.errors.NotFound:
        app.logger.error(f"Container {container_name} not found")
        return False
    except Exception as e:
        app.logger.error(f"Error restarting container {container_name}: {str(e)}")
        return False


def get_db_connection():
    return psycopg2.connect(
        host=os.environ.get('POSTGRES_HOST', 'db'),
        database=os.environ.get('POSTGRES_DB', 'ecommerce'),
        user=os.environ.get('POSTGRES_USER', 'user'),
        password=os.environ.get('POSTGRES_PASSWORD', 'password')
    )


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in to access this page.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


def calculate_metrics():
    try:
        app.logger.info("Starting metrics calculation")

        metrics = {
            'current_latency': 0,
            'detection_rate': 0,
            'total_requests': 0,
            'threats_detected': 0,
            'latency_history': [],
            'detection_history': []
        }

        log_files = glob.glob('/mnt/logs/*_json.log')
        app.logger.info(f"Found log files: {log_files}")

        logs = []
        for log_file in log_files:
            try:
                with open(log_file, 'r') as f:
                    file_logs = [json.loads(line) for line in f if line.strip()]
                    app.logger.info(f"Read {len(file_logs)} logs from {log_file}")
                    logs.extend(file_logs)
            except Exception as e:
                app.logger.error(f"Error reading log file {log_file}: {e}")

        if not logs:
            app.logger.warning("No logs found")
            return metrics

        app.logger.info(f"Total logs collected: {len(logs)}")

        now = datetime.utcnow()
        one_minute_ago = now - timedelta(minutes=1)

        recent_logs = []
        for log in logs:
            try:
                timestamp_str = log['@timestamp']
                if 'Z' in timestamp_str:
                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                else:
                    timestamp = datetime.fromisoformat(timestamp_str)

                if timestamp >= one_minute_ago:
                    recent_logs.append((timestamp, log))
            except Exception as e:
                app.logger.error(f"Error parsing timestamp: {e}")
                continue

        app.logger.info(f"Recent logs (last minute): {len(recent_logs)}")

        if not recent_logs:
            return metrics

        five_seconds_ago = now - timedelta(seconds=5)
        current_logs = [
            log for timestamp, log in recent_logs
            if timestamp >= five_seconds_ago
        ]

        app.logger.info(f"Logs in last 5 seconds: {len(current_logs)}")

        if current_logs:
            metrics['current_latency'] = round(
                sum(log.get('response_time_ms', 0) for log in current_logs) / len(current_logs)
            )
            metrics['total_requests'] = len(current_logs)
            metrics['threats_detected'] = sum(1 for log in current_logs if log.get('threat_type'))
            metrics['detection_rate'] = round(
                (metrics['threats_detected'] / metrics['total_requests']) * 100, 1
            ) if metrics['total_requests'] > 0 else 0

        time_slots = defaultdict(lambda: {'latencies': [], 'threats': 0, 'total': 0})

        for i in range(12):
            slot_time = now - timedelta(seconds=i * 5)
            slot_time = slot_time.replace(microsecond=0)
            slot_time = slot_time.replace(second=(slot_time.second // 5) * 5)
            time_slots[slot_time] = {'latencies': [], 'threats': 0, 'total': 0}

        for timestamp, log in recent_logs:
            try:
                slot_time = timestamp.replace(microsecond=0)
                slot_time = slot_time.replace(second=(slot_time.second // 5) * 5)

                if slot_time in time_slots:
                    time_slots[slot_time]['latencies'].append(log.get('response_time_ms', 0))
                    time_slots[slot_time]['total'] += 1
                    if log.get('threat_type'):
                        time_slots[slot_time]['threats'] += 1
            except Exception as e:
                app.logger.error(f"Error processing log for time slots: {e}")
                continue

        history_points = []
        for slot_time in sorted(time_slots.keys(), reverse=True):
            slot_data = time_slots[slot_time]
            avg_latency = round(sum(slot_data['latencies']) / len(slot_data['latencies'])) if slot_data[
                'latencies'] else 0
            detection_rate = round((slot_data['threats'] / slot_data['total']) * 100, 1) if slot_data[
                                                                                                'total'] > 0 else 0

            history_points.append({
                'time': slot_time.strftime('%H:%M:%S'),
                'latency': avg_latency,
                'detection_rate': detection_rate
            })

        history_points.reverse()

        metrics['latency_history'] = history_points
        metrics['detection_history'] = history_points

        # app.logger.info(f"Final metrics calculated: {json.dumps(metrics, indent=2)}")
        return metrics

    except Exception as e:
        app.logger.error(f"Error calculating metrics: {e}")
        return None


@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match.')
            return render_template('register.html')

        try:
            conn = get_db_connection()
            cur = conn.cursor()

            cur.execute('SELECT id FROM users WHERE username = %s', (username,))
            if cur.fetchone() is not None:
                flash('Username already exists.')
                return render_template('register.html')

            cur.execute(
                'INSERT INTO users (username, password) VALUES (%s, %s)',
                (username, password)
            )

            conn.commit()
            cur.close()
            conn.close()

            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'An error occurred during registration: {str(e)}')
            return render_template('register.html')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        try:
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

            cur.execute('SELECT * FROM users WHERE username = %s AND password = %s',
                        (username, password))
            user = cur.fetchone()

            cur.close()
            conn.close()

            if user:
                session['username'] = username
                flash('Login successful!')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password.')
        except Exception as e:
            flash(f'An error occurred during login: {str(e)}')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.')
    return redirect(url_for('login'))


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if 'username' not in session:
        flash('Please log in to access the dashboard.')
        return redirect(url_for('login'))
    return render_template('dashboard.html')


@app.route('/config', methods=['GET', 'POST'])
@login_required
def config():
    if 'username' not in session:
        flash('Please log in to access the configuration.')
        return redirect(url_for('login'))

    locust_config = load_config('/mnt/locust/locust_config.yaml')
    detector_config = load_config('/app/detector_config.yaml')
    responder_config = load_config('/app/responder_config.yaml')

    if request.method == 'POST':
        try:
            locust_config['normal_users']['count'] = int(request.form.get('normal_users_count'))
            locust_config['threat_users']['count'] = int(request.form.get('threat_users_count'))

            threat_types = [
                'sql_injection', 'xss', 'path_traversal', 'command_injection',
                'brute_force', 'web_scraping', 'ddos'
            ]

            for threat_type in threat_types:
                enabled_key = f'{threat_type}_enabled'
                locust_config['threat_users'][threat_type]['enabled'] = request.form.get(enabled_key) is not None

            detector_config['ddos']['threshold'] = int(request.form.get('ddos_threshold'))
            responder_config['rate_limit']['max_requests'] = int(request.form.get('rate_limit_max_requests'))

            save_config('/mnt/locust/locust_config.yaml', locust_config)
            save_config('/app/detector_config.yaml', detector_config)
            save_config('/app/responder_config.yaml', responder_config)

            restart_container('project_files-locust-1')
            restart_container('project_files-threat-locust-1')
            restart_container('project_files-threat-detector-1')
            restart_container('project_files-threat-responder-1')

            flash('Configuration updated and services restarted.')
        except Exception as e:
            flash(f'Error updating configuration: {str(e)}')
        return redirect(url_for('config'))

    return render_template('config.html',
                           locust_config=locust_config,
                           detector_config=detector_config,
                           responder_config=responder_config)


@app.route('/logs')
@login_required
def logs():
    if 'username' not in session:
        flash('Please log in to view logs.')
        return redirect(url_for('login'))

    index = request.args.get('index', 'normal-logs')
    search_term = request.args.get('search', '')
    page = int(request.args.get('page', 1))
    page_size = 10
    time_filter = request.args.get('time_filter', '')

    time_value = request.args.get('time_value', '')
    time_unit = request.args.get('time_unit', 'minutes')

    body = {
        "query": {
            "bool": {
                "must": [
                    {"multi_match": {"query": search_term, "fields": ["*"]}} if search_term else {"match_all": {}}
                ]
            }
        },
        "sort": [
            {"@timestamp": {"order": "desc"}}
        ],
        "from": (page - 1) * page_size,
        "size": page_size
    }

    if time_value and time_unit:
        time_value = int(time_value)
        now = datetime.utcnow()
        if time_unit == 'minutes':
            time_from = now - timedelta(minutes=time_value)
        elif time_unit == 'seconds':
            time_from = now - timedelta(seconds=time_value)
        else:
            time_from = now - timedelta(minutes=time_value)

        body['query']['bool']['must'].append({
            "range": {
                "@timestamp": {
                    "gte": time_from.isoformat(),
                    "lte": now.isoformat()
                }
            }
        })

    result = es.search(index=index, body=body)

    logs = [hit['_source'] for hit in result['hits']['hits']]
    total_logs = result['hits']['total']['value']
    total_pages = (total_logs + page_size - 1) // page_size

    return render_template('logs.html',
                           logs=logs,
                           index=index,
                           search_term=search_term,
                           page=page,
                           total_pages=total_pages,
                           time_value=time_value,
                           time_unit=time_unit)


@app.route('/log_details')
@login_required
def log_details():
    if 'username' not in session:
        flash('Please log in to view log details.')
        return redirect(url_for('login'))

    log_data = request.args.get('log')
    if not log_data:
        flash('No log data provided.')
        return redirect(url_for('logs'))

    try:
        log = json.loads(urllib.parse.unquote(log_data))
    except json.JSONDecodeError:
        flash('Invalid log data.')
        return redirect(url_for('logs'))

    return render_template('log_details.html', log=log)


@app.route('/metrics')
@login_required
def get_metrics():
    metrics = calculate_metrics()
    if metrics is None:
        return jsonify({'error': 'Failed to calculate metrics'}), 500
    return jsonify(metrics)


@app.errorhandler(500)
def internal_error(error):
    flash('An error occurred. Please try again later.')
    return render_template('error.html'), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5123, debug=True)
