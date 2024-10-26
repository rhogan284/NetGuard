import json
import os
import time
import urllib.parse
from datetime import datetime, timedelta
from functools import wraps

import docker
import psycopg2
import psycopg2.extras
import yaml
from elasticsearch import Elasticsearch
from flask import Flask, render_template, request, redirect, url_for, session, flash

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

    return render_template('config.html', locust_config=locust_config, detector_config=detector_config,
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


@app.errorhandler(500)
def internal_error(error):
    flash('An error occurred. Please try again later.')
    return render_template('error.html'), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5123, debug=True)
