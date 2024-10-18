from flask import Flask, render_template, request, redirect, url_for, session, flash
import time

app = Flask(__name__)
app.secret_key = 'your_secret_key'

users = {
    'admin': 'password123'
}

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username] == password:
            session['username'] = username
            flash('Login successful!')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.')
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'username' not in session:
        flash('Please log in to access the dashboard.')
        return redirect(url_for('login'))

    time_range = 'now-15m'  # Last 15 minutes
    auto_refresh = '30s'    # Default refresh interval

    if request.method == 'POST':
        time_range = request.form.get('time_range')
        auto_refresh = request.form.get('auto_refresh')

    kibana_url = f"http://your_kibana_ip:5601/app/kibana#/dashboard/12345678-1234-1234-1234-123456789abc?embed=true&_g=(time:(from:{time_range},to:now),refreshInterval:(pause:!f,value:{auto_refresh}))"
    return render_template('dashboard.html', kibana_url=kibana_url, time_range=time_range, auto_refresh=auto_refresh)

@app.errorhandler(500)
def internal_error(error):
    flash('An error occurred. Please try again later.')
    return render_template('error.html'), 500

if __name__ == '__main__':
    app.run(port=6000, debug=True)