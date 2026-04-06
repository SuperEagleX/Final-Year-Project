"""
PhishGuard Backend API
======================
A RESTful API built with Python Flask for the PhishGuard phishing
simulation and security awareness platform.

Author: [Your Name]
Student ID: [Your ID]
Final Year Project — Cybersecurity
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import hashlib
import hmac
import secrets
import csv
import io
import json
from datetime import datetime, timedelta

# ── App Setup ──────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)  # Allow frontend to talk to this API

DB_PATH    = 'phishguard.db'
SECRET_KEY = 'phishguard-secret-key-change-in-production'


# ── Database Setup ─────────────────────────────────────────────────────────
def get_db():
    """Get a database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Return rows as dictionaries
    return conn


def init_db():
    """Create all database tables if they don't exist."""
    conn = get_db()
    c = conn.cursor()

    # Users table (admins and employees)
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT NOT NULL,
            email      TEXT UNIQUE NOT NULL,
            password   TEXT NOT NULL,
            role       TEXT DEFAULT 'employee',
            department TEXT DEFAULT '',
            risk_score INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Campaigns table
    c.execute('''
        CREATE TABLE IF NOT EXISTS campaigns (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            name         TEXT NOT NULL,
            template     TEXT DEFAULT '',
            status       TEXT DEFAULT 'draft',
            sender_name  TEXT DEFAULT '',
            sender_email TEXT DEFAULT '',
            start_date   TEXT DEFAULT '',
            end_date     TEXT DEFAULT '',
            created_at   TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Employees targeted in each campaign
    c.execute('''
        CREATE TABLE IF NOT EXISTS campaign_targets (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_id INTEGER,
            name        TEXT,
            email       TEXT,
            department  TEXT,
            FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
        )
    ''')

    # Tracking events (opened, clicked, submitted, reported)
    c.execute('''
        CREATE TABLE IF NOT EXISTS tracking_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_id INTEGER,
            email       TEXT,
            event_type  TEXT,
            ip_address  TEXT DEFAULT '',
            user_agent  TEXT DEFAULT '',
            timestamp   TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
        )
    ''')

    # Training modules
    c.execute('''
        CREATE TABLE IF NOT EXISTS training_modules (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            title       TEXT NOT NULL,
            description TEXT DEFAULT '',
            duration    TEXT DEFAULT '5 min',
            difficulty  TEXT DEFAULT 'beginner',
            order_num   INTEGER DEFAULT 0
        )
    ''')

    # Quiz results
    c.execute('''
        CREATE TABLE IF NOT EXISTS quiz_results (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER,
            module_id   INTEGER,
            score       INTEGER,
            total       INTEGER,
            percentage  INTEGER,
            passed      INTEGER DEFAULT 0,
            completed_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (module_id) REFERENCES training_modules(id)
        )
    ''')

    # Badges earned by employees
    c.execute('''
        CREATE TABLE IF NOT EXISTS badges (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER,
            badge_name  TEXT,
            badge_icon  TEXT,
            earned_at   TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')

    # Seed default admin user
    admin_password = hash_password('admin123')
    c.execute('''
        INSERT OR IGNORE INTO users (name, email, password, role, department)
        VALUES (?, ?, ?, ?, ?)
    ''', ('Super Admin', 'admin@phishguard.com', admin_password, 'admin', 'IT Security'))

    # Seed default employee user
    emp_password = hash_password('emp123')
    c.execute('''
        INSERT OR IGNORE INTO users (name, email, password, role, department)
        VALUES (?, ?, ?, ?, ?)
    ''', ('James Lim', 'employee@phishguard.com', emp_password, 'employee', 'Finance'))

    # Seed training modules
    modules = [
        ('What is Phishing?',                      'Learn the basics of phishing attacks',              '5 min',  'beginner',     1),
        ('Spotting Suspicious Links & Domains',    'Learn to identify fake URLs and domains',           '7 min',  'beginner',     2),
        ('Urgency & Social Engineering Tactics',   'Understand manipulation techniques used by hackers','8 min',  'intermediate', 3),
        ('Analysing Email Headers & Sender Info',  'Learn to read and verify email headers',            '10 min', 'intermediate', 4),
        ('Business Email Compromise (BEC)',        'Understand CEO fraud and BEC attacks',              '12 min', 'advanced',     5),
        ('What To Do When You Are Phished',        'Steps to take after falling for a phishing attack', '6 min',  'beginner',     6),
    ]
    c.executemany('''
        INSERT OR IGNORE INTO training_modules (title, description, duration, difficulty, order_num)
        VALUES (?, ?, ?, ?, ?)
    ''', modules)

    conn.commit()
    conn.close()
    print('✅ Database initialised successfully')


# ── Helper Functions ───────────────────────────────────────────────────────
def hash_password(password):
    """Hash a password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()


def generate_token(user_id, role):
    """Generate a simple session token."""
    raw = f'{user_id}:{role}:{secrets.token_hex(16)}'
    return hashlib.sha256(raw.encode()).hexdigest()


def get_token_from_request():
    """Extract Bearer token from Authorization header."""
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        return auth[7:]
    return None


def calculate_risk_score(email):
    """
    Calculate employee risk score based on their phishing simulation history.

    Risk Score Formula (0-100):
    - Each click event:      +25 points
    - Each submission event: +35 points
    - Each open event:       +5  points
    - Each report event:     -10 points (good behaviour)
    - Completed training:    -15 points per module passed
    Score is clamped between 0 and 100.
    """
    conn = get_db()
    c = conn.cursor()

    # Get all tracking events for this employee
    c.execute('SELECT event_type FROM tracking_events WHERE email = ?', (email,))
    events = c.fetchall()

    score = 0
    for event in events:
        t = event['event_type']
        if   t == 'clicked':   score += 25
        elif t == 'submitted': score += 35
        elif t == 'opened':    score += 5
        elif t == 'reported':  score -= 10

    # Get user id
    c.execute('SELECT id FROM users WHERE email = ?', (email,))
    user = c.fetchone()
    if user:
        # Deduct points for completed training modules
        c.execute('''
            SELECT COUNT(*) as cnt FROM quiz_results
            WHERE user_id = ? AND passed = 1
        ''', (user['id'],))
        passed = c.fetchone()['cnt']
        score -= passed * 15

    conn.close()

    # Clamp between 0 and 100
    return max(0, min(100, score))


def update_risk_score(email):
    """Recalculate and save risk score for an employee."""
    score = calculate_risk_score(email)
    conn = get_db()
    conn.execute('UPDATE users SET risk_score = ? WHERE email = ?', (score, email))
    conn.commit()
    conn.close()
    return score


# ── Auth Routes ────────────────────────────────────────────────────────────
@app.route('/api/login', methods=['POST'])
def login():
    """
    POST /api/login
    Authenticate a user and return a session token.
    Body: { email, password }
    """
    data = request.get_json()
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Email and password required'}), 400

    conn = get_db()
    user = conn.execute(
        'SELECT * FROM users WHERE email = ? AND password = ?',
        (data['email'], hash_password(data['password']))
    ).fetchone()
    conn.close()

    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401

    token = generate_token(user['id'], user['role'])

    return jsonify({
        'success': True,
        'token':   token,
        'user': {
            'id':         user['id'],
            'name':       user['name'],
            'email':      user['email'],
            'role':       user['role'],
            'department': user['department'],
            'risk_score': user['risk_score'],
        }
    })


# ── Dashboard Routes ───────────────────────────────────────────────────────
@app.route('/api/dashboard/stats', methods=['GET'])
def dashboard_stats():
    """
    GET /api/dashboard/stats
    Returns live stats for the admin dashboard.
    """
    conn = get_db()

    # Total emails sent (all tracking events)
    total_sent = conn.execute(
        'SELECT COUNT(DISTINCT email) FROM tracking_events'
    ).fetchone()[0]

    # Count each event type
    opened    = conn.execute("SELECT COUNT(*) FROM tracking_events WHERE event_type='opened'").fetchone()[0]
    clicked   = conn.execute("SELECT COUNT(*) FROM tracking_events WHERE event_type='clicked'").fetchone()[0]
    submitted = conn.execute("SELECT COUNT(*) FROM tracking_events WHERE event_type='submitted'").fetchone()[0]
    reported  = conn.execute("SELECT COUNT(*) FROM tracking_events WHERE event_type='reported'").fetchone()[0]

    # Total campaigns
    total_campaigns = conn.execute('SELECT COUNT(*) FROM campaigns').fetchone()[0]
    active_campaigns = conn.execute(
        "SELECT COUNT(*) FROM campaigns WHERE status='active'"
    ).fetchone()[0]

    # Total employees
    total_employees = conn.execute(
        "SELECT COUNT(*) FROM users WHERE role='employee'"
    ).fetchone()[0]

    # High risk employees (score >= 70)
    high_risk = conn.execute(
        "SELECT COUNT(*) FROM users WHERE role='employee' AND risk_score >= 70"
    ).fetchone()[0]

    conn.close()

    # Calculate rates
    open_rate   = round((opened   / total_sent * 100), 1) if total_sent > 0 else 0
    click_rate  = round((clicked  / total_sent * 100), 1) if total_sent > 0 else 0
    report_rate = round((reported / total_sent * 100), 1) if total_sent > 0 else 0

    return jsonify({
        'total_sent':       total_sent,
        'open_rate':        open_rate,
        'click_rate':       click_rate,
        'report_rate':      report_rate,
        'total_campaigns':  total_campaigns,
        'active_campaigns': active_campaigns,
        'total_employees':  total_employees,
        'high_risk_count':  high_risk,
    })


# ── Campaign Routes ────────────────────────────────────────────────────────
@app.route('/api/campaigns', methods=['GET'])
def get_campaigns():
    """GET /api/campaigns — List all campaigns with their stats."""
    conn = get_db()
    campaigns = conn.execute(
        'SELECT * FROM campaigns ORDER BY created_at DESC'
    ).fetchall()

    result = []
    for c in campaigns:
        cid = c['id']
        # Get target count
        targets = conn.execute(
            'SELECT COUNT(*) FROM campaign_targets WHERE campaign_id=?', (cid,)
        ).fetchone()[0]
        # Get event counts
        clicked  = conn.execute(
            "SELECT COUNT(*) FROM tracking_events WHERE campaign_id=? AND event_type='clicked'", (cid,)
        ).fetchone()[0]
        opened   = conn.execute(
            "SELECT COUNT(*) FROM tracking_events WHERE campaign_id=? AND event_type='opened'", (cid,)
        ).fetchone()[0]
        reported = conn.execute(
            "SELECT COUNT(*) FROM tracking_events WHERE campaign_id=? AND event_type='reported'", (cid,)
        ).fetchone()[0]

        result.append({
            'id':           cid,
            'name':         c['name'],
            'template':     c['template'],
            'status':       c['status'],
            'sender_name':  c['sender_name'],
            'sender_email': c['sender_email'],
            'start_date':   c['start_date'],
            'end_date':     c['end_date'],
            'created_at':   c['created_at'],
            'stats': {
                'total':    targets,
                'opened':   opened,
                'clicked':  clicked,
                'reported': reported,
                'click_rate': round(clicked / targets * 100, 1) if targets > 0 else 0,
            }
        })

    conn.close()
    return jsonify(result)


@app.route('/api/campaigns', methods=['POST'])
def create_campaign():
    """POST /api/campaigns — Create a new campaign."""
    data = request.get_json()
    if not data or not data.get('name'):
        return jsonify({'error': 'Campaign name is required'}), 400

    conn = get_db()
    cursor = conn.execute('''
        INSERT INTO campaigns (name, template, status, sender_name, sender_email, start_date, end_date)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        data.get('name', ''),
        data.get('template', ''),
        data.get('status', 'draft'),
        data.get('sender_name', ''),
        data.get('sender_email', ''),
        data.get('start_date', ''),
        data.get('end_date', ''),
    ))
    campaign_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return jsonify({
        'success':     True,
        'campaign_id': campaign_id,
        'message':     f'Campaign "{data["name"]}" created successfully'
    }), 201


@app.route('/api/campaigns/<int:campaign_id>/status', methods=['PUT'])
def update_campaign_status(campaign_id):
    """PUT /api/campaigns/<id>/status — Update campaign status."""
    data = request.get_json()
    status = data.get('status', 'active')

    conn = get_db()
    conn.execute(
        'UPDATE campaigns SET status=? WHERE id=?', (status, campaign_id)
    )
    conn.commit()
    conn.close()

    return jsonify({'success': True, 'status': status})


# ── Employee Routes ────────────────────────────────────────────────────────
@app.route('/api/employees', methods=['GET'])
def get_employees():
    """GET /api/employees — List all employees with risk scores."""
    conn = get_db()
    employees = conn.execute('''
        SELECT id, name, email, department, risk_score
        FROM users WHERE role='employee'
        ORDER BY risk_score DESC
    ''').fetchall()
    conn.close()

    return jsonify([dict(e) for e in employees])


@app.route('/api/employees/upload', methods=['POST'])
def upload_employees():
    """
    POST /api/employees/upload
    Upload a CSV file of employees and add them to the database.
    Also assigns them to a campaign if campaign_id is provided.
    """
    data = request.get_json()
    if not data or not data.get('employees'):
        return jsonify({'error': 'No employee data provided'}), 400

    employees  = data['employees']       # List of {name, email, department}
    campaign_id = data.get('campaign_id')

    conn = get_db()
    added = 0
    for emp in employees:
        email = emp.get('email', '').strip()
        name  = emp.get('name', '').strip()
        dept  = emp.get('department', '').strip()

        if not email:
            continue

        # Add to users table if not already there
        existing = conn.execute(
            'SELECT id FROM users WHERE email=?', (email,)
        ).fetchone()

        if not existing:
            default_pw = hash_password('changeme123')
            conn.execute('''
                INSERT INTO users (name, email, password, role, department)
                VALUES (?, ?, ?, 'employee', ?)
            ''', (name, email, default_pw, dept))

        # Add to campaign targets if campaign_id given
        if campaign_id:
            conn.execute('''
                INSERT INTO campaign_targets (campaign_id, name, email, department)
                VALUES (?, ?, ?, ?)
            ''', (campaign_id, name, email, dept))
        added += 1

    conn.commit()
    conn.close()

    return jsonify({
        'success': True,
        'added':   added,
        'message': f'{added} employees uploaded successfully'
    }), 201


# ── Tracking Routes ────────────────────────────────────────────────────────
@app.route('/api/track/open', methods=['GET'])
def track_open():
    """
    GET /api/track/open?campaign_id=X&email=Y
    Called when an employee opens the phishing email.
    Returns a 1x1 transparent pixel (tracking pixel).
    """
    campaign_id = request.args.get('campaign_id')
    email       = request.args.get('email', '')

    if campaign_id and email:
        conn = get_db()
        conn.execute('''
            INSERT INTO tracking_events (campaign_id, email, event_type, ip_address, user_agent)
            VALUES (?, ?, 'opened', ?, ?)
        ''', (campaign_id, email, request.remote_addr, request.user_agent.string))
        conn.commit()
        conn.close()
        update_risk_score(email)

    # Return a 1x1 transparent GIF pixel
    pixel = b'\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00\x21\xf9\x04\x00\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b'
    from flask import Response
    return Response(pixel, mimetype='image/gif')


@app.route('/api/track/click', methods=['GET'])
def track_click():
    """
    GET /api/track/click?campaign_id=X&email=Y
    Called when an employee clicks the phishing link.
    Logs the click event then redirects to the phishing landing page.
    """
    campaign_id = request.args.get('campaign_id', '')
    email       = request.args.get('email', '')

    if campaign_id and email:
        conn = get_db()
        conn.execute('''
            INSERT INTO tracking_events (campaign_id, email, event_type, ip_address, user_agent)
            VALUES (?, ?, 'clicked', ?, ?)
        ''', (campaign_id, email, request.remote_addr, request.user_agent.string))
        conn.commit()
        conn.close()
        update_risk_score(email)
        print(f'🎣 Click tracked: {email} in campaign {campaign_id}')

    from flask import redirect
    # Redirect to phishing landing page — passes campaign_id and email so
    # the landing page can log a submission if the user enters credentials
    return redirect(
        f'http://127.0.0.1:8080/phishing-landing.html'
        f'?campaign_id={campaign_id}&email={email}'
    )


@app.route('/api/track/submit', methods=['POST'])
def track_submit():
    """
    POST /api/track/submit
    Called when an employee submits credentials on the phishing landing page.
    Body: { campaign_id, email }
    This is the highest-risk event — employee both clicked AND entered credentials.
    """
    data        = request.get_json()
    campaign_id = data.get('campaign_id')
    email       = data.get('email', '')

    if not campaign_id or not email:
        return jsonify({'error': 'campaign_id and email required'}), 400

    conn = get_db()
    conn.execute('''
        INSERT INTO tracking_events (campaign_id, email, event_type, ip_address, user_agent)
        VALUES (?, ?, 'submitted', ?, ?)
    ''', (campaign_id, email, request.remote_addr, request.user_agent.string))
    conn.commit()
    conn.close()

    new_score = update_risk_score(email)
    print(f'🚨 Credentials submitted: {email} in campaign {campaign_id} | New risk score: {new_score}')

    return jsonify({
        'success':       True,
        'new_risk_score': new_score,
        'redirect':       f'http://127.0.0.1:8080/awareness-training.html?caught=1&campaign_id={campaign_id}'
    })


@app.route('/api/track/report', methods=['POST'])
def track_report():
    """
    POST /api/track/report
    Called when an employee reports a phishing email.
    Body: { campaign_id, email }
    """
    data        = request.get_json()
    campaign_id = data.get('campaign_id')
    email       = data.get('email', '')

    if campaign_id and email:
        conn = get_db()
        conn.execute('''
            INSERT INTO tracking_events (campaign_id, email, event_type)
            VALUES (?, ?, 'reported')
        ''', (campaign_id, email))
        conn.commit()
        conn.close()
        score = update_risk_score(email)
        return jsonify({'success': True, 'new_risk_score': score})

    return jsonify({'error': 'Missing campaign_id or email'}), 400


# ── Training Routes ────────────────────────────────────────────────────────
@app.route('/api/training/modules', methods=['GET'])
def get_modules():
    """GET /api/training/modules — List all training modules."""
    conn    = get_db()
    modules = conn.execute(
        'SELECT * FROM training_modules ORDER BY order_num'
    ).fetchall()
    conn.close()
    return jsonify([dict(m) for m in modules])


@app.route('/api/training/progress/<int:user_id>', methods=['GET'])
def get_progress(user_id):
    """
    GET /api/training/progress/<user_id>
    Get training progress and quiz results for an employee.
    """
    conn = get_db()

    # Get all quiz results for this user
    results = conn.execute('''
        SELECT qr.*, tm.title, tm.difficulty
        FROM quiz_results qr
        JOIN training_modules tm ON qr.module_id = tm.id
        WHERE qr.user_id = ?
        ORDER BY qr.completed_at DESC
    ''', (user_id,)).fetchall()

    # Get badges
    badges = conn.execute(
        'SELECT * FROM badges WHERE user_id=?', (user_id,)
    ).fetchall()

    # Get total modules
    total_modules = conn.execute(
        'SELECT COUNT(*) FROM training_modules'
    ).fetchone()[0]

    # Count passed modules
    passed_modules = conn.execute('''
        SELECT COUNT(DISTINCT module_id) FROM quiz_results
        WHERE user_id=? AND passed=1
    ''', (user_id,)).fetchone()[0]

    conn.close()

    return jsonify({
        'user_id':        user_id,
        'total_modules':  total_modules,
        'passed_modules': passed_modules,
        'completion_pct': round(passed_modules / total_modules * 100) if total_modules > 0 else 0,
        'quiz_results':   [dict(r) for r in results],
        'badges':         [dict(b) for b in badges],
    })


@app.route('/api/quiz/submit', methods=['POST'])
def submit_quiz():
    """
    POST /api/quiz/submit
    Save a quiz result and update the employee's risk score.
    Body: { user_id, module_id, score, total }
    """
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    user_id   = data.get('user_id')
    module_id = data.get('module_id')
    score     = data.get('score', 0)
    total     = data.get('total', 5)

    if not user_id or not module_id:
        return jsonify({'error': 'user_id and module_id required'}), 400

    percentage = round(score / total * 100)
    passed     = 1 if percentage >= 60 else 0

    conn = get_db()

    # Save quiz result
    conn.execute('''
        INSERT INTO quiz_results (user_id, module_id, score, total, percentage, passed)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (user_id, module_id, score, total, percentage, passed))

    # Award badge if passed
    badge_earned = None
    if passed:
        badges_map = {
            1: ('Phish Aware',    '🎣'),
            2: ('Link Detective', '🔍'),
            3: ('Pressure Pro',   '⚡'),
            4: ('Header Hero',    '📧'),
            5: ('BEC Buster',     '🏢'),
            6: ('Cyber Shield',   '🛡️'),
        }
        if module_id in badges_map:
            badge_name, badge_icon = badges_map[module_id]
            # Only award badge once
            existing_badge = conn.execute('''
                SELECT id FROM badges WHERE user_id=? AND badge_name=?
            ''', (user_id, badge_name)).fetchone()

            if not existing_badge:
                conn.execute('''
                    INSERT INTO badges (user_id, badge_name, badge_icon)
                    VALUES (?, ?, ?)
                ''', (user_id, badge_name, badge_icon))
                badge_earned = {'name': badge_name, 'icon': badge_icon}

    # Get user email to update risk score
    user = conn.execute('SELECT email FROM users WHERE id=?', (user_id,)).fetchone()
    conn.commit()
    conn.close()

    new_risk_score = 0
    if user and passed:
        new_risk_score = update_risk_score(user['email'])

    return jsonify({
        'success':        True,
        'percentage':     percentage,
        'passed':         bool(passed),
        'badge_earned':   badge_earned,
        'new_risk_score': new_risk_score,
        'message':        f'Quiz submitted! You scored {percentage}%'
    })


# ── Risk Score Route ───────────────────────────────────────────────────────
@app.route('/api/employees/<int:user_id>/risk', methods=['GET'])
def get_risk_score(user_id):
    """GET /api/employees/<id>/risk — Get current risk score for an employee."""
    conn = get_db()
    user = conn.execute(
        'SELECT email, risk_score FROM users WHERE id=?', (user_id,)
    ).fetchone()
    conn.close()

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Recalculate fresh score
    fresh_score = update_risk_score(user['email'])

    level = 'low'
    if fresh_score >= 70: level = 'high'
    elif fresh_score >= 40: level = 'medium'

    return jsonify({
        'user_id':    user_id,
        'risk_score': fresh_score,
        'risk_level': level,
    })


import os
import urllib.request
import ssl

# ── GoPhish Integration ────────────────────────────────────────────────────
GOPHISH_URL     = 'https://127.0.0.1:3333'
GOPHISH_API_KEY = 'YOUR_GOPHISH_API_KEY_HERE'  # ← paste your GoPhish API key

def gophish_request(endpoint, method='GET', data=None):
    """Make an authenticated request to the GoPhish API."""
    url     = f'{GOPHISH_URL}/api/{endpoint}/?api_key={GOPHISH_API_KEY}'
    headers = {'Content-Type': 'application/json'}
    body    = json.dumps(data).encode() if data else None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    req      = urllib.request.Request(url, data=body, headers=headers, method=method)
    response = urllib.request.urlopen(req, context=ctx)
    return json.loads(response.read().decode())


# ── Template File Loader ───────────────────────────────────────────────────
TEMPLATES_DIR  = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
TEMPLATES_META = os.path.join(TEMPLATES_DIR, 'templates.json')

def load_templates():
    """Load all template metadata from templates.json."""
    with open(TEMPLATES_META, 'r') as f:
        return json.load(f)

def load_template_html(filename):
    """Load HTML content of a specific template file."""
    path = os.path.join(TEMPLATES_DIR, filename)
    if not os.path.exists(path):
        raise FileNotFoundError(f'Template file not found: {filename}')
    with open(path, 'r') as f:
        return f.read()

def get_template_by_name(name):
    """Find a template by name and return its metadata + HTML."""
    templates = load_templates()
    for t in templates:
        if t['name'] == name:
            t['html'] = load_template_html(t['file'])
            return t
    # Default to first template if not found
    t = templates[0]
    t['html'] = load_template_html(t['file'])
    return t


# ── Awareness Landing Page ─────────────────────────────────────────────────
AWARENESS_PAGE_HTML = """<!DOCTYPE html>
<html>
<body style="font-family:Arial,sans-serif;text-align:center;padding:60px 20px;background:#020b18;color:#cde4f8">
  <div style="max-width:500px;margin:0 auto;background:#071628;border:1px solid #0d2847;border-radius:16px;padding:40px">
    <div style="font-size:4rem;margin-bottom:20px">🎣</div>
    <h1 style="color:#ff4560;margin-bottom:16px">You have been phished!</h1>
    <p style="color:#cde4f8;line-height:1.8;margin-bottom:24px">
      This was a <strong style="color:#00d4ff">simulated phishing test</strong> run by
      your company IT Security team.
    </p>
    <div style="background:#0d2847;border-radius:10px;padding:20px;text-align:left;margin-bottom:24px">
      <p style="color:#ffb300;font-weight:700;margin-bottom:12px">Red flags you missed:</p>
      <ul style="color:#cde4f8;line-height:2;padding-left:20px">
        <li>The sender domain was not the real company domain</li>
        <li>The email created artificial urgency</li>
        <li>It threatened consequences for not acting immediately</li>
      </ul>
    </div>
    <a href="http://127.0.0.1:8080/awareness-training.html"
       style="background:linear-gradient(135deg,#0077ff,#00d4ff);color:#000;
       padding:12px 28px;border-radius:8px;text-decoration:none;font-weight:800">
      Start Security Training
    </a>
  </div>
</body></html>"""


# ── Template Routes ────────────────────────────────────────────────────────
@app.route('/api/templates', methods=['GET'])
def get_templates():
    """GET /api/templates — List all available phishing templates."""
    try:
        templates = load_templates()
        return jsonify(templates)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/templates/<int:template_id>', methods=['GET'])
def get_template(template_id):
    """GET /api/templates/<id> — Get a single template with full HTML."""
    try:
        templates = load_templates()
        template  = next((t for t in templates if t['id'] == template_id), None)
        if not template:
            return jsonify({'error': 'Template not found'}), 404
        template['html'] = load_template_html(template['file'])
        return jsonify(template)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/templates', methods=['POST'])
def create_template():
    """
    POST /api/templates — Admin creates a new phishing template.
    Body: { name, subject, category, difficulty, description, sender_name, html }
    """
    data = request.get_json()
    required = ['name', 'subject', 'category', 'difficulty', 'html']
    for field in required:
        if not data.get(field):
            return jsonify({'error': f'Missing required field: {field}'}), 400
    try:
        templates = load_templates()
        filename  = data['name'].lower().replace(' ', '_').replace('/', '_') + '.html'
        filepath  = os.path.join(TEMPLATES_DIR, filename)

        # Save HTML file
        with open(filepath, 'w') as f:
            f.write(f"<!--\n  Template: {data['name']}\n  Category: {data['category']}\n  Difficulty: {data['difficulty']}\n-->\n{data['html']}")

        # Add to templates.json
        new_template = {
            'id':             max(t['id'] for t in templates) + 1 if templates else 1,
            'name':           data['name'],
            'file':           filename,
            'subject':        data['subject'],
            'category':       data['category'],
            'difficulty':     data['difficulty'],
            'description':    data.get('description', ''),
            'sender_name':    data.get('sender_name', 'IT Support'),
            'avg_click_rate': 0,
        }
        templates.append(new_template)
        with open(TEMPLATES_META, 'w') as f:
            json.dump(templates, f, indent=2)

        print(f'✅ New template created: {data["name"]} → {filename}')
        return jsonify({'success': True, 'template': new_template}), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/templates/<int:template_id>', methods=['DELETE'])
def delete_template(template_id):
    """DELETE /api/templates/<id> — Delete a template."""
    try:
        templates = load_templates()
        template  = next((t for t in templates if t['id'] == template_id), None)
        if not template:
            return jsonify({'error': 'Template not found'}), 404
        filepath = os.path.join(TEMPLATES_DIR, template['file'])
        if os.path.exists(filepath):
            os.remove(filepath)
        templates = [t for t in templates if t['id'] != template_id]
        with open(TEMPLATES_META, 'w') as f:
            json.dump(templates, f, indent=2)
        return jsonify({'success': True, 'message': f'Template "{template["name"]}" deleted'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── Campaign Send Route ────────────────────────────────────────────────────
@app.route('/api/campaigns/<int:campaign_id>/send', methods=['POST'])
def send_campaign_emails(campaign_id):
    """
    POST /api/campaigns/<id>/send
    Pushes campaign from PhishGuard into GoPhish and triggers email delivery.
    Templates come from YOUR backend — GoPhish only handles sending.
    """
    conn     = get_db()
    campaign = conn.execute(
        'SELECT * FROM campaigns WHERE id=?', (campaign_id,)
    ).fetchone()
    targets  = conn.execute(
        'SELECT * FROM campaign_targets WHERE campaign_id=?', (campaign_id,)
    ).fetchall()
    conn.close()

    if not campaign:
        return jsonify({'error': 'Campaign not found'}), 404
    if not targets:
        return jsonify({'error': 'No targets found — upload employees first'}), 400

    template_name = campaign['template'] or 'IT Password Reset'

    try:
        template = get_template_by_name(template_name)
    except Exception as e:
        return jsonify({'error': f'Could not load template: {str(e)}'}), 500

    try:
        gophish_template_name = f'PG_{campaign_id}_{template_name}'
        page_name  = f'PG_Awareness_{campaign_id}'
        group_name = f'PG_Group_{campaign_id}'
        camp_name  = f'PG_Campaign_{campaign_id}'

        # ── Helper: delete GoPhish object by name if it exists ──────────────
        def gophish_delete_if_exists(endpoint, name):
            """Find object by name and delete it so we can recreate cleanly."""
            try:
                items = gophish_request(endpoint)
                # items is a list; find matching name
                if isinstance(items, list):
                    for item in items:
                        if item.get('name') == name:
                            gophish_request(f'{endpoint}/{item["id"]}', 'DELETE')
                            print(f'🗑️  Deleted existing GoPhish {endpoint}: {name}')
                            break
            except Exception as e:
                print(f'⚠️ Could not clean up {endpoint}/{name}: {e}')

        # Step 1 — Clean up then push YOUR template into GoPhish
        gophish_delete_if_exists('templates', gophish_template_name)
        gophish_request('templates', 'POST', {
            'name':    gophish_template_name,
            'subject': template['subject'],
            'html':    template['html'],
        })
        print(f'✅ Template pushed to GoPhish: {gophish_template_name}')

        # Step 2 — Clean up then push YOUR landing page into GoPhish
        gophish_delete_if_exists('pages', page_name)
        gophish_request('pages', 'POST', {
            'name':                page_name,
            'html':                AWARENESS_PAGE_HTML,
            'capture_credentials': True,
            'capture_passwords':   False,
            'redirect_url':        'http://127.0.0.1:8080/awareness-training.html',
        })
        print('✅ Landing page pushed to GoPhish')

        # Step 3 — Clean up then push targets as a GoPhish group
        gophish_delete_if_exists('groups', group_name)
        gophish_request('groups', 'POST', {
            'name': group_name,
            'targets': [{
                'first_name': t['name'].split(' ')[0],
                'last_name':  ' '.join(t['name'].split(' ')[1:]),
                'email':      t['email'],
                'position':   t['department'],
            } for t in targets]
        })
        print(f'✅ Group pushed to GoPhish: {len(targets)} targets')

        # Step 4 — Clean up then launch campaign in GoPhish
        gophish_delete_if_exists('campaigns', camp_name)
        gophish_campaign = {
            'name':        camp_name,
            'template':    {'name': gophish_template_name},
            'page':        {'name': page_name},
            'smtp':        {'name': 'Brevo SMTP'},
            'url':         f'http://127.0.0.1:5000/api/track/click?campaign_id={campaign_id}',
            'launch_date': (datetime.utcnow() - timedelta(minutes=2)).strftime('%Y-%m-%dT%H:%M:%S+00:00'),
            'groups':      [{'name': group_name}],
        }
        result = gophish_request('campaigns', 'POST', gophish_campaign)
        print(f'✅ Campaign launched in GoPhish. ID: {result["id"]}')

        # Step 5 — Update status in YOUR database
        conn = get_db()
        conn.execute("UPDATE campaigns SET status='active' WHERE id=?", (campaign_id,))
        conn.commit()
        conn.close()

        return jsonify({
            'success':    True,
            'gophish_id': result['id'],
            'targets':    len(targets),
            'message':    f'Campaign launched — {len(targets)} phishing emails queued via GoPhish'
        })

    except Exception as e:
        print(f'❌ Error launching campaign: {e}')
        return jsonify({'error': str(e)}), 500


# ── Health Check ───────────────────────────────────────────────────────────
@app.route('/api/health', methods=['GET'])
def health():
    """GET /api/health — Check if the API is running."""
    return jsonify({
        'status':  'ok',
        'message': 'PhishGuard API is running',
        'version': '1.0.0',
        'time':    datetime.now().isoformat(),
    })


# ── Run ────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    init_db()
    print('🚀 PhishGuard API starting on http://127.0.0.1:5000')
    print('📋 Available endpoints:')
    print('   POST /api/login')
    print('   GET  /api/dashboard/stats')
    print('   GET  /api/campaigns')
    print('   POST /api/campaigns')
    print('   GET  /api/employees')
    print('   POST /api/employees/upload')
    print('   GET  /api/track/open')
    print('   GET  /api/track/click')
    print('   POST /api/track/report')
    print('   GET  /api/training/modules')
    print('   GET  /api/training/progress/<user_id>')
    print('   POST /api/quiz/submit')
    print('   GET  /api/employees/<id>/risk')
    print('   GET  /api/health')
    print('   GET  /api/templates')
    print('   POST /api/templates')
    print('   DEL  /api/templates/<id>')
    print('   POST /api/campaigns/<id>/send')
    app.run(debug=True, host='0.0.0.0', port=5000)
