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
CORS(app, resources={r'/api/*': {'origins': '*'}, r'/landing/*': {'origins': '*'}})  # Allow all origins for demo

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

    # Email logs — persistent record of every phishing email sent
    c.execute('''
        CREATE TABLE IF NOT EXISTS email_logs (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_id      INTEGER,
            recipient_email  TEXT,
            recipient_name   TEXT,
            subject          TEXT,
            template_name    TEXT,
            html_body        TEXT DEFAULT '',
            status           TEXT DEFAULT 'sent',
            sent_at          TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
        )
    ''')
    # Add html_body column if upgrading from older DB
    try:
        c.execute("ALTER TABLE email_logs ADD COLUMN html_body TEXT DEFAULT ''")
    except Exception:
        pass  # Column already exists

    # Training learners — employees who register on the awareness training page
    c.execute('''
        CREATE TABLE IF NOT EXISTS training_learners (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name    TEXT NOT NULL,
            department   TEXT NOT NULL,
            session_key  TEXT UNIQUE,
            campaign_id  TEXT DEFAULT '',
            registered_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Module content — full content + quiz stored as JSON
    c.execute('''
        CREATE TABLE IF NOT EXISTS module_content (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            module_id    INTEGER UNIQUE NOT NULL,
            content_html TEXT DEFAULT '',
            quiz_json    TEXT DEFAULT '[]',
            updated_at   TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (module_id) REFERENCES training_modules(id)
        )
    ''')

    # Module completions — which learner passed which module
    c.execute('''
        CREATE TABLE IF NOT EXISTS module_completions (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            learner_id    INTEGER NOT NULL,
            module_id     INTEGER NOT NULL,
            score         INTEGER DEFAULT 0,
            total         INTEGER DEFAULT 5,
            percentage    INTEGER DEFAULT 0,
            passed        INTEGER DEFAULT 0,
            completed_at  TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (learner_id) REFERENCES training_learners(id),
            FOREIGN KEY (module_id) REFERENCES training_modules(id)
        )
    ''')
    # Upgrade: add missing columns to training_modules
    for col_def in [
        ("icon",        "TEXT DEFAULT '&#127908;'"),
        ("color",       "TEXT DEFAULT '#00d4ff15'"),
        ("meta_json",   "TEXT DEFAULT '[]'"),
        ("category",    "TEXT DEFAULT 'general'"),
    ]:
        try:
            c.execute(f"ALTER TABLE training_modules ADD COLUMN {col_def[0]} {col_def[1]}")
        except Exception:
            pass

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

    # Seed training modules (8 modules)
    modules = [
        (1, 'What is Phishing?',                      'Learn the basics of phishing attacks',              '5 min',  'beginner',     1, '&#127908;', '#00d4ff15', '["&#9201; 5 min","&#128221; 5 questions","&#128308; Beginner"]'),
        (2, 'Spotting Suspicious Links & Domains',    'Learn to identify fake URLs and domains',           '7 min',  'beginner',     2, '&#128279;', '#00e5a015', '["&#9201; 7 min","&#128221; 5 questions","&#128308; Beginner"]'),
        (3, 'Urgency & Social Engineering',           'Understand psychological manipulation tactics',     '8 min',  'beginner',     3, '&#9889;',   '#ffb30015', '["&#9201; 8 min","&#128221; 5 questions","&#128308; Beginner"]'),
        (4, 'Email Headers & Sender Analysis',        'Learn to read and verify email headers',            '8 min',  'intermediate', 4, '&#128231;', '#0077ff15', '["&#9201; 8 min","&#128221; 5 questions","&#128992; Intermediate"]'),
        (5, 'Business Email Compromise (BEC)',        'Understand CEO fraud and BEC attacks',              '8 min',  'advanced',     5, '&#127970;', '#9b59b618', '["&#9201; 8 min","&#128221; 5 questions","&#128308; Advanced"]'),
        (6, 'Credential Phishing & Fake Login Pages', 'Recognise and avoid fake login pages',             '7 min',  'intermediate', 6, '&#128272;', '#ff456018', '["&#9201; 7 min","&#128221; 5 questions","&#128992; Intermediate"]'),
        (7, 'Safe Email & Attachment Practices',      'Safe handling of emails and file attachments',     '7 min',  'beginner',     7, '&#128206;', '#2ecc7115', '["&#9201; 7 min","&#128221; 5 questions","&#128308; Beginner"]'),
        (8, 'What To Do When You Are Phished',       'Steps to take after a phishing incident',          '6 min',  'beginner',     8, '&#128737;', '#ffffff08', '["&#9201; 6 min","&#128221; 5 questions","&#128308; Beginner"]'),
    ]
    for m in modules:
        c.execute('''
            INSERT OR IGNORE INTO training_modules (id, title, description, duration, difficulty, order_num, icon, color, meta_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', m)

    # ── Deduplicate training_modules — keep only the 8 canonical rows (id 1-8)
    # Remove any rows with id > 8 that have the same title as a canonical row
    c.execute('''
        DELETE FROM training_modules
        WHERE id > 8
        AND title IN (
            SELECT title FROM training_modules WHERE id <= 8
        )
    ''')
    # Also remove any extra rows beyond the 8 we seeded
    c.execute('''
        DELETE FROM training_modules
        WHERE id NOT IN (1,2,3,4,5,6,7,8)
    ''')

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

        submitted = conn.execute(
            "SELECT COUNT(*) FROM tracking_events WHERE campaign_id=? AND event_type='submitted'", (cid,)
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
                'total':       targets,
                'opened':      opened,
                'clicked':     clicked,
                'submitted':   submitted,
                'reported':    reported,
                'open_rate':   round(opened    / targets * 100, 1) if targets > 0 else 0,
                'click_rate':  round(clicked   / targets * 100, 1) if targets > 0 else 0,
                'submit_rate': round(submitted / targets * 100, 1) if targets > 0 else 0,
                'report_rate': round(reported  / targets * 100, 1) if targets > 0 else 0,
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


@app.route('/api/campaigns/<int:campaign_id>', methods=['GET'])
def get_campaign(campaign_id):
    """GET /api/campaigns/<id> — Get single campaign with full stats."""
    conn = get_db()
    c = conn.execute('SELECT * FROM campaigns WHERE id=?', (campaign_id,)).fetchone()
    if not c:
        conn.close()
        return jsonify({'error': 'Not found'}), 404
    targets   = conn.execute('SELECT COUNT(*) FROM campaign_targets WHERE campaign_id=?', (campaign_id,)).fetchone()[0]
    opened    = conn.execute("SELECT COUNT(*) FROM tracking_events WHERE campaign_id=? AND event_type='opened'",    (campaign_id,)).fetchone()[0]
    clicked   = conn.execute("SELECT COUNT(*) FROM tracking_events WHERE campaign_id=? AND event_type='clicked'",   (campaign_id,)).fetchone()[0]
    submitted = conn.execute("SELECT COUNT(*) FROM tracking_events WHERE campaign_id=? AND event_type='submitted'", (campaign_id,)).fetchone()[0]
    reported  = conn.execute("SELECT COUNT(*) FROM tracking_events WHERE campaign_id=? AND event_type='reported'",  (campaign_id,)).fetchone()[0]
    # Per-target detail with timestamps for timeline
    target_rows = conn.execute('''
        SELECT ct.email, ct.name, ct.department,
            MAX(CASE WHEN te.event_type='opened'    THEN 1 ELSE 0 END) as opened,
            MAX(CASE WHEN te.event_type='clicked'   THEN 1 ELSE 0 END) as clicked,
            MAX(CASE WHEN te.event_type='submitted' THEN 1 ELSE 0 END) as submitted,
            MAX(CASE WHEN te.event_type='reported'  THEN 1 ELSE 0 END) as reported,
            MAX(CASE WHEN te.event_type='opened'    THEN te.timestamp END) as opened_at,
            MAX(CASE WHEN te.event_type='clicked'   THEN te.timestamp END) as clicked_at,
            MAX(CASE WHEN te.event_type='submitted' THEN te.timestamp END) as submitted_at,
            MAX(CASE WHEN te.event_type='reported'  THEN te.timestamp END) as reported_at
        FROM campaign_targets ct
        LEFT JOIN tracking_events te ON te.email=ct.email AND te.campaign_id=ct.campaign_id
        WHERE ct.campaign_id=?
        GROUP BY ct.email
        ORDER BY ct.name
    ''', (campaign_id,)).fetchall()
    conn.close()

    def split_name(full):
        parts = (full or '').strip().split(' ', 1)
        return parts[0], parts[1] if len(parts) > 1 else ''

    target_list = []
    for t in target_rows:
        fn, ln = split_name(t['name'])
        target_list.append({
            'email':        t['email'],
            'name':         t['name'] or '',
            'first_name':   fn,
            'last_name':    ln,
            'department':   t['department'] or '',
            'opened':       t['opened'],
            'clicked':      t['clicked'],
            'submitted':    t['submitted'],
            'reported':     t['reported'],
            'opened_at':    t['opened_at'],
            'clicked_at':   t['clicked_at'],
            'submitted_at': t['submitted_at'],
            'reported_at':  t['reported_at'],
        })

    return jsonify({
        'id': campaign_id, 'name': c['name'], 'template': c['template'],
        'status': c['status'], 'sender_name': c['sender_name'],
        'sender_email': c['sender_email'], 'start_date': c['start_date'],
        'end_date': c['end_date'], 'created_at': c['created_at'],
        'stats': {
            'total': targets, 'opened': opened, 'clicked': clicked,
            'submitted': submitted, 'reported': reported,
            'open_rate':   round(opened/targets*100,1)    if targets else 0,
            'click_rate':  round(clicked/targets*100,1)   if targets else 0,
            'submit_rate': round(submitted/targets*100,1) if targets else 0,
            'report_rate': round(reported/targets*100,1)  if targets else 0,
        },
        'targets': target_list
    })


@app.route('/api/campaigns/<int:campaign_id>', methods=['DELETE'])
def delete_campaign(campaign_id):
    """DELETE /api/campaigns/<id> — Delete campaign and all related data."""
    conn = get_db()
    conn.execute('DELETE FROM tracking_events WHERE campaign_id=?',  (campaign_id,))
    conn.execute('DELETE FROM campaign_targets WHERE campaign_id=?', (campaign_id,))
    conn.execute('DELETE FROM email_logs WHERE campaign_id=?',       (campaign_id,))
    conn.execute('DELETE FROM campaigns WHERE id=?',                 (campaign_id,))
    conn.commit()
    conn.close()
    print(f'🗑️ Campaign {campaign_id} deleted')
    return jsonify({'success': True})


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
    conn = get_db()
    employees = conn.execute('''
        SELECT u.id, u.name, u.email, u.department, u.risk_score, u.created_at,
               COUNT(DISTINCT ct.campaign_id) as campaigns_targeted,
               COUNT(DISTINCT CASE WHEN te.event_type='clicked'   THEN te.campaign_id END) as campaigns_clicked,
               COUNT(DISTINCT CASE WHEN te.event_type='submitted' THEN te.campaign_id END) as campaigns_submitted
        FROM users u
        LEFT JOIN campaign_targets ct ON ct.email = u.email
        LEFT JOIN tracking_events  te ON te.email = u.email
        WHERE u.role='employee'
        GROUP BY u.id ORDER BY u.risk_score DESC, u.name
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


@app.route('/api/employees', methods=['POST'])
def create_employee():
    data  = request.get_json()
    email = (data.get('email') or '').strip()
    name  = (data.get('name')  or '').strip()
    dept  = (data.get('department') or '').strip()
    position = (data.get('position') or '').strip()
    if not email or not name:
        return jsonify({'error': 'name and email are required'}), 400
    conn = get_db()
    if conn.execute('SELECT id FROM users WHERE email=?', (email,)).fetchone():
        conn.close(); return jsonify({'error': 'Email already exists'}), 409
    default_pw = hash_password('changeme123')
    conn.execute('INSERT INTO users (name, email, password, role, department) VALUES (?,?,?,?,?)',
        (name, email, default_pw, 'employee', dept))
    conn.commit(); conn.close()
    return jsonify({'success': True}), 201


@app.route('/api/employees/<int:emp_id>', methods=['PUT'])
def update_employee(emp_id):
    data = request.get_json()
    conn = get_db()
    for field in ('name', 'email', 'department'):
        if field in data:
            conn.execute('UPDATE users SET ' + field + "=? WHERE id=? AND role='employee'", (data[field], emp_id))
    conn.commit(); conn.close()
    return jsonify({'success': True})


@app.route('/api/employees/<int:emp_id>', methods=['DELETE'])
def delete_employee(emp_id):
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id=? AND role='employee'", (emp_id,))
    conn.commit(); conn.close()
    return jsonify({'success': True})


@app.route('/api/employees/stats', methods=['GET'])
def get_employee_stats():
    conn = get_db()
    total    = conn.execute("SELECT COUNT(*) FROM users WHERE role='employee'").fetchone()[0]
    high_risk = conn.execute("SELECT COUNT(*) FROM users WHERE role='employee' AND risk_score>=70").fetchone()[0]
    med_risk  = conn.execute("SELECT COUNT(*) FROM users WHERE role='employee' AND risk_score>=30 AND risk_score<70").fetchone()[0]
    low_risk  = conn.execute("SELECT COUNT(*) FROM users WHERE role='employee' AND risk_score<30").fetchone()[0]
    depts     = conn.execute("SELECT department, COUNT(*) as cnt FROM users WHERE role='employee' GROUP BY department ORDER BY cnt DESC").fetchall()
    # Campaigns each employee has been targeted in
    most_targeted = conn.execute('''
        SELECT u.name, u.email, u.department, u.risk_score,
               COUNT(DISTINCT ct.campaign_id) as campaigns
        FROM users u
        LEFT JOIN campaign_targets ct ON ct.email = u.email
        WHERE u.role='employee'
        GROUP BY u.id ORDER BY campaigns DESC, u.risk_score DESC LIMIT 5
    ''').fetchall()
    conn.close()
    return jsonify({
        'total': total, 'high_risk': high_risk, 'med_risk': med_risk, 'low_risk': low_risk,
        'departments': [dict(d) for d in depts],
        'most_targeted': [dict(m) for m in most_targeted],
    })


@app.route('/api/employees/export-csv', methods=['GET'])
def export_employees_csv():
    import csv, io
    conn = get_db()
    emps = conn.execute('''
        SELECT u.name, u.email, u.department, u.risk_score,
               COUNT(DISTINCT ct.campaign_id) as campaigns_targeted,
               COUNT(DISTINCT CASE WHEN te.event_type='clicked' THEN te.campaign_id END) as campaigns_clicked
        FROM users u
        LEFT JOIN campaign_targets ct ON ct.email=u.email
        LEFT JOIN tracking_events  te ON te.email=u.email
        WHERE u.role='employee'
        GROUP BY u.id ORDER BY u.name
    ''').fetchall()
    conn.close()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Name','Email','Department','Risk Score','Campaigns Targeted','Campaigns Clicked'])
    for e in emps:
        writer.writerow([e['name'],e['email'],e['department'],e['risk_score'],e['campaigns_targeted'],e['campaigns_clicked']])
    from flask import Response
    return Response(output.getvalue(), mimetype='text/csv',
        headers={'Content-Disposition': 'attachment;filename=employees.csv'})


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
    GoPhish passes {{.Email}} which resolves to the recipient's email.
    """
    campaign_id = request.args.get('campaign_id', '')
    email       = request.args.get('email', '').strip()

    # If email is empty, try to look it up from GoPhish RId
    if not email:
        rid = request.args.get('rid', '')
        if rid:
            try:
                # Look up email from email_logs using campaign_id
                conn_lookup = get_db()
                log = conn_lookup.execute(
                    'SELECT recipient_email FROM email_logs WHERE campaign_id=? LIMIT 1',
                    (campaign_id,)
                ).fetchone()
                conn_lookup.close()
                if log:
                    email = log['recipient_email']
            except Exception as e:
                print(f'⚠️ RId lookup failed: {e}')

    if campaign_id and email:
        conn = get_db()
        # Avoid duplicate click events for same email+campaign
        existing = conn.execute(
            "SELECT id FROM tracking_events WHERE campaign_id=? AND email=? AND event_type='clicked'",
            (campaign_id, email)
        ).fetchone()
        if not existing:
            conn.execute('''
                INSERT INTO tracking_events (campaign_id, email, event_type, ip_address, user_agent)
                VALUES (?, ?, 'clicked', ?, ?)
            ''', (campaign_id, email, request.remote_addr, request.user_agent.string))
            conn.commit()
            print(f'🎣 Click tracked: {email} in campaign {campaign_id}')
        conn.close()
        update_risk_score(email)
    else:
        print(f'⚠️ Click event with no email — campaign_id={campaign_id}')

    from flask import redirect

    # Look up template metadata to determine routing by phishing_type
    phishing_type = 'link'  # default
    template_category = ''
    landing_page  = None

    if campaign_id:
        try:
            conn2 = get_db()
            camp  = conn2.execute('SELECT template FROM campaigns WHERE id=?', (campaign_id,)).fetchone()
            conn2.close()
            if camp and camp['template']:
                templates_meta = load_templates()
                match = next((t for t in templates_meta if t['name'] == camp['template']), None)
                if match:
                    phishing_type      = match.get('phishing_type', 'link')
                    template_category  = match.get('category', '')
                    if match.get('landing_file'):
                        landing_page = match['landing_file']
                    print(f'✅ Template type={phishing_type} category={template_category}')
        except Exception as e:
            print(f'⚠️ Could not resolve template: {e}')

    # ── Route based on phishing type ────────────────────────────────────────
    # link / attachment → go straight to training (no landing page)
    # landing / credential → go to fake landing page first; submit → training
    if phishing_type in ('link', 'attachment'):
        # Straight to awareness training — mark as full fail immediately
        training_url = (
            f'http://127.0.0.1:8088/awareness-training.html'
            f'?caught=1&stage=clicked&campaign_id={campaign_id}'
            f'&phishing_type={phishing_type}&category={template_category}'
        )
        return redirect(training_url)
    else:
        # landing / credential → go to landing page first
        if not landing_page:
            landing_page = 'it_password_reset_landing.html'
        return redirect(
            f'http://127.0.0.1:5000/landing/{landing_page}'
            f'?campaign_id={campaign_id}&email={email}'
            f'&phishing_type={phishing_type}&category={template_category}'
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

    # Look up phishing_type + category for context-aware training redirect
    phishing_type_s = ''; category_s = ''
    if campaign_id:
        try:
            conn3 = get_db()
            camp3 = conn3.execute('SELECT template FROM campaigns WHERE id=?', (campaign_id,)).fetchone()
            conn3.close()
            if camp3 and camp3['template']:
                tmatch = next((t for t in load_templates() if t['name'] == camp3['template']), None)
                if tmatch:
                    phishing_type_s = tmatch.get('phishing_type', '')
                    category_s      = tmatch.get('category', '')
        except Exception:
            pass

    redirect_url = (
        f'http://127.0.0.1:8088/awareness-training.html'
        f'?caught=1&stage=submitted&campaign_id={campaign_id}'
        f'&phishing_type={phishing_type_s}&category={category_s}'
    )
    return jsonify({'success': True, 'new_risk_score': new_score, 'redirect': redirect_url})


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

    if not email:
        return jsonify({'error': 'email is required'}), 400

    # If no campaign_id provided, try to find the most recent active campaign
    # for this employee so the report is still associated
    if not campaign_id:
        try:
            conn_lookup = get_db()
            recent = conn_lookup.execute('''
                SELECT te.campaign_id FROM tracking_events te
                WHERE te.email = ? AND te.event_type IN ('sent', 'opened', 'clicked')
                ORDER BY te.timestamp DESC LIMIT 1
            ''', (email,)).fetchone()
            if not recent:
                # Try email_logs
                recent = conn_lookup.execute(
                    'SELECT campaign_id FROM email_logs WHERE recipient_email=? ORDER BY sent_at DESC LIMIT 1',
                    (email,)
                ).fetchone()
            conn_lookup.close()
            if recent:
                campaign_id = recent['campaign_id']
        except Exception as e:
            print(f'⚠️ Could not look up campaign for report: {e}')

    conn = get_db()
    # Avoid duplicate reported events
    existing = conn.execute(
        "SELECT id FROM tracking_events WHERE campaign_id=? AND email=? AND event_type='reported'",
        (campaign_id, email)
    ).fetchone()
    if not existing:
        conn.execute('''
            INSERT INTO tracking_events (campaign_id, email, event_type, ip_address, user_agent)
            VALUES (?, ?, 'reported', ?, ?)
        ''', (campaign_id, email, request.remote_addr, request.user_agent.string))
        conn.commit()
        print(f'🛡️ Phishing reported: {email} campaign {campaign_id}')
    conn.close()
    score = update_risk_score(email)
    return jsonify({'success': True, 'new_risk_score': score, 'campaign_id': campaign_id})


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
GOPHISH_API_KEY = '0f0510cd5099b035ab814ce78bb65c39a7c4ec103eab70940826d03ff2eb311b'

def gophish_request(endpoint, method='GET', data=None):
    """Make an authenticated request to the GoPhish API."""
    url     = f'{GOPHISH_URL}/api/{endpoint}/?api_key={GOPHISH_API_KEY}'
    headers = {'Content-Type': 'application/json'}
    body    = json.dumps(data).encode() if data else None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        response = urllib.request.urlopen(req, context=ctx)
        raw = response.read().decode()
        if not raw.strip():
            return {}
        result = json.loads(raw)
        # GoPhish returns {"success": false, "message": "..."} on logical errors
        # But only raise for POST/PUT — DELETE and GET may use different formats
        if method in ('POST', 'PUT') and isinstance(result, dict) and result.get('success') is False:
            msg = result.get('message', 'Unknown GoPhish error')
            print(f'❌ GoPhish API error [{method} {endpoint}]: {msg}')
            raise Exception(f'GoPhish: {msg}')
        return result
    except urllib.error.HTTPError as e:
        body_text = e.read().decode()
        print(f'❌ GoPhish HTTP {e.code} [{method} {endpoint}]: {body_text[:300]}')
        raise Exception(f'GoPhish HTTP {e.code}: {body_text[:200]}')
    except urllib.error.URLError as e:
        print(f'❌ GoPhish connection error [{method} {endpoint}]: {e.reason}')
        raise Exception(f'GoPhish unreachable: {e.reason}')



# ── Admin User Management Routes ───────────────────────────────────────────
@app.route('/api/admin/users', methods=['GET'])
def get_all_users():
    """GET /api/admin/users — List all users (admins + employees)."""
    conn = get_db()
    users = conn.execute(
        'SELECT id, name, email, role, department, risk_score, created_at FROM users ORDER BY role, name'
    ).fetchall()
    conn.close()
    return jsonify([dict(u) for u in users])


@app.route('/api/admin/users', methods=['POST'])
def create_user():
    """POST /api/admin/users — Create a new user."""
    d = request.get_json()
    if not d.get('name') or not d.get('email') or not d.get('password'):
        return jsonify({'error': 'name, email and password required'}), 400
    conn = get_db()
    try:
        conn.execute(
            'INSERT INTO users (name, email, password, role, department) VALUES (?,?,?,?,?)',
            (d['name'], d['email'], hash_password(d['password']),
             d.get('role','employee'), d.get('department',''))
        )
        conn.commit()
        new_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        conn.close()
        return jsonify({'success': True, 'id': new_id}), 201
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 500


@app.route('/api/admin/users/<int:uid>', methods=['PUT'])
def update_user(uid):
    """PUT /api/admin/users/<id> — Update a user."""
    d = request.get_json()
    conn = get_db()
    for field in ('name', 'email', 'role', 'department'):
        if field in d:
            conn.execute(f'UPDATE users SET {field}=? WHERE id=?', (d[field], uid))
    if d.get('password'):
        conn.execute('UPDATE users SET password=? WHERE id=?', (hash_password(d['password']), uid))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/admin/users/<int:uid>', methods=['DELETE'])
def delete_user(uid):
    """DELETE /api/admin/users/<id> — Delete a user."""
    conn = get_db()
    # Don't allow deleting the last admin
    admin_count = conn.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0]
    user = conn.execute('SELECT role FROM users WHERE id=?', (uid,)).fetchone()
    if user and user['role'] == 'admin' and admin_count <= 1:
        conn.close()
        return jsonify({'error': 'Cannot delete the last administrator'}), 400
    conn.execute('DELETE FROM users WHERE id=?', (uid,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


# ── SMTP / Phish Profile Routes ────────────────────────────────────────────
@app.route('/api/smtp-profiles', methods=['GET'])
def get_smtp_profiles():
    conn = get_db()
    profiles = conn.execute('SELECT * FROM smtp_profiles ORDER BY id').fetchall()
    conn.close()
    return jsonify([dict(p) for p in profiles])


@app.route('/api/smtp-profiles', methods=['POST'])
def create_smtp_profile():
    d = request.get_json()
    if not d.get('name'):
        return jsonify({'error': 'Name is required'}), 400
    conn = get_db()
    try:
        conn.execute('''
            INSERT INTO smtp_profiles
            (name, type, host, port, username, password, from_name, from_email, use_tls, use_ssl, ignore_cert_errors, is_active)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,0)
        ''', (d['name'], d.get('type','mailhog'), d.get('host','127.0.0.1'),
              int(d.get('port',1025)), d.get('username',''), d.get('password',''),
              d.get('from_name','PhishGuard'), d.get('from_email','phishguard@localhost'),
              int(d.get('use_tls',0)), int(d.get('use_ssl',0)), int(d.get('ignore_cert_errors',1))))
        conn.commit()
        new_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        conn.close()
        return jsonify({'success': True, 'id': new_id}), 201
    except Exception as e:
        conn.close()
        return jsonify({'error': str(e)}), 500


@app.route('/api/smtp-profiles/<int:pid>', methods=['PUT'])
def update_smtp_profile(pid):
    d = request.get_json()
    conn = get_db()
    for field in ('name','type','host','port','username','password','from_name','from_email','use_tls','use_ssl','ignore_cert_errors'):
        if field in d:
            conn.execute(f'UPDATE smtp_profiles SET {field}=? WHERE id=?', (d[field], pid))
    conn.commit(); conn.close()
    return jsonify({'success': True})


@app.route('/api/smtp-profiles/<int:pid>', methods=['DELETE'])
def delete_smtp_profile(pid):
    conn = get_db()
    conn.execute('DELETE FROM smtp_profiles WHERE id=?', (pid,))
    conn.commit(); conn.close()
    return jsonify({'success': True})


@app.route('/api/smtp-profiles/<int:pid>/activate', methods=['POST'])
def activate_smtp_profile(pid):
    conn = get_db()
    conn.execute('UPDATE smtp_profiles SET is_active=0')  # deactivate all
    conn.execute('UPDATE smtp_profiles SET is_active=1 WHERE id=?', (pid,))
    conn.commit(); conn.close()
    return jsonify({'success': True})


@app.route('/api/smtp-profiles/<int:pid>/test', methods=['POST'])
def test_smtp_profile(pid):
    """Test SMTP profile by pushing it to GoPhish and checking connectivity."""
    conn = get_db()
    profile = conn.execute('SELECT * FROM smtp_profiles WHERE id=?', (pid,)).fetchone()
    conn.close()
    if not profile:
        return jsonify({'error': 'Profile not found'}), 404
    p = dict(profile)
    try:
        # Build GoPhish SMTP object
        gp_smtp = {
            'name':               f'PG_TEST_SMTP_{pid}',
            'host':               f'{p["host"]}:{p["port"]}',
            'from_address':       f'{p["from_name"]} <{p["from_email"]}>',
            'username':           p['username'],
            'password':           p['password'],
            'ignore_cert_errors': bool(p['ignore_cert_errors']),
        }
        # Delete existing test profile in GoPhish
        try:
            items = gophish_request('smtp')
            for item in (items or []):
                if item.get('name') == gp_smtp['name']:
                    gophish_request(f'smtp/{item["id"]}', 'DELETE')
        except: pass
        result = gophish_request('smtp', 'POST', gp_smtp)
        return jsonify({'success': True, 'message': f'Profile "{p["name"]}" pushed to GoPhish OK', 'gophish_id': result.get('id')})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ── GoPhish Diagnostic Endpoint ───────────────────────────────────────────
@app.route('/api/gophish/test', methods=['GET'])
def test_gophish():
    """GET /api/gophish/test — Check GoPhish connectivity and list resources."""
    results = {}
    for resource in ['smtp', 'templates', 'pages', 'groups', 'campaigns']:
        try:
            data = gophish_request(resource)
            count = len(data) if isinstance(data, list) else 1
            results[resource] = {'ok': True, 'count': count}
            if resource == 'smtp':
                results['smtp_profiles'] = [s.get('name','?') for s in (data if isinstance(data,list) else [])]
        except Exception as e:
            results[resource] = {'ok': False, 'error': str(e)}
    return jsonify({'gophish_url': GOPHISH_URL, 'results': results})


# ── Template File Loader ───────────────────────────────────────────────────
TEMPLATES_DIR  = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
TEMPLATES_META  = os.path.join(TEMPLATES_DIR, 'templates.json')
LANDING_META    = os.path.join(TEMPLATES_DIR, 'landing_pages.json')

def load_landing_pages():
    if not os.path.exists(LANDING_META):
        print(f'⚠️  landing_pages.json not found: {LANDING_META}')
        return []
    with open(LANDING_META, 'r', encoding='utf-8') as f:
        content = f.read().strip()
        if not content:
            return []
        return json.loads(content)

def save_landing_pages(pages):
    with open(LANDING_META, 'w') as f:
        json.dump(pages, f, indent=2)

def load_templates():
    """Load all template metadata from templates.json."""
    if not os.path.exists(TEMPLATES_META):
        print(f'⚠️  templates.json not found, creating empty: {TEMPLATES_META}')
        os.makedirs(TEMPLATES_DIR, exist_ok=True)
        with open(TEMPLATES_META, 'w') as f:
            json.dump([], f)
        return []
    with open(TEMPLATES_META, 'r', encoding='utf-8') as f:
        content = f.read().strip()
        if not content:
            return []
        return json.loads(content)

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
    <a href="http://127.0.0.1:8088/awareness-training.html"
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
    except FileNotFoundError:
        print(f'❌ templates.json not found at: {TEMPLATES_META}')
        return jsonify([])   # return empty list instead of 500
    except Exception as e:
        import traceback
        print(f'❌ get_templates error: {e}')
        traceback.print_exc()
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
            'difficulty':     data.get('difficulty','Medium'),
            'description':    data.get('description', ''),
            'sender_name':    data.get('sender_name', 'IT Support'),
            'sender_email':   data.get('sender_email', ''),
            'avg_click_rate': 0,
            'language':       data.get('language', 'english'),
            'phishing_type':  data.get('phishing_type', 'link'),
            'template_type':  'email',
            'landing_file':   data.get('landing_file', ''),
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


@app.route('/api/templates/<int:template_id>', methods=['PUT'])
def update_template(template_id):
    """PUT /api/templates/<id> — Edit template metadata."""
    try:
        data      = request.get_json()
        templates = load_templates()
        tmpl      = next((t for t in templates if t['id'] == template_id), None)
        if not tmpl:
            return jsonify({'error': 'Template not found'}), 404
        for field in ('name','subject','description','category','difficulty','language','sender_name','sender_email','phishing_type','landing_file','template_type'):
            if field in data:
                tmpl[field] = data[field]
        # Update HTML file if provided
        if data.get('html'):
            fpath = os.path.join(TEMPLATES_DIR, tmpl['file'])
            with open(fpath, 'w') as hf:
                hf.write(data['html'])
        with open(TEMPLATES_META, 'w') as f:
            json.dump(templates, f, indent=2)
        return jsonify({'success': True, 'template': tmpl})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── Landing Page Routes ────────────────────────────────────────────────────
@app.route('/api/landing-pages', methods=['GET'])
def get_landing_pages():
    try:
        pages = load_landing_pages()
        return jsonify(pages)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/landing-pages/<int:page_id>', methods=['GET'])
def get_landing_page(page_id):
    try:
        pages = load_landing_pages()
        page  = next((p for p in pages if p['id'] == page_id), None)
        if not page:
            return jsonify({'error': 'Not found'}), 404
        fpath = os.path.join(TEMPLATES_DIR, page['file'])
        page['html'] = open(fpath).read() if os.path.exists(fpath) else ''
        return jsonify(page)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/landing-pages', methods=['POST'])
def create_landing_page():
    data = request.get_json()
    if not data.get('name'):
        return jsonify({'error': 'name is required'}), 400
    try:
        pages    = load_landing_pages()
        slug     = data['name'].lower().replace(' ','_').replace('/','_')
        filename = slug + '_landing.html'
        fpath    = os.path.join(TEMPLATES_DIR, filename)
        # Save HTML
        html_content = data.get('html', '<html><body><h1>Landing Page</h1></body></html>')
        with open(fpath, 'w') as f:
            f.write(html_content)
        new_page = {
            'id':                  max(p['id'] for p in pages) + 1 if pages else 1,
            'name':                data['name'],
            'file':                filename,
            'description':         data.get('description', ''),
            'capture_credentials': data.get('capture_credentials', False),
            'capture_passwords':   data.get('capture_passwords', False),
            'redirect_url':        data.get('redirect_url', ''),
            'linked_template':     data.get('linked_template', ''),
            'category':            data.get('category', ''),
            'difficulty':          data.get('difficulty', 'Medium'),
        }
        pages.append(new_page)
        save_landing_pages(pages)
        return jsonify({'success': True, 'page': new_page}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/landing-pages/<int:page_id>', methods=['PUT'])
def update_landing_page(page_id):
    data = request.get_json()
    try:
        pages = load_landing_pages()
        page  = next((p for p in pages if p['id'] == page_id), None)
        if not page:
            return jsonify({'error': 'Not found'}), 404
        for field in ('name','description','capture_credentials','capture_passwords','redirect_url','linked_template','category','difficulty'):
            if field in data:
                page[field] = data[field]
        if data.get('html'):
            fpath = os.path.join(TEMPLATES_DIR, page['file'])
            with open(fpath, 'w') as f:
                f.write(data['html'])
        save_landing_pages(pages)
        return jsonify({'success': True, 'page': page})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/landing-pages/<int:page_id>', methods=['DELETE'])
def delete_landing_page(page_id):
    try:
        pages = load_landing_pages()
        page  = next((p for p in pages if p['id'] == page_id), None)
        if not page:
            return jsonify({'error': 'Not found'}), 404
        fpath = os.path.join(TEMPLATES_DIR, page['file'])
        if os.path.exists(fpath):
            os.remove(fpath)
        save_landing_pages([p for p in pages if p['id'] != page_id])
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/landing-pages/<int:page_id>/preview', methods=['GET'])
def preview_landing_page(page_id):
    try:
        pages = load_landing_pages()
        page  = next((p for p in pages if p['id'] == page_id), None)
        if not page:
            return jsonify({'error': 'Not found'}), 404
        fpath = os.path.join(TEMPLATES_DIR, page['file'])
        html  = open(fpath).read() if os.path.exists(fpath) else '<p>No content</p>'
        from flask import Response
        return Response(html, mimetype='text/html')
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# -- Training Learner Routes ---------------------------------------------------
@app.route('/api/training/register', methods=['POST'])
def register_learner():
    data = request.get_json()
    full_name   = (data.get('full_name') or '').strip()
    department  = (data.get('department') or '').strip()
    campaign_id = str(data.get('campaign_id') or '')
    if not full_name or not department:
        return jsonify({'error': 'full_name and department are required'}), 400
    import secrets as _sec
    session_key = _sec.token_hex(16)
    conn = get_db()
    conn.execute(
        'INSERT INTO training_learners (full_name, department, session_key, campaign_id) VALUES (?,?,?,?)',
        (full_name, department, session_key, campaign_id)
    )
    learner_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
    conn.commit(); conn.close()
    return jsonify({'success': True, 'session_key': session_key, 'learner_id': learner_id})


@app.route('/api/training/modules/full', methods=['GET'])
def get_modules_full():
    conn = get_db()
    # Guard against duplicate titles — keep only the lowest id per title
    modules = conn.execute('''
        SELECT * FROM training_modules
        WHERE id IN (SELECT MIN(id) FROM training_modules GROUP BY title)
        ORDER BY order_num, id
    ''').fetchall()
    result  = []
    for m in modules:
        mc   = conn.execute('SELECT content_html, quiz_json FROM module_content WHERE module_id=?', (m['id'],)).fetchone()
        keys = m.keys()
        result.append({
            'id':           m['id'],
            'title':        m['title'],
            'description':  m['description'],
            'duration':     m['duration'],
            'difficulty':   m['difficulty'],
            'order_num':    m['order_num'],
            'icon':         m['icon']      if 'icon'      in keys else '&#127908;',
            'color':        m['color']     if 'color'     in keys else '#00d4ff15',
            'meta_json':    m['meta_json'] if 'meta_json' in keys else '[]',
            'content_html': mc['content_html'] if mc else '',
            'quiz_json':    mc['quiz_json']    if mc else '[]',
        })
    conn.close()
    return jsonify(result)


@app.route('/api/training/modules', methods=['POST'])
def create_module():
    data = request.get_json()
    if not data or not data.get('title'):
        return jsonify({'error': 'title is required'}), 400
    conn   = get_db()
    cursor = conn.execute(
        'INSERT INTO training_modules (title,description,duration,difficulty,order_num,icon,color,meta_json) VALUES (?,?,?,?,?,?,?,?)',
        (data['title'], data.get('description',''), data.get('duration','5 min'),
         data.get('difficulty','beginner'), data.get('order_num',99),
         data.get('icon','&#127908;'), data.get('color','#00d4ff15'), data.get('meta_json','[]'))
    )
    module_id = cursor.lastrowid
    conn.execute(
        'INSERT OR REPLACE INTO module_content (module_id,content_html,quiz_json,updated_at) VALUES (?,?,?,CURRENT_TIMESTAMP)',
        (module_id, data.get('content_html',''), data.get('quiz_json','[]'))
    )
    conn.commit(); conn.close()
    return jsonify({'success': True, 'module_id': module_id}), 201


@app.route('/api/training/modules/<int:module_id>', methods=['PUT'])
def update_module(module_id):
    data = request.get_json()
    conn = get_db()
    if not conn.execute('SELECT id FROM training_modules WHERE id=?', (module_id,)).fetchone():
        conn.close(); return jsonify({'error': 'Not found'}), 404
    for field in ('title','description','duration','difficulty','order_num','icon','color','meta_json'):
        if field in data:
            conn.execute('UPDATE training_modules SET ' + field + '=? WHERE id=?', (data[field], module_id))
    if 'content_html' in data or 'quiz_json' in data:
        if conn.execute('SELECT id FROM module_content WHERE module_id=?', (module_id,)).fetchone():
            conn.execute('UPDATE module_content SET content_html=?,quiz_json=?,updated_at=CURRENT_TIMESTAMP WHERE module_id=?',
                (data.get('content_html',''), data.get('quiz_json','[]'), module_id))
        else:
            conn.execute('INSERT INTO module_content (module_id,content_html,quiz_json) VALUES (?,?,?)',
                (module_id, data.get('content_html',''), data.get('quiz_json','[]')))
    conn.commit(); conn.close()
    return jsonify({'success': True})


@app.route('/api/training/modules/<int:module_id>', methods=['DELETE'])
def delete_module(module_id):
    conn = get_db()
    conn.execute('DELETE FROM module_content     WHERE module_id=?', (module_id,))
    conn.execute('DELETE FROM module_completions WHERE module_id=?', (module_id,))
    conn.execute('DELETE FROM training_modules   WHERE id=?',        (module_id,))
    conn.commit(); conn.close()
    return jsonify({'success': True})


@app.route('/api/training/complete', methods=['POST'])
def complete_module():
    data        = request.get_json()
    session_key = data.get('session_key','')
    module_id   = data.get('module_id')
    score       = int(data.get('score', 0))
    total       = int(data.get('total', 5))
    if not session_key or not module_id:
        return jsonify({'error': 'session_key and module_id required'}), 400
    conn    = get_db()
    learner = conn.execute('SELECT id FROM training_learners WHERE session_key=?', (session_key,)).fetchone()
    if not learner:
        conn.close(); return jsonify({'error': 'Invalid session'}), 401
    pct    = round(score / total * 100)
    passed = 1 if pct >= 60 else 0
    conn.execute('INSERT INTO module_completions (learner_id,module_id,score,total,percentage,passed) VALUES (?,?,?,?,?,?)',
        (learner['id'], module_id, score, total, pct, passed))
    conn.commit(); conn.close()
    return jsonify({'success': True, 'passed': bool(passed), 'percentage': pct})


@app.route('/api/training/completions', methods=['GET'])
def get_all_completions():
    conn = get_db()
    completions = conn.execute('''
        SELECT tl.full_name, tl.department, tl.campaign_id, tl.registered_at,
               tm.title as module_title, tm.difficulty,
               mc.score, mc.total, mc.percentage, mc.passed, mc.completed_at
        FROM module_completions mc
        JOIN training_learners  tl ON mc.learner_id = tl.id
        JOIN training_modules   tm ON mc.module_id  = tm.id
        ORDER BY mc.completed_at DESC
    ''').fetchall()
    learners = conn.execute('''
        SELECT tl.id, tl.full_name, tl.department, tl.campaign_id, tl.registered_at,
               COUNT(mc.id)   as modules_attempted,
               SUM(mc.passed) as modules_passed
        FROM training_learners tl
        LEFT JOIN module_completions mc ON mc.learner_id = tl.id
        GROUP BY tl.id ORDER BY tl.registered_at DESC
    ''').fetchall()
    conn.close()
    return jsonify({'completions': [dict(r) for r in completions], 'learners': [dict(l) for l in learners]})


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
        print(f'⚠️  No targets in campaign_targets for campaign {campaign_id} — checking users table')
        # Fall back: grab all employees from users table
        conn2 = get_db()
        fallback = conn2.execute("SELECT name, email, department FROM users WHERE role='employee'").fetchall()
        conn2.close()
        if not fallback:
            return jsonify({'error': 'No targets found — add employees first'}), 400
        targets = fallback
        print(f'✅ Using {len(targets)} employees from roster as fallback targets')

    template_name = campaign['template'] or 'IT Password Reset'

    try:
        template = get_template_by_name(template_name)
    except Exception as e:
        return jsonify({'error': f'Could not load template: {str(e)}'}), 500

    try:
        import time as _time
        _ts = int(_time.time())
        # Use timestamp so names are always unique — avoids GoPhish 409 conflicts
        gophish_template_name = f'PG_{campaign_id}_{_ts}'
        page_name  = f'PG_Page_{campaign_id}_{_ts}'
        group_name = f'PG_Group_{campaign_id}_{_ts}'
        camp_name  = f'PG_Camp_{campaign_id}_{_ts}'

        # ── Helper: delete GoPhish object by name if it exists ──────────────
        def gophish_delete_if_exists(endpoint, name):
            try:
                items = gophish_request(endpoint)
                if isinstance(items, list):
                    for item in items:
                        if item.get('name') == name:
                            gophish_request(f'{endpoint}/{item["id"]}', 'DELETE')
                            print(f'🗑️  Deleted existing GoPhish {endpoint}: {name}')
                            break
            except Exception as ex:
                print(f'⚠️ Could not clean up {endpoint}/{name}: {ex}')

        # Step 1 — Clean up then push YOUR template into GoPhish
        gophish_delete_if_exists('templates', gophish_template_name)
        sender_name  = (campaign['sender_name']  or '') or template.get('sender_name',  'PhishGuard')
        sender_email = (campaign['sender_email'] or '') or template.get('sender_email', 'phishguard@local')
        gophish_request('templates', 'POST', {
            'name':            gophish_template_name,
            'subject':         template['subject'],
            'html':            template['html'],
            'envelope_sender': f'{sender_name} <{sender_email}>',
        })
        print(f'✅ Template pushed to GoPhish: {gophish_template_name}')

        # Step 2 — Clean up then push correct landing page HTML into GoPhish
        # Use the template's matching landing page if available
        landing_html = AWARENESS_PAGE_HTML  # default fallback
        landing_file = template.get('landing_file', '')
        if landing_file:
            try:
                landing_path = os.path.join(TEMPLATES_DIR, landing_file)
                with open(landing_path, 'r') as lf:
                    landing_html = lf.read()
            except Exception as e:
                print(f'⚠️ Could not load landing file {landing_file}: {e}')

        gophish_delete_if_exists('pages', page_name)
        gophish_request('pages', 'POST', {
            'name':                page_name,
            'html':                landing_html,
            'capture_credentials': True,
            'capture_passwords':   False,
            'redirect_url':        f'http://127.0.0.1:8088/awareness-training.html?caught=1&campaign_id={campaign_id}',
        })
        print(f'✅ Landing page pushed to GoPhish: {landing_file or "default"}')

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
        # Get active SMTP profile from PhishGuard DB
        _conn = get_db()
        _active_profile = _conn.execute(
            'SELECT * FROM smtp_profiles WHERE is_active=1 ORDER BY id LIMIT 1'
        ).fetchone()
        if not _active_profile:
            _active_profile = _conn.execute('SELECT * FROM smtp_profiles ORDER BY id LIMIT 1').fetchone()
        _conn.close()

        if not _active_profile:
            return jsonify({'error': 'No SMTP profile configured. Add one in Phish Profiles page.'}), 500

        _p = dict(_active_profile)
        print(f'📧 Using SMTP profile: {_p["name"]} ({_p["host"]}:{_p["port"]})')

        # Ensure this profile exists in GoPhish — push/update it
        _gp_smtp_name = f'PG_SMTP_{_p["id"]}'
        _gp_smtp_obj  = {
            'name':               _gp_smtp_name,
            'host':               f'{_p["host"]}:{_p["port"]}',
            'from_address':       f'{_p["from_name"]} <{_p["from_email"]}>',
            'username':           _p['username'] or '',
            'password':           _p['password'] or '',
            'ignore_cert_errors': bool(_p['ignore_cert_errors']),
        }
        # Push to GoPhish (delete+recreate to update)
        try:
            _existing = gophish_request('smtp')
            for _item in (_existing or []):
                if _item.get('name') == _gp_smtp_name:
                    gophish_request(f'smtp/{_item["id"]}', 'DELETE')
                    break
        except: pass
        try:
            gophish_request('smtp', 'POST', _gp_smtp_obj)
            print(f'✅ SMTP profile pushed to GoPhish: {_gp_smtp_name}')
        except Exception as _se:
            print(f'⚠️ Could not push SMTP profile to GoPhish: {_se}')

        smtp_name = _gp_smtp_name

        gophish_campaign = {
            'name':        camp_name,
            'template':    {'name': gophish_template_name},
            'page':        {'name': page_name},
            'smtp':        {'name': smtp_name},
            # {{.Email}} is a GoPhish placeholder — it inserts the recipient email
            # This is how track_click knows WHO clicked
            'url':         f'http://127.0.0.1:5000/api/track/click?campaign_id={campaign_id}&email={{{{.Email}}}}',
            'launch_date': (datetime.utcnow() - timedelta(minutes=2)).strftime('%Y-%m-%dT%H:%M:%S+00:00'),
            'groups':      [{'name': group_name}],
        }
        try:
            result = gophish_request('campaigns', 'POST', gophish_campaign)
        except Exception as gex:
            err_msg = str(gex)
            print(f'❌ GoPhish campaign POST failed: {err_msg}')
            # Try to extract the response body for more detail
            raise Exception(f'GoPhish error: {err_msg}')
        print(f'✅ Campaign launched in GoPhish. ID: {result["id"]}')

        # Step 5 — Update status in YOUR database + save email logs
        conn = get_db()
        conn.execute("UPDATE campaigns SET status='active' WHERE id=?", (campaign_id,))

        # Save a log entry for every target — including personalised HTML body
        raw_html = template.get('html', '')
        for t in targets:
            first_name = t['name'].split(' ')[0] if t['name'] else 'Employee'
            # Build the hidden report link — looks like a standard unsubscribe footer
            # If an employee is suspicious and clicks this instead of the main CTA,
            # it logs a 'reported' event (good behaviour) instead of 'clicked' (bad)
            # Use &amp; in href so HTML parsers don't mangle the URL
            report_url = (
                f'http://127.0.0.1:5000/api/track/report-link'
                f'?campaign_id={campaign_id}&amp;email={t["email"]}'
            )
            report_footer = (
                f'<div style="margin-top:24px;padding-top:12px;border-top:1px solid #eee;'
                f'font-size:11px;color:#aaa;text-align:center">'
                f'This message was sent to {t["email"]}. '
                f'<a href="{report_url}" style="color:#aaa;text-decoration:underline">'
                f'Unsubscribe</a> &middot; '
                f'<a href="{report_url}" style="color:#aaa;text-decoration:underline">'
                f'Email Preferences</a>'
                f'</div>'
            )
            # Personalise the HTML for this specific recipient
            # Our own open tracking pixel — fires when email is opened
            open_pixel = (
                f'<img src="http://127.0.0.1:5000/api/track/open'
                f'?campaign_id={campaign_id}&email={t["email"]}"'
                f' width="1" height="1" style="display:none" alt=""/>'
            )
            click_url = (
                f'http://127.0.0.1:5000/api/track/click'
                f'?campaign_id={campaign_id}&email={t["email"]}'
            )
            personalised = raw_html \
                .replace('{{.FirstName}}', first_name) \
                .replace('{{.Email}}',     t['email']) \
                .replace('{{.Tracker}}',   open_pixel) \
                .replace('{{.RId}}',       '') \
                .replace('{{.URL}}',       click_url)
            # Inject report footer before </body> if it exists, else append
            if '</body>' in personalised.lower():
                personalised = personalised.replace('</body>', report_footer + '</body>')
                personalised = personalised.replace('</BODY>', report_footer + '</BODY>')
            else:
                personalised += report_footer
            conn.execute('''
                INSERT INTO email_logs
                    (campaign_id, recipient_email, recipient_name, subject, template_name, html_body)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                campaign_id,
                t['email'],
                t['name'],
                template.get('subject', ''),
                template_name,
                personalised,
            ))
        conn.commit()
        conn.close()
        print(f'✅ Saved {len(targets)} email log entries with HTML to database')

        return jsonify({
            'success':    True,
            'gophish_id': result['id'],
            'targets':    len(targets),
            'message':    f'Campaign launched — {len(targets)} phishing emails queued via GoPhish'
        })

    except Exception as e:
        print(f'❌ Error launching campaign: {e}')
        return jsonify({'error': str(e)}), 500


# ── Serve Phishing Landing Pages ──────────────────────────────────────────
@app.route('/landing/<path:filename>', methods=['GET'])
def serve_landing_page(filename):
    """
    GET /landing/<filename>?campaign_id=X&email=Y
    Serves phishing landing pages directly from the templates/ folder.
    Avoids needing the frontend HTTP server to serve backend files.
    """
    from flask import send_from_directory, abort
    landing_path = os.path.join(TEMPLATES_DIR, filename)
    if not os.path.exists(landing_path):
        print(f'❌ Landing page not found: {landing_path}')
        abort(404)
    print(f'✅ Serving landing page: {filename}')
    return send_from_directory(TEMPLATES_DIR, filename)


# ── Email Log Routes (for Mailhog persistence) ─────────────────────────────
@app.route('/api/email-logs', methods=['GET'])
def get_email_logs():
    """GET /api/email-logs — Get all stored phishing emails sent."""
    conn = get_db()
    logs = conn.execute('''
        SELECT el.*, c.name as campaign_name
        FROM email_logs el
        LEFT JOIN campaigns c ON el.campaign_id = c.id
        ORDER BY el.sent_at DESC
        LIMIT 100
    ''').fetchall()
    conn.close()
    return jsonify([dict(l) for l in logs])


@app.route('/api/email-logs', methods=['POST'])
def save_email_log():
    """
    POST /api/email-logs
    Store a record of a phishing email that was sent.
    Body: { campaign_id, recipient_email, recipient_name, subject, template_name }
    """
    data = request.get_json()
    conn = get_db()
    conn.execute('''
        INSERT INTO email_logs (campaign_id, recipient_email, recipient_name, subject, template_name)
        VALUES (?, ?, ?, ?, ?)
    ''', (
        data.get('campaign_id'),
        data.get('recipient_email', ''),
        data.get('recipient_name', ''),
        data.get('subject', ''),
        data.get('template_name', ''),
    ))
    conn.commit()
    conn.close()
    return jsonify({'success': True}), 201


# ── Recent Tracking Events ────────────────────────────────────────────────
@app.route('/api/tracking/recent', methods=['GET'])
def get_recent_events():
    """
    GET /api/tracking/recent?limit=50
    Returns recent tracking events with employee name and campaign name.
    Used to populate the live activity feed on the dashboard.
    """
    limit = request.args.get('limit', 50)
    conn  = get_db()
    events = conn.execute('''
        SELECT
            te.id,
            te.event_type,
            te.email,
            te.timestamp,
            te.campaign_id,
            c.name  AS campaign_name,
            u.name  AS employee_name,
            u.department
        FROM tracking_events te
        LEFT JOIN campaigns c ON te.campaign_id = c.id
        LEFT JOIN users u     ON te.email = u.email
        ORDER BY te.timestamp DESC
        LIMIT ?
    ''', (limit,)).fetchall()
    conn.close()
    return jsonify([dict(e) for e in events])


# ── Dashboard Stats with submitted count ──────────────────────────────────
@app.route('/api/dashboard/full', methods=['GET'])
def dashboard_full():
    """
    GET /api/dashboard/full
    Returns all stats needed for the dashboard in one call:
    stat cards, donut chart data, campaign table, risk leaderboard,
    recent events feed, and per-campaign chart data.
    """
    conn = get_db()

    # ── Stat card numbers ──────────────────────────────────────────────────
    total_sent = conn.execute(
        'SELECT COUNT(*) FROM email_logs'
    ).fetchone()[0]

    opened    = conn.execute("SELECT COUNT(*) FROM tracking_events WHERE event_type='opened'").fetchone()[0]
    clicked   = conn.execute("SELECT COUNT(*) FROM tracking_events WHERE event_type='clicked'").fetchone()[0]
    submitted = conn.execute("SELECT COUNT(*) FROM tracking_events WHERE event_type='submitted'").fetchone()[0]
    reported  = conn.execute("SELECT COUNT(*) FROM tracking_events WHERE event_type='reported'").fetchone()[0]

    open_rate   = round(opened    / total_sent * 100, 1) if total_sent > 0 else 0
    click_rate  = round(clicked   / total_sent * 100, 1) if total_sent > 0 else 0
    report_rate = round(reported  / total_sent * 100, 1) if total_sent > 0 else 0
    submit_rate = round(submitted / total_sent * 100, 1) if total_sent > 0 else 0

    # ── Campaign table ─────────────────────────────────────────────────────
    campaigns_raw = conn.execute(
        'SELECT * FROM campaigns ORDER BY created_at DESC LIMIT 10'
    ).fetchall()

    campaigns = []
    for c in campaigns_raw:
        cid     = c['id']
        targets = conn.execute(
            'SELECT COUNT(*) FROM campaign_targets WHERE campaign_id=?', (cid,)
        ).fetchone()[0]
        cl = conn.execute(
            "SELECT COUNT(*) FROM tracking_events WHERE campaign_id=? AND event_type='clicked'", (cid,)
        ).fetchone()[0]
        sb = conn.execute(
            "SELECT COUNT(*) FROM tracking_events WHERE campaign_id=? AND event_type='submitted'", (cid,)
        ).fetchone()[0]
        campaigns.append({
            'id':         cid,
            'name':       c['name'],
            'template':   c['template'],
            'status':     c['status'],
            'sent':       targets,
            'clicked':    cl,
            'submitted':  sb,
            'click_rate': round(cl / targets * 100, 1) if targets > 0 else 0,
        })

    # ── Risk leaderboard ───────────────────────────────────────────────────
    employees = conn.execute('''
        SELECT id, name, email, department, risk_score
        FROM users WHERE role='employee'
        ORDER BY risk_score DESC LIMIT 8
    ''').fetchall()

    # ── Recent events feed ─────────────────────────────────────────────────
    recent = conn.execute('''
        SELECT
            te.event_type,
            te.email,
            te.timestamp,
            te.campaign_id,
            c.name  AS campaign_name,
            u.name  AS employee_name,
            u.department
        FROM tracking_events te
        LEFT JOIN campaigns c ON te.campaign_id = c.id
        LEFT JOIN users u     ON te.email = u.email
        ORDER BY te.timestamp DESC
        LIMIT 20
    ''').fetchall()

    # ── Per-campaign chart data (last 6 campaigns) ─────────────────────────
    chart_campaigns = conn.execute(
        'SELECT id, name FROM campaigns ORDER BY created_at DESC LIMIT 6'
    ).fetchall()
    chart_labels     = []
    chart_click_data = []
    chart_submit_data = []
    for cc in reversed(list(chart_campaigns)):
        cid   = cc['id']
        tgts  = conn.execute(
            'SELECT COUNT(*) FROM campaign_targets WHERE campaign_id=?', (cid,)
        ).fetchone()[0]
        cl = conn.execute(
            "SELECT COUNT(*) FROM tracking_events WHERE campaign_id=? AND event_type='clicked'", (cid,)
        ).fetchone()[0]
        sb = conn.execute(
            "SELECT COUNT(*) FROM tracking_events WHERE campaign_id=? AND event_type='submitted'", (cid,)
        ).fetchone()[0]
        chart_labels.append(cc['name'][:12])
        chart_click_data.append(round(cl / tgts * 100, 1) if tgts > 0 else 0)
        chart_submit_data.append(round(sb / tgts * 100, 1) if tgts > 0 else 0)

    conn.close()

    return jsonify({
        'stats': {
            'total_sent':   total_sent,
            'opened':       opened,
            'clicked':      clicked,
            'submitted':    submitted,
            'reported':     reported,
            'open_rate':    open_rate,
            'click_rate':   click_rate,
            'report_rate':  report_rate,
            'submit_rate':  submit_rate,
        },
        'campaigns':   campaigns,
        'employees':   [dict(e) for e in employees],
        'recent':      [dict(r) for r in recent],
        'chart': {
            'labels':      chart_labels,
            'click_rate':  chart_click_data,
            'submit_rate': chart_submit_data,
        }
    })


# ── Inbox API ─────────────────────────────────────────────────────────────
@app.route('/api/inbox', methods=['GET'])
def get_inbox():
    """
    GET /api/inbox?email=X
    Returns all emails sent to a specific recipient from email_logs.
    If no email param, returns all emails (admin view).
    """
    recipient = request.args.get('email', '')
    conn = get_db()
    if recipient:
        rows = conn.execute('''
            SELECT el.*, c.name as campaign_name,
            CASE WHEN EXISTS (
                SELECT 1 FROM tracking_events te
                WHERE te.email = el.recipient_email
                AND te.campaign_id = el.campaign_id
                AND te.event_type = 'opened'
            ) THEN 1 ELSE 0 END AS opened,
            CASE WHEN EXISTS (
                SELECT 1 FROM tracking_events te
                WHERE te.email = el.recipient_email
                AND te.campaign_id = el.campaign_id
                AND te.event_type = 'clicked'
            ) THEN 1 ELSE 0 END AS clicked,
            CASE WHEN EXISTS (
                SELECT 1 FROM tracking_events te
                WHERE te.email = el.recipient_email
                AND te.campaign_id = el.campaign_id
                AND te.event_type = 'submitted'
            ) THEN 1 ELSE 0 END AS submitted
            FROM email_logs el
            LEFT JOIN campaigns c ON el.campaign_id = c.id
            WHERE el.recipient_email = ?
            ORDER BY el.sent_at DESC
        ''', (recipient,)).fetchall()
    else:
        rows = conn.execute('''
            SELECT el.*, c.name as campaign_name,
            CASE WHEN EXISTS (
                SELECT 1 FROM tracking_events te
                WHERE te.email = el.recipient_email
                AND te.campaign_id = el.campaign_id
                AND te.event_type = 'opened'
            ) THEN 1 ELSE 0 END AS opened,
            CASE WHEN EXISTS (
                SELECT 1 FROM tracking_events te
                WHERE te.email = el.recipient_email
                AND te.campaign_id = el.campaign_id
                AND te.event_type = 'clicked'
            ) THEN 1 ELSE 0 END AS clicked,
            CASE WHEN EXISTS (
                SELECT 1 FROM tracking_events te
                WHERE te.email = el.recipient_email
                AND te.campaign_id = el.campaign_id
                AND te.event_type = 'submitted'
            ) THEN 1 ELSE 0 END AS submitted
            FROM email_logs el
            LEFT JOIN campaigns c ON el.campaign_id = c.id
            ORDER BY el.sent_at DESC
            LIMIT 200
        ''').fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route('/api/inbox/<int:email_id>', methods=['GET'])
def get_email(email_id):
    """
    GET /api/inbox/<id>
    Returns a single email with full HTML body.
    Also logs an 'opened' tracking event if not already logged.
    """
    conn = get_db()
    row = conn.execute(
        'SELECT * FROM email_logs WHERE id=?', (email_id,)
    ).fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'Email not found'}), 404

    # Log open event if not already tracked
    existing = conn.execute(
        "SELECT id FROM tracking_events WHERE campaign_id=? AND email=? AND event_type='opened'",
        (row['campaign_id'], row['recipient_email'])
    ).fetchone()
    if not existing:
        conn.execute('''
            INSERT INTO tracking_events (campaign_id, email, event_type, ip_address, user_agent)
            VALUES (?, ?, 'opened', ?, ?)
        ''', (row['campaign_id'], row['recipient_email'],
               request.remote_addr, request.user_agent.string))
        conn.commit()
        update_risk_score(row['recipient_email'])
        print(f'📧 Open tracked: {row["recipient_email"]} opened email {email_id}')

    conn.close()
    return jsonify(dict(row))


# ── Option B: Report via hidden link in email ─────────────────────────────
@app.route('/api/track/report-link', methods=['GET'])
def track_report_link():
    """
    GET /api/track/report-link?campaign_id=X&email=Y
    Called when an employee clicks the hidden Unsubscribe / Email Preferences
    link in the phishing email footer. Logs a 'reported' event — good behaviour.
    Redirects to a neutral page so the employee doesn't know they were being tested.
    """
    from flask import redirect
    campaign_id = request.args.get('campaign_id', '')
    email       = request.args.get('email', '').strip()

    if campaign_id and email:
        conn = get_db()
        # Only log if not already reported
        existing = conn.execute(
            "SELECT id FROM tracking_events WHERE campaign_id=? AND email=? AND event_type='reported'",
            (campaign_id, email)
        ).fetchone()
        if not existing:
            conn.execute('''
                INSERT INTO tracking_events (campaign_id, email, event_type, ip_address, user_agent)
                VALUES (?, ?, 'reported', ?, ?)
            ''', (campaign_id, email, request.remote_addr, request.user_agent.string))
            conn.commit()
            update_risk_score(email)
            print(f'🛡️ Phishing reported via hidden link: {email} in campaign {campaign_id}')
        conn.close()

    # Redirect to a neutral page — employee thinks they just unsubscribed
    # Does NOT reveal this was a phishing test
    return redirect('http://127.0.0.1:8088/unsubscribe.html')


# ── Sent Emails Display (persistent, survives Mailhog restart) ────────────
@app.route('/api/emails/sent', methods=['GET'])
def get_sent_emails():
    """
    GET /api/emails/sent
    Returns all emails sent with their tracking status.
    Persists in SQLite so Mailhog resets don't lose history.
    """
    conn = get_db()
    rows = conn.execute('''
        SELECT
            el.id,
            el.campaign_id,
            el.recipient_email,
            el.recipient_name,
            el.subject,
            el.template_name,
            el.status,
            el.sent_at,
            c.name AS campaign_name,
            CASE WHEN EXISTS (
                SELECT 1 FROM tracking_events te
                WHERE te.email = el.recipient_email
                AND te.campaign_id = el.campaign_id
                AND te.event_type = 'opened'
            ) THEN 1 ELSE 0 END AS opened,
            CASE WHEN EXISTS (
                SELECT 1 FROM tracking_events te
                WHERE te.email = el.recipient_email
                AND te.campaign_id = el.campaign_id
                AND te.event_type = 'clicked'
            ) THEN 1 ELSE 0 END AS clicked,
            CASE WHEN EXISTS (
                SELECT 1 FROM tracking_events te
                WHERE te.email = el.recipient_email
                AND te.campaign_id = el.campaign_id
                AND te.event_type = 'submitted'
            ) THEN 1 ELSE 0 END AS submitted,
            CASE WHEN EXISTS (
                SELECT 1 FROM tracking_events te
                WHERE te.email = el.recipient_email
                AND te.campaign_id = el.campaign_id
                AND te.event_type = 'reported'
            ) THEN 1 ELSE 0 END AS reported
        FROM email_logs el
        LEFT JOIN campaigns c ON el.campaign_id = c.id
        ORDER BY el.sent_at DESC
        LIMIT 200
    ''').fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


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
def migrate_db():
    """Add any missing tables/columns to an existing database (safe to run repeatedly)."""
    conn = get_db()
    c = conn.cursor()

    # smtp_profiles table
    c.execute('''
        CREATE TABLE IF NOT EXISTS smtp_profiles (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL UNIQUE,
            type        TEXT DEFAULT 'mailhog',
            host        TEXT DEFAULT '127.0.0.1',
            port        INTEGER DEFAULT 1025,
            username    TEXT DEFAULT '',
            password    TEXT DEFAULT '',
            from_name   TEXT DEFAULT 'PhishGuard',
            from_email  TEXT DEFAULT 'phishguard@localhost',
            use_tls     INTEGER DEFAULT 0,
            use_ssl     INTEGER DEFAULT 0,
            is_active   INTEGER DEFAULT 0,
            ignore_cert_errors INTEGER DEFAULT 1,
            created_at  TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    # Seed default Mailhog profile if empty
    if conn.execute('SELECT COUNT(*) FROM smtp_profiles').fetchone()[0] == 0:
        conn.execute('''
            INSERT INTO smtp_profiles (name, type, host, port, from_name, from_email, is_active)
            VALUES ('Mailhog (Local)', 'mailhog', '127.0.0.1', 1025, 'PhishGuard', 'phishguard@localhost', 1)
        ''')
        print('✅ Seeded default Mailhog SMTP profile')

    # campaign sender_name / sender_email columns (in case old DB missing them)
    try:
        c.execute('ALTER TABLE campaigns ADD COLUMN sender_name TEXT DEFAULT ""')
        print('✅ Added sender_name to campaigns')
    except: pass
    try:
        c.execute('ALTER TABLE campaigns ADD COLUMN sender_email TEXT DEFAULT ""')
        print('✅ Added sender_email to campaigns')
    except: pass

    conn.commit()
    conn.close()
    print('✅ Database migration complete')


if __name__ == '__main__':
    init_db()
    migrate_db()
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
