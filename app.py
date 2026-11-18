import os
import hashlib
import uuid
import secrets
import time
from functools import wraps
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file, Response, session
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from database import init_db, get_db_connection
from csv_processor import process_csv_content
from detector import analyze_records

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 # 16MB max upload

# Secure Session Configuration & Environment Variable Validation
app.secret_key = os.environ.get('FLASK_SECRET_KEY')
if not app.secret_key:
    if os.environ.get('FLASK_ENV') == 'production':
        raise RuntimeError("CRITICAL: FLASK_SECRET_KEY environment variable is missing in production!")
    app.secret_key = secrets.token_hex(32)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=False # Set to True in production HTTPS deployment
)

EVIDENCE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'evidence')
os.makedirs(EVIDENCE_DIR, exist_ok=True)

# Initialize DB on startup
init_db()

def log_security_event(event_type, severity='Medium', details='', client_ip='unknown'):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO security_audit_logs (event_type, severity, details, client_ip)
            VALUES (?, ?, ?, ?)
        ''', (event_type, severity, details, client_ip))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Audit log error: {e}")

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

@app.errorhandler(400)
def bad_request(e):
    client_ip = request.remote_addr or 'unknown'
    log_security_event('BAD_REQUEST', 'Low', f'Path: {request.path}', client_ip)
    return jsonify({'ok': False, 'error': {'code': 'BAD_REQUEST', 'message': str(e.description if hasattr(e, 'description') else 'Invalid request.')}}), 400

@app.errorhandler(404)
def not_found(e):
    client_ip = request.remote_addr or 'unknown'
    log_security_event('NOT_FOUND', 'Low', f'Path: {request.path}', client_ip)
    return jsonify({'ok': False, 'error': {'code': 'NOT_FOUND', 'message': 'Requested resource not found.'}}), 404

@app.errorhandler(405)
def method_not_allowed(e):
    client_ip = request.remote_addr or 'unknown'
    log_security_event('METHOD_NOT_ALLOWED', 'Low', f'Path: {request.path}', client_ip)
    return jsonify({'ok': False, 'error': {'code': 'METHOD_NOT_ALLOWED', 'message': 'HTTP method not allowed for this endpoint.'}}), 405

@app.errorhandler(413)
def payload_too_large(e):
    client_ip = request.remote_addr or 'unknown'
    log_security_event('PAYLOAD_TOO_LARGE', 'Medium', f'Path: {request.path}', client_ip)
    return jsonify({'ok': False, 'error': {'code': 'PAYLOAD_TOO_LARGE', 'message': 'File or request body exceeds the maximum permitted size (16MB).'}}), 413

@app.errorhandler(429)
def rate_limit_exceeded(e):
    client_ip = request.remote_addr or 'unknown'
    log_security_event('RATE_LIMIT_EXCEEDED', 'High', f'Endpoint: {request.endpoint}', client_ip)
    return jsonify({'ok': False, 'error': {'code': 'RATE_LIMIT_EXCEEDED', 'message': 'Too many rapid requests. Please wait before retrying.'}}), 429

@app.errorhandler(500)
def internal_server_error(e):
    client_ip = request.remote_addr or 'unknown'
    log_security_event('INTERNAL_SERVER_ERROR', 'Critical', f'Path: {request.path}', client_ip)
    return jsonify({'ok': False, 'error': {'code': 'INTERNAL_SERVER_ERROR', 'message': 'An internal server error occurred.'}}), 500

@app.route('/api/security/audit-logs', methods=['GET'])
def get_security_audit_logs():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM security_audit_logs ORDER BY id DESC LIMIT 50')
    rows = cursor.fetchall()
    logs = [dict(r) for r in rows]
    conn.close()
    return jsonify({'ok': True, 'data': logs})

# Login throttling store
login_attempts_store = {}

def check_throttle(key):
    now = time.time()
    record = login_attempts_store.get(key)
    if record and record['lockout_until'] > now:
        return False, int(record['lockout_until'] - now)
    return True, 0

def record_failed_attempt(key):
    now = time.time()
    record = login_attempts_store.get(key, {'count': 0, 'lockout_until': 0})
    record['count'] += 1
    if record['count'] >= 5:
        record['lockout_until'] = now + 60
    login_attempts_store[key] = record

def clear_throttle(key):
    if key in login_attempts_store:
        del login_attempts_store[key]

request_timestamps = {}

def check_rate_limit(key, limit_seconds=0.2):
    now = time.time()
    last = request_timestamps.get(key, 0)
    if now - last < limit_seconds:
        return False
    request_timestamps[key] = now
    return True

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id'):
            return jsonify({
                'ok': False,
                'error': {
                    'code': 'UNAUTHENTICATED',
                    'message': 'Authentication required. Please log in.'
                }
            }), 401
        return f(*args, **kwargs)
    return decorated

def role_required(allowed_roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not session.get('user_id'):
                return jsonify({
                    'ok': False,
                    'error': {
                        'code': 'UNAUTHENTICATED',
                        'message': 'Authentication required. Please log in.'
                    }
                }), 401
            user_role = session.get('role')
            if user_role not in allowed_roles:
                return jsonify({
                    'ok': False,
                    'error': {
                        'code': 'FORBIDDEN',
                        'message': 'You do not have permission to perform this action.'
                    }
                }), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

def calculate_sha256_from_stream(stream):
    hasher = hashlib.sha256()
    stream.seek(0)
    for chunk in iter(lambda: stream.read(4096), b""):
        hasher.update(chunk)
    stream.seek(0)
    return hasher.hexdigest()

def calculate_sha256_file(filepath):
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    data = request.get_json(silent=True) or request.form
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()
    
    client_ip = request.remote_addr or 'unknown'
    throttle_key = f"{client_ip}_{username}"
    
    allowed, retry_in = check_throttle(throttle_key)
    if not allowed:
        return jsonify({
            'ok': False,
            'error': {
                'code': 'TOO_MANY_REQUESTS',
                'message': f'Too many failed login attempts. Please try again in {retry_in} seconds.'
            }
        }), 429
        
    if not username or not password:
        return jsonify({
            'ok': False,
            'error': {
                'code': 'INVALID_REQUEST',
                'message': 'Username and password are required.'
            }
        }), 400
        
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()
    
    if not user or not check_password_hash(user['password_hash'], password):
        record_failed_attempt(throttle_key)
        return jsonify({
            'ok': False,
            'error': {
                'code': 'INVALID_CREDENTIALS',
                'message': 'Invalid username or password.'
            }
        }), 401
        
    clear_throttle(throttle_key)
    
    # Session security: regenerate session
    session.regenerate = True if hasattr(session, 'regenerate') else None
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['role'] = user['role']
    
    return jsonify({
        'ok': True,
        'data': {
            'user': {
                'id': user['id'],
                'username': user['username'],
                'role': user['role']
            }
        }
    })

@app.route('/api/auth/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({
        'ok': True,
        'data': {
            'message': 'Logged out successfully.'
        }
    })

def validate_password_policy(password):
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long."
    return True, ""

@app.route('/api/auth/change-password', methods=['POST'])
@login_required
def api_change_password():
    data = request.get_json(silent=True) or request.form
    current_password = data.get('current_password', '').strip()
    new_password = data.get('new_password', '').strip()
    
    if not current_password or not new_password:
        return jsonify({
            'ok': False,
            'error': {
                'code': 'INVALID_REQUEST',
                'message': 'Current password and new password are required.'
            }
        }), 400
        
    valid_policy, policy_msg = validate_password_policy(new_password)
    if not valid_policy:
        return jsonify({
            'ok': False,
            'error': {
                'code': 'WEAK_PASSWORD',
                'message': policy_msg
            }
        }), 400
        
    user_id = session.get('user_id')
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    
    if not user or not check_password_hash(user['password_hash'], current_password):
        conn.close()
        return jsonify({
            'ok': False,
            'error': {
                'code': 'INVALID_CREDENTIALS',
                'message': 'Current password is incorrect.'
            }
        }), 401
        
    new_hash = generate_password_hash(new_password)
    cursor.execute('UPDATE users SET password_hash = ? WHERE id = ?', (new_hash, user_id))
    conn.commit()
    conn.close()
    
    # Invalidate session after password change for security
    session.clear()
    
    return jsonify({
        'ok': True,
        'data': {
            'message': 'Password changed successfully. Please log in again with your new password.'
        }
    })

@app.route('/api/auth/me', methods=['GET'])
@login_required
def api_me():
    return jsonify({
        'ok': True,
        'data': {
            'user': {
                'id': session.get('user_id'),
                'username': session.get('username'),
                'role': session.get('role')
            }
        }
    })

@app.route('/api/stats', methods=['GET'])
def get_stats():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get latest run
    cursor.execute('SELECT * FROM analysis_runs ORDER BY id DESC LIMIT 1')
    run = cursor.fetchone()
    
    if not run:
        conn.close()
        return jsonify({
            'total_events': 0,
            'suspicious_events': 0,
            'critical_alerts': 0,
            'last_status': 'No Analysis Performed',
            'severity_breakdown': {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0},
            'events_over_time': {},
            'normal_vs_suspicious': {'Normal': 0, 'Suspicious': 0},
            'recent_activity': []
        })
    
    run_id = run['id']
    
    cursor.execute('SELECT COUNT(*) FROM log_events WHERE run_id = ?', (run_id,))
    total_events = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM log_events WHERE run_id = ? AND severity IN ('Critical', 'High', 'Medium')", (run_id,))
    suspicious_events = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM log_events WHERE run_id = ? AND severity = 'Critical'", (run_id,))
    critical_alerts = cursor.fetchone()[0]
    
    # Severity breakdown
    cursor.execute("SELECT severity, COUNT(*) as count FROM log_events WHERE run_id = ? GROUP BY severity", (run_id,))
    sev_rows = cursor.fetchall()
    severity_breakdown = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
    for row in sev_rows:
        if row['severity'] in severity_breakdown:
            severity_breakdown[row['severity']] = row['count']
            
    normal_count = total_events - suspicious_events
    normal_vs_suspicious = {'Normal': normal_count, 'Suspicious': suspicious_events}
    
    # Events over time (by date/hour prefix from timestamp)
    cursor.execute("SELECT substr(timestamp, 1, 13) as time_slot, COUNT(*) as count FROM log_events WHERE run_id = ? GROUP BY time_slot ORDER BY time_slot", (run_id,))
    time_rows = cursor.fetchall()
    events_over_time = {row['time_slot']: row['count'] for row in time_rows}
    
    # Recent activity
    cursor.execute("SELECT timestamp, source_ip, event_type, severity, detection_reason FROM log_events WHERE run_id = ? ORDER BY id DESC LIMIT 10", (run_id,))
    recent_rows = cursor.fetchall()
    recent_activity = [dict(row) for row in recent_rows]
    
    conn.close()
    
    return jsonify({
        'total_events': total_events,
        'suspicious_events': suspicious_events,
        'critical_alerts': critical_alerts,
        'last_status': run['status'],
        'filename': run['filename'],
        'severity_breakdown': severity_breakdown,
        'events_over_time': events_over_time,
        'normal_vs_suspicious': normal_vs_suspicious,
        'recent_activity': recent_activity
    })

@app.route('/api/logs', methods=['GET'])
def get_logs():
    search = request.args.get('search', '').strip()
    severity = request.args.get('severity', '').strip()
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get latest run_id
    cursor.execute('SELECT id FROM analysis_runs ORDER BY id DESC LIMIT 1')
    run = cursor.fetchone()
    if not run:
        conn.close()
        return jsonify({'logs': [], 'total': 0, 'page': page, 'per_page': per_page})
        
    run_id = run['id']
    
    query = 'SELECT * FROM log_events WHERE run_id = ?'
    params = [run_id]
    
    if search:
        query += ' AND (source_ip LIKE ? OR event_type LIKE ? OR username LIKE ? OR status LIKE ?)'
        term = f'%{search}%'
        params.extend([term, term, term, term])
        
    if severity and severity != 'All':
        query += ' AND severity = ?'
        params.append(severity)
        
    # Count total matching
    count_query = f'SELECT COUNT(*) FROM ({query})'
    cursor.execute(count_query, params)
    total_matching = cursor.fetchone()[0]
    
    # Pagination
    query += ' ORDER BY id DESC LIMIT ? OFFSET ?'
    offset = (page - 1) * per_page
    params.extend([per_page, offset])
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    logs = [dict(row) for row in rows]
    
    conn.close()
    return jsonify({
        'logs': logs,
        'total': total_matching,
        'page': page,
        'per_page': per_page
    })

@app.route('/api/detections', methods=['GET'])
def get_detections():
    search = request.args.get('search', '').strip()
    severity = request.args.get('severity', '').strip()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT id FROM analysis_runs ORDER BY id DESC LIMIT 1')
    run = cursor.fetchone()
    if not run:
        conn.close()
        return jsonify({'detections': []})
        
    run_id = run['id']
    query = 'SELECT * FROM detections WHERE run_id = ?'
    params = [run_id]
    
    if search:
        query += ' AND (source_ip LIKE ? OR rule_triggered LIKE ? OR evidence LIKE ?)'
        term = f'%{search}%'
        params.extend([term, term, term])
        
    if severity and severity != 'All':
        query += ' AND severity = ?'
        params.append(severity)
        
    query += ' ORDER BY id DESC'
    cursor.execute(query, params)
    rows = cursor.fetchall()
    detections = [dict(row) for row in rows]
    
    conn.close()
    return jsonify({'detections': detections})

@app.route('/api/upload', methods=['POST'])
def upload_file():
    client_ip = request.remote_addr or 'unknown'
    if not check_rate_limit(f"{client_ip}:upload", limit_seconds=0.05):
        return jsonify({'ok': False, 'error': {'code': 'RATE_LIMIT_EXCEEDED', 'message': 'Too many rapid upload requests.'}}), 429

    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request.'}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected.'}), 400
        
    if not file.filename.lower().endswith('.csv'):
        return jsonify({'error': 'Invalid file format. Please upload a .csv file.'}), 400
        
    try:
        parsed = process_csv_content(file)
        valid_records = parsed['valid_records']
        total_records = parsed['total']
        invalid_count = parsed['invalid_count']
        
        if not valid_records:
            return jsonify({'error': 'No valid log records found in the uploaded CSV file.'}), 400
            
        analysis_result = analyze_records(valid_records)
        final_records = analysis_result['records']
        detections = analysis_result['detections']
        findings = analysis_result['findings']
        suspicious_count = analysis_result['suspicious_count']
        
        investigation_id = 1
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO analysis_runs (investigation_id, filename, total_records, valid_records, invalid_records, suspicious_count, rules_evaluated, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (investigation_id, file.filename, total_records, len(final_records), invalid_count, suspicious_count, 3, 'Completed'))
        run_id = cursor.lastrowid
        
        event_id_map = []
        for rec in final_records:
            cursor.execute('''
                INSERT INTO log_events (run_id, timestamp, source_ip, event_type, username, status, severity, detection_reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (run_id, rec['timestamp'], rec['source_ip'], rec['event_type'], rec['username'], rec['status'], rec['severity'], rec['detection_reason']))
            event_id_map.append(cursor.lastrowid)
            
        for det in detections:
            cursor.execute('''
                INSERT INTO detections (run_id, timestamp, source_ip, rule_triggered, severity, evidence, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (run_id, det['timestamp'], det['source_ip'], det['rule_triggered'], det['severity'], det['evidence'], det['status']))
            
        for find in findings:
            cursor.execute('''
                INSERT INTO findings (investigation_id, analysis_run_id, rule_id, rule_name, description, severity, status, detected_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (investigation_id, run_id, find['rule_id'], find['rule_name'], find['description'], find['severity'], find['status'], find['detected_at']))
            finding_id = cursor.lastrowid
            
            for evt_idx in find.get('supporting_event_ids', []):
                if 1 <= evt_idx <= len(event_id_map):
                    real_event_id = event_id_map[evt_idx - 1]
                    cursor.execute('INSERT INTO finding_events (finding_id, event_id) VALUES (?, ?)', (finding_id, real_event_id))
            
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Log analysis completed successfully.',
            'stats': {
                'total': total_records,
                'valid': len(final_records),
                'invalid': invalid_count,
                'suspicious': suspicious_count
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/load-sample', methods=['POST'])
def load_sample():
    client_ip = request.remote_addr or 'unknown'
    if not check_rate_limit(f"{client_ip}:load-sample", limit_seconds=0.05):
        return jsonify({'ok': False, 'error': {'code': 'RATE_LIMIT_EXCEEDED', 'message': 'Too many rapid requests.'}}), 429

    root_dir = os.path.dirname(os.path.abspath(__file__))
    sample_path = os.path.join(root_dir, 'data', 'sample_logs.csv')
    if not os.path.exists(sample_path):
        sample_path = os.path.join(os.getcwd(), 'data', 'sample_logs.csv')
    if not os.path.exists(sample_path):
        return jsonify({'error': f'Sample dataset file not found at {sample_path}.'}), 404
        
    try:
        with open(sample_path, 'r', encoding='utf-8') as f:
            parsed = process_csv_content(f)
            
        valid_records = parsed['valid_records']
        total_records = parsed['total']
        invalid_count = parsed['invalid_count']
        
        analysis_result = analyze_records(valid_records)
        final_records = analysis_result['records']
        detections = analysis_result['detections']
        findings = analysis_result['findings']
        suspicious_count = analysis_result['suspicious_count']
        
        investigation_id = 1
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO analysis_runs (investigation_id, filename, total_records, valid_records, invalid_records, suspicious_count, rules_evaluated, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (investigation_id, 'sample_logs.csv (Demo)', total_records, len(final_records), invalid_count, suspicious_count, 3, 'Completed'))
        run_id = cursor.lastrowid
        
        event_id_map = []
        for rec in final_records:
            cursor.execute('''
                INSERT INTO log_events (run_id, timestamp, source_ip, event_type, username, status, severity, detection_reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (run_id, rec['timestamp'], rec['source_ip'], rec['event_type'], rec['username'], rec['status'], rec['severity'], rec['detection_reason']))
            event_id_map.append(cursor.lastrowid)
            
        for det in detections:
            cursor.execute('''
                INSERT INTO detections (run_id, timestamp, source_ip, rule_triggered, severity, evidence, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (run_id, det['timestamp'], det['source_ip'], det['rule_triggered'], det['severity'], det['evidence'], det['status']))
            
        for find in findings:
            cursor.execute('''
                INSERT INTO findings (investigation_id, analysis_run_id, rule_id, rule_name, description, severity, status, detected_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (investigation_id, run_id, find['rule_id'], find['rule_name'], find['description'], find['severity'], find['status'], find['detected_at']))
            finding_id = cursor.lastrowid
            
            for evt_idx in find.get('supporting_event_ids', []):
                if 1 <= evt_idx <= len(event_id_map):
                    real_event_id = event_id_map[evt_idx - 1]
                    cursor.execute('INSERT INTO finding_events (finding_id, event_id) VALUES (?, ?)', (finding_id, real_event_id))
            
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Sample dataset loaded and analyzed successfully.',
            'stats': {
                'total': total_records,
                'valid': len(final_records),
                'invalid': invalid_count,
                'suspicious': suspicious_count
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/investigations', methods=['GET'])
@login_required
def get_investigations():
    search = request.args.get('search', '').strip()
    status = request.args.get('status', '').strip()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = 'SELECT * FROM investigations WHERE 1=1'
    params = []
    
    if search:
        query += ' AND (title LIKE ? OR investigation_uid LIKE ?)'
        term = f'%{search}%'
        params.extend([term, term])
        
    if status and status != 'All':
        query += ' AND status = ?'
        params.append(status)
        
    query += ' ORDER BY id DESC'
    cursor.execute(query, params)
    rows = cursor.fetchall()
    
    investigations = []
    for row in rows:
        inv = dict(row)
        # Get evidence count
        cursor.execute('SELECT COUNT(*) FROM evidence_files WHERE investigation_id = ?', (inv['id'],))
        inv['evidence_count'] = cursor.fetchone()[0]
        
        # Get findings count via analysis_runs
        cursor.execute('''
            SELECT COUNT(d.id) FROM detections d 
            JOIN analysis_runs ar ON d.run_id = ar.id 
            WHERE ar.investigation_id = ?
        ''', (inv['id'],))
        inv['findings_count'] = cursor.fetchone()[0]
        
        investigations.append(inv)
        
    conn.close()
    return jsonify({
        'ok': True,
        'data': {
            'investigations': investigations
        }
    })

@app.route('/api/investigations', methods=['POST'])
@role_required(['Administrator', 'Analyst'])
def create_investigation():
    data = request.get_json(silent=True) or request.form
    title = data.get('title', '').strip()
    description = data.get('description', '').strip()
    status = data.get('status', 'Open').strip()
    user_id = session.get('user_id')
    
    if not title:
        return jsonify({
            'ok': False,
            'error': {
                'code': 'INVALID_REQUEST',
                'message': 'Investigation title is required.'
            }
        }), 400
        
    valid_statuses = ['Open', 'In Progress', 'Completed', 'Archived']
    if status not in valid_statuses:
        status = 'Open'
        
    investigation_uid = f"INV-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
    
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO investigations (investigation_uid, title, description, status, user_id)
            VALUES (?, ?, ?, ?, ?)
        ''', (investigation_uid, title, description, status, user_id))
        conn.commit()
        inv_id = cursor.lastrowid
        
        cursor.execute('SELECT * FROM investigations WHERE id = ?', (inv_id,))
        created_inv = dict(cursor.fetchone())
        created_inv['evidence_count'] = 0
        created_inv['findings_count'] = 0
        
        conn.close()
        return jsonify({
            'ok': True,
            'data': {
                'item': created_inv
            }
        }), 201
    except Exception as e:
        conn.close()
        return jsonify({
            'ok': False,
            'error': {
                'code': 'DATABASE_ERROR',
                'message': str(e)
            }
        }), 500

@app.route('/api/investigations/<int:id>', methods=['GET'])
@login_required
def get_investigation_details(id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM investigations WHERE id = ?', (id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return jsonify({
            'ok': False,
            'error': {
                'code': 'NOT_FOUND',
                'message': 'Investigation not found.'
            }
        }), 404
        
    inv = dict(row)
    
    # Evidence count and list
    cursor.execute('SELECT * FROM evidence_files WHERE investigation_id = ? ORDER BY id DESC', (id,))
    evidence_rows = cursor.fetchall()
    inv['evidence_files'] = [dict(e) for e in evidence_rows]
    inv['evidence_count'] = len(evidence_rows)
    
    # Analysis runs and findings count
    cursor.execute('SELECT * FROM analysis_runs WHERE investigation_id = ? ORDER BY id DESC', (id,))
    run_rows = cursor.fetchall()
    inv['analysis_runs'] = [dict(r) for r in run_rows]
    
    cursor.execute('''
        SELECT COUNT(d.id) FROM detections d 
        JOIN analysis_runs ar ON d.run_id = ar.id 
        WHERE ar.investigation_id = ?
    ''', (id,))
    inv['findings_count'] = cursor.fetchone()[0]
    
    conn.close()
    return jsonify({
        'ok': True,
        'data': {
            'item': inv
        }
    })

@app.route('/api/investigations/<int:id>', methods=['PUT', 'PATCH'])
@role_required(['Administrator', 'Analyst'])
def update_investigation(id):
    data = request.get_json(silent=True) or request.form
    title = data.get('title', '').strip()
    description = data.get('description', '').strip()
    status = data.get('status', '').strip()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM investigations WHERE id = ?', (id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return jsonify({
            'ok': False,
            'error': {
                'code': 'NOT_FOUND',
                'message': 'Investigation not found.'
            }
        }), 404
        
    current = dict(row)
    new_title = title if title else current['title']
    new_desc = description if description else current['description']
    new_status = status if status in ['Open', 'In Progress', 'Completed', 'Archived'] else current['status']
    
    cursor.execute('''
        UPDATE investigations 
        SET title = ?, description = ?, status = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    ''', (new_title, new_desc, new_status, id))
    conn.commit()
    
    cursor.execute('SELECT * FROM investigations WHERE id = ?', (id,))
    updated_inv = dict(cursor.fetchone())
    
    # counts
    cursor.execute('SELECT COUNT(*) FROM evidence_files WHERE investigation_id = ?', (id,))
    updated_inv['evidence_count'] = cursor.fetchone()[0]
    cursor.execute('''
        SELECT COUNT(d.id) FROM detections d 
        JOIN analysis_runs ar ON d.run_id = ar.id 
        WHERE ar.investigation_id = ?
    ''', (id,))
    updated_inv['findings_count'] = cursor.fetchone()[0]
    
    conn.close()
    return jsonify({
        'ok': True,
        'data': {
            'item': updated_inv
        }
    })

@app.route('/api/investigations/<int:id>/evidence', methods=['POST'])
@role_required(['Administrator', 'Analyst'])
def upload_investigation_evidence(id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM investigations WHERE id = ?', (id,))
    inv = cursor.fetchone()
    if not inv:
        conn.close()
        return jsonify({
            'ok': False,
            'error': {
                'code': 'NOT_FOUND',
                'message': 'Investigation not found.'
            }
        }), 404
        
    if 'file' not in request.files:
        conn.close()
        return jsonify({
            'ok': False,
            'error': {
                'code': 'INVALID_FILE',
                'message': 'No file part in the request.'
            }
        }), 400
        
    file = request.files['file']
    if file.filename == '':
        conn.close()
        return jsonify({
            'ok': False,
            'error': {
                'code': 'INVALID_FILE',
                'message': 'No file selected.'
            }
        }), 400
        
    if not file.filename.lower().endswith('.csv'):
        conn.close()
        return jsonify({
            'ok': False,
            'error': {
                'code': 'UNSUPPORTED_MEDIA_TYPE',
                'message': 'Invalid file format. Only CSV files are supported.'
            }
        }), 415
        
    # Check if empty file
    file.stream.seek(0, os.SEEK_END)
    file_size = file.stream.tell()
    file.stream.seek(0)
    
    if file_size == 0:
        conn.close()
        return jsonify({
            'ok': False,
            'error': {
                'code': 'INVALID_FILE',
                'message': 'The uploaded CSV file is empty.'
            }
        }), 400
        
    try:
        # Calculate SHA-256 hash from original bytes
        sha256_hash = calculate_sha256_from_stream(file.stream)
        
        # Check duplicate upload in same investigation
        cursor.execute('SELECT id FROM evidence_files WHERE investigation_id = ? AND sha256_hash = ?', (id, sha256_hash))
        if cursor.fetchone():
            conn.close()
            return jsonify({
                'ok': False,
                'error': {
                    'code': 'DUPLICATE_FILE',
                    'message': 'An identical evidence file (matching SHA-256 hash) has already been uploaded to this investigation.'
                }
            }), 409
            
        original_filename = secure_filename(file.filename) or 'evidence.csv'
        stored_filename = f"{uuid.uuid4().hex}_{original_filename}"
        stored_path = os.path.join(EVIDENCE_DIR, stored_filename)
        
        file.save(stored_path)
        
        # Save metadata in SQLite
        cursor.execute('''
            INSERT INTO evidence_files (investigation_id, original_filename, stored_filename, file_size, sha256_hash, processing_status)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (id, original_filename, stored_filename, file_size, sha256_hash, 'Uploaded'))
        conn.commit()
        evidence_id = cursor.lastrowid
        
        cursor.execute('SELECT * FROM evidence_files WHERE id = ?', (evidence_id,))
        evidence_record = dict(cursor.fetchone())
        
        conn.close()
        return jsonify({
            'ok': True,
            'data': {
                'item': evidence_record
            }
        }), 201
        
    except Exception as e:
        conn.close()
        return jsonify({
            'ok': False,
            'error': {
                'code': 'INTERNAL_ERROR',
                'message': str(e)
            }
        }), 500

@app.route('/api/investigations/<int:id>/evidence', methods=['GET'])
@login_required
def get_investigation_evidence(id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM investigations WHERE id = ?', (id,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({
            'ok': False,
            'error': {
                'code': 'NOT_FOUND',
                'message': 'Investigation not found.'
            }
        }), 404
        
    cursor.execute('SELECT * FROM evidence_files WHERE investigation_id = ? ORDER BY id DESC', (id,))
    rows = cursor.fetchall()
    evidence_list = []
    for row in rows:
        ev = dict(row)
        # Verify integrity on listing or provide verification status
        stored_path = os.path.join(EVIDENCE_DIR, ev['stored_filename'])
        if os.path.exists(stored_path):
            current_hash = calculate_sha256_file(stored_path)
            ev['integrity_status'] = 'Integrity Verified' if current_hash == ev['sha256_hash'] else 'Integrity Mismatch'
        else:
            ev['integrity_status'] = 'Verification Failed (File Missing)'
        evidence_list.append(ev)
        
    conn.close()
    return jsonify({
        'ok': True,
        'data': {
            'evidence_files': evidence_list
        }
    })

@app.route('/api/investigations/<int:investigation_id>/analyze', methods=['POST'])
@login_required
@role_required(['Administrator', 'Analyst'])
def run_investigation_analysis(investigation_id):
    client_ip = request.remote_addr or 'unknown'
    if not check_rate_limit(f"{client_ip}:analyze", limit_seconds=0.05):
        return jsonify({
            'ok': False,
            'error': {
                'code': 'RATE_LIMIT_EXCEEDED',
                'message': 'Too many rapid analysis requests.'
            }
        }), 429

    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get latest analysis run or events for this investigation
    cursor.execute('SELECT * FROM analysis_runs WHERE investigation_id = ? ORDER BY id DESC LIMIT 1', (investigation_id,))
    run = cursor.fetchone()
    
    if not run:
        # Fallback to absolute latest run if no investigation-specific run exists
        cursor.execute('SELECT * FROM analysis_runs ORDER BY id DESC LIMIT 1')
        run = cursor.fetchone()
        
    if not run:
        conn.close()
        return jsonify({
            'ok': False,
            'error': {
                'code': 'NOT_FOUND',
                'message': 'No events found to analyze for this investigation.'
            }
        }), 404
        
    run_id = run['id']
    cursor.execute('SELECT * FROM log_events WHERE run_id = ?', (run_id,))
    rows = cursor.fetchall()
    records = [dict(r) for r in rows]
    
    if not records:
        conn.close()
        return jsonify({
            'ok': False,
            'error': {
                'code': 'INVALID_REQUEST',
                'message': 'No valid log records found for analysis.'
            }
        }), 400
        
    analysis_result = analyze_records(records)
    findings = analysis_result['findings']
    
    # Store new analysis run
    cursor.execute('''
        INSERT INTO analysis_runs (investigation_id, filename, total_records, valid_records, invalid_records, suspicious_count, rules_evaluated, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (investigation_id, run['filename'], len(records), len(records), 0, analysis_result['suspicious_count'], 3, 'Completed'))
    new_run_id = cursor.lastrowid
    
    # Map event IDs
    event_id_map = [r['id'] for r in rows]
    
    for find in findings:
        cursor.execute('''
            INSERT INTO findings (investigation_id, analysis_run_id, rule_id, rule_name, description, severity, status, detected_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (investigation_id, new_run_id, find['rule_id'], find['rule_name'], find['description'], find['severity'], find['status'], find['detected_at']))
        finding_id = cursor.lastrowid
        
        for evt_idx in find.get('supporting_event_ids', []):
            if 1 <= evt_idx <= len(event_id_map):
                real_event_id = event_id_map[evt_idx - 1]
                cursor.execute('INSERT INTO finding_events (finding_id, event_id) VALUES (?, ?)', (finding_id, real_event_id))
                
    conn.commit()
    conn.close()
    
    return jsonify({
        'ok': True,
        'data': {
            'analysis_run_id': new_run_id,
            'investigation_id': investigation_id,
            'events_analyzed': len(records),
            'rules_evaluated': 3,
            'findings_generated': len(findings),
            'status': 'Completed'
        }
    })

@app.route('/api/investigations/<int:investigation_id>/analysis-runs', methods=['GET'])
@login_required
def get_analysis_runs(investigation_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM analysis_runs WHERE investigation_id = ? ORDER BY id DESC', (investigation_id,))
    rows = cursor.fetchall()
    runs = [dict(r) for r in rows]
    conn.close()
    return jsonify({'ok': True, 'data': runs})

@app.route('/api/investigations/<int:investigation_id>/findings', methods=['GET'])
@login_required
def get_investigation_findings(investigation_id):
    severity = request.args.get('severity', '').strip()
    status = request.args.get('status', '').strip()
    rule = request.args.get('rule', '').strip()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = 'SELECT * FROM findings WHERE investigation_id = ?'
    params = [investigation_id]
    
    if severity and severity != 'All':
        query += ' AND severity = ?'
        params.append(severity)
    if status and status != 'All':
        query += ' AND status = ?'
        params.append(status)
    if rule:
        query += ' AND (rule_id = ? OR rule_name LIKE ?)'
        params.extend([rule, f'%{rule}%'])
        
    query += ' ORDER BY id DESC'
    cursor.execute(query, params)
    rows = cursor.fetchall()
    findings = []
    for r in rows:
        f = dict(r)
        # Get supporting event IDs
        cursor.execute('SELECT event_id FROM finding_events WHERE finding_id = ?', (f['id'],))
        f['supporting_event_ids'] = [e['event_id'] for e in cursor.fetchall()]
        findings.append(f)
        
    conn.close()
    return jsonify({'ok': True, 'data': findings})

@app.route('/api/findings/<int:finding_id>', methods=['GET'])
@login_required
def get_finding_details(finding_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM findings WHERE id = ?', (finding_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return jsonify({
            'ok': False,
            'error': {
                'code': 'NOT_FOUND',
                'message': 'Finding not found.'
            }
        }), 404
        
    finding = dict(row)
    
    # Get supporting events
    cursor.execute('''
        SELECT e.* FROM log_events e
        JOIN finding_events fe ON e.id = fe.event_id
        WHERE fe.finding_id = ?
    ''', (finding_id,))
    finding['supporting_events'] = [dict(e) for e in cursor.fetchall()]
    finding['supporting_event_ids'] = [e['id'] for e in finding['supporting_events']]
    
    # Get notes
    cursor.execute('SELECT * FROM finding_notes WHERE finding_id = ? ORDER BY id DESC', (finding_id,))
    finding['notes'] = [dict(n) for n in cursor.fetchall()]
    
    conn.close()
    return jsonify({'ok': True, 'data': finding})

@app.route('/api/findings/<int:finding_id>/status', methods=['PATCH'])
@login_required
@role_required(['Administrator', 'Analyst'])
def update_finding_status(finding_id):
    data = request.get_json() or {}
    new_status = data.get('status', '').strip()
    
    valid_statuses = ['New', 'Under Review', 'Resolved', 'False Positive']
    if new_status not in valid_statuses:
        return jsonify({
            'ok': False,
            'error': {
                'code': 'INVALID_REQUEST',
                'message': f'Invalid status. Must be one of {valid_statuses}'
            }
        }), 400
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM findings WHERE id = ?', (finding_id,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({
            'ok': False,
            'error': {
                'code': 'NOT_FOUND',
                'message': 'Finding not found.'
            }
        }), 404
        
    cursor.execute('UPDATE findings SET status = ? WHERE id = ?', (new_status, finding_id))
    conn.commit()
    conn.close()
    
    return jsonify({'ok': True, 'data': {'id': finding_id, 'status': new_status}})

@app.route('/api/findings/<int:finding_id>/notes', methods=['POST'])
@login_required
@role_required(['Administrator', 'Analyst'])
def add_finding_note(finding_id):
    data = request.get_json() or {}
    note_text = data.get('note_text', '').strip()
    
    if not note_text:
        return jsonify({
            'ok': False,
            'error': {
                'code': 'INVALID_REQUEST',
                'message': 'Note text cannot be empty.'
            }
        }), 400
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM findings WHERE id = ?', (finding_id,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({
            'ok': False,
            'error': {
                'code': 'NOT_FOUND',
                'message': 'Finding not found.'
            }
        }), 404
        
    cursor.execute('INSERT INTO finding_notes (finding_id, note_text) VALUES (?, ?)', (finding_id, note_text))
    note_id = cursor.lastrowid
    conn.commit()
    
    cursor.execute('SELECT * FROM finding_notes WHERE id = ?', (note_id,))
    note = dict(cursor.fetchone())
    conn.close()
    
    return jsonify({'ok': True, 'data': note})

@app.route('/api/evidence/<int:id>', methods=['GET'])
def get_evidence_details(id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM evidence_files WHERE id = ?', (id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return jsonify({
            'ok': False,
            'error': {
                'code': 'NOT_FOUND',
                'message': 'Evidence record not found.'
            }
        }), 404
        
    ev = dict(row)
    stored_path = os.path.join(EVIDENCE_DIR, ev['stored_filename'])
    
    if os.path.exists(stored_path):
        recalculated_hash = calculate_sha256_file(stored_path)
        if recalculated_hash == ev['sha256_hash']:
            ev['integrity_status'] = 'Integrity Verified'
        else:
            ev['integrity_status'] = 'Integrity Mismatch'
    else:
        ev['integrity_status'] = 'Verification Failed (File Missing)'
        
    conn.close()
    return jsonify({
        'ok': True,
        'data': {
            'item': ev
        }
    })

@app.route('/api/download-template', methods=['GET'])
def download_template():
    template_content = "timestamp,source_ip,event_type,username,status\n2026-10-14 12:00:00,192.168.1.100,login_attempt,john_doe,success\n"
    return Response(
        template_content,
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=shadowtrace_template.csv"}
    )

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
