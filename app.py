import os
import io
import csv
import re
import uuid
import hashlib
from flask import Flask, render_template, request, jsonify, send_file, Response, after_this_request
import hashlib
from datetime import datetime
from flask import Flask, render_template, request, jsonify, Response
import time
from flask import Flask, render_template, request, jsonify, Response
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
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from config import get_config

app = Flask(__name__)
cfg = get_config()
app.config.from_object(cfg)
app.config['MAX_CONTENT_LENGTH'] = cfg.MAX_CONTENT_LENGTH

# Create required folders outside public static/
for _folder in [cfg.UPLOAD_FOLDER, cfg.REPORTS_FOLDER, cfg.BACKUPS_FOLDER]:
    os.makedirs(_folder, exist_ok=True)

# ── Security helpers ─────────────────────────────────────────────────────────

ALLOWED_EXTENSIONS = {'csv'}

def allowed_file(filename: str) -> bool:
    """Only allow .csv uploads. Case-insensitive."""
    return '.' in filename and filename.rsplit('.', 1)[-1].lower() in ALLOWED_EXTENSIONS

def safe_filename(original: str) -> str:
    """Generate a server-side UUID filename; never use the original name as path."""
    ext = original.rsplit('.', 1)[-1].lower() if '.' in original else 'bin'
    return f"{uuid.uuid4().hex}.{ext}"

def sanitize_csv_field(value) -> str:
    """
    Prevent CSV formula injection (Excel / Google Sheets).
    Strip leading =, +, -, @ characters that trigger formula execution.
    """
    s = str(value) if value is not None else ''
    if s and s[0] in ('=', '+', '-', '@', '\t', '\r'):
        s = "'" + s
    return s

def add_security_headers(response):
    """Attach security headers to every response (Member 4 — SECURITY4)."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    )
    return response

app.after_request(add_security_headers)

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

# In-memory rate limiting tracker
request_timestamps = {}

def check_rate_limit(key, limit_seconds=0.2):
    now = time.time()
    last = request_timestamps.get(key, 0)
    if now - last < limit_seconds:
        return False
    request_timestamps[key] = now
    return True

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
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PATCH, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return response

def is_api_request():
    """Determine if the request expects JSON or is targeting an API route."""
    return request.path.startswith('/api/') or request.accept_mimetypes.best == 'application/json'

@app.errorhandler(400)
def bad_request(e):
    client_ip = request.remote_addr or 'unknown'
    log_security_event('BAD_REQUEST', 'Low', f'Path: {request.path}', client_ip)
    msg = str(e.description if hasattr(e, 'description') else 'Invalid request.')
    if is_api_request():
        return jsonify({'ok': False, 'error': {'code': 'BAD_REQUEST', 'message': msg}}), 400
    return render_template('error.html', code=400, title='Bad Request', description=msg), 400

@app.errorhandler(403)
def forbidden(e):
    client_ip = request.remote_addr or 'unknown'
    log_security_event('FORBIDDEN', 'Medium', f'Path: {request.path}', client_ip)
    msg = str(e.description if hasattr(e, 'description') else 'You do not have permission to access this resource.')
    if is_api_request():
        return jsonify({'ok': False, 'error': {'code': 'FORBIDDEN', 'message': msg}}), 403
    return render_template('error.html', code=403, title='Access Forbidden', description=msg), 403

@app.errorhandler(404)
def not_found(e):
    client_ip = request.remote_addr or 'unknown'
    log_security_event('NOT_FOUND', 'Low', f'Path: {request.path}', client_ip)
    msg = 'The requested endpoint or resource was not found on this server.'
    if is_api_request():
        return jsonify({'ok': False, 'error': {'code': 'NOT_FOUND', 'message': 'Requested resource not found.'}}), 404
    return render_template('error.html', code=404, title='Resource Not Found', description=msg), 404

@app.errorhandler(405)
def method_not_allowed(e):
    client_ip = request.remote_addr or 'unknown'
    log_security_event('METHOD_NOT_ALLOWED', 'Low', f'Path: {request.path}', client_ip)
    msg = 'HTTP method not allowed for this route.'
    if is_api_request():
        return jsonify({'ok': False, 'error': {'code': 'METHOD_NOT_ALLOWED', 'message': 'HTTP method not allowed for this endpoint.'}}), 405
    return render_template('error.html', code=405, title='Method Not Allowed', description=msg), 405

@app.errorhandler(413)
def payload_too_large(e):
    client_ip = request.remote_addr or 'unknown'
    log_security_event('PAYLOAD_TOO_LARGE', 'Medium', f'Path: {request.path}', client_ip)
    msg = 'Payload exceeds the maximum permitted size limit (16MB).'
    if is_api_request():
        return jsonify({'ok': False, 'error': {'code': 'PAYLOAD_TOO_LARGE', 'message': msg}}), 413
    return render_template('error.html', code=413, title='Payload Too Large', description=msg), 413

@app.errorhandler(429)
def rate_limit_exceeded(e):
    client_ip = request.remote_addr or 'unknown'
    log_security_event('RATE_LIMIT_EXCEEDED', 'High', f'Endpoint: {request.endpoint}', client_ip)
    msg = 'Too many requests received in a short period. Please throttle your requests.'
    if is_api_request():
        return jsonify({'ok': False, 'error': {'code': 'RATE_LIMIT_EXCEEDED', 'message': 'Too many rapid requests. Please wait before retrying.'}}), 429
    return render_template('error.html', code=429, title='Rate Limit Exceeded', description=msg), 429

@app.errorhandler(500)
def internal_server_error(e):
    client_ip = request.remote_addr or 'unknown'
    log_security_event('INTERNAL_SERVER_ERROR', 'Critical', f'Path: {request.path}', client_ip)
    msg = 'An unexpected internal server error occurred within the security console.'
    if is_api_request():
        return jsonify({'ok': False, 'error': {'code': 'INTERNAL_SERVER_ERROR', 'message': 'An internal server error occurred.'}}), 500
    return render_template('error.html', code=500, title='Internal Server Error', description=msg), 500

@app.route('/api/security/audit-logs', methods=['GET'])
def get_security_audit_logs():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM security_audit_logs ORDER BY id DESC LIMIT 50')
    rows = cursor.fetchall()
    logs = [dict(r) for r in rows]
    conn.close()
    return jsonify({'ok': True, 'data': logs})

# Initialize DB on startup
init_db()

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
    
    if not user or not check_password_hash(user['password_hash'], password):
        record_failed_attempt(throttle_key)
        log_security_event('LOGIN_FAILED', 'Medium', f'Failed login attempt for username: {username}', client_ip)
        err_msg = 'Invalid username or password.'
        if user:
            cursor.execute('''
                SELECT password_hash, changed_at FROM password_history
                WHERE user_id = ? AND changed_at >= datetime('now', '-30 days')
                ORDER BY id DESC
            ''', (user['id'],))
            for hist in cursor.fetchall():
                if check_password_hash(hist['password_hash'], password):
                    try:
                        changed_dt = datetime.fromisoformat(str(hist['changed_at']).replace('Z', ''))
                        days_ago = max(0, (datetime.utcnow() - changed_dt).days)
                        when_str = 'today' if days_ago == 0 else f'{days_ago} day{"s" if days_ago != 1 else ""} ago'
                        err_msg = f'Incorrect password — this is an old password that was changed {when_str}.'
                    except Exception:
                        err_msg = 'Incorrect password — this is an old password that was recently changed.'
                    break
        conn.close()
        return jsonify({
            'ok': False,
            'error': {
                'code': 'INVALID_CREDENTIALS',
                'message': err_msg
            }
        }), 401
        
    conn.close()
    clear_throttle(throttle_key)

    # Check if MFA is enabled for this user
    if user['mfa_enabled']:
        has_totp = bool(user['totp_secret'])
        has_email = bool(user['email'])
        session['pending_mfa_user_id'] = user['id']
        return jsonify({
            'ok': True,
            'data': {
                'mfa_required': True,
                'username': user['username'],
                'methods': {'totp': has_totp, 'email': has_email}
            }
        })

    # Session security: regenerate session
    session.regenerate = True if hasattr(session, 'regenerate') else None
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['role'] = user['role']
    
    log_security_event('LOGIN_SUCCESS', 'Low', f'Successful login for username: {username} (Role: {user["role"]})', client_ip)
    
    return jsonify({
        'ok': True,
        'data': {
            'user': {
                'id': user['id'],
                'username': user['username'],
                'role': user['role'],
                'mfa_enabled': bool(user['mfa_enabled'])
            }
        }
    })


@app.route('/api/auth/login/send-otp', methods=['POST'])
def api_login_send_otp():
    uid = session.get('pending_mfa_user_id')
    if not uid:
        return jsonify({'ok': False, 'error': {'code': 'NO_PENDING_MFA', 'message': 'No pending MFA login session.'}}), 400
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, email FROM users WHERE id = ?', (uid,))
    user = cursor.fetchone()
    if not user or not user['email']:
        conn.close()
        return jsonify({'ok': False, 'error': {'code': 'NO_EMAIL', 'message': 'No email configured for this account.'}}), 400

    otp_code = f"{int.from_bytes(os.urandom(3), 'big') % 1000000:06d}"
    expires_at = datetime.utcnow() + timedelta(minutes=10)
    cursor.execute('INSERT INTO otp_codes (user_id, code, expires_at) VALUES (?, ?, ?)', (user['id'], otp_code, expires_at.isoformat()))
    conn.commit()
    conn.close()

    ok, err_msg = send_otp_email(user['email'], user['username'], otp_code)
    if not ok:
        return jsonify({'ok': False, 'error': {'code': 'EMAIL_FAILED', 'message': f'Failed to send OTP: {err_msg}'}}), 500
    return jsonify({'ok': True, 'data': {'message': f'OTP sent to {user["email"]}.'}})


@app.route('/api/auth/login/mfa', methods=['POST'])
def api_login_mfa():
    uid = session.get('pending_mfa_user_id')
    if not uid:
        return jsonify({'ok': False, 'error': {'code': 'NO_PENDING_MFA', 'message': 'No pending MFA login session.'}}), 400
    data = request.get_json(silent=True) or {}
    code = (data.get('code') or '').strip()
    method = (data.get('method') or 'totp').strip()

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (uid,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return jsonify({'ok': False, 'error': {'code': 'NOT_FOUND', 'message': 'User not found.'}}), 404

    verified = False
    if method == 'totp' and user['totp_secret'] and verify_totp(user['totp_secret'], code):
        verified = True
    elif method == 'email':
        cursor.execute('SELECT id, expires_at FROM otp_codes WHERE user_id = ? AND code = ? AND used = 0 ORDER BY id DESC LIMIT 1', (uid, code))
        otp_row = cursor.fetchone()
        if otp_row and datetime.fromisoformat(otp_row['expires_at']) > datetime.utcnow():
            verified = True
            cursor.execute('UPDATE otp_codes SET used = 1 WHERE id = ?', (otp_row['id'],))
            conn.commit()

    conn.close()
    if not verified:
        return jsonify({'ok': False, 'error': {'code': 'INVALID_MFA', 'message': 'Invalid or expired verification code.'}}), 401

    session.pop('pending_mfa_user_id', None)
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['role'] = user['role']
    log_security_event('LOGIN_SUCCESS_MFA', 'Low', f'MFA login ({method}) for {user["username"]}', request.remote_addr or 'unknown')
    return jsonify({'ok': True, 'data': {'user': {'id': user['id'], 'username': user['username'], 'role': user['role'], 'mfa_enabled': True}}})


@app.route('/api/auth/mfa/toggle', methods=['POST'])
@login_required
def api_mfa_toggle():
    data = request.get_json(silent=True) or {}
    enable = bool(data.get('enabled'))
    user_id = session.get('user_id')
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT totp_secret, email FROM users WHERE id = ?', (user_id,))
    row = cursor.fetchone()
    if enable and not (row['totp_secret'] or row['email']):
        conn.close()
        return jsonify({'ok': False, 'error': {'code': 'NO_MFA_METHOD', 'message': 'Connect Google Authenticator or add an email first before enabling MFA.'}}), 400
    cursor.execute('UPDATE users SET mfa_enabled = ? WHERE id = ?', (1 if enable else 0, user_id))
    conn.commit()
    conn.close()
    log_security_event('MFA_TOGGLED', 'Medium', f'User {session.get("username")} {"enabled" if enable else "disabled"} MFA', request.remote_addr or 'unknown')
    return jsonify({'ok': True, 'data': {'mfa_enabled': enable}})

@app.route('/api/auth/logout', methods=['POST'])
def api_logout():
    client_ip = request.remote_addr or 'unknown'
    username = session.get('username', 'unknown')
    log_security_event('LOGOUT', 'Low', f'User logged out: {username}', client_ip)
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
    username = session.get('username', 'unknown')
    client_ip = request.remote_addr or 'unknown'
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
    
    log_security_event('PASSWORD_CHANGE', 'Medium', f'Password changed for user: {username}', client_ip)
    
    # Invalidate session after password change for security
    session.clear()
    
    return jsonify({
        'ok': True,
        'data': {
            'message': 'Password changed successfully. Please log in again with your new password.'
        }
    })

@app.route('/api/auth/change-username', methods=['POST'])
@login_required
def api_change_username():
    data = request.get_json(silent=True) or {}
    new_username = (data.get('username') or '').strip()
    if not new_username or len(new_username) < 3:
        return jsonify({'ok': False, 'error': {'code': 'INVALID_USERNAME', 'message': 'Username must be at least 3 characters.'}}), 400

    user_id = session.get('user_id')
    old_username = session.get('username')
    if new_username == old_username:
        return jsonify({'ok': False, 'error': {'code': 'SAME_USERNAME', 'message': 'New username is the same as your current username.'}}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE username = ? AND id != ?', (new_username, user_id))
    if cursor.fetchone():
        conn.close()
        return jsonify({'ok': False, 'error': {'code': 'DUPLICATE_USER', 'message': f'Username "{new_username}" is already taken.'}}), 409

    cursor.execute('UPDATE users SET username = ? WHERE id = ?', (new_username, user_id))
    conn.commit()
    conn.close()

    session['username'] = new_username
    client_ip = request.remote_addr or 'unknown'
    log_security_event('USERNAME_CHANGED', 'Low', f'User {old_username} changed username to {new_username}', client_ip)
    return jsonify({'ok': True, 'data': {'username': new_username, 'role': session.get('role')}})


SOC_ROLE_PERMISSIONS = {
    'Administrator': {
        'manage_users': True,
        'upload_logs': True,
        'manage_investigations': True,
        'triage_findings': True,
        'export_reports': True,
        'view_audit': True,
    },
    'Admin': {
        'manage_users': True,
        'upload_logs': True,
        'manage_investigations': True,
        'triage_findings': True,
        'export_reports': True,
        'view_audit': True,
    },
    'Analyst': {
        'manage_users': False,
        'upload_logs': True,
        'manage_investigations': True,
        'triage_findings': True,
        'export_reports': True,
        'view_audit': True,
    },
    'Viewer': {
        'manage_users': False,
        'upload_logs': False,
        'manage_investigations': False,
        'triage_findings': False,
        'export_reports': True,
        'view_audit': True,
    }
}

@app.route('/api/auth/me', methods=['GET'])
@login_required
def api_me():
    role = session.get('role', 'Viewer')
    return jsonify({
        'ok': True,
        'data': {
            'user': {
                'id': session.get('user_id'),
                'username': session.get('username'),
                'role': role,
                'permissions': SOC_ROLE_PERMISSIONS.get(role, SOC_ROLE_PERMISSIONS['Viewer'])
            }
        }
    })


import base64
import hmac
import hashlib
import struct
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def generate_totp_secret(length=16):
    raw = os.urandom(10)
    return base64.b32encode(raw).decode('utf-8').rstrip('=')

def get_totp_token(secret, interval=30, offset=0):
    key = base64.b32decode(secret.upper() + '=' * ((8 - len(secret) % 8) % 8))
    counter = int(time.time() // interval) + offset
    msg = struct.pack('>Q', counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    o = digest[-1] & 0x0F
    token = (struct.unpack('>I', digest[o:o+4])[0] & 0x7FFFFFFF) % 1000000
    return f"{token:06d}"

def verify_totp(secret, code):
    if not secret or not code:
        return False
    code = str(code).strip()
    return hmac.compare_digest(get_totp_token(secret, offset=0), code)

def send_otp_email(to_email, username, otp_code):
    sender_email = os.environ.get('SMTP_EMAIL', 'hamdankaleem2007@gmail.com')
    app_password = os.environ.get('SMTP_APP_PASSWORD', '')
    if not app_password:
        return False, 'SMTP_APP_PASSWORD is not configured in environment.'

    msg = MIMEMultipart('alternative')
    msg['Subject'] = f'ShadowTrace SOC — Verification Code: {otp_code}'
    msg['From'] = f'ShadowTrace SOC Security <{sender_email}>'
    msg['To'] = to_email

    html_body = f"""
    <div style="font-family:Inter,Arial,sans-serif;background:#0a0f1e;color:#e2e8f0;padding:24px;border-radius:12px;border:1px solid #1e293b;">
      <h2 style="color:#22d3ee;margin-top:0;">ShadowTrace Security Operations Center</h2>
      <p>Hello <strong>{username}</strong>,</p>
      <p>Your one-time verification code is:</p>
      <div style="font-size:28px;font-weight:700;letter-spacing:6px;color:#22d3ee;background:#0f172a;padding:12px 20px;border-radius:8px;display:inline-block;border:1px solid #334155;">
        {otp_code}
      </div>
      <p style="font-size:12px;color:#94a3b8;margin-top:16px;">This code expires in 10 minutes. If you did not request this, please contact your SOC Administrator immediately.</p>
      <hr style="border:none;border-top:1px solid #1e293b;margin:20px 0;" />
      <p style="font-size:12px;color:#64748b;margin:0;">
        <strong>ShadowTrace SOC Security Team</strong><br/>
        The Three Bugs Cybersecurity Operations<br/>
        Automated Security Notification · {sender_email}
      </p>
    </div>
    """
    msg.attach(MIMEText(html_body, 'html'))

    try:
        with smtplib.SMTP('smtp.gmail.com', 587, timeout=10) as server:
            server.starttls()
            server.login(sender_email, app_password)
            server.sendmail(sender_email, [to_email], msg.as_string())
        return True, 'OTP sent'
    except Exception as e:
        return False, str(e)


@app.route('/api/auth/mfa/setup', methods=['POST'])
@login_required
def api_mfa_setup():
    user_id = session.get('user_id')
    username = session.get('username')
    secret = generate_totp_secret()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET totp_secret = ? WHERE id = ?', (secret, user_id))
    conn.commit()
    conn.close()
    otpauth_uri = f"otpauth://totp/ShadowTrace:{username}?secret={secret}&issuer=ShadowTrace"
    return jsonify({'ok': True, 'data': {'secret': secret, 'otpauth_uri': otpauth_uri}})


@app.route('/api/auth/mfa/verify', methods=['POST'])
@login_required
def api_mfa_verify():
    data = request.get_json(silent=True) or {}
    code = (data.get('code') or '').strip()
    user_id = session.get('user_id')
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT totp_secret FROM users WHERE id = ?', (user_id,))
    row = cursor.fetchone()
    if not row or not verify_totp(row['totp_secret'], code):
        conn.close()
        return jsonify({'ok': False, 'error': {'code': 'INVALID_MFA', 'message': 'Invalid 6-digit Google Authenticator code.'}}), 400
    cursor.execute('UPDATE users SET mfa_enabled = 1 WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    log_security_event('MFA_ENABLED', 'Low', f'User {session.get("username")} enabled Google Authenticator MFA', request.remote_addr or 'unknown')
    return jsonify({'ok': True, 'data': {'mfa_enabled': True}})


@app.route('/api/auth/forgot-password/lookup', methods=['POST'])
def api_forgot_password_lookup():
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    if not username:
        return jsonify({'ok': False, 'error': {'code': 'MISSING_USER', 'message': 'Please enter a username to search.'}}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT username, email, totp_secret, mfa_enabled FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        return jsonify({'ok': False, 'error': {'code': 'NOT_FOUND', 'message': f'Username "{username}" was not found.'}}), 404

    email = user['email'] or ''
    masked_email = ''
    if '@' in email:
        local, dom = email.split('@', 1)
        masked_email = (local[:2] + '***@' + dom) if len(local) > 2 else ('***@' + dom)

    return jsonify({
        'ok': True,
        'data': {
            'username': user['username'],
            'has_email': bool(email),
            'masked_email': masked_email,
            'has_totp': bool(user['totp_secret'])
        }
    })


@app.route('/api/auth/forgot-password/verify-code', methods=['POST'])
def api_forgot_password_verify_code():
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    code = (data.get('code') or '').strip()
    method = (data.get('method') or 'email').strip()

    if not username or not code:
        return jsonify({'ok': False, 'error': {'code': 'MISSING_FIELDS', 'message': 'Username and 6-digit code are required.'}}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, totp_secret FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return jsonify({'ok': False, 'error': {'code': 'NOT_FOUND', 'message': 'User not found.'}}), 404

    verified = False
    if method == 'totp' and user['totp_secret'] and verify_totp(user['totp_secret'], code):
        verified = True
    elif method == 'email':
        cursor.execute('SELECT id, expires_at FROM otp_codes WHERE user_id = ? AND code = ? AND used = 0 ORDER BY id DESC LIMIT 1', (user['id'], code))
        otp_row = cursor.fetchone()
        if otp_row and datetime.fromisoformat(otp_row['expires_at']) > datetime.utcnow():
            verified = True

    conn.close()
    if not verified:
        return jsonify({'ok': False, 'error': {'code': 'INVALID_CODE', 'message': 'Wrong or expired 6-digit verification code.'}}), 400

    return jsonify({'ok': True, 'data': {'verified': True, 'message': 'Code verified! You can now set a new password.'}})


@app.route('/api/auth/forgot-password/request', methods=['POST'])
def api_forgot_password_request():
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    if not username:
        return jsonify({'ok': False, 'error': {'code': 'MISSING_USER', 'message': 'Username is required.'}}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, email, mfa_enabled FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return jsonify({'ok': False, 'error': {'code': 'NOT_FOUND', 'message': 'User not found.'}}), 404

    if user['mfa_enabled']:
        conn.close()
        return jsonify({'ok': True, 'data': {'method': 'totp', 'message': 'Enter the 6-digit code from your Google Authenticator app.'}})

    if not user['email']:
        conn.close()
        return jsonify({'ok': False, 'error': {'code': 'NO_RECOVERY', 'message': 'Neither Google Authenticator nor an email address is configured for this account. Contact your SOC Admin.'}}), 400

    otp_code = f"{int.from_bytes(os.urandom(3), 'big') % 1000000:06d}"
    expires_at = datetime.utcnow() + timedelta(minutes=10)
    cursor.execute('INSERT INTO otp_codes (user_id, code, expires_at) VALUES (?, ?, ?)', (user['id'], otp_code, expires_at.isoformat()))
    conn.commit()
    conn.close()

    ok, err_msg = send_otp_email(user['email'], user['username'], otp_code)
    if not ok:
        return jsonify({'ok': False, 'error': {'code': 'EMAIL_FAILED', 'message': f'Could not send OTP email: {err_msg}'}}), 500

    return jsonify({'ok': True, 'data': {'method': 'email', 'message': f'A 6-digit OTP has been sent to {user["email"]}.'}})


@app.route('/api/auth/forgot-password/reset', methods=['POST'])
def api_forgot_password_reset():
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    code = (data.get('code') or '').strip()
    new_password = data.get('new_password') or ''

    valid, msg = validate_password_policy(new_password)
    if not valid:
        return jsonify({'ok': False, 'error': {'code': 'WEAK_PASSWORD', 'message': msg}}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, password_hash, totp_secret, mfa_enabled FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return jsonify({'ok': False, 'error': {'code': 'NOT_FOUND', 'message': 'User not found.'}}), 404

    verified = False
    if user['mfa_enabled'] and verify_totp(user['totp_secret'], code):
        verified = True
    else:
        cursor.execute('SELECT id, expires_at FROM otp_codes WHERE user_id = ? AND code = ? AND used = 0 ORDER BY id DESC LIMIT 1', (user['id'], code))
        otp_row = cursor.fetchone()
        if otp_row and datetime.fromisoformat(otp_row['expires_at']) > datetime.utcnow():
            verified = True
            cursor.execute('UPDATE otp_codes SET used = 1 WHERE id = ?', (otp_row['id'],))

    if not verified:
        conn.close()
        return jsonify({'ok': False, 'error': {'code': 'INVALID_CODE', 'message': 'Invalid or expired verification code.'}}), 400

    # Check last 5 passwords (current + last 4 in history)
    if check_password_hash(user['password_hash'], new_password):
        conn.close()
        return jsonify({'ok': False, 'error': {'code': 'PASSWORD_REUSED', 'message': 'This password was already used and is in your last 5 passwords. Please choose a different password.'}}), 400

    cursor.execute('SELECT password_hash FROM password_history WHERE user_id = ? ORDER BY id DESC LIMIT 4', (user['id'],))
    for hist in cursor.fetchall():
        if check_password_hash(hist['password_hash'], new_password):
            conn.close()
            return jsonify({'ok': False, 'error': {'code': 'PASSWORD_REUSED', 'message': 'This password was already used and is in your last 5 passwords. Please choose a different password.'}}), 400

    # Record old password in history
    cursor.execute('INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)', (user['id'], user['password_hash']))
    cursor.execute('UPDATE users SET password_hash = ? WHERE id = ?', (generate_password_hash(new_password), user['id']))
    conn.commit()
    conn.close()
    log_security_event('PASSWORD_RESET_MFA', 'Medium', f'Password reset via MFA/OTP for {username}', request.remote_addr or 'unknown')
    return jsonify({'ok': True, 'data': {'message': 'Password reset successfully. You can now log in.'}})


@app.route('/api/users', methods=['GET'])
@role_required(['Admin', 'Administrator'])
def api_list_users():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, role, email, mfa_enabled, created_at FROM users ORDER BY id ASC')
    users = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify({'ok': True, 'data': users})


@app.route('/api/users', methods=['POST'])
@role_required(['Admin', 'Administrator'])
def api_create_user():
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    role = (data.get('role') or 'Analyst').strip()
    email = (data.get('email') or '').strip()

    if not username or len(username) < 3:
        return jsonify({'ok': False, 'error': {'code': 'INVALID_USERNAME', 'message': 'Username must be at least 3 characters.'}}), 400
    if role not in SOC_ROLE_PERMISSIONS:
        return jsonify({'ok': False, 'error': {'code': 'INVALID_ROLE', 'message': 'Role must be Admin, Analyst, or Viewer.'}}), 400

    valid, msg = validate_password_policy(password)
    if not valid:
        return jsonify({'ok': False, 'error': {'code': 'WEAK_PASSWORD', 'message': msg}}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
    if cursor.fetchone():
        conn.close()
        return jsonify({'ok': False, 'error': {'code': 'DUPLICATE_USER', 'message': f'Username "{username}" already exists.'}}), 409

    pw_hash = generate_password_hash(password)
    cursor.execute('INSERT INTO users (username, password_hash, role, email) VALUES (?, ?, ?, ?)', (username, pw_hash, role, email))
    new_id = cursor.lastrowid
    conn.commit()
    conn.close()

    client_ip = request.remote_addr or 'unknown'
    log_security_event('USER_CREATED', 'Medium', f'Admin {session.get("username")} created user {username} with role {role}', client_ip)
    return jsonify({'ok': True, 'data': {'id': new_id, 'username': username, 'role': role}}), 201


@app.route('/api/users/<int:user_id>', methods=['PATCH'])
@role_required(['Admin', 'Administrator'])
def api_update_user_role(user_id):
    data = request.get_json(silent=True) or {}
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, role, email FROM users WHERE id = ?', (user_id,))
    target = cursor.fetchone()
    if not target:
        conn.close()
        return jsonify({'ok': False, 'error': {'code': 'NOT_FOUND', 'message': 'User not found.'}}), 404

    new_username = (data.get('username') if 'username' in data else target['username']).strip()
    new_email = (data.get('email') if 'email' in data else (target['email'] or '')).strip()
    new_role = (data.get('role') if 'role' in data else target['role']).strip()

    if not new_username or len(new_username) < 3:
        conn.close()
        return jsonify({'ok': False, 'error': {'code': 'INVALID_USERNAME', 'message': 'Username must be at least 3 characters.'}}), 400
    if new_role not in SOC_ROLE_PERMISSIONS:
        conn.close()
        return jsonify({'ok': False, 'error': {'code': 'INVALID_ROLE', 'message': 'Role must be Admin, Analyst, or Viewer.'}}), 400
    if user_id == session.get('user_id') and new_role not in ('Admin', 'Administrator'):
        conn.close()
        return jsonify({'ok': False, 'error': {'code': 'SELF_DEMOTE_BLOCKED', 'message': 'You cannot demote your own active Admin account.'}}), 400

    cursor.execute('SELECT id FROM users WHERE username = ? AND id != ?', (new_username, user_id))
    if cursor.fetchone():
        conn.close()
        return jsonify({'ok': False, 'error': {'code': 'DUPLICATE_USER', 'message': f'Username "{new_username}" is already taken.'}}), 409

    cursor.execute('UPDATE users SET username = ?, email = ?, role = ? WHERE id = ?', (new_username, new_email, new_role, user_id))
    conn.commit()
    conn.close()

    if user_id == session.get('user_id'):
        session['username'] = new_username

    client_ip = request.remote_addr or 'unknown'
    log_security_event('USER_UPDATED', 'Medium', f'Admin {session.get("username")} updated user {new_username} (Role: {new_role}, Email: {new_email})', client_ip)
    return jsonify({'ok': True, 'data': {'id': user_id, 'username': new_username, 'email': new_email, 'role': new_role}})


@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@role_required(['Admin', 'Administrator'])
def api_delete_user(user_id):
    if user_id == session.get('user_id'):
        return jsonify({'ok': False, 'error': {'code': 'SELF_DELETE_BLOCKED', 'message': 'You cannot delete your own active account.'}}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT username, role FROM users WHERE id = ?', (user_id,))
    target = cursor.fetchone()
    if not target:
        conn.close()
        return jsonify({'ok': False, 'error': {'code': 'NOT_FOUND', 'message': 'User not found.'}}), 404

    cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

    client_ip = request.remote_addr or 'unknown'
    log_security_event('USER_DELETED', 'High', f'Admin {session.get("username")} deleted user {target["username"]} ({target["role"]})', client_ip)
    return jsonify({'ok': True, 'data': {'deleted_id': user_id}})

@app.route('/api/stats', methods=['GET'])
def get_stats():
    run_id_param = request.args.get('run_id')
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get specified or latest run
    if run_id_param:
        cursor.execute('SELECT * FROM analysis_runs WHERE id = ?', (run_id_param,))
    else:
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
    
    # Events over time
    cursor.execute("SELECT substr(COALESCE(normalized_timestamp, timestamp), 1, 13) as time_slot, COUNT(*) as count FROM log_events WHERE run_id = ? GROUP BY time_slot ORDER BY time_slot", (run_id,))
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
    run_id_param = request.args.get('run_id')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if run_id_param:
        cursor.execute('SELECT id FROM analysis_runs WHERE id = ?', (run_id_param,))
    else:
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
        
    count_query = f'SELECT COUNT(*) FROM ({query})'
    cursor.execute(count_query, params)
    total_matching = cursor.fetchone()[0]
    
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
    run_id_param = request.args.get('run_id')
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if run_id_param:
        cursor.execute('SELECT id FROM analysis_runs WHERE id = ?', (run_id_param,))
    else:
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

# ==========================================
# MEMBER 3 API ENDPOINTS (PRD §3)
# ==========================================

@app.route('/api/investigations/<int:investigation_id>/analyze', methods=['POST'])
def run_investigation_analysis(investigation_id):
    client_ip = request.remote_addr or 'unknown'
    if not check_rate_limit(f"{client_ip}:analyze", limit_seconds=0.05):
        return jsonify({'ok': False, 'error': {'code': 'RATE_LIMIT_EXCEEDED', 'message': 'Too many rapid analysis requests.'}}), 429

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
        return jsonify({'ok': False, 'error': 'No events found to analyze for this investigation.'}), 404
        
    run_id = run['id']
    cursor.execute('SELECT * FROM log_events WHERE run_id = ?', (run_id,))
    rows = cursor.fetchall()
    records = [dict(r) for r in rows]
    
    if not records:
        conn.close()
        return jsonify({'ok': False, 'error': 'No valid log records found for analysis.'}), 400
        
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
def get_analysis_runs(investigation_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM analysis_runs WHERE investigation_id = ? ORDER BY id DESC', (investigation_id,))
    rows = cursor.fetchall()
    runs = [dict(r) for r in rows]
    conn.close()
    return jsonify({'ok': True, 'data': runs})

@app.route('/api/investigations/<int:investigation_id>/findings', methods=['GET'])
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
        # Get supporting event IDs and source IP
        cursor.execute('''
            SELECT fe.event_id, le.source_ip 
            FROM finding_events fe 
            LEFT JOIN log_events le ON fe.event_id = le.id 
            WHERE fe.finding_id = ?
        ''', (f['id'],))
        ev_rows = cursor.fetchall()
        f['supporting_event_ids'] = [e['event_id'] for e in ev_rows]
        source_ips = [e['source_ip'] for e in ev_rows if e['source_ip']]
        f['source_ip'] = source_ips[0] if source_ips else '—'
        findings.append(f)
        
    conn.close()
    return jsonify({'ok': True, 'data': findings})

@app.route('/api/findings/<int:finding_id>', methods=['GET'])
def get_finding_details(finding_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM findings WHERE id = ?', (finding_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return jsonify({'ok': False, 'error': 'Finding not found'}), 404
        
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
def update_finding_status(finding_id):
    data = request.get_json() or {}
    new_status = data.get('status', '').strip()
    
    valid_statuses = ['New', 'Under Review', 'Resolved', 'False Positive']
    if new_status not in valid_statuses:
        return jsonify({'ok': False, 'error': f'Invalid status. Must be one of {valid_statuses}'}), 400
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM findings WHERE id = ?', (finding_id,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({'ok': False, 'error': 'Finding not found'}), 404
        
    cursor.execute('UPDATE findings SET status = ? WHERE id = ?', (new_status, finding_id))
    conn.commit()
    conn.close()
    
    return jsonify({'ok': True, 'data': {'id': finding_id, 'status': new_status}})

@app.route('/api/findings/<int:finding_id>/notes', methods=['POST'])
def add_finding_note(finding_id):
    data = request.get_json() or {}
    note_text = data.get('note_text', '').strip()
    
    if not note_text:
        return jsonify({'ok': False, 'error': 'Note text cannot be empty.'}), 400
        
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM findings WHERE id = ?', (finding_id,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({'ok': False, 'error': 'Finding not found'}), 404
        
    cursor.execute('INSERT INTO finding_notes (finding_id, note_text) VALUES (?, ?)', (finding_id, note_text))
    note_id = cursor.lastrowid
    conn.commit()
    
    cursor.execute('SELECT * FROM finding_notes WHERE id = ?', (note_id,))
    note = dict(cursor.fetchone())
    conn.close()
    
    return jsonify({'ok': True, 'data': note})

# ==========================================
# FILE UPLOAD & SAMPLE ENDPOINTS
# ==========================================

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
        
    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file format. Only .csv files are permitted.'}), 400
        
    stored_path = None
    try:
        raw_bytes = file.read()
        file_size = len(raw_bytes)
        if file_size == 0:
            return jsonify({'error': 'Uploaded file is empty.'}), 400
        if file_size > cfg.MAX_CONTENT_LENGTH:
            return jsonify({'error': 'File exceeds maximum upload size limit (16MB).'}), 400

        # Calculate SHA-256 evidence integrity hash (SECURITY-4 Section 3)
        sha256_hash = hashlib.sha256(raw_bytes).hexdigest()

        # Secure file storage outside public static/ with safe UUID filename (SECURITY-4 Section 2)
        stored_name = safe_filename(file.filename)
        target_path = os.path.join(cfg.UPLOAD_FOLDER, stored_name)
        
        # Path traversal verification
        abs_target = os.path.abspath(target_path)
        abs_root = os.path.abspath(cfg.UPLOAD_FOLDER)
        if not abs_target.startswith(abs_root):
            return jsonify({'error': 'Invalid file destination path detected.'}), 400

        # Save evidence file
        with open(target_path, 'wb') as f_out:
            f_out.write(raw_bytes)
        stored_path = target_path

        # Parse CSV content safely
        stream = io.StringIO(raw_bytes.decode('utf-8', errors='replace'))
        parsed = process_csv_content(stream)
        valid_records = parsed['valid_records']
        total_records = parsed['total']
        invalid_count = parsed['invalid_count']
        
        if not valid_records:
            if stored_path and os.path.exists(stored_path):
                os.remove(stored_path)
            return jsonify({'error': 'No valid log records found in the uploaded CSV file.'}), 400
            
        analysis_result = analyze_records(valid_records)
        final_records = analysis_result['records']
        detections = analysis_result['detections']
        findings = analysis_result['findings']
        suspicious_count = analysis_result['suspicious_count']
        
        # Save to SQLite with transaction safety
        investigation_id = 1
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO analysis_runs (investigation_id, filename, total_records, valid_records, invalid_records, suspicious_count, status, sha256_hash, stored_filename, rules_evaluated)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (investigation_id, os.path.basename(file.filename), total_records, len(final_records), invalid_count, suspicious_count, 'Completed', sha256_hash, stored_name, 3))
        run_id = cursor.lastrowid
        
        # Record in evidence integrity table
        cursor.execute('''
            INSERT INTO evidence (run_id, original_filename, stored_filename, file_path, file_size, sha256_hash, verification_status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (run_id, os.path.basename(file.filename), stored_name, target_path, file_size, sha256_hash, 'Verified'))

        
        event_id_map = []
        for rec in final_records:
            cursor.execute('''
                INSERT INTO log_events (run_id, timestamp, normalized_timestamp, source_ip, event_type, username, status, severity, detection_reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (run_id, rec['timestamp'], rec['normalized_timestamp'], rec['source_ip'], rec['event_type'], rec['username'], rec['status'], rec['severity'], rec['detection_reason']))
            event_id_map.append(cursor.lastrowid)
            
        for det in detections:
            cursor.execute('''
                INSERT INTO detections (run_id, timestamp, source_ip, rule_triggered, severity, evidence, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (run_id, det['timestamp'], det['source_ip'], det['rule_triggered'], det['severity'], det['evidence'], det['status']))
            
        # Audit logs: EVIDENCE_UPLOADED & CSV_PROCESSED
        cursor.execute('''
            INSERT INTO audit_trail (run_id, action_type, description, related_record_type, related_record_id)
            VALUES (?, ?, ?, ?, ?)
        ''', (run_id, 'EVIDENCE_UPLOADED', f'Evidence file stored securely: {os.path.basename(file.filename)} (SHA256: {sha256_hash[:16]}...)', 'evidence', run_id))

        cursor.execute('''
            INSERT INTO audit_trail (run_id, action_type, description, related_record_type, related_record_id)
            VALUES (?, ?, ?, ?, ?)
        ''', (run_id, 'CSV_PROCESSED', f'Processed {total_records} rows ({len(final_records)} valid, {invalid_count} invalid)', 'analysis_runs', run_id))

            
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
            'message': 'Evidence stored securely and log analysis completed successfully.',
            'sha256': sha256_hash,
            'stats': {
                'total': total_records,
                'valid': len(final_records),
                'invalid': invalid_count,
                'suspicious': suspicious_count
            }
        })
        
    except Exception as e:
        # Atomic cleanup on error: prevent orphaned files (SECURITY-4 Section 2.2)
        if stored_path and os.path.exists(stored_path):
            try:
                os.remove(stored_path)
            except Exception:
                pass
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
        with open(sample_path, 'rb') as f:
            raw_bytes = f.read()

        sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
        stream = io.StringIO(raw_bytes.decode('utf-8', errors='replace'))
        parsed = process_csv_content(stream)
            
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
            INSERT INTO analysis_runs (investigation_id, filename, total_records, valid_records, invalid_records, suspicious_count, status, sha256_hash, stored_filename, rules_evaluated)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (investigation_id, 'sample_logs.csv (Demo)', total_records, len(final_records), invalid_count, suspicious_count, 'Completed', sha256_hash, 'data/sample_logs.csv', 3))
        run_id = cursor.lastrowid
        
        cursor.execute('''
            INSERT INTO evidence (run_id, original_filename, stored_filename, file_path, file_size, sha256_hash, verification_status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (run_id, 'sample_logs.csv (Demo)', 'sample_logs.csv', sample_path, len(raw_bytes), sha256_hash, 'Verified'))

        
        event_id_map = []
        for rec in final_records:
            cursor.execute('''
                INSERT INTO log_events (run_id, timestamp, normalized_timestamp, source_ip, event_type, username, status, severity, detection_reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (run_id, rec['timestamp'], rec['normalized_timestamp'], rec['source_ip'], rec['event_type'], rec['username'], rec['status'], rec['severity'], rec['detection_reason']))
            event_id_map.append(cursor.lastrowid)
            
        for det in detections:
            cursor.execute('''
                INSERT INTO detections (run_id, timestamp, source_ip, rule_triggered, severity, evidence, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (run_id, det['timestamp'], det['source_ip'], det['rule_triggered'], det['severity'], det['evidence'], det['status']))
            
        cursor.execute('''
            INSERT INTO audit_trail (run_id, action_type, description, related_record_type, related_record_id)
            VALUES (?, ?, ?, ?, ?)
        ''', (run_id, 'CSV_PROCESSED', 'Built-in sample dataset loaded and analyzed.', 'analysis_runs', run_id))

            
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
            'sha256': sha256_hash,
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
            INSERT INTO evidence_files (investigation_id, original_filename, stored_filename, original_name, stored_name, file_size, size_bytes, sha256_hash, sha256, processing_status, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (id, original_filename, stored_filename, original_filename, stored_filename, file_size, file_size, sha256_hash, sha256_hash, 'Uploaded', 'Pending'))
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

# ─────────────────────────────────────────────────────────
# MEMBER 4 — Investigation Reports & Export + Audit Trail
# ─────────────────────────────────────────────────────────

@app.route('/api/runs', methods=['GET'])
def get_all_runs():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, investigation_id, filename, timestamp, status, total_records, suspicious_count FROM analysis_runs ORDER BY id DESC')
    rows = cursor.fetchall()
    runs = [dict(r) for r in rows]
    conn.close()
    return jsonify({'ok': True, 'data': runs})

@app.route('/api/runs/<int:run_id>/activate', methods=['POST'])
def activate_run(run_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id, filename, total_records, valid_records, invalid_records, suspicious_count, status, sha256_hash, timestamp FROM analysis_runs WHERE id = ?', (run_id,))
    run = cursor.fetchone()
    if not run:
        conn.close()
        return jsonify({'ok': False, 'error': f'Analysis Run #{run_id} not found.'}), 404
    
    run_dict = dict(run)
    conn.close()
    return jsonify({
        'ok': True,
        'message': f'Analysis Run #{run_id} loaded successfully.',
        'run': run_dict,
        'stats': {
            'total': run_dict.get('total_records', 0),
            'valid': run_dict.get('valid_records', 0),
            'invalid': run_dict.get('invalid_records', 0),
            'suspicious': run_dict.get('suspicious_count', 0)
        }
    })

# TASK 3 — Report Preview
@app.route('/api/investigations/<int:run_id>/report', methods=['GET'])
def report_preview(run_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM analysis_runs WHERE id = ?', (run_id,))
    run = cursor.fetchone()
    if not run:
        # Check if there are any runs at all
        cursor.execute('SELECT COUNT(*) FROM analysis_runs')
        total_runs = cursor.fetchone()[0]
        conn.close()
        if total_runs == 0:
            return jsonify({'ok': False, 'error': 'No analysis runs exist yet. Please upload a CSV log file or click "Load Sample Dataset" first.'}), 404
        return jsonify({'ok': False, 'error': f'Analysis Run #{run_id} not found. Please select a valid Run ID.'}), 404

    cursor.execute('SELECT COUNT(*) FROM log_events WHERE run_id = ?', (run_id,))
    event_count = cursor.fetchone()[0]

    cursor.execute('SELECT COUNT(*) FROM detections WHERE run_id = ?', (run_id,))
    findings_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM log_events WHERE run_id = ? AND severity = 'Critical'", (run_id,))
    critical_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM log_events WHERE run_id = ? AND severity = 'High'", (run_id,))
    high_count = cursor.fetchone()[0]

    conn.close()
    return jsonify({
        'ok': True,
        'data': {
            'investigation_id': run_id,
            'title': run['filename'],
            'status': run['status'],
            'analyzed_at': run['timestamp'],
            'total_records': run['total_records'],
            'valid_records': run['valid_records'],
            'invalid_records': run['invalid_records'],
            'suspicious_count': run['suspicious_count'],
            'event_count': event_count,
            'findings_count': findings_count,
            'critical_alerts': critical_count,
            'high_alerts': high_count,
        }
    })


# TASK 4 — PDF Report Generator
@app.route('/api/investigations/<int:run_id>/reports', methods=['POST'])
def generate_report(run_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM analysis_runs WHERE id = ?', (run_id,))
    run = cursor.fetchone()
    if not run:
        cursor.execute('SELECT COUNT(*) FROM analysis_runs')
        total_runs = cursor.fetchone()[0]
        conn.close()
        if total_runs == 0:
            return jsonify({'ok': False, 'error': 'No analysis runs exist yet. Please upload a CSV log file or click "Load Sample Dataset" first.'}), 404
        return jsonify({'ok': False, 'error': f'Analysis Run #{run_id} not found.'}), 404

    cursor.execute('SELECT * FROM detections WHERE run_id = ?', (run_id,))
    detections = cursor.fetchall()

    cursor.execute("SELECT severity, COUNT(*) as cnt FROM log_events WHERE run_id = ? GROUP BY severity", (run_id,))
    sev_rows = cursor.fetchall()
    severity_breakdown = {r['severity']: r['cnt'] for r in sev_rows}

    # Audit log
    cursor.execute('''
        INSERT INTO audit_trail (run_id, action_type, description, related_record_type, related_record_id)
        VALUES (?, ?, ?, ?, ?)
    ''', (run_id, 'REPORT_GENERATED', f'PDF report generated for investigation run #{run_id}', 'analysis_runs', run_id))
    conn.commit()
    conn.close()

    # Build PDF in memory
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter,
                            topMargin=40, bottomMargin=40, leftMargin=50, rightMargin=50)
    styles = getSampleStyleSheet()
    story = []

    # Title
    story.append(Paragraph("ShadowTrace — Investigation Report", styles['Title']))
    story.append(Spacer(1, 6))
    story.append(Paragraph("The Three Bugs · Security Operations Console", styles['Normal']))
    story.append(Spacer(1, 20))

    # Investigation Info
    story.append(Paragraph("Investigation Details", styles['Heading2']))
    info_data = [
        ['Field', 'Value'],
        ['Investigation ID', str(run_id)],
        ['Filename', run['filename']],
        ['Analysis Status', run['status']],
        ['Analyzed At', run['timestamp']],
        ['Total Records', str(run['total_records'])],
        ['Valid Records', str(run['valid_records'])],
        ['Invalid Records', str(run['invalid_records'])],
        ['Suspicious Events', str(run['suspicious_count'])],
    ]
    info_table = Table(info_data, colWidths=[180, 320])
    info_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e3a5f')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BACKGROUND', (0, 1), (0, -1), colors.HexColor('#f0f4f8')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
    ]))
    story.append(info_table)
    story.append(Spacer(1, 20))

    # Severity Breakdown
    story.append(Paragraph("Event Severity Summary", styles['Heading2']))
    sev_data = [['Severity', 'Count']]
    for sev in ['Critical', 'High', 'Medium', 'Low']:
        sev_data.append([sev, str(severity_breakdown.get(sev, 0))])
    sev_table = Table(sev_data, colWidths=[180, 320])
    sev_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e3a5f')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
    ]))
    story.append(sev_table)
    story.append(Spacer(1, 20))

    # Threat Findings
    story.append(Paragraph("Threat Findings", styles['Heading2']))
    if detections:
        det_data = [['#', 'Rule Triggered', 'Severity', 'Source IP', 'Evidence']]
        for i, d in enumerate(detections, 1):
            evidence_text = d['evidence'][:55] + '...' if len(d['evidence']) > 55 else d['evidence']
            det_data.append([str(i), d['rule_triggered'], d['severity'], d['source_ip'], evidence_text])
        det_table = Table(det_data, colWidths=[20, 140, 60, 90, 185])
        det_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#7f1d1d')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#fff5f5')]),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        story.append(det_table)
    else:
        story.append(Paragraph("No threat findings recorded for this investigation.", styles['Normal']))

    story.append(Spacer(1, 20))
    story.append(Paragraph(
        f"Report generated by ShadowTrace — The Three Bugs Security Operations Console",
        styles['Normal']
    ))

    doc.build(story)
    buffer.seek(0)
    return send_file(
        buffer,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f'shadowtrace_report_{run_id}.pdf'
    )


# TASK 5 — CSV Export: Events
@app.route('/api/investigations/<int:run_id>/exports/events', methods=['GET'])
def export_events(run_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM analysis_runs WHERE id = ?', (run_id,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({'ok': False, 'error': 'Investigation not found'}), 404

    cursor.execute('SELECT * FROM log_events WHERE run_id = ?', (run_id,))
    rows = cursor.fetchall()

    # Audit log
    cursor.execute('''
        INSERT INTO audit_trail (run_id, action_type, description, related_record_type, related_record_id)
        VALUES (?, ?, ?, ?, ?)
    ''', (run_id, 'EXPORT_EVENTS', f'Events CSV exported for run #{run_id}', 'log_events', run_id))
    conn.commit()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['id', 'run_id', 'timestamp', 'source_ip', 'event_type', 'username', 'status', 'severity', 'detection_reason'])
    for row in rows:
        # Prevent CSV formula injection (SECURITY-4 Section 9)
        writer.writerow([
            sanitize_csv_field(row['id']),
            sanitize_csv_field(row['run_id']),
            sanitize_csv_field(row['timestamp']),
            sanitize_csv_field(row['source_ip']),
            sanitize_csv_field(row['event_type']),
            sanitize_csv_field(row['username']),
            sanitize_csv_field(row['status']),
            sanitize_csv_field(row['severity']),
            sanitize_csv_field(row['detection_reason'])
        ])
    output.seek(0)
    return Response(output.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition': f'attachment; filename=events_run_{run_id}.csv'})


# TASK 5 — CSV Export: Findings / Detections
@app.route('/api/investigations/<int:run_id>/exports/findings', methods=['GET'])
def export_findings(run_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM analysis_runs WHERE id = ?', (run_id,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({'ok': False, 'error': 'Investigation not found'}), 404

    cursor.execute('SELECT * FROM detections WHERE run_id = ?', (run_id,))
    rows = cursor.fetchall()

    cursor.execute('''
        INSERT INTO audit_trail (run_id, action_type, description, related_record_type, related_record_id)
        VALUES (?, ?, ?, ?, ?)
    ''', (run_id, 'EXPORT_FINDINGS', f'Findings CSV exported for run #{run_id}', 'detections', run_id))
    conn.commit()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['id', 'run_id', 'timestamp', 'source_ip', 'rule_triggered', 'severity', 'evidence', 'status'])
    for row in rows:
        # Prevent CSV formula injection (SECURITY-4 Section 9)
        writer.writerow([
            sanitize_csv_field(row['id']),
            sanitize_csv_field(row['run_id']),
            sanitize_csv_field(row['timestamp']),
            sanitize_csv_field(row['source_ip']),
            sanitize_csv_field(row['rule_triggered']),
            sanitize_csv_field(row['severity']),
            sanitize_csv_field(row['evidence']),
            sanitize_csv_field(row['status'])
        ])
    output.seek(0)
    return Response(output.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition': f'attachment; filename=findings_run_{run_id}.csv'})


# TASK 5 — CSV Export: Evidence Metadata
@app.route('/api/investigations/<int:run_id>/exports/evidence', methods=['GET'])
def export_evidence(run_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM analysis_runs WHERE id = ?', (run_id,))
    run = cursor.fetchone()
    if not run:
        conn.close()
        return jsonify({'ok': False, 'error': 'Investigation not found'}), 404

    cursor.execute('''
        INSERT INTO audit_trail (run_id, action_type, description, related_record_type, related_record_id)
        VALUES (?, ?, ?, ?, ?)
    ''', (run_id, 'EXPORT_EVIDENCE', f'Evidence metadata CSV exported for run #{run_id}', 'analysis_runs', run_id))
    conn.commit()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['id', 'filename', 'uploaded_at', 'total_records', 'valid_records', 'invalid_records', 'suspicious_count', 'status', 'sha256_hash'])
    sha = run['sha256_hash'] if 'sha256_hash' in run.keys() else 'N/A'
    writer.writerow([
        sanitize_csv_field(run['id']),
        sanitize_csv_field(run['filename']),
        sanitize_csv_field(run['timestamp']),
        sanitize_csv_field(run['total_records']),
        sanitize_csv_field(run['valid_records']),
        sanitize_csv_field(run['invalid_records']),
        sanitize_csv_field(run['suspicious_count']),
        sanitize_csv_field(run['status']),
        sanitize_csv_field(sha)
    ])
    output.seek(0)
    return Response(output.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition': f'attachment; filename=evidence_run_{run_id}.csv'})


# TASK 6 — Audit Trail: Get Activity History
@app.route('/api/investigations/<int:run_id>/activity', methods=['GET'])
def get_activity(run_id):
    action_type = request.args.get('action_type', '').strip()
    date_from   = request.args.get('date_from', '').strip()
    date_to     = request.args.get('date_to', '').strip()

    conn = get_db_connection()
    cursor = conn.cursor()

    query = 'SELECT * FROM audit_trail WHERE run_id = ?'
    params = [run_id]

    if action_type:
        query += ' AND action_type = ?'
        params.append(action_type)
    if date_from:
        query += ' AND timestamp >= ?'
        params.append(date_from)
    if date_to:
        query += ' AND timestamp <= ?'
        params.append(date_to)

    query += ' ORDER BY timestamp DESC'
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    return jsonify({'ok': True, 'data': [dict(r) for r in rows]})


# TASK 6 — Audit Trail: Get all activity (all runs)
@app.route('/api/activity', methods=['GET'])
def get_all_activity():
    action_type = request.args.get('action_type', '').strip()
    date_from   = request.args.get('date_from', '').strip()
    date_to     = request.args.get('date_to', '').strip()

    conn = get_db_connection()
    cursor = conn.cursor()

    query = 'SELECT * FROM audit_trail WHERE 1=1'
    params = []

    if action_type:
        query += ' AND action_type = ?'
        params.append(action_type)
    if date_from:
        query += ' AND timestamp >= ?'
        params.append(date_from)
    if date_to:
        query += ' AND timestamp <= ?'
        params.append(date_to)

    query += ' ORDER BY timestamp DESC LIMIT 100'
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    return jsonify({'ok': True, 'data': [dict(r) for r in rows]})


# ─────────────────────────────────────────────────────────
# SECURITY-4 — Operational & Integrity Endpoints
# ─────────────────────────────────────────────────────────

# SHA-256 Evidence Verification (SECURITY-4 Section 3 & 15)
@app.route('/api/investigations/<int:run_id>/verify-integrity', methods=['GET', 'POST'])
def verify_evidence_integrity(run_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM evidence WHERE run_id = ? ORDER BY id DESC LIMIT 1', (run_id,))
    ev = cursor.fetchone()
    
    if not ev:
        cursor.execute('SELECT * FROM analysis_runs WHERE id = ?', (run_id,))
        run = cursor.fetchone()
        if not run:
            cursor.execute('SELECT COUNT(*) FROM analysis_runs')
            total_runs = cursor.fetchone()[0]
            conn.close()
            if total_runs == 0:
                return jsonify({'ok': False, 'error': 'No analysis runs exist yet. Please upload a CSV log file or load sample data first.'}), 404
            return jsonify({'ok': False, 'error': f'Analysis Run #{run_id} not found.'}), 404
        recorded_hash = run['sha256_hash'] if 'sha256_hash' in run.keys() else None
        stored_file = run['stored_filename'] if 'stored_filename' in run.keys() else None
        file_path = os.path.join(cfg.UPLOAD_FOLDER, stored_file) if stored_file else None
    else:
        recorded_hash = ev['sha256_hash']
        stored_file = ev['stored_filename']
        file_path = ev['file_path']

    if not recorded_hash or not file_path:
        conn.close()
        return jsonify({
            'ok': True,
            'investigation_id': run_id,
            'status': 'NO_FILE_RECORD',
            'verified': False,
            'message': 'No physical file stored for this run.'
        })

    if not os.path.exists(file_path):
        conn.close()
        return jsonify({
            'ok': False,
            'investigation_id': run_id,
            'status': 'FILE_MISSING',
            'verified': False,
            'message': 'Recorded evidence file could not be found on storage disk.'
        }), 404

    with open(file_path, 'rb') as f:
        current_hash = hashlib.sha256(f.read()).hexdigest()

    is_matched = (current_hash.lower() == recorded_hash.lower())
    status_str = 'VERIFIED_MATCH' if is_matched else 'HASH_MISMATCH'

    # Record integrity check in audit trail
    cursor.execute('''
        INSERT INTO audit_trail (run_id, action_type, description, related_record_type, related_record_id)
        VALUES (?, ?, ?, ?, ?)
    ''', (run_id, 'INTEGRITY_CHECK', f'Evidence SHA-256 verification: {status_str}', 'evidence', run_id))
    conn.commit()
    conn.close()

    return jsonify({
        'ok': True,
        'investigation_id': run_id,
        'status': status_str,
        'verified': is_matched,
        'recorded_sha256': recorded_hash,
        'computed_sha256': current_hash,
        'message': 'Evidence integrity verified: file matches recorded SHA-256 hash.' if is_matched else 'WARNING: Hash mismatch! File content has changed from upload time.'
    })


# Safe SQLite Database Backup (SECURITY-4 Section 8)
@app.route('/api/admin/backup', methods=['POST'])
def trigger_backup():
    try:
        from database import backup_db
        dest = backup_db()
        filename = os.path.basename(dest)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO audit_trail (run_id, action_type, description, related_record_type, related_record_id)
            VALUES (NULL, 'DATABASE_BACKUP', ?, 'database', NULL)
        ''', (f'Database backup created: {filename}',))
        conn.commit()
        conn.close()
        
        return jsonify({
            'ok': True,
            'message': 'Secure database backup created successfully.',
            'backup_file': filename
        })
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


# ================= MEMBER 2 SPECIFIC API ENDPOINTS =================

@app.route('/api/evidence/<int:evidence_id>/process', methods=['POST'])
def process_evidence_endpoint(evidence_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM evidence_files WHERE id = ?', (evidence_id,))
    evidence = cursor.fetchone()
    
    if not evidence:
        conn.close()
        return jsonify({'ok': False, 'error': {'code': 'NOT_FOUND', 'message': 'Evidence file not found.'}}), 404
        
    investigation_id = evidence['investigation_id']
    stored_name = evidence['stored_name'] or evidence['stored_filename']
    
    upload_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'uploads')
    file_path = os.path.join(upload_dir, stored_name) if stored_name else None
    
    if not file_path or not os.path.exists(file_path):
        if stored_name:
            ev_path = os.path.join(EVIDENCE_DIR, stored_name)
            if os.path.exists(ev_path):
                file_path = ev_path
        if not file_path or not os.path.exists(file_path):
            sample_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'sample_logs.csv')
            if os.path.exists(sample_path):
                file_path = sample_path
            else:
                conn.close()
                return jsonify({'ok': False, 'error': {'code': 'FILE_NOT_FOUND', 'message': 'Physical evidence file missing on server.'}}), 404
            
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            parsed = process_csv_content(f)
            
        total_rows = parsed['total']
        valid_records = parsed['valid_records']
        invalid_count = parsed['invalid_count']
        duplicate_count = parsed['duplicate_count']
        processing_status = parsed['processing_status']
        
        cursor.execute('''
            INSERT INTO processing_runs (investigation_id, evidence_id, total_rows, valid_rows, invalid_rows, duplicate_rows, processing_status, completed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (investigation_id, evidence_id, total_rows, len(valid_records), invalid_count, duplicate_count, processing_status))
        
        analysis_result = analyze_records(valid_records)
        final_records = analysis_result['records']
        detections = analysis_result['detections']
        suspicious_count = analysis_result['suspicious_count']
        
        cursor.execute('''
            INSERT INTO analysis_runs (investigation_id, evidence_id, filename, total_records, valid_records, invalid_records, suspicious_count, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (investigation_id, evidence_id, evidence['original_name'], total_rows, len(final_records), invalid_count, suspicious_count, 'Completed'))
        run_id = cursor.lastrowid
        
        for rec in final_records:
            cursor.execute('''
                INSERT INTO log_events (run_id, investigation_id, evidence_id, source_row_number, timestamp, normalized_timestamp, source_ip, event_type, username, status, severity, detection_reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (run_id, investigation_id, evidence_id, rec['source_row_number'], rec['timestamp'], rec['normalized_timestamp'], rec['source_ip'], rec['event_type'], rec['username'], rec['status'], rec['severity'], rec['detection_reason']))
            
        for det in detections:
            cursor.execute('''
                INSERT INTO detections (run_id, timestamp, source_ip, rule_triggered, severity, evidence, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (run_id, det['timestamp'], det['source_ip'], det['rule_triggered'], det['severity'], det['evidence'], det['status']))
            
        cursor.execute('UPDATE evidence_files SET total_rows = ?, valid_rows = ?, invalid_rows = ?, status = ? WHERE id = ?',
                       (total_rows, len(valid_records), invalid_count, processing_status, evidence_id))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'ok': True,
            'data': {
                'evidence_id': evidence_id,
                'investigation_id': investigation_id,
                'total_rows': total_rows,
                'valid_rows': len(valid_records),
                'invalid_rows': invalid_count,
                'duplicate_rows': duplicate_count,
                'processing_status': processing_status,
                'invalid_details': parsed['invalid_rows']
            }
        })
    except Exception as e:
        conn.close()
        return jsonify({'ok': False, 'error': {'code': 'PROCESSING_ERROR', 'message': str(e)}}), 400

@app.route('/api/investigations/<int:investigation_id>/events', methods=['GET'])
def get_investigation_events(investigation_id):
    username = request.args.get('username', '').strip()
    source_ip = request.args.get('source_ip', '').strip()
    event_type = request.args.get('event_type', '').strip()
    status = request.args.get('status', '').strip()
    evidence_id = request.args.get('evidence_id', type=int)
    start_date = request.args.get('start_date', '').strip()
    end_date = request.args.get('end_date', '').strip()
    sort_order = request.args.get('sort', 'oldest').strip().lower()
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = 'SELECT * FROM log_events WHERE investigation_id = ?'
    params = [investigation_id]
    
    cursor.execute('SELECT COUNT(*) FROM log_events WHERE investigation_id = ?', (investigation_id,))
    if cursor.fetchone()[0] == 0:
        cursor.execute('SELECT id FROM analysis_runs ORDER BY id DESC LIMIT 1')
        run = cursor.fetchone()
        if run:
            query = 'SELECT * FROM log_events WHERE run_id = ?'
            params = [run['id']]
            
    if username:
        query += ' AND username LIKE ?'
        params.append(f'%{username}%')
    if source_ip:
        query += ' AND source_ip LIKE ?'
        params.append(f'%{source_ip}%')
    if event_type:
        query += ' AND event_type LIKE ?'
        params.append(f'%{event_type}%')
    if status and status != 'All':
        query += ' AND status = ?'
        params.append(status)
    if evidence_id:
        query += ' AND evidence_id = ?'
        params.append(evidence_id)
    if start_date:
        query += ' AND COALESCE(normalized_timestamp, timestamp) >= ?'
        params.append(start_date)
    if end_date:
        query += ' AND COALESCE(normalized_timestamp, timestamp) <= ?'
        params.append(end_date)
        
    count_query = f'SELECT COUNT(*) FROM ({query})'
    cursor.execute(count_query, params)
    total = cursor.fetchone()[0]
    
    if sort_order == 'newest':
        query += ' ORDER BY COALESCE(normalized_timestamp, timestamp) DESC, id DESC'
    else:
        query += ' ORDER BY COALESCE(normalized_timestamp, timestamp) ASC, id ASC'
        
    query += ' LIMIT ? OFFSET ?'
    offset = (page - 1) * per_page
    params.extend([per_page, offset])
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    events = [dict(row) for row in rows]
    conn.close()
    
    return jsonify({
        'ok': True,
        'data': {
            'events': events,
            'total': total,
            'page': page,
            'per_page': per_page
        }
    })

@app.route('/api/events/<int:event_id>', methods=['GET'])
def get_event_detail(event_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM log_events WHERE id = ?', (event_id,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return jsonify({'ok': False, 'error': {'code': 'NOT_FOUND', 'message': 'Event not found.'}}), 404
        
    return jsonify({
        'ok': True,
        'data': dict(row)
    })

@app.route('/api/evidence/<int:evidence_id>/processing-summary', methods=['GET'])
def get_processing_summary(evidence_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM processing_runs WHERE evidence_id = ? ORDER BY id DESC LIMIT 1', (evidence_id,))
    row = cursor.fetchone()
    
    if not row:
        cursor.execute('SELECT * FROM evidence_files WHERE id = ?', (evidence_id,))
        ev = cursor.fetchone()
        conn.close()
        if not ev:
            return jsonify({'ok': False, 'error': {'code': 'NOT_FOUND', 'message': 'Evidence not found.'}}), 404
        return jsonify({
            'ok': True,
            'data': {
                'evidence_id': evidence_id,
                'total_rows': ev['total_rows'],
                'valid_rows': ev['valid_rows'],
                'invalid_rows': ev['invalid_rows'],
                'duplicate_rows': 0,
                'processing_status': ev['status']
            }
        })
        
    conn.close()
    return jsonify({
        'ok': True,
        'data': dict(row)
    })

@app.route('/api/investigations', methods=['GET', 'POST'])
def handle_investigations():
    conn = get_db_connection()
    cursor = conn.cursor()
    if request.method == 'POST':
        data = request.get_json(silent=True)
        if data is None:
            conn.close()
            return jsonify({'ok': False, 'error': {'code': 'INVALID_JSON', 'message': 'Invalid or incomplete JSON payload.'}}), 400
        title = data.get('title', 'Untitled Investigation').strip()
        case_reference = data.get('case_reference', '').strip()
        notes = data.get('notes', '').strip()
        
        cursor.execute('''
            INSERT INTO investigations (title, case_reference, notes, status)
            VALUES (?, ?, ?, 'Open')
        ''', (title, case_reference, notes))
        conn.commit()
        inv_id = cursor.lastrowid
        cursor.execute('SELECT * FROM investigations WHERE id = ?', (inv_id,))
        inv = dict(cursor.fetchone())
        conn.close()
        return jsonify({'ok': True, 'data': inv}), 201
    else:
        cursor.execute('SELECT * FROM investigations ORDER BY id DESC')
        invs = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return jsonify({'ok': True, 'data': {'investigations': invs}})

@app.route('/api/investigations/<int:investigation_id>', methods=['GET'])
def get_investigation_detail(investigation_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM investigations WHERE id = ?', (investigation_id,))
    inv = cursor.fetchone()
    if not inv:
        conn.close()
        return jsonify({'ok': False, 'error': {'code': 'NOT_FOUND', 'message': 'Investigation not found.'}}), 404
    inv_dict = dict(inv)
    
    cursor.execute('SELECT * FROM evidence_files WHERE investigation_id = ?', (investigation_id,))
    inv_dict['evidence_files'] = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return jsonify({'ok': True, 'data': inv_dict})

@app.route('/api/investigations/<int:investigation_id>/evidence', methods=['POST', 'GET'])
def handle_investigation_evidence(investigation_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM investigations WHERE id = ?', (investigation_id,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({'ok': False, 'error': {'code': 'NOT_FOUND', 'message': 'Investigation not found.'}}), 404
        
    if request.method == 'POST':
        if 'file' not in request.files:
            conn.close()
            return jsonify({'ok': False, 'error': {'code': 'NO_FILE', 'message': 'No file part in the request.'}}), 400
        file = request.files['file']
        if file.filename == '':
            conn.close()
            return jsonify({'ok': False, 'error': {'code': 'NO_FILE', 'message': 'No file selected.'}}), 400
            
        if not file.filename.lower().endswith('.csv'):
            conn.close()
            return jsonify({'ok': False, 'error': {'code': 'INVALID_FORMAT', 'message': 'Please upload a .csv file.'}}), 400
            
        content_bytes = file.read()
        file.seek(0)
        sha256_hash = hashlib.sha256(content_bytes).hexdigest()
        size_bytes = len(content_bytes)
        
        stored_name = f"inv_{investigation_id}_{int(datetime.now().timestamp())}_{file.filename}"
        upload_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'uploads')
        os.makedirs(upload_dir, exist_ok=True)
        file_dest_path = os.path.join(upload_dir, stored_name)
        with open(file_dest_path, 'wb') as f_out:
            f_out.write(content_bytes)
        
        cursor.execute('''
            INSERT INTO evidence_files (investigation_id, original_name, stored_name, sha256, size_bytes, status)
            VALUES (?, ?, ?, ?, ?, 'Pending')
        ''', (investigation_id, file.filename, stored_name, sha256_hash, size_bytes))
        conn.commit()
        ev_id = cursor.lastrowid
        
        cursor.execute('SELECT * FROM evidence_files WHERE id = ?', (ev_id,))
        ev = dict(cursor.fetchone())
        conn.close()
        return jsonify({'ok': True, 'data': ev}), 201
    else:
        cursor.execute('SELECT * FROM evidence_files WHERE investigation_id = ?', (investigation_id,))
        evs = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return jsonify({'ok': True, 'data': {'evidence_files': evs}})

if __name__ == '__main__':
    # Production vs Development debug settings (SECURITY-4 Section 4.1)
    app.run(debug=cfg.DEBUG, host='127.0.0.1' if cfg.DEBUG else '0.0.0.0', port=5000)
