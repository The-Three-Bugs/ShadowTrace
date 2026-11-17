import os
import hashlib
import uuid
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file, Response
from werkzeug.utils import secure_filename
from database import init_db, get_db_connection
from csv_processor import process_csv_content
from detector import analyze_records

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 # 16MB max upload

EVIDENCE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'evidence')
os.makedirs(EVIDENCE_DIR, exist_ok=True)

# Initialize DB on startup
init_db()

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
            
        # Run detector
        analysis_result = analyze_records(valid_records)
        final_records = analysis_result['records']
        detections = analysis_result['detections']
        suspicious_count = analysis_result['suspicious_count']
        
        # Save to SQLite
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO analysis_runs (filename, total_records, valid_records, invalid_records, suspicious_count, status)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (file.filename, total_records, len(final_records), invalid_count, suspicious_count, 'Completed'))
        run_id = cursor.lastrowid
        
        for rec in final_records:
            cursor.execute('''
                INSERT INTO log_events (run_id, timestamp, source_ip, event_type, username, status, severity, detection_reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (run_id, rec['timestamp'], rec['source_ip'], rec['event_type'], rec['username'], rec['status'], rec['severity'], rec['detection_reason']))
            
        for det in detections:
            cursor.execute('''
                INSERT INTO detections (run_id, timestamp, source_ip, rule_triggered, severity, evidence, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (run_id, det['timestamp'], det['source_ip'], det['rule_triggered'], det['severity'], det['evidence'], det['status']))
            
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
    sample_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'sample_logs.csv')
    if not os.path.exists(sample_path):
        return jsonify({'error': 'Sample dataset file not found.'}), 404
        
    try:
        with open(sample_path, 'r', encoding='utf-8') as f:
            parsed = process_csv_content(f)
            
        valid_records = parsed['valid_records']
        total_records = parsed['total']
        invalid_count = parsed['invalid_count']
        
        analysis_result = analyze_records(valid_records)
        final_records = analysis_result['records']
        detections = analysis_result['detections']
        suspicious_count = analysis_result['suspicious_count']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO analysis_runs (filename, total_records, valid_records, invalid_records, suspicious_count, status)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', ('sample_logs.csv (Demo)', total_records, len(final_records), invalid_count, suspicious_count, 'Completed'))
        run_id = cursor.lastrowid
        
        for rec in final_records:
            cursor.execute('''
                INSERT INTO log_events (run_id, timestamp, source_ip, event_type, username, status, severity, detection_reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (run_id, rec['timestamp'], rec['source_ip'], rec['event_type'], rec['username'], rec['status'], rec['severity'], rec['detection_reason']))
            
        for det in detections:
            cursor.execute('''
                INSERT INTO detections (run_id, timestamp, source_ip, rule_triggered, severity, evidence, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (run_id, det['timestamp'], det['source_ip'], det['rule_triggered'], det['severity'], det['evidence'], det['status']))
            
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
def create_investigation():
    data = request.get_json(silent=True) or request.form
    title = data.get('title', '').strip()
    description = data.get('description', '').strip()
    status = data.get('status', 'Open').strip()
    
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
            INSERT INTO investigations (investigation_uid, title, description, status)
            VALUES (?, ?, ?, ?)
        ''', (investigation_uid, title, description, status))
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

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
