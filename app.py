import os
import hashlib
from datetime import datetime
from flask import Flask, render_template, request, jsonify, Response
from database import init_db, get_db_connection
from csv_processor import process_csv_content
from detector import analyze_records

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 # 16MB max upload

# Initialize DB on startup
init_db()

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
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
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
            
        analysis_result = analyze_records(valid_records)
        final_records = analysis_result['records']
        detections = analysis_result['detections']
        suspicious_count = analysis_result['suspicious_count']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO analysis_runs (filename, total_records, valid_records, invalid_records, suspicious_count, status)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (file.filename, total_records, len(final_records), invalid_count, suspicious_count, 'Completed'))
        run_id = cursor.lastrowid
        
        for rec in final_records:
            cursor.execute('''
                INSERT INTO log_events (run_id, timestamp, normalized_timestamp, source_ip, event_type, username, status, severity, detection_reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (run_id, rec['timestamp'], rec['normalized_timestamp'], rec['source_ip'], rec['event_type'], rec['username'], rec['status'], rec['severity'], rec['detection_reason']))
            
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
                INSERT INTO log_events (run_id, timestamp, normalized_timestamp, source_ip, event_type, username, status, severity, detection_reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (run_id, rec['timestamp'], rec['normalized_timestamp'], rec['source_ip'], rec['event_type'], rec['username'], rec['status'], rec['severity'], rec['detection_reason']))
            
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

@app.route('/api/download-template', methods=['GET'])
def download_template():
    template_content = "timestamp,source_ip,event_type,username,status\n2026-10-14 12:00:00,192.168.1.100,login_attempt,john_doe,success\n"
    return Response(
        template_content,
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=shadowtrace_template.csv"}
    )

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
    stored_name = evidence['stored_name']
    
    upload_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'uploads')
    file_path = os.path.join(upload_dir, stored_name)
    
    if not os.path.exists(file_path):
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
        data = request.get_json() or {}
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
    app.run(debug=True, host='0.0.0.0', port=5000)
