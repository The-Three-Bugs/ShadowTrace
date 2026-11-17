import os
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

# ==========================================
# MEMBER 3 API ENDPOINTS (PRD §3)
# ==========================================

@app.route('/api/investigations/<int:investigation_id>/analyze', methods=['POST'])
def run_investigation_analysis(investigation_id):
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
        # Get supporting event IDs
        cursor.execute('SELECT event_id FROM finding_events WHERE finding_id = ?', (f['id'],))
        f['supporting_event_ids'] = [e['event_id'] for e in cursor.fetchall()]
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
