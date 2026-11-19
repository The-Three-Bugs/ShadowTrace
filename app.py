import os
import io
import csv
import re
import uuid
import hashlib
from flask import Flask, render_template, request, jsonify, send_file, Response, after_this_request
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
    response.headers['X-Frame-Options'] = 'DENY'
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
            
        # Run detector
        analysis_result = analyze_records(valid_records)
        final_records = analysis_result['records']
        detections = analysis_result['detections']
        suspicious_count = analysis_result['suspicious_count']
        
        # Save to SQLite with transaction safety
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO analysis_runs (filename, total_records, valid_records, invalid_records, suspicious_count, status, sha256_hash, stored_filename)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (os.path.basename(file.filename), total_records, len(final_records), invalid_count, suspicious_count, 'Completed', sha256_hash, stored_name))
        run_id = cursor.lastrowid
        
        # Record in evidence integrity table
        cursor.execute('''
            INSERT INTO evidence (run_id, original_filename, stored_filename, file_path, file_size, sha256_hash, verification_status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (run_id, os.path.basename(file.filename), stored_name, target_path, file_size, sha256_hash, 'Verified'))

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
            
        # Audit logs: EVIDENCE_UPLOADED & CSV_PROCESSED
        cursor.execute('''
            INSERT INTO audit_trail (run_id, action_type, description, related_record_type, related_record_id)
            VALUES (?, ?, ?, ?, ?)
        ''', (run_id, 'EVIDENCE_UPLOADED', f'Evidence file stored securely: {os.path.basename(file.filename)} (SHA256: {sha256_hash[:16]}...)', 'evidence', run_id))

        cursor.execute('''
            INSERT INTO audit_trail (run_id, action_type, description, related_record_type, related_record_id)
            VALUES (?, ?, ?, ?, ?)
        ''', (run_id, 'CSV_PROCESSED', f'Processed {total_records} rows ({len(final_records)} valid, {invalid_count} invalid)', 'analysis_runs', run_id))

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
    sample_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'sample_logs.csv')
    if not os.path.exists(sample_path):
        return jsonify({'error': 'Sample dataset file not found.'}), 404
        
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
        suspicious_count = analysis_result['suspicious_count']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO analysis_runs (filename, total_records, valid_records, invalid_records, suspicious_count, status, sha256_hash, stored_filename)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', ('sample_logs.csv (Demo)', total_records, len(final_records), invalid_count, suspicious_count, 'Completed', sha256_hash, 'data/sample_logs.csv'))
        run_id = cursor.lastrowid
        
        cursor.execute('''
            INSERT INTO evidence (run_id, original_filename, stored_filename, file_path, file_size, sha256_hash, verification_status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (run_id, 'sample_logs.csv (Demo)', 'sample_logs.csv', sample_path, len(raw_bytes), sha256_hash, 'Verified'))

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
            
        cursor.execute('''
            INSERT INTO audit_trail (run_id, action_type, description, related_record_type, related_record_id)
            VALUES (?, ?, ?, ?, ?)
        ''', (run_id, 'CSV_PROCESSED', 'Built-in sample dataset loaded and analyzed.', 'analysis_runs', run_id))

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

# TASK 3 — Report Preview
@app.route('/api/investigations/<int:run_id>/report', methods=['GET'])
def report_preview(run_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM analysis_runs WHERE id = ?', (run_id,))
    run = cursor.fetchone()
    if not run:
        conn.close()
        return jsonify({'ok': False, 'error': 'Investigation not found'}), 404

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
        conn.close()
        return jsonify({'ok': False, 'error': 'Investigation not found'}), 404

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
            conn.close()
            return jsonify({'ok': False, 'error': 'Investigation not found'}), 404
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


if __name__ == '__main__':
    # Production vs Development debug settings (SECURITY-4 Section 4.1)
    app.run(debug=cfg.DEBUG, host='127.0.0.1' if cfg.DEBUG else '0.0.0.0', port=5000)
