import sqlite3
import os
import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'shadowtrace.db')

def get_db_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # Security: enforce foreign keys (Member 4 - SECURITY-4 Requirement 7)
    conn.execute('PRAGMA foreign_keys = ON;')
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Enable foreign keys
    cursor.execute('PRAGMA foreign_keys = ON;')
    
    # 1. Users table (Member 1 - Security) - created first so foreign keys can reference users(id)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'Analyst',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Seed or reset default users (Admin, Analyst, Viewer) for test isolation and consistency
    from werkzeug.security import generate_password_hash
    default_users = [
        ('admin', generate_password_hash('AdminSecret123!'), 'Administrator'),
        ('analyst', generate_password_hash('AnalystPass123!'), 'Analyst'),
        ('viewer', generate_password_hash('ViewerPass123!'), 'Viewer')
    ]
    for uname, phash, urole in default_users:
        cursor.execute('SELECT id FROM users WHERE username = ?', (uname,))
        row = cursor.fetchone()
        if row:
            cursor.execute('UPDATE users SET password_hash = ?, role = ? WHERE username = ?', (phash, urole, uname))
        else:
            cursor.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)', (uname, phash, urole))

    # 2. Investigations table (Member 1)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS investigations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigation_uid TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            status TEXT DEFAULT 'Open',
            user_id INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        )
    ''')
    
    # Migration: ensure columns exist in investigations
    cursor.execute("PRAGMA table_info(investigations)")
    columns = [col['name'] for col in cursor.fetchall()]
    if 'investigation_uid' not in columns:
        try:
            cursor.execute("ALTER TABLE investigations ADD COLUMN investigation_uid TEXT;")
        except Exception:
            pass
    if 'title' not in columns:
        try:
            cursor.execute("ALTER TABLE investigations ADD COLUMN title TEXT;")
            if 'name' in columns:
                cursor.execute("UPDATE investigations SET title = name WHERE title IS NULL")
            if 'case_reference' in columns:
                cursor.execute("UPDATE investigations SET title = case_reference WHERE title IS NULL")
        except Exception:
            pass
    if 'description' not in columns:
        try:
            cursor.execute("ALTER TABLE investigations ADD COLUMN description TEXT;")
            if 'notes' in columns:
                cursor.execute("UPDATE investigations SET description = notes WHERE description IS NULL")
        except Exception:
            pass
    if 'status' not in columns:
        try:
            cursor.execute("ALTER TABLE investigations ADD COLUMN status TEXT DEFAULT 'Open';")
        except Exception:
            pass
    if 'user_id' not in columns:
        try:
            cursor.execute("ALTER TABLE investigations ADD COLUMN user_id INTEGER;")
        except Exception:
            pass
    if 'updated_at' not in columns:
        try:
            cursor.execute("ALTER TABLE investigations ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP;")
        except Exception:
            pass

    # Ensure default investigation exists
    cursor.execute('SELECT COUNT(*) FROM investigations')
    if cursor.fetchone()[0] == 0:
        cursor.execute(
            "INSERT INTO investigations (investigation_uid, title, description, status) VALUES (?, ?, ?, ?)",
            ('INV-DEFAULT-001', 'Default Investigation', 'Default auto-created investigation', 'Open')
        )
    else:
        try:
            cursor.execute("UPDATE investigations SET investigation_uid = 'INV-DEFAULT-' || id WHERE investigation_uid IS NULL")
        except Exception:
            pass
        try:
            cursor.execute("UPDATE investigations SET title = COALESCE(title, name, case_reference, 'Default Investigation') WHERE title IS NULL")
        except Exception:
            pass
    
    # 3. Evidence files table (Unified Member 1 & Member 2)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS evidence_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigation_id INTEGER NOT NULL,
            original_filename TEXT,
            original_name TEXT,
            stored_filename TEXT,
            stored_name TEXT,
            file_size INTEGER DEFAULT 0,
            size_bytes INTEGER DEFAULT 0,
            sha256_hash TEXT,
            sha256 TEXT,
            upload_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            imported_at DATETIME,
            processing_status TEXT DEFAULT 'Uploaded',
            status TEXT DEFAULT 'Pending',
            total_rows INTEGER DEFAULT 0,
            valid_rows INTEGER DEFAULT 0,
            invalid_rows INTEGER DEFAULT 0,
            FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
        )
    ''')
    
    # Migration for evidence_files columns
    cursor.execute("PRAGMA table_info(evidence_files)")
    ev_columns = [col['name'] for col in cursor.fetchall()]
    for col_pair in [('original_filename', 'original_name'), ('stored_filename', 'stored_name'), ('file_size', 'size_bytes'), ('sha256_hash', 'sha256'), ('processing_status', 'status')]:
        col1, col2 = col_pair
        if col1 not in ev_columns and col2 in ev_columns:
            try:
                cursor.execute(f"ALTER TABLE evidence_files ADD COLUMN {col1} TEXT;")
                cursor.execute(f"UPDATE evidence_files SET {col1} = {col2} WHERE {col1} IS NULL")
            except Exception:
                pass
        if col2 not in ev_columns and col1 in ev_columns:
            try:
                cursor.execute(f"ALTER TABLE evidence_files ADD COLUMN {col2} TEXT;")
                cursor.execute(f"UPDATE evidence_files SET {col2} = {col1} WHERE {col2} IS NULL")
            except Exception:
                pass

    # 4. Processing runs table (Member 2)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS processing_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigation_id INTEGER,
            evidence_id INTEGER,
            total_rows INTEGER DEFAULT 0,
            valid_rows INTEGER DEFAULT 0,
            invalid_rows INTEGER DEFAULT 0,
            duplicate_rows INTEGER DEFAULT 0,
            processing_status TEXT DEFAULT 'Pending',
            started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            completed_at DATETIME,
            error_summary TEXT,
            FOREIGN KEY (investigation_id) REFERENCES investigations(id),
            FOREIGN KEY (evidence_id) REFERENCES evidence_files(id)
        )
    ''')
    
    # 5. Analysis runs table (Member 3)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS analysis_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigation_id INTEGER DEFAULT 1,
            evidence_id INTEGER,
            filename TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            total_records INTEGER DEFAULT 0,
            valid_records INTEGER DEFAULT 0,
            invalid_records INTEGER DEFAULT 0,
            suspicious_count INTEGER DEFAULT 0,
            status TEXT DEFAULT 'Completed',
            sha256_hash TEXT,
            stored_filename TEXT
            rules_evaluated INTEGER DEFAULT 3,
            status TEXT DEFAULT 'Completed',
            FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE SET NULL,
            FOREIGN KEY (evidence_id) REFERENCES evidence_files(id) ON DELETE SET NULL
        )
    ''')
    
    # Check and migrate columns in analysis_runs
    cursor.execute("PRAGMA table_info(analysis_runs)")
    ar_columns = [col['name'] for col in cursor.fetchall()]
    if 'investigation_id' not in ar_columns:
        cursor.execute("ALTER TABLE analysis_runs ADD COLUMN investigation_id INTEGER DEFAULT 1")
    if 'rules_evaluated' not in ar_columns:
        cursor.execute("ALTER TABLE analysis_runs ADD COLUMN rules_evaluated INTEGER DEFAULT 3")
    if 'status' not in ar_columns:
        cursor.execute("ALTER TABLE analysis_runs ADD COLUMN status TEXT DEFAULT 'Completed'")
    
    # 6. Log events table (Member 2 & 3)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS log_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER,
            investigation_id INTEGER,
            evidence_id INTEGER,
            source_row_number INTEGER,
            timestamp TEXT,
            normalized_timestamp TEXT,
            source_ip TEXT,
            event_type TEXT,
            username TEXT,
            status TEXT,
            severity TEXT DEFAULT 'Low',
            detection_reason TEXT,
            FOREIGN KEY (run_id) REFERENCES analysis_runs(id) ON DELETE CASCADE
            FOREIGN KEY (run_id) REFERENCES analysis_runs(id),
            FOREIGN KEY (investigation_id) REFERENCES investigations(id),
            FOREIGN KEY (evidence_id) REFERENCES evidence_files(id)
        )
    ''')
    
    # 7. Detections / Threats table (legacy compatibility)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER,
            timestamp TEXT,
            source_ip TEXT,
            rule_triggered TEXT,
            severity TEXT,
            evidence TEXT,
            status TEXT DEFAULT 'Active',
            FOREIGN KEY (run_id) REFERENCES analysis_runs(id) ON DELETE CASCADE
        )
    ''')
    
    # Evidence metadata & integrity table (Member 4 - SECURITY-4 Requirement 2 & 3)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER,
            original_filename TEXT NOT NULL,
            stored_filename TEXT NOT NULL,
            file_path TEXT NOT NULL,
            file_size INTEGER DEFAULT 0,
            sha256_hash TEXT NOT NULL,
            uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            verification_status TEXT DEFAULT 'Verified',
            FOREIGN KEY (run_id) REFERENCES analysis_runs(id) ON DELETE CASCADE
        )
    ''')

    # Reports table (Member 4)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER,
            report_name TEXT NOT NULL,
            generated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            file_path TEXT,
            report_status TEXT DEFAULT 'Generated',
            FOREIGN KEY (run_id) REFERENCES analysis_runs(id) ON DELETE CASCADE
        )
    ''')

    # Audit Trail table (Member 4 - SECURITY-4 Requirement 10)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_trail (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER,
            action_type TEXT NOT NULL,
            description TEXT,
            related_record_type TEXT,
            related_record_id INTEGER,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    
    # 8. Findings table (Member 3 PRD)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigation_id INTEGER DEFAULT 1,
            analysis_run_id INTEGER,
            rule_id TEXT,
            rule_name TEXT,
            description TEXT,
            severity TEXT,
            status TEXT DEFAULT 'New',
            detected_at TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (analysis_run_id) REFERENCES analysis_runs(id)
        )
    ''')
    
    # 9. Finding events relationship table (Member 3 PRD)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS finding_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id INTEGER,
            event_id INTEGER,
            FOREIGN KEY (finding_id) REFERENCES findings(id),
            FOREIGN KEY (event_id) REFERENCES log_events(id)
        )
    ''')
    
    # 10. Finding notes table (Member 3 PRD)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS finding_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id INTEGER,
            note_text TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (finding_id) REFERENCES findings(id)
        )
    ''')

    # 11. Security audit logs table (Security-3 PRD §10)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            severity TEXT DEFAULT 'Medium',
            details TEXT,
            client_ip TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()

def backup_db(backup_dest=None):
    """
    Safe SQLite backup procedure (Member 4 - SECURITY-4 Requirement 8).
    Creates an atomic, consistent backup of the SQLite database.
    """
    if backup_dest is None:
        backup_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backups')
        os.makedirs(backup_dir, exist_ok=True)
        ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_dest = os.path.join(backup_dir, f'shadowtrace_backup_{ts}.db')
    
    conn = get_db_connection()
    bck = sqlite3.connect(backup_dest)
    with bck:
        conn.backup(bck)
    bck.close()
    conn.close()
    return backup_dest

if __name__ == '__main__':
    init_db()
