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
    
    # Analysis runs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS analysis_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            total_records INTEGER DEFAULT 0,
            valid_records INTEGER DEFAULT 0,
            invalid_records INTEGER DEFAULT 0,
            suspicious_count INTEGER DEFAULT 0,
            status TEXT DEFAULT 'Completed',
            sha256_hash TEXT,
            stored_filename TEXT
        )
    ''')
    
    # Log events table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS log_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER,
            timestamp TEXT,
            source_ip TEXT,
            event_type TEXT,
            username TEXT,
            status TEXT,
            severity TEXT DEFAULT 'Low',
            detection_reason TEXT,
            FOREIGN KEY (run_id) REFERENCES analysis_runs(id) ON DELETE CASCADE
        )
    ''')
    
    # Detections / Threats table
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
