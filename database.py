import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'shadowtrace.db')

def get_db_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Investigations table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS investigations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Ensure default investigation exists
    cursor.execute('SELECT COUNT(*) FROM investigations')
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO investigations (name) VALUES ('Default Investigation')")
    
    # Analysis runs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS analysis_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigation_id INTEGER DEFAULT 1,
            filename TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            total_records INTEGER DEFAULT 0,
            valid_records INTEGER DEFAULT 0,
            invalid_records INTEGER DEFAULT 0,
            suspicious_count INTEGER DEFAULT 0,
            rules_evaluated INTEGER DEFAULT 3,
            status TEXT DEFAULT 'Completed'
        )
    ''')
    
    # Check and migrate columns in analysis_runs if table already existed
    cursor.execute("PRAGMA table_info(analysis_runs)")
    columns = [col['name'] for col in cursor.fetchall()]
    if 'investigation_id' not in columns:
        cursor.execute("ALTER TABLE analysis_runs ADD COLUMN investigation_id INTEGER DEFAULT 1")
    if 'rules_evaluated' not in columns:
        cursor.execute("ALTER TABLE analysis_runs ADD COLUMN rules_evaluated INTEGER DEFAULT 3")
    
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
            FOREIGN KEY (run_id) REFERENCES analysis_runs(id)
        )
    ''')
    
    # Detections / Threats table (legacy compatibility)
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
            FOREIGN KEY (run_id) REFERENCES analysis_runs(id)
        )
    ''')
    
    # Findings table (Member 3 PRD)
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
    
    # Finding events relationship table (Member 3 PRD)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS finding_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id INTEGER,
            event_id INTEGER,
            FOREIGN KEY (finding_id) REFERENCES findings(id),
            FOREIGN KEY (event_id) REFERENCES log_events(id)
        )
    ''')
    
    # Finding notes table (Member 3 PRD)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS finding_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id INTEGER,
            note_text TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (finding_id) REFERENCES findings(id)
        )
    ''')

    # Security audit logs table (Security-3 PRD §10)
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

if __name__ == '__main__':
    init_db()
