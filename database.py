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
            title TEXT NOT NULL,
            case_reference TEXT,
            notes TEXT,
            status TEXT DEFAULT 'Open',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Evidence files table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS evidence_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigation_id INTEGER,
            original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            sha256 TEXT,
            size_bytes INTEGER DEFAULT 0,
            imported_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            total_rows INTEGER DEFAULT 0,
            valid_rows INTEGER DEFAULT 0,
            invalid_rows INTEGER DEFAULT 0,
            status TEXT DEFAULT 'Pending',
            FOREIGN KEY (investigation_id) REFERENCES investigations(id)
        )
    ''')

    # Analysis runs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS analysis_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigation_id INTEGER,
            evidence_id INTEGER,
            filename TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            total_records INTEGER DEFAULT 0,
            valid_records INTEGER DEFAULT 0,
            invalid_records INTEGER DEFAULT 0,
            suspicious_count INTEGER DEFAULT 0,
            status TEXT DEFAULT 'Completed',
            FOREIGN KEY (investigation_id) REFERENCES investigations(id),
            FOREIGN KEY (evidence_id) REFERENCES evidence_files(id)
        )
    ''')

    # Processing runs table (Member 2 requirement)
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
    
    # Log events table
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
            FOREIGN KEY (run_id) REFERENCES analysis_runs(id),
            FOREIGN KEY (investigation_id) REFERENCES investigations(id),
            FOREIGN KEY (evidence_id) REFERENCES evidence_files(id)
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
            FOREIGN KEY (run_id) REFERENCES analysis_runs(id)
        )
    ''')
    
    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
