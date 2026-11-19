import csv
import io
from datetime import datetime

def parse_timestamp(ts_str):
    """
    Parses various timestamp formats into a standard ISO-8601 UTC string (YYYY-MM-DDTHH:MM:SS).
    Returns (normalized_str, success_bool).
    """
    if not ts_str or not isinstance(ts_str, str):
        return '2026-10-14T00:00:00', False
    
    ts_str = ts_str.strip()
    formats = [
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%d %H:%M',
        '%d/%m/%Y %H:%M:%S',
        '%m/%d/%Y %H:%M:%S',
        '%Y-%m-%d'
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(ts_str, fmt)
            return dt.strftime('%Y-%m-%dT%H:%M:%S'), True
        except ValueError:
            continue
            
    return ts_str, False

def process_csv_content(file_stream):
    """
    Processes a CSV file stream (bytes or string), validates columns,
    normalizes timestamps and events, tracks invalid rows and duplicates,
    and returns a summary dictionary.
    """
    if hasattr(file_stream, 'read'):
        content = file_stream.read()
        if isinstance(content, bytes):
            content = content.decode('utf-8', errors='ignore')
    else:
        content = str(file_stream)

    f = io.StringIO(content)
    reader = csv.reader(f)
    
    try:
        header = next(reader)
    except StopIteration:
        raise ValueError("Uploaded CSV file is empty.")

    # Normalize header: lowercase, strip whitespace
    normalized_header = [col.strip().lower() for col in header]
    
    req_cols = ['timestamp', 'username', 'source_ip', 'event_type', 'status']
    col_map = {}
    missing_cols = []
    
    for req in req_cols:
        if req in normalized_header:
            col_map[req] = normalized_header.index(req)
        else:
            missing_cols.append(req)

    if missing_cols:
        raise ValueError(f"CSV missing required columns: {', '.join(missing_cols)}. Expected columns: {', '.join(req_cols)}.")

    valid_records = []
    invalid_rows = []
    seen_records = set()
    duplicate_count = 0
    total_count = 0

    row_number = 1 # Header is row 1
    for row in reader:
        row_number += 1
        total_count += 1
        
        if not row or all(not cell.strip() for cell in row):
            invalid_rows.append({
                'row_number': row_number,
                'reason': 'Empty or blank row.'
            })
            continue

        try:
            raw_ts = row[col_map['timestamp']].strip() if len(row) > col_map['timestamp'] else ''
            username = row[col_map['username']].strip() if len(row) > col_map['username'] else 'anonymous'
            source_ip = row[col_map['source_ip']].strip() if len(row) > col_map['source_ip'] else ''
            event_type = row[col_map['event_type']].strip() if len(row) > col_map['event_type'] else ''
            status = row[col_map['status']].strip() if len(row) > col_map['status'] else 'unknown'

            # Validation checks
            reasons = []
            if not source_ip:
                reasons.append("Missing source_ip")
            if not event_type:
                reasons.append("Missing event_type")
            
            norm_ts, ts_parsed = parse_timestamp(raw_ts)
            if not raw_ts:
                reasons.append("Missing timestamp")
            
            if reasons:
                invalid_rows.append({
                    'row_number': row_number,
                    'reason': '; '.join(reasons)
                })
                continue

            # Duplicate check
            record_key = (norm_ts, username, source_ip, event_type, status)
            if record_key in seen_records:
                duplicate_count += 1
                continue
            seen_records.add(record_key)

            valid_records.append({
                'source_row_number': row_number,
                'timestamp': raw_ts,
                'normalized_timestamp': norm_ts,
                'username': username,
                'source_ip': source_ip,
                'event_type': event_type,
                'status': status,
                'severity': 'Low',
                'detection_reason': 'Normal activity'
            })
        except Exception as e:
            invalid_rows.append({
                'row_number': row_number,
                'reason': f"Parsing error: {str(e)}"
            })

    invalid_count = len(invalid_rows)
    processing_status = 'Completed'
    if invalid_count > 0:
        processing_status = 'Completed with Errors'
    if total_count == 0:
        processing_status = 'Failed'

    return {
        'total': total_count,
        'valid_records': valid_records,
        'invalid_count': invalid_count,
        'invalid_rows': invalid_rows,
        'duplicate_count': duplicate_count,
        'processing_status': processing_status
    }
