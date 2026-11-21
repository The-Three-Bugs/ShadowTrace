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

COLUMN_ALIASES = {
    'timestamp': ['timestamp', 'time', 'date', 'datetime', 'created_at', 'event_time', 'log_time', 'ts'],
    'source_ip': ['source_ip', 'src_ip', 'ip', 'ip_address', 'client_ip', 'remote_addr', 'src', 'srcaddr', 'host_ip'],
    'event_type': ['event_type', 'event', 'attack_type', 'threat_label', 'activity', 'protocol', 'type', 'category', 'log_type', 'request_path'],
    'username': ['username', 'user', 'user_name', 'account', 'actor', 'userid', 'user_id', 'principal'],
    'status': ['status', 'action', 'result', 'outcome', 'state', 'decision', 'severity'],
    'log_source': ['log_type', 'log_source', 'source', 'sensor'],
    'threat_label': ['threat_label', 'label', 'attack_type', 'classification'],
    'user_agent': ['user_agent', 'ua', 'agent'],
}


def _resolve_column_map(normalized_header):
    """Map any real-world CSV header to ShadowTrace's canonical fields."""
    col_map = {}
    for canonical, aliases in COLUMN_ALIASES.items():
        for alias in aliases:
            if alias in normalized_header:
                col_map[canonical] = normalized_header.index(alias)
                break
    return col_map


def process_csv_content(file_stream, max_rows=10000):
    """
    Processes a CSV file stream (bytes, string, or file-like), automatically
    maps real-world/Kaggle column schemas, normalizes timestamps and events,
    tracks invalid rows and duplicates, and returns a summary dictionary.
    """
    if hasattr(file_stream, 'readline'):
        f = file_stream
    elif hasattr(file_stream, 'read'):
        content = file_stream.read()
        if isinstance(content, bytes):
            content = content.decode('utf-8', errors='ignore')
        f = io.StringIO(content)
    else:
        f = io.StringIO(str(file_stream))

    reader = csv.reader(f)
    
    try:
        header = next(reader)
    except StopIteration:
        raise ValueError("Uploaded CSV file is empty.")

    # Normalize header: lowercase, strip whitespace
    normalized_header = [col.strip().lower() for col in header]
    col_map = _resolve_column_map(normalized_header)

    # Only timestamp and source_ip (or event_type) are strictly needed; others default gracefully
    if 'timestamp' not in col_map and 'source_ip' not in col_map:
        raise ValueError(
            "CSV must contain at least a timestamp or source IP column "
            f"(found: {', '.join(header[:10])})."
        )

    valid_records = []
    invalid_rows = []
    seen_records = set()
    duplicate_count = 0
    total_count = 0

    row_number = 1 # Header is row 1
    for row in reader:
        if max_rows and total_count >= max_rows:
            break
        row_number += 1
        total_count += 1
        
        if not row or all(not cell.strip() for cell in row):
            invalid_rows.append({
                'row_number': row_number,
                'reason': 'Empty or blank row.'
            })
            continue

        try:
            def _get(field, default=''):
                idx = col_map.get(field)
                if idx is not None:
                    return row[idx].strip() if len(row) > idx else ''
                return default

            raw_ts = _get('timestamp', '2026-10-14 00:00:00')
            username = _get('username', 'unknown')
            source_ip = _get('source_ip', '0.0.0.0')
            event_type = _get('event_type', 'network_event')
            status = _get('status', 'unknown')
            log_source = _get('log_source', '')
            threat_label = _get('threat_label', '')
            user_agent = _get('user_agent', '')

            # If event_type is generic like 'benign' and log_source exists, make event_type descriptive
            if event_type.lower() in ('benign', 'normal', 'clean') and log_source:
                event_type = f"{log_source}_traffic"
            elif log_source and event_type.lower() == log_source.lower():
                event_type = f"{log_source}_event"

            # Validation checks & field length limits
            reasons = []
            if len(username) > 255 or len(source_ip) > 255 or len(event_type) > 255 or len(status) > 255 or len(raw_ts) > 255:
                reasons.append("Field length exceeds maximum allowed limit (255 characters)")
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
                'log_source': log_source,
                'threat_label': threat_label,
                'user_agent': user_agent,
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
