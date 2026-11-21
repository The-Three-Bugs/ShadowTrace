def analyze_records(records):
    """
    Applies the 3 detection rules to the list of log records in accordance with Member 3 PRD:
    Rule 1 (RULE-01): Repeated Failed Login Attempts (3+ failed logins from same IP/username)
    Rule 2 (RULE-02): Successful Login Following Repeated Failures (successful login after multiple failed attempts)
    Rule 3 (RULE-03): Sensitive File Access Following Suspicious Login Activity
    """
    detections = []
    findings = []
    
    if not records:
        return {
            'records': [],
            'detections': [],
            'findings': [],
            'suspicious_count': 0
        }

    ip_failed_counts = {}
    ip_events = {}

    for idx, rec in enumerate(records):
        ip = rec.get('source_ip', '127.0.0.1')
        if ip not in ip_events:
            ip_events[ip] = []
        # Store index reference for supporting events
        rec['_temp_index'] = idx + 1
        ip_events[ip].append(rec)

        evt_lower = str(rec.get('event_type', '')).lower()
        status_lower = str(rec.get('status', '')).lower()

        # Count failed logins
        if 'login' in evt_lower and status_lower in ['failed', 'failure', 'error', 'blocked']:
            if ip not in ip_failed_counts:
                ip_failed_counts[ip] = 0
            ip_failed_counts[ip] += 1

    # Track flagged IPs for Rule 1
    flagged_ips_rule1 = set()
    for ip, count in ip_failed_counts.items():
        if count >= 3:
            flagged_ips_rule1.add(ip)
            # Find contributing event ids/indices
            event_indices = [r['_temp_index'] for r in ip_events[ip] if 'login' in str(r.get('event_type', '')).lower() and str(r.get('status', '')).lower() in ['failed', 'failure', 'error', 'blocked']]
            
            evidence_text = f'Detected {count} failed login attempts from source IP {ip}.'
            detections.append({
                'timestamp': '2026-10-14 00:00:00',
                'source_ip': ip,
                'rule_triggered': 'Rule 1: Repeated Failed Logins',
                'severity': 'Medium' if count < 5 else 'Critical',
                'evidence': evidence_text,
                'status': 'Active'
            })
            findings.append({
                'rule_id': 'RULE-01',
                'rule_name': 'Repeated Failed Login Attempts',
                'description': evidence_text,
                'severity': 'Medium' if count < 5 else 'Critical',
                'status': 'New',
                'detected_at': '2026-10-14 00:00:00',
                'supporting_event_ids': event_indices
            })

    # Check Rule 2: Successful Login Following Repeated Failures
    for ip, events in ip_events.items():
        failed_before_success = 0
        failed_indices = []
        for rec in events:
            evt_lower = str(rec.get('event_type', '')).lower()
            status_lower = str(rec.get('status', '')).lower()
            if 'login' in evt_lower:
                if status_lower in ['failed', 'failure', 'error']:
                    failed_before_success += 1
                    failed_indices.append(rec['_temp_index'])
                elif status_lower in ['success', 'successful'] and failed_before_success >= 2:
                    succ_idx = rec['_temp_index']
                    supporting = failed_indices + [succ_idx]
                    evidence_text = f'Successful login by {rec.get("username", "unknown")} from {ip} following {failed_before_success} failed login attempts.'
                    detections.append({
                        'timestamp': rec.get('timestamp', '2026-10-14 00:00:00'),
                        'source_ip': ip,
                        'rule_triggered': 'Rule 2: Successful Login Following Repeated Failures',
                        'severity': 'Medium',
                        'evidence': evidence_text,
                        'status': 'Active'
                    })
                    findings.append({
                        'rule_id': 'RULE-02',
                        'rule_name': 'Successful Login Following Repeated Failures',
                        'description': evidence_text,
                        'severity': 'Medium',
                        'status': 'New',
                        'detected_at': rec.get('timestamp', '2026-10-14 00:00:00'),
                        'supporting_event_ids': supporting
                    })

    # Check Rule 3: Sensitive File Access Following Suspicious Activity
    for rec in records:
        evt_lower = str(rec.get('event_type', '')).lower()
        status_lower = str(rec.get('status', '')).lower()
        
        suspicious_keywords = ['unauthorized', 'access_denied', 'forbidden', 'privilege_escalation', 'port_scan', 'breach', 'sensitive']
        if any(kw in evt_lower or kw in status_lower for kw in suspicious_keywords):
            rec['severity'] = 'High'
            rec['detection_reason'] = f'Suspicious access indicator matched ({rec.get("event_type")} / {rec.get("status")})'
            evidence_text = f'Unauthorized or sensitive access attempt ({rec.get("event_type")}) by user {rec.get("username")} from {rec.get("source_ip")}.'
            detections.append({
                'timestamp': rec.get('timestamp', '2026-10-14 00:00:00'),
                'source_ip': rec.get('source_ip', '127.0.0.1'),
                'rule_triggered': 'Rule 3: Sensitive File Access Following Suspicious Login Activity',
                'severity': 'High',
                'evidence': evidence_text,
                'status': 'Active'
            })
            findings.append({
                'rule_id': 'RULE-03',
                'rule_name': 'Sensitive File Access Following Suspicious Login Activity',
                'description': evidence_text,
                'severity': 'High',
                'status': 'New',
                'detected_at': rec.get('timestamp', '2026-10-14 00:00:00'),
                'supporting_event_ids': [rec['_temp_index']]
            })

    # Check Rule 4: Threat Signatures, Scanner User-Agents & DDoS / Volumetric Flood
    critical_sigs = ['ddos', 'dos', 'ransomware', 'malware', 'exploit', 'sql_injection', 'xss', 'malicious', 'attack']
    scanner_sigs = ['nmap', 'sqlmap', 'nikto', 'masscan', 'hydra', 'dirbuster']
    for rec in records:
        evt_lower = str(rec.get('event_type', '')).lower()
        status_lower = str(rec.get('status', '')).lower()
        threat_lower = str(rec.get('threat_label', '')).lower()
        ua_lower = str(rec.get('user_agent', '')).lower()

        if any(sig in threat_lower or sig in evt_lower for sig in critical_sigs):
            rec['severity'] = 'Critical'
            rec['detection_reason'] = f'Critical threat signature detected ({rec.get("threat_label") or rec.get("event_type")})'
        elif any(sig in ua_lower for sig in scanner_sigs):
            if rec.get('severity') == 'Low':
                rec['severity'] = 'High'
                rec['detection_reason'] = f'Automated security scanner detected ({rec.get("user_agent")})'
        elif status_lower in ['blocked', 'denied', 'dropped'] and rec.get('severity') == 'Low':
            rec['severity'] = 'Medium'
            rec['detection_reason'] = f'Blocked/denied {rec.get("event_type")} traffic from {rec.get("source_ip")}'

    # Volumetric / DDoS detection per source IP
    for ip, events in ip_events.items():
        blocked_cnt = sum(1 for r in events if str(r.get('status', '')).lower() in ['blocked', 'denied', 'dropped'])
        if len(events) >= 40 or blocked_cnt >= 10:
            sev = 'Critical' if (len(events) >= 80 or blocked_cnt >= 25) else 'High'
            evidence_text = f'Volumetric / DDoS anomaly from {ip}: {len(events)} total events ({blocked_cnt} blocked).'
            detections.append({
                'timestamp': events[0].get('timestamp', '2026-10-14 00:00:00'),
                'source_ip': ip,
                'rule_triggered': 'Rule 4: DDoS / Volumetric Flood & Perimeter Probe',
                'severity': sev,
                'evidence': evidence_text,
                'status': 'Active'
            })
            findings.append({
                'rule_id': 'RULE-04',
                'rule_name': 'DDoS / Volumetric Flood & Perimeter Probe',
                'description': evidence_text,
                'severity': sev,
                'status': 'New',
                'detected_at': events[0].get('timestamp', '2026-10-14 00:00:00'),
                'supporting_event_ids': [r['_temp_index'] for r in events[:25]]
            })
            for r in events:
                if r.get('severity') in ['Low', 'Medium']:
                    r['severity'] = sev
                    r['detection_reason'] = evidence_text

    # Update record severities for Rule 1
    for rec in records:
        ip = rec.get('source_ip')
        if ip in flagged_ips_rule1 and rec.get('severity') == 'Low':
            rec['severity'] = 'Medium'
            rec['detection_reason'] = f'IP {ip} flagged under RULE-01 (Repeated Failed Logins).'

    # Clean up temp index
    for rec in records:
        if '_temp_index' in rec:
            del rec['_temp_index']

    suspicious_count = sum(1 for r in records if r.get('severity') in ['Critical', 'High', 'Medium'])

    return {
        'records': records,
        'detections': detections,
        'findings': findings,
        'suspicious_count': suspicious_count
    }
