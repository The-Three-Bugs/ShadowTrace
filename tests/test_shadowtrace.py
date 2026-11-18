import sys
import os
import unittest
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from database import init_db, get_db_connection
from csv_processor import process_csv_content
from detector import analyze_records
from app import app, check_rate_limit, request_timestamps

class TestShadowTrace(unittest.TestCase):
    def setUp(self):
        init_db()
        self.client = app.test_client()
        request_timestamps.clear()

    def test_csv_processor(self):
        sample_csv = "timestamp,source_ip,event_type,username,status\n2026-10-14 10:00:00,192.168.1.100,login_attempt,alice,success\n"
        result = process_csv_content(sample_csv)
        self.assertEqual(result['total'], 1)
        self.assertEqual(len(result['valid_records']), 1)
        self.assertEqual(result['valid_records'][0]['source_ip'], '192.168.1.100')

    def test_detector_rules(self):
        records = [
            {'timestamp': '2026-10-14 10:00:00', 'source_ip': '1.2.3.4', 'event_type': 'login_attempt', 'username': 'admin', 'status': 'failed', 'severity': 'Low', 'detection_reason': ''},
            {'timestamp': '2026-10-14 10:00:01', 'source_ip': '1.2.3.4', 'event_type': 'login_attempt', 'username': 'admin', 'status': 'failed', 'severity': 'Low', 'detection_reason': ''},
            {'timestamp': '2026-10-14 10:00:02', 'source_ip': '1.2.3.4', 'event_type': 'login_attempt', 'username': 'admin', 'status': 'failed', 'severity': 'Low', 'detection_reason': ''},
            {'timestamp': '2026-10-14 10:00:03', 'source_ip': '1.2.3.4', 'event_type': 'login_attempt', 'username': 'admin', 'status': 'success', 'severity': 'Low', 'detection_reason': ''},
            {'timestamp': '2026-10-14 10:00:05', 'source_ip': '5.6.7.8', 'event_type': 'unauthorized_access', 'username': 'guest', 'status': 'forbidden', 'severity': 'Low', 'detection_reason': ''}
        ]
        res = analyze_records(records)
        self.assertTrue(res['suspicious_count'] > 0)

    def test_security_headers(self):
        res = self.client.get('/api/stats')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers.get('X-Content-Type-Options'), 'nosniff')
        self.assertEqual(res.headers.get('X-Frame-Options'), 'SAMEORIGIN')
        self.assertEqual(res.headers.get('Referrer-Policy'), 'strict-origin-when-cross-origin')
        # Verify Access-Control-Allow-* lines are NOT present as requested
        self.assertNotIn('Access-Control-Allow-Origin', res.headers)

    def test_centralized_error_handlers(self):
        # 404 Not Found
        res = self.client.get('/api/nonexistent-endpoint-security-test')
        self.assertEqual(res.status_code, 404)
        data = res.get_json()
        self.assertFalse(data['ok'])
        self.assertEqual(data['error']['code'], 'NOT_FOUND')

    def test_rate_limit_function(self):
        key = "test_ip:action"
        self.assertTrue(check_rate_limit(key, 0.5))
        self.assertFalse(check_rate_limit(key, 0.5))

    def test_security_audit_logging(self):
        # Trigger a 404 to generate a security audit log entry
        self.client.get('/api/nonexistent-endpoint-audit-test')
        res = self.client.get('/api/security/audit-logs')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data['ok'])
        logs = data['data']
        self.assertTrue(len(logs) > 0)
        self.assertTrue(any(log['event_type'] == 'NOT_FOUND' for log in logs))

if __name__ == '__main__':
    unittest.main()
