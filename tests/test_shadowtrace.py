import sys
import os
import unittest
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from database import init_db, get_db_connection
from csv_processor import process_csv_content
from detector import analyze_records
from app import app

class TestShadowTrace(unittest.TestCase):
    def setUp(self):
        init_db()
        self.client = app.test_client()

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
        self.assertTrue(any(f['rule_id'] == 'RULE-01' for f in res['findings']))
        self.assertTrue(any(f['rule_id'] == 'RULE-02' for f in res['findings']))
        self.assertTrue(any(f['rule_id'] == 'RULE-03' for f in res['findings']))

    def test_member3_findings_and_api(self):
        # Load sample or test data via upload/load-sample endpoint
        res = self.client.post('/api/load-sample')
        self.assertEqual(res.status_code, 200)

        # Test listing findings
        res_findings = self.client.get('/api/investigations/1/findings')
        self.assertEqual(res_findings.status_code, 200)
        data = res_findings.get_json()
        self.assertTrue(data['ok'])
        findings = data['data']
        self.assertTrue(len(findings) > 0)

        finding_id = findings[0]['id']

        # Test get finding details
        res_detail = self.client.get(f'/api/findings/{finding_id}')
        self.assertEqual(res_detail.status_code, 200)
        detail_data = res_detail.get_json()
        self.assertTrue(detail_data['ok'])
        self.assertIn('supporting_events', detail_data['data'])

        # Test update finding status
        res_status = self.client.patch(f'/api/findings/{finding_id}/status', json={'status': 'Under Review'})
        self.assertEqual(res_status.status_code, 200)
        status_data = res_status.get_json()
        self.assertTrue(status_data['ok'])
        self.assertEqual(status_data['data']['status'], 'Under Review')

        # Test add finding note
        res_note = self.client.post(f'/api/findings/{finding_id}/notes', json={'note_text': 'Investigating suspicious activity source IP.'})
        self.assertEqual(res_note.status_code, 200)
        note_data = res_note.get_json()
        self.assertTrue(note_data['ok'])
        self.assertEqual(note_data['data']['note_text'], 'Investigating suspicious activity source IP.')

        # Test analysis runs history
        res_runs = self.client.get('/api/investigations/1/analysis-runs')
        self.assertEqual(res_runs.status_code, 200)
        runs_data = res_runs.get_json()
        self.assertTrue(runs_data['ok'])
        self.assertTrue(len(runs_data['data']) > 0)

if __name__ == '__main__':
    unittest.main()
