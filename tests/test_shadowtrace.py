import sys
import os
import unittest
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from database import init_db, get_db_connection
from csv_processor import process_csv_content, parse_timestamp
from detector import analyze_records
from app import app

class TestShadowTraceMember2(unittest.TestCase):
    def setUp(self):
        db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'instance', 'shadowtrace.db')
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except OSError:
                pass
        init_db()
        self.app = app.test_client()
        self.app.testing = True

    def test_timestamp_normalization(self):
        norm, ok = parse_timestamp("2026-10-14 10:30:00")
        self.assertTrue(ok)
        self.assertEqual(norm, "2026-10-14T10:30:00")

        norm2, ok2 = parse_timestamp("invalid-date")
        self.assertFalse(ok2)
        self.assertEqual(norm2, "invalid-date")

    def test_csv_processor_validation_and_normalization(self):
        sample_csv = "Timestamp,Username,Source_IP,Event_Type,Status\n2026-10-14 10:00:00, alice , 192.168.1.100 , login_attempt , success\n"
        result = process_csv_content(sample_csv)
        self.assertEqual(result['total'], 1)
        self.assertEqual(len(result['valid_records']), 1)
        self.assertEqual(result['invalid_count'], 0)
        self.assertEqual(result['duplicate_count'], 0)
        self.assertEqual(result['valid_records'][0]['username'], 'alice')
        self.assertEqual(result['valid_records'][0]['normalized_timestamp'], '2026-10-14T10:00:00')

    def test_csv_processor_duplicates_and_invalid_rows(self):
        sample_csv = (
            "timestamp,username,source_ip,event_type,status\n"
            "2026-10-14 10:00:00,admin,192.168.1.10,login,failed\n"
            "2026-10-14 10:00:00,admin,192.168.1.10,login,failed\n" # Duplicate
            ",guest,,login,failed\n" # Invalid row (missing source_ip and timestamp)
        )
        result = process_csv_content(sample_csv)
        self.assertEqual(result['total'], 3)
        self.assertEqual(len(result['valid_records']), 1)
        self.assertEqual(result['duplicate_count'], 1)
        self.assertEqual(result['invalid_count'], 1)
        self.assertEqual(result['processing_status'], 'Completed with Errors')

    def test_missing_required_columns(self):
        bad_csv = "username,status\nalice,success\n"
        with self.assertRaises(ValueError):
            process_csv_content(bad_csv)

    def test_member2_api_integration(self):
        # Create an investigation
        res = self.app.post('/api/investigations', json={
            'title': 'Test Investigation M2',
            'case_reference': 'CASE-2026-002',
            'notes': 'Testing Member 2 endpoints'
        })
        self.assertEqual(res.status_code, 201)
        data = json.loads(res.data)
        self.assertTrue(data['ok'])
        inv_id = data['data']['id']

        # Upload evidence file to investigation
        csv_data = "timestamp,username,source_ip,event_type,status\n2026-10-14 10:00:00,admin,192.168.1.10,login,failed\n"
        from io import BytesIO
        res_ev = self.app.post(f'/api/investigations/{inv_id}/evidence', data={
            'file': (BytesIO(csv_data.encode('utf-8')), 'test_logs.csv')
        })
        self.assertEqual(res_ev.status_code, 201)
        ev_data = json.loads(res_ev.data)
        self.assertTrue(ev_data['ok'])
        ev_id = ev_data['data']['id']

        # Process evidence
        res_proc = self.app.post(f'/api/evidence/{ev_id}/process')
        self.assertEqual(res_proc.status_code, 200)
        proc_data = json.loads(res_proc.data)
        self.assertTrue(proc_data['ok'])
        self.assertEqual(proc_data['data']['valid_rows'], 1)

        # Get processing summary
        res_sum = self.app.get(f'/api/evidence/{ev_id}/processing-summary')
        self.assertEqual(res_sum.status_code, 200)
        sum_data = json.loads(res_sum.data)
        self.assertTrue(sum_data['ok'])
        self.assertEqual(sum_data['data']['valid_rows'], 1)

        # Get investigation events
        res_events = self.app.get(f'/api/investigations/{inv_id}/events?username=admin&sort=oldest')
        self.assertEqual(res_events.status_code, 200)
        evs_data = json.loads(res_events.data)
        self.assertTrue(evs_data['ok'])
        self.assertEqual(evs_data['data']['total'], 1)
        event_id = evs_data['data']['events'][0]['id']

        # Get event detail
        res_detail = self.app.get(f'/api/events/{event_id}')
        self.assertEqual(res_detail.status_code, 200)
        detail_data = json.loads(res_detail.data)
        self.assertTrue(detail_data['ok'])
        self.assertEqual(detail_data['data']['username'], 'admin')

    def test_detector_rules(self):
        records = [
            {'timestamp': '2026-10-14 10:00:00', 'normalized_timestamp': '2026-10-14T10:00:00', 'source_ip': '1.2.3.4', 'event_type': 'login_attempt', 'username': 'admin', 'status': 'failed', 'severity': 'Low', 'detection_reason': ''},
            {'timestamp': '2026-10-14 10:00:01', 'normalized_timestamp': '2026-10-14T10:00:01', 'source_ip': '1.2.3.4', 'event_type': 'login_attempt', 'username': 'admin', 'status': 'failed', 'severity': 'Low', 'detection_reason': ''},
            {'timestamp': '2026-10-14 10:00:02', 'normalized_timestamp': '2026-10-14T10:00:02', 'source_ip': '1.2.3.4', 'event_type': 'login_attempt', 'username': 'admin', 'status': 'failed', 'severity': 'Low', 'detection_reason': ''},
            {'timestamp': '2026-10-14 10:00:03', 'normalized_timestamp': '2026-10-14T10:00:03', 'source_ip': '1.2.3.4', 'event_type': 'login_attempt', 'username': 'admin', 'status': 'failed', 'severity': 'Low', 'detection_reason': ''},
            {'timestamp': '2026-10-14 10:00:04', 'normalized_timestamp': '2026-10-14T10:00:04', 'source_ip': '1.2.3.4', 'event_type': 'login_attempt', 'username': 'admin', 'status': 'failed', 'severity': 'Low', 'detection_reason': ''},
            {'timestamp': '2026-10-14 10:00:05', 'normalized_timestamp': '2026-10-14T10:00:05', 'source_ip': '5.6.7.8', 'event_type': 'unauthorized_access', 'username': 'guest', 'status': 'forbidden', 'severity': 'Low', 'detection_reason': ''}
        ]
        res = analyze_records(records)
        self.assertTrue(res['suspicious_count'] > 0)
        self.assertTrue(any('Rule 1' in d['rule_triggered'] for d in res['detections']))

if __name__ == '__main__':
    unittest.main()
