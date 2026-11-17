import sys
import os
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from database import init_db, get_db_connection
from csv_processor import process_csv_content
from detector import analyze_records

class TestShadowTrace(unittest.TestCase):
    def setUp(self):
        init_db()

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
            {'timestamp': '2026-10-14 10:00:03', 'source_ip': '1.2.3.4', 'event_type': 'login_attempt', 'username': 'admin', 'status': 'failed', 'severity': 'Low', 'detection_reason': ''},
            {'timestamp': '2026-10-14 10:00:04', 'source_ip': '1.2.3.4', 'event_type': 'login_attempt', 'username': 'admin', 'status': 'failed', 'severity': 'Low', 'detection_reason': ''},
            {'timestamp': '2026-10-14 10:00:05', 'source_ip': '5.6.7.8', 'event_type': 'unauthorized_access', 'username': 'guest', 'status': 'forbidden', 'severity': 'Low', 'detection_reason': ''}
        ]
        res = analyze_records(records)
        self.assertTrue(res['suspicious_count'] > 0)
        self.assertTrue(any('Rule 1' in d['rule_triggered'] for d in res['detections']))
        self.assertTrue(any('Rule 2' in d['rule_triggered'] for d in res['detections']))

    def test_investigations_and_evidence(self):
        from app import app
        client = app.test_client()
        
        # 1. Test missing title validation on investigation creation
        res_err = client.post('/api/investigations', json={'title': ''})
        self.assertEqual(res_err.status_code, 400)
        self.assertFalse(res_err.get_json()['ok'])

        # 2. Create valid investigation
        res = client.post('/api/investigations', json={'title': 'Test Breach Investigation', 'description': 'Testing investigation creation', 'status': 'Open'})
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertTrue(data['ok'])
        inv_id = data['data']['item']['id']
        
        # 3. Get investigations with search and filtering
        res2 = client.get('/api/investigations?search=Breach&status=Open')
        self.assertEqual(res2.status_code, 200)
        self.assertGreaterEqual(len(res2.get_json()['data']['investigations']), 1)

        # 4. Get non-existent investigation (404)
        res_404 = client.get('/api/investigations/99999')
        self.assertEqual(res_404.status_code, 404)

        # 5. Update investigation status
        res_update = client.put(f'/api/investigations/{inv_id}', json={'status': 'In Progress'})
        self.assertEqual(res_update.status_code, 200)
        self.assertEqual(res_update.get_json()['data']['item']['status'], 'In Progress')

        # 6. Test invalid file extension upload (415)
        import io
        txt_data = b"some text content"
        txt_file = {'file': (io.BytesIO(txt_data), 'test.txt')}
        res_ext = client.post(f'/api/investigations/{inv_id}/evidence', data=txt_file, content_type='multipart/form-data')
        self.assertEqual(res_ext.status_code, 415)

        # 7. Test empty file upload (400)
        empty_file = {'file': (io.BytesIO(b""), 'empty.csv')}
        res_empty = client.post(f'/api/investigations/{inv_id}/evidence', data=empty_file, content_type='multipart/form-data')
        self.assertEqual(res_empty.status_code, 400)

        # 8. Upload valid CSV evidence
        csv_data = b"timestamp,source_ip,event_type,username,status\n2026-10-14 12:00:00,192.168.1.100,login_attempt,bob,success\n"
        data_file = {'file': (io.BytesIO(csv_data), 'test_log.csv')}
        res3 = client.post(f'/api/investigations/{inv_id}/evidence', data=data_file, content_type='multipart/form-data')
        self.assertEqual(res3.status_code, 201)
        ev_data = res3.get_json()
        self.assertTrue(ev_data['ok'])
        ev_id = ev_data['data']['item']['id']

        # 9. Test duplicate upload conflict (409)
        data_file_dup = {'file': (io.BytesIO(csv_data), 'test_log_dup.csv')}
        res_dup = client.post(f'/api/investigations/{inv_id}/evidence', data=data_file_dup, content_type='multipart/form-data')
        self.assertEqual(res_dup.status_code, 409)

        # 10. Check evidence verification and metadata
        res4 = client.get(f'/api/evidence/{ev_id}')
        self.assertEqual(res4.status_code, 200)
        ev_details = res4.get_json()
        self.assertEqual(ev_details['data']['item']['integrity_status'], 'Integrity Verified')

        # 10.1 Test Integrity Mismatch case (tamper stored file)
        from app import EVIDENCE_DIR
        stored_filename = ev_details['data']['item']['stored_filename']
        stored_path = os.path.join(EVIDENCE_DIR, stored_filename)
        with open(stored_path, 'wb') as f:
            f.write(b"tampered content")

        res_mismatch = client.get(f'/api/evidence/{ev_id}')
        self.assertEqual(res_mismatch.status_code, 200)
        self.assertEqual(res_mismatch.get_json()['data']['item']['integrity_status'], 'Integrity Mismatch')

        # 10.2 Test Verification Failed (File Missing) case (delete stored file)
        os.remove(stored_path)
        res_missing = client.get(f'/api/evidence/{ev_id}')
        self.assertEqual(res_missing.status_code, 200)
        self.assertEqual(res_missing.get_json()['data']['item']['integrity_status'], 'Verification Failed (File Missing)')

        # 10.3 Check investigation evidence listing endpoint
        res_list_ev = client.get(f'/api/investigations/{inv_id}/evidence')
        self.assertEqual(res_list_ev.status_code, 200)
        self.assertGreaterEqual(len(res_list_ev.get_json()['data']['evidence_files']), 1)

        # 11. Get non-existent evidence details (404)
        res_ev_404 = client.get('/api/evidence/99999')
        self.assertEqual(res_ev_404.status_code, 404)

if __name__ == '__main__':
    unittest.main()
