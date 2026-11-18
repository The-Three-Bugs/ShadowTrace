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
        from app import login_attempts_store
        login_attempts_store.clear()

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
        
        # Log in as analyst for investigation/evidence operations
        client.post('/api/auth/login', json={'username': 'analyst', 'password': 'AnalystPass123!'})

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

    def test_authentication_and_authorization(self):
        from app import app
        client = app.test_client()

        # 1. Test unauthenticated access to protected route
        res_unauth = client.get('/api/auth/me')
        self.assertEqual(res_unauth.status_code, 401)
        self.assertFalse(res_unauth.get_json()['ok'])

        # 2. Test invalid login credentials
        res_bad_login = client.post('/api/auth/login', json={'username': 'admin', 'password': 'WrongPassword123!'})
        self.assertEqual(res_bad_login.status_code, 401)
        self.assertFalse(res_bad_login.get_json()['ok'])
        # Ensure generic error message doesn't reveal user existence details
        self.assertIn('Invalid username or password', res_bad_login.get_json()['error']['message'])

        # 3. Test valid login
        res_login = client.post('/api/auth/login', json={'username': 'admin', 'password': 'AdminSecret123!'})
        self.assertEqual(res_login.status_code, 200)
        login_data = res_login.get_json()
        self.assertTrue(login_data['ok'])
        self.assertEqual(login_data['data']['user']['username'], 'admin')
        self.assertEqual(login_data['data']['user']['role'], 'Administrator')

        # 4. Test /api/auth/me after login
        res_me = client.get('/api/auth/me')
        self.assertEqual(res_me.status_code, 200)
        self.assertEqual(res_me.get_json()['data']['user']['username'], 'admin')

        # 5. Test logout
        res_logout = client.post('/api/auth/logout')
        self.assertEqual(res_logout.status_code, 200)
        self.assertTrue(res_logout.get_json()['ok'])

        # Verify session cleared
        res_me_after = client.get('/api/auth/me')
        self.assertEqual(res_me_after.status_code, 401)

        # 6. Test login throttling after 5 failed attempts
        for _ in range(5):
            client.post('/api/auth/login', json={'username': 'analyst', 'password': 'BadPassword'})
        
        res_throttle = client.post('/api/auth/login', json={'username': 'analyst', 'password': 'BadPassword'})
        self.assertEqual(res_throttle.status_code, 429)
        self.assertEqual(res_throttle.get_json()['error']['code'], 'TOO_MANY_REQUESTS')

    def test_password_policy_and_change(self):
        from app import app
        client = app.test_client()

        # 1. Login as viewer
        client.post('/api/auth/login', json={'username': 'viewer', 'password': 'ViewerPass123!'})

        # 2. Test weak password rejection (< 8 chars)
        res_weak = client.post('/api/auth/change-password', json={'current_password': 'ViewerPass123!', 'new_password': 'short'})
        self.assertEqual(res_weak.status_code, 400)
        self.assertEqual(res_weak.get_json()['error']['code'], 'WEAK_PASSWORD')

        # 3. Test incorrect current password rejection
        res_bad_curr = client.post('/api/auth/change-password', json={'current_password': 'WrongPassword!', 'new_password': 'NewSecurePass123!'})
        self.assertEqual(res_bad_curr.status_code, 401)

        # 4. Test successful password change and session invalidation
        res_change = client.post('/api/auth/change-password', json={'current_password': 'ViewerPass123!', 'new_password': 'NewSecurePass123!'})
        self.assertEqual(res_change.status_code, 200)
        self.assertTrue(res_change.get_json()['ok'])

        # Verify session was invalidated (requires re-login)
        res_me = client.get('/api/auth/me')
        self.assertEqual(res_me.status_code, 401)

        # 5. Verify login works with new password
        res_login_new = client.post('/api/auth/login', json={'username': 'viewer', 'password': 'NewSecurePass123!'})
        self.assertEqual(res_login_new.status_code, 200)
        self.assertTrue(res_login_new.get_json()['ok'])

    def test_authorization_roles_and_idor(self):
        from app import app
        import io
        client = app.test_client()

        # 1. Login as Viewer (read-only role)
        client.post('/api/auth/login', json={'username': 'viewer', 'password': 'ViewerPass123!'})

        # 2. Viewer attempts restricted action: Create investigation (should be 403 Forbidden)
        res_viewer_create = client.post('/api/investigations', json={'title': 'Viewer Breach', 'description': 'Unauthorized create'})
        self.assertEqual(res_viewer_create.status_code, 403)
        self.assertEqual(res_viewer_create.get_json()['error']['code'], 'FORBIDDEN')

        # 3. Logout Viewer and login as Analyst
        client.post('/api/auth/logout')
        client.post('/api/auth/login', json={'username': 'analyst', 'password': 'AnalystPass123!'})

        # 4. Analyst creates investigation successfully (201 Created)
        res_analyst_create = client.post('/api/investigations', json={'title': 'Analyst Incident', 'description': 'Authorized create'})
        self.assertEqual(res_analyst_create.status_code, 201)
        inv_id = res_analyst_create.get_json()['data']['item']['id']

        # 5. Analyst uploads evidence
        csv_data = b"timestamp,source_ip,event_type,username,status\n2026-10-14 12:00:00,10.0.0.1,login_type,user1,success\n"
        evidence_file = {'file': (io.BytesIO(csv_data), 'analyst_evidence.csv')}
        res_upload = client.post(f'/api/investigations/{inv_id}/evidence', data=evidence_file, content_type='multipart/form-data')
        self.assertEqual(res_upload.status_code, 201)
        ev_id = res_upload.get_json()['data']['item']['id']

        # 6. Verify evidence details and parent-child IDOR verification
        res_ev = client.get(f'/api/evidence/{ev_id}')
        self.assertEqual(res_ev.status_code, 200)
        self.assertEqual(res_ev.get_json()['data']['item']['investigation_id'], inv_id)

if __name__ == '__main__':
    unittest.main()
