import os
import re
import sys
import tempfile
import time
import unittest
from types import ModuleType
from unittest.mock import patch

os.environ.setdefault('DNS_PANEL_DISABLE_SCHEDULER', '1')
_test_db_dir = tempfile.mkdtemp(prefix='dns_panel_test_routes_')
os.environ.setdefault('DNS_PANEL_DB_PATH', os.path.join(_test_db_dir, 'test.db'))
os.environ.setdefault('SECRET_KEY', 'test_secret_key')

monitor_stub = ModuleType('monitor')
monitor_stub.check_all_instances = lambda: None
monitor_stub.get_client = lambda inst=None: None
monitor_stub.ecs_start = lambda client=None, instance_id=None: (True, 'ok')
monitor_stub.ecs_stop = lambda client=None, instance_id=None: (True, 'ok')
monitor_stub.check_and_manage_instance = lambda instance_id=None: None
monitor_stub.ecs_release = lambda client=None, instance_id=None: (True, 'ok')
monitor_stub.get_region_traffic = lambda *args, **kwargs: 0
monitor_stub.get_security_groups = lambda *args, **kwargs: ([], 'stub')
monitor_stub.describe_sg_rules = lambda *args, **kwargs: []
monitor_stub.authorize_sg = lambda *args, **kwargs: (True, 'ok')
monitor_stub.revoke_sg = lambda *args, **kwargs: (True, 'ok')
monitor_stub.ecs_enable_ipv6 = lambda *args, **kwargs: (True, 'ok', [])
monitor_stub.get_ecs_ipv6_info = lambda *args, **kwargs: {}
monitor_stub.get_cdt_three_month_billing = lambda *args, **kwargs: {'months': [], 'total_traffic': 0, 'total_amount': 0, 'currency': 'CNY', 'scope': 'account', 'provider': 'stub'}
monitor_stub.BillingQueryError = type('BillingQueryError', (Exception,), {})
sys.modules.setdefault('monitor', monitor_stub)

flask_sock_stub = ModuleType('flask_sock')


class _Sock:
    def init_app(self, app):
        return None

    def route(self, path):
        def _decorator(fn):
            return fn

        return _decorator


flask_sock_stub.Sock = _Sock
sys.modules.setdefault('flask_sock', flask_sock_stub)

from werkzeug.security import generate_password_hash
from app import app
from models import db, User, EcsInstance, ScheduleTask


def _extract_csrf_token(client):
    resp = client.get('/', follow_redirects=True)
    html = resp.get_data(as_text=True)
    marker = 'name="csrf-token" content="'
    idx = html.find(marker)
    if idx < 0:
        return ''
    start = idx + len(marker)
    end = html.find('"', start)
    return html[start:end] if end > start else ''


class RoutesHardeningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config['TESTING'] = True
        cls.client = app.test_client()
        with app.app_context():
            db.drop_all()
            db.create_all()
            user = User(username='tester', password_hash=generate_password_hash('pass123456'))
            db.session.add(user)
            db.session.commit()

    def setUp(self):
        token = _extract_csrf_token(self.client)
        self.client.post('/login', data={'username': 'tester', 'password': 'pass123456', 'csrf_token': token})
        self.csrf_token = _extract_csrf_token(self.client)
        with app.app_context():
            ScheduleTask.query.delete()
            EcsInstance.query.delete()
            db.session.commit()
            self.instance = EcsInstance(
                name='inst1',
                access_key_id='ak',
                access_key_secret='sk',
                region_id='cn-hangzhou',
                instance_id='i-123',
                is_encrypted=False,
            )
            db.session.add(self.instance)
            db.session.commit()
            self.instance_id = self.instance.id

    def tearDown(self):
        self.client.get('/logout')

    def test_delete_instance_requires_post(self):
        res = self.client.get(f'/instance/delete/{self.instance_id}', follow_redirects=False)
        self.assertEqual(res.status_code, 405)

    def test_delete_instance_requires_csrf_token(self):
        res = self.client.post(f'/instance/delete/{self.instance_id}', follow_redirects=False)
        self.assertEqual(res.status_code, 302)
        with app.app_context():
            self.assertIsNotNone(db.session.get(EcsInstance, self.instance_id))

    def test_delete_instance_by_post(self):
        res = self.client.post(
            f'/instance/delete/{self.instance_id}',
            data={'csrf_token': self.csrf_token},
            follow_redirects=False,
        )
        self.assertEqual(res.status_code, 302)
        with app.app_context():
            self.assertIsNone(db.session.get(EcsInstance, self.instance_id))

    def test_schedule_reject_invalid_day(self):
        res = self.client.post(
            f'/instance/{self.instance_id}/schedules',
            data={'action': 'start', 'hour': '10', 'minute': '30', 'days_of_week': '0,8', 'csrf_token': self.csrf_token},
            follow_redirects=False,
        )
        self.assertEqual(res.status_code, 302)
        with app.app_context():
            self.assertEqual(ScheduleTask.query.filter_by(instance_id=self.instance_id).count(), 0)

    def test_response_contains_request_id_header(self):
        res = self.client.get('/dashboard')
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.headers.get('X-Request-ID'))


    def test_batch_action_requires_selection(self):
        res = self.client.post(
            '/batch_action',
            data={'action': 'start', 'csrf_token': self.csrf_token},
            follow_redirects=True,
        )
        self.assertEqual(res.status_code, 200)
        self.assertIn('请先勾选至少一个实例，再执行批量操作', res.get_data(as_text=True))

    @patch('routes.ecs_start', return_value=(True, 'ok'))
    @patch('routes.get_client', return_value=object())
    def test_batch_action_selected_instances_only(self, _mock_client, mock_start):
        with app.app_context():
            selected = db.session.get(EcsInstance, self.instance_id)
            selected.status = 'Stopped'
            selected.tag = 'group-a'
            inst2 = EcsInstance(
                name='inst2',
                access_key_id='ak2',
                access_key_secret='sk2',
                region_id='cn-hangzhou',
                instance_id='i-456',
                is_encrypted=False,
                status='Stopped',
                tag='group-a',
            )
            db.session.add(inst2)
            db.session.commit()
            selected_id = selected.id
            other_id = inst2.id

        res = self.client.post(
            '/batch_action',
            data={
                'action': 'start',
                'tag': 'group-a',
                'instance_ids': [str(selected_id)],
                'csrf_token': self.csrf_token,
            },
            follow_redirects=False,
        )
        self.assertEqual(res.status_code, 302)
        self.assertEqual(mock_start.call_count, 1)
        with app.app_context():
            selected = db.session.get(EcsInstance, selected_id)
            other = db.session.get(EcsInstance, other_id)
            self.assertEqual(selected.status, 'Starting')
            self.assertEqual(other.status, 'Stopped')

    def test_api_404_returns_json_error(self):
        res = self.client.get('/api/not-found')
        self.assertEqual(res.status_code, 404)
        data = res.get_json()
        self.assertFalse(data.get('success', True))
        self.assertTrue(data.get('message'))

    def test_public_ipv6_script_token_valid(self):
        detail = self.client.get(f'/instance/{self.instance_id}')
        self.assertEqual(detail.status_code, 200)
        html = detail.get_data(as_text=True)
        m = re.search(r"/public/instance/(\d+)/ipv6_script\.sh\?token=([^'\"]+)", html)
        self.assertIsNotNone(m)

        script_res = self.client.get(f"/public/instance/{self.instance_id}/ipv6_script.sh?token={m.group(2)}")
        self.assertEqual(script_res.status_code, 200)
        body = script_res.get_data(as_text=True)
        self.assertIn('set -euo pipefail', body)
        self.assertIn('TARGET_IPV6=', body)

    def test_public_ipv6_script_token_invalid_or_expired_forbidden(self):
        # invalid token
        bad = self.client.get(f'/public/instance/{self.instance_id}/ipv6_script.sh?token=bad-token')
        self.assertEqual(bad.status_code, 403)

        # expired token
        old_expire = app.config.get('IPV6_SCRIPT_TOKEN_EXPIRES', 1800)
        app.config['IPV6_SCRIPT_TOKEN_EXPIRES'] = 1
        try:
            detail = self.client.get(f'/instance/{self.instance_id}')
            html = detail.get_data(as_text=True)
            m = re.search(r"/public/instance/(\d+)/ipv6_script\.sh\?token=([^'\"]+)", html)
            self.assertIsNotNone(m)
            token = m.group(2)
            time.sleep(2.2)
            expired = self.client.get(f'/public/instance/{self.instance_id}/ipv6_script.sh?token={token}')
            self.assertEqual(expired.status_code, 403)
        finally:
            app.config['IPV6_SCRIPT_TOKEN_EXPIRES'] = old_expire

    @patch('routes.get_cdt_three_month_billing')
    def test_api_billing_cdt_three_months_success(self, mock_billing):
        mock_billing.return_value = {
            'months': [
                {'month': '2026-01', 'traffic': 12.3, 'traffic_unit': 'GB', 'amount': 3.2},
                {'month': '2026-02', 'traffic': 23.4, 'traffic_unit': 'GB', 'amount': 6.4},
                {'month': '2026-03', 'traffic': 34.5, 'traffic_unit': 'GB', 'amount': 9.6},
            ],
            'total_traffic': 70.2,
            'total_amount': 19.2,
            'currency': 'CNY',
            'scope': 'instance',
            'provider': 'aliyun_billing_query_bill_overview',
        }

        res = self.client.get(f'/api/billing/cdt/three_months?instance_id={self.instance.instance_id}')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data['success'])
        self.assertEqual(data['scope'], 'instance')
        self.assertEqual(len(data['months']), 3)
        self.assertIn('total_traffic', data)
        self.assertIn('total_amount', data)
        self.assertEqual(data['currency'], 'CNY')

    @patch('routes.get_cdt_three_month_billing', side_effect=Exception('RequestLimitExceeded throttling'))
    def test_api_billing_cdt_three_months_rate_limited(self, _mock_billing):
        res = self.client.get(f'/api/billing/cdt/three_months?instance_id={self.instance.instance_id}')
        self.assertEqual(res.status_code, 502)
        data = res.get_json()
        self.assertFalse(data['success'])
        self.assertEqual(data['error_code'], 'API_RATE_LIMITED')

    def test_api_billing_cdt_three_months_instance_not_found(self):
        res = self.client.get('/api/billing/cdt/three_months?instance_id=i-not-exist')
        self.assertEqual(res.status_code, 404)
        data = res.get_json()
        self.assertFalse(data['success'])
        self.assertEqual(data['error_code'], 'INSTANCE_NOT_FOUND')


if __name__ == '__main__':
    unittest.main()
