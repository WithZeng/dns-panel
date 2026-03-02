import os
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault('DNS_PANEL_DISABLE_SCHEDULER', '1')
_test_db_dir = tempfile.mkdtemp(prefix='dns_panel_test_import_text_')
os.environ.setdefault('DNS_PANEL_DB_PATH', os.path.join(_test_db_dir, 'test.db'))
os.environ.setdefault('SECRET_KEY', 'test_secret_key')

from werkzeug.security import generate_password_hash
from app import app
from models import db, User, EcsInstance


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


class AccountImportTextTests(unittest.TestCase):
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
            EcsInstance.query.delete()
            db.session.commit()

    def tearDown(self):
        self.client.get('/logout')

    @patch('routes._sync_account_to_github', return_value=(True, 'WithZeng/aliyun-accounts/accounts/demo/account.yaml'))
    @patch('routes._discover_ecs_instances_all_regions')
    def test_import_text_create_and_update(self, mock_discover, mock_sync):
        mock_discover.return_value = [
            {
                'instance_id': 'i-aaa',
                'name': 'ecs-a',
                'region_id': 'cn-hangzhou',
                'status': 'Running',
                'public_ip': '1.1.1.1',
                'private_ip': '10.0.0.1',
                'ipv6_addr': '2408::1',
            }
        ]

        payload = '登录名称: demo\nAccessKey ID: LTAI1234567890ABCDEF\nAccessKey Secret: abcdefghijklmnopqrstuvwx123456\n备注: 测试账号'
        resp = self.client.post('/account/import_text', data={'account_text': payload, 'csrf_token': self.csrf_token}, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)

        with app.app_context():
            inst = EcsInstance.query.filter_by(instance_id='i-aaa').first()
            self.assertIsNotNone(inst)
            self.assertTrue(inst.monitoring_enabled)
            self.assertTrue(inst.auto_start_enabled)
            self.assertFalse(inst.auto_stop_enabled)
            self.assertEqual(inst.traffic_strategy, 'life')
            self.assertEqual(inst.life_total_limit, 500)

        # duplicate import should update, not append
        mock_discover.return_value = [
            {
                'instance_id': 'i-aaa',
                'name': 'ecs-a-2',
                'region_id': 'cn-hangzhou',
                'status': 'Stopped',
                'public_ip': '2.2.2.2',
                'private_ip': '10.0.0.2',
                'ipv6_addr': '',
            }
        ]
        resp2 = self.client.post('/account/import_text', data={'account_text': payload, 'csrf_token': self.csrf_token}, follow_redirects=True)
        self.assertEqual(resp2.status_code, 200)

        with app.app_context():
            all_rows = EcsInstance.query.filter_by(instance_id='i-aaa').all()
            self.assertEqual(len(all_rows), 1)
            inst = all_rows[0]
            self.assertEqual(inst.name, 'ecs-a-2')
            self.assertEqual(inst.public_ip, '2.2.2.2')
            self.assertEqual(inst.status, 'Stopped')

        self.assertTrue(mock_sync.called)


if __name__ == '__main__':
    unittest.main()
