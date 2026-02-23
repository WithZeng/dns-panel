import os
import sys
import tempfile
import unittest
from types import ModuleType
from unittest.mock import patch

os.environ.setdefault('DNS_PANEL_DISABLE_SCHEDULER', '1')
_test_db_dir = tempfile.mkdtemp(prefix='dns_panel_test_')
os.environ.setdefault('DNS_PANEL_DB_PATH', os.path.join(_test_db_dir, 'test.db'))
os.environ.setdefault('SECRET_KEY', 'test_secret_key')
os.environ.setdefault('PUBLIC_PANEL_URL', 'https://panel.example.com')

monitor_stub = ModuleType('monitor')
monitor_stub.check_all_instances = lambda: None
monitor_stub.get_client = lambda inst=None: None
monitor_stub.ecs_start = lambda client=None, instance_id=None: None
monitor_stub.ecs_stop = lambda client=None, instance_id=None: None
monitor_stub.check_and_manage_instance = lambda instance_id=None: None
monitor_stub.ecs_release = lambda client=None, instance_id=None: None
monitor_stub.get_region_traffic = lambda *args, **kwargs: {}
monitor_stub.get_security_groups = lambda *args, **kwargs: []
monitor_stub.describe_sg_rules = lambda *args, **kwargs: []
monitor_stub.authorize_sg = lambda *args, **kwargs: (True, 'ok')
monitor_stub.revoke_sg = lambda *args, **kwargs: (True, 'ok')
monitor_stub.ecs_enable_ipv6 = lambda *args, **kwargs: (True, 'ok')
monitor_stub.get_ecs_ipv6_info = lambda *args, **kwargs: {}
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
from models import db, User


class DnsFailoverApiTests(unittest.TestCase):
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
        self.client.post('/login', data={'username': 'tester', 'password': 'pass123456'})

    def tearDown(self):
        self.client.get('/logout')

    @patch('probe_routes._ping_from_panel')
    def test_manual_test_panel_mode(self, mock_ping):
        mock_ping.return_value = {
            'ok': True,
            'reachable': True,
            'avg_ms': 12.3,
            'message': 'reachable',
            'command': 'ping -n -c 4 1.1.1.1',
            'output': 'ok',
            'exit_code': 0,
            'source': 'panel_local',
        }
        res = self.client.post('/api/dns/failover/manual-test', json={
            'host': '1.1.1.1',
            'mode': 'panel_local',
            'packet_count': 4,
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data['success'])
        self.assertEqual(data['source'], 'panel_local')
        self.assertTrue(data['reachable'])

    @patch('probe_routes._ping_via_checker')
    def test_manual_test_checker_mode(self, mock_checker):
        mock_checker.return_value = {
            'ok': True,
            'reachable': False,
            'avg_ms': None,
            'message': 'unreachable',
            'command': "curl -s 'http://1.2.3.4:8888/ping?host=1.1.1.1'",
            'output': '{"reachable": false}',
            'exit_code': 0,
            'source': 'checker',
        }
        res = self.client.post('/api/dns/failover/manual-test', json={
            'host': '1.1.1.1',
            'mode': 'checker',
            'tester_ip': '1.2.3.4',
            'packet_count': 2,
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data['success'])
        self.assertEqual(data['source'], 'checker')
        self.assertFalse(data['reachable'])

    def test_checker_deploy_uses_public_panel_url(self):
        res = self.client.get('/dns/failover/checker-deploy')
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)
        self.assertIn('https://panel.example.com/agent/install_checker_cn.sh', html)


if __name__ == '__main__':
    unittest.main()


