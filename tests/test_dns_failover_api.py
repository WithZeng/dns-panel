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
os.environ['PUBLIC_PANEL_URL'] = 'https://panel.example.com'

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
from models import db, User, ProbeServer, DnsFailover


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
        token = _extract_csrf_token(self.client)
        self.client.post('/login', data={'username': 'tester', 'password': 'pass123456', 'csrf_token': token})
        self.csrf_token = _extract_csrf_token(self.client)

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
        }, headers={'X-CSRFToken': self.csrf_token})
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
        }, headers={'X-CSRFToken': self.csrf_token})
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

    def test_csrf_missing_for_api_post_returns_400(self):
        res = self.client.post('/api/dns/failover/manual-test', json={'host': '1.1.1.1'})
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertFalse(data.get('success', True))
        self.assertIn('CSRF', data.get('message', ''))

    def test_csrf_wrong_token_for_api_post_returns_400(self):
        res = self.client.post(
            '/api/dns/failover/manual-test',
            json={'host': '1.1.1.1'},
            headers={'X-CSRFToken': 'bad-token'},
        )
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertFalse(data.get('success', True))

    def test_csrf_missing_for_toggle_rule_returns_302(self):
        with app.app_context():
            srv = ProbeServer(name='p1', token='tok1', server_type='generic')
            db.session.add(srv)
            db.session.flush()
            rule = DnsFailover(domain='a.example.com', primary_server_id=srv.id, current_active_server_id=srv.id)
            db.session.add(rule)
            db.session.commit()
            rule_id = rule.id

        res = self.client.post(f'/dns/failover/rule/{rule_id}/toggle')
        self.assertEqual(res.status_code, 302)

    def test_csrf_missing_for_reset_probe_token_returns_400(self):
        with app.app_context():
            srv = ProbeServer(name='p2', token='tok2', server_type='generic')
            db.session.add(srv)
            db.session.commit()
            sid = srv.id

        res = self.client.post(f'/api/probe/servers/{sid}/reset-token')
        self.assertEqual(res.status_code, 400)

    def test_csrf_missing_for_edit_dns_rule_returns_302(self):
        with app.app_context():
            s1 = ProbeServer(name='p3', token='tok3', server_type='generic')
            s2 = ProbeServer(name='p4', token='tok4', server_type='generic')
            db.session.add_all([s1, s2])
            db.session.flush()
            rule = DnsFailover(domain='b.example.com', primary_server_id=s1.id, current_active_server_id=s1.id)
            db.session.add(rule)
            db.session.commit()
            rule_id = rule.id

        res = self.client.post(
            f'/dns/failover/rule/{rule_id}/edit',
            data={'domain': 'c.example.com', 'primary_server_id': str(1), 'backup_server_ids': []},
        )
        self.assertEqual(res.status_code, 302)

    def test_csrf_missing_for_delete_probe_server_returns_400(self):
        with app.app_context():
            srv = ProbeServer(name='p5', token='tok5', server_type='generic')
            db.session.add(srv)
            db.session.commit()
            sid = srv.id

        res = self.client.delete(f'/api/probe/servers/{sid}')
        self.assertEqual(res.status_code, 400)

    def test_csrf_wrong_token_for_reset_probe_token_returns_400(self):
        with app.app_context():
            srv = ProbeServer(name='p6', token='tok6', server_type='generic')
            db.session.add(srv)
            db.session.commit()
            sid = srv.id

        res = self.client.post(
            f'/api/probe/servers/{sid}/reset-token',
            headers={'X-CSRFToken': 'bad-token'},
        )
        self.assertEqual(res.status_code, 400)

    def test_csrf_wrong_token_for_toggle_rule_returns_302(self):
        with app.app_context():
            srv = ProbeServer(name='p7', token='tok7', server_type='generic')
            db.session.add(srv)
            db.session.flush()
            rule = DnsFailover(domain='d.example.com', primary_server_id=srv.id, current_active_server_id=srv.id)
            db.session.add(rule)
            db.session.commit()
            rule_id = rule.id

        res = self.client.post(
            f'/dns/failover/rule/{rule_id}/toggle',
            headers={'X-CSRFToken': 'bad-token'},
        )
        self.assertEqual(res.status_code, 302)

    def test_csrf_wrong_token_for_edit_rule_returns_302(self):
        with app.app_context():
            s1 = ProbeServer(name='p8', token='tok8', server_type='generic')
            db.session.add(s1)
            db.session.flush()
            rule = DnsFailover(domain='e.example.com', primary_server_id=s1.id, current_active_server_id=s1.id)
            db.session.add(rule)
            db.session.commit()
            rule_id = rule.id

        res = self.client.post(
            f'/dns/failover/rule/{rule_id}/edit',
            data={'domain': 'f.example.com'},
            headers={'X-CSRFToken': 'bad-token'},
        )
        self.assertEqual(res.status_code, 302)

    def test_csrf_wrong_token_for_delete_probe_server_returns_400(self):
        with app.app_context():
            srv = ProbeServer(name='p9', token='tok9', server_type='generic')
            db.session.add(srv)
            db.session.commit()
            sid = srv.id

        res = self.client.delete(
            f'/api/probe/servers/{sid}',
            headers={'X-CSRFToken': 'bad-token'},
        )
        self.assertEqual(res.status_code, 400)


if __name__ == '__main__':
    unittest.main()


