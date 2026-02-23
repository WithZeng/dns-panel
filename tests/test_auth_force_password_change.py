import os
import sys
import tempfile
import unittest
from types import ModuleType

os.environ.setdefault('DNS_PANEL_DISABLE_SCHEDULER', '1')
_test_db_dir = tempfile.mkdtemp(prefix='dns_panel_test_auth_')
os.environ.setdefault('DNS_PANEL_DB_PATH', os.path.join(_test_db_dir, 'test.db'))
os.environ.setdefault('SECRET_KEY', 'test_secret_key')

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


class AuthForcePasswordChangeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config['TESTING'] = True
        cls.client = app.test_client()
        with app.app_context():
            db.drop_all()
            db.create_all()
            user = User(
                username='first_user',
                password_hash=generate_password_hash('oldpass123'),
                force_password_change=True,
            )
            db.session.add(user)
            db.session.commit()

    def setUp(self):
        with app.app_context():
            user = User.query.filter_by(username='first_user').first()
            user.password_hash = generate_password_hash('oldpass123')
            user.force_password_change = True
            db.session.commit()

    def test_login_redirects_to_change_password_when_forced(self):
        res = self.client.post('/login', data={'username': 'first_user', 'password': 'oldpass123'}, follow_redirects=False)
        self.assertEqual(res.status_code, 302)
        self.assertIn('/change_password', res.headers.get('Location', ''))

    def test_change_password_clears_force_flag(self):
        self.client.post('/login', data={'username': 'first_user', 'password': 'oldpass123'}, follow_redirects=True)
        res = self.client.post('/change_password', data={
            'old_password': 'oldpass123',
            'new_password': 'newpass123',
            'confirm_password': 'newpass123',
        }, follow_redirects=False)
        self.assertEqual(res.status_code, 302)

        with app.app_context():
            user = User.query.filter_by(username='first_user').first()
            self.assertFalse(user.force_password_change)


if __name__ == '__main__':
    unittest.main()


