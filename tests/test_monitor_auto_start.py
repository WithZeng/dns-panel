import os
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

sys.modules.setdefault('fcntl', types.SimpleNamespace(flock=lambda *args, **kwargs: None, LOCK_EX=1, LOCK_NB=2, LOCK_UN=8))

os.environ.setdefault('DNS_PANEL_DISABLE_SCHEDULER', '1')
_test_db_dir = tempfile.mkdtemp(prefix='dns_panel_test_auto_start_')
os.environ.setdefault('DNS_PANEL_DB_PATH', os.path.join(_test_db_dir, 'test.db'))
os.environ.setdefault('SECRET_KEY', 'test_secret_key')

from app import app
from models import db, EcsInstance
from monitor import check_and_manage_instance


class MonitorAutoStartTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config['TESTING'] = True
        with app.app_context():
            db.drop_all()
            db.create_all()

    def setUp(self):
        with app.app_context():
            EcsInstance.query.delete()
            instance = EcsInstance(
                name='hk-ecs',
                access_key_id='ak',
                access_key_secret='sk',
                region_id='cn-hongkong',
                instance_id='i-hk001',
                status='Stopped',
                auto_start_enabled=True,
                auto_stop_enabled=False,
                monitoring_enabled=True,
            )
            db.session.add(instance)
            db.session.commit()
            self.instance_db_id = instance.id

    @patch('monitor.get_total_traffic_gb', return_value=0)
    @patch('monitor.get_client', return_value=object())
    @patch('monitor.ecs_start', return_value=(True, 'ok'))
    @patch('monitor.get_ecs_info')
    def test_auto_start_when_instance_offline(self, mock_get_info, mock_start, _mock_client, _mock_traffic):
        mock_get_info.return_value = {
            'status': 'Stopped',
            'public_ip': '',
            'private_ip': '10.0.0.10',
            'ipv6_addr': '',
        }

        with app.app_context():
            check_and_manage_instance(self.instance_db_id)
            db.session.expire_all()
            instance = db.session.get(EcsInstance, self.instance_db_id)
            self.assertEqual(instance.status, 'Starting')

        mock_start.assert_called_once()

    @patch('monitor.get_total_traffic_gb', return_value=0)
    @patch('monitor.get_client', return_value=object())
    @patch('monitor.ecs_start', return_value=(True, 'ok'))
    @patch('monitor.get_ecs_info')
    def test_auto_start_when_instance_stopping(self, mock_get_info, mock_start, _mock_client, _mock_traffic):
        mock_get_info.return_value = {
            'status': 'Stopping',
            'public_ip': '',
            'private_ip': '10.0.0.10',
            'ipv6_addr': '',
        }

        with app.app_context():
            check_and_manage_instance(self.instance_db_id)

        mock_start.assert_called_once()


    @patch('monitor.get_total_traffic_gb', return_value=0)
    @patch('monitor.get_client', return_value=object())
    @patch('monitor.ecs_start', return_value=(True, 'ok'))
    @patch('monitor.get_ecs_info')
    def test_check_forces_start_even_when_auto_start_disabled(self, mock_get_info, mock_start, _mock_client, _mock_traffic):
        mock_get_info.return_value = {
            'status': 'Stopped',
            'public_ip': '',
            'private_ip': '10.0.0.10',
            'ipv6_addr': '',
        }

        with app.app_context():
            instance = db.session.get(EcsInstance, self.instance_db_id)
            instance.auto_start_enabled = False
            db.session.commit()

            check_and_manage_instance(self.instance_db_id)
            db.session.expire_all()
            instance = db.session.get(EcsInstance, self.instance_db_id)
            self.assertEqual(instance.status, 'Starting')

        mock_start.assert_called_once()

    @patch('monitor.get_total_traffic_gb', return_value=0)
    @patch('monitor.get_client', return_value=object())
    @patch('monitor.ecs_start', return_value=(True, 'ok'))
    @patch('monitor.get_ecs_info')
    @patch('monitor._is_probe_online', return_value=True)
    def test_check_forces_start_even_when_probe_online(self, _mock_probe, mock_get_info, mock_start, _mock_client, _mock_traffic):
        mock_get_info.return_value = {
            'status': 'Stopped',
            'public_ip': '',
            'private_ip': '10.0.0.10',
            'ipv6_addr': '',
        }

        with app.app_context():
            check_and_manage_instance(self.instance_db_id)

        mock_start.assert_called_once()


if __name__ == '__main__':
    unittest.main()
