from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import json
import secrets
from crypto_utils import encrypt, decrypt

db = SQLAlchemy()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    # Login lockout
    failed_login_count = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    force_password_change = db.Column(db.Boolean, default=False)
    # Customizable dashboard widget order (JSON list)
    dashboard_layout = db.Column(db.Text, default='')


class EcsInstance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    access_key_id = db.Column(db.String(500), nullable=False)
    access_key_secret = db.Column(db.String(500), nullable=False)
    region_id = db.Column(db.String(50), nullable=False)
    instance_id = db.Column(db.String(50), nullable=False)

    # 1. Traffic Strategy
    traffic_strategy = db.Column(db.String(50), default='cycle', nullable=False)

    # 2. Limits & Pricing (Float)
    monthly_limit = db.Column(db.Float, default=0.0)
    life_total_limit = db.Column(db.Float, default=0.0)
    hourly_price = db.Column(db.Float, default=0.0)
    monthly_free_allowance = db.Column(db.Float, default=200.0)

    # 3. Counters (Float - Incremental)
    total_traffic_sum = db.Column(db.Float, default=0.0)
    current_month_traffic = db.Column(db.Float, default=0.0)
    last_api_traffic = db.Column(db.Float, default=0.0)

    # 4. Alert
    alert_threshold_pct = db.Column(db.Integer, default=80)

    # 5. Tag / Group
    tag = db.Column(db.String(100), default='')

    # 6. Notes (free-text memo)
    notes = db.Column(db.Text, default='')

    # 7. Meta
    status = db.Column(db.String(50), default='Unknown')
    auto_stop_enabled = db.Column(db.Boolean, default=False)
    auto_start_enabled = db.Column(db.Boolean, default=False)
    monitoring_enabled = db.Column(db.Boolean, default=True)
    is_encrypted = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    real_creation_time = db.Column(db.DateTime, nullable=True)
    last_checked = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    traffic_logs = db.relationship('TrafficLog', backref='instance', lazy='dynamic',
                                   cascade='all, delete-orphan')
    operation_logs = db.relationship('OperationLog', backref='instance', lazy='dynamic',
                                     cascade='all, delete-orphan')

    # --- AK/SK encryption helpers ---
    @property
    def decrypted_ak(self):
        if self.is_encrypted:
            return decrypt(self.access_key_id)
        return self.access_key_id

    @property
    def decrypted_sk(self):
        if self.is_encrypted:
            return decrypt(self.access_key_secret)
        return self.access_key_secret

    def set_ak_sk(self, ak, sk):
        """Encrypt and store AK/SK."""
        self.access_key_id = encrypt(ak)
        self.access_key_secret = encrypt(sk)
        self.is_encrypted = True


class TrafficLog(db.Model):
    """Records traffic readings over time for charting."""
    id = db.Column(db.Integer, primary_key=True)
    instance_id = db.Column(db.Integer, db.ForeignKey('ecs_instance.id'), nullable=False)
    traffic_gb = db.Column(db.Float, default=0.0)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class OperationLog(db.Model):
    """Records user/system actions for audit trail."""
    id = db.Column(db.Integer, primary_key=True)
    instance_id = db.Column(db.Integer, db.ForeignKey('ecs_instance.id'), nullable=True)
    action = db.Column(db.String(50), nullable=False)
    detail = db.Column(db.String(500), default='')
    operator = db.Column(db.String(100), default='system')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class AlertConfig(db.Model):
    """Global webhook notification settings."""
    id = db.Column(db.Integer, primary_key=True)
    notify_type = db.Column(db.String(50), default='wechat')  # wechat, dingtalk, telegram
    webhook_url = db.Column(db.String(500), default='')
    enabled = db.Column(db.Boolean, default=False)


class NotificationLog(db.Model):
    """Records every notification attempt for history/audit."""
    id = db.Column(db.Integer, primary_key=True)
    instance_name = db.Column(db.String(150), default='')
    notify_type = db.Column(db.String(50), nullable=False)
    message = db.Column(db.Text, nullable=False)
    success = db.Column(db.Boolean, default=True)
    error_message = db.Column(db.String(500), default='')
    attempts = db.Column(db.Integer, default=1)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class ScheduleTask(db.Model):
    """Scheduled start/stop tasks for instances."""
    id = db.Column(db.Integer, primary_key=True)
    instance_id = db.Column(db.Integer, db.ForeignKey('ecs_instance.id'), nullable=False)
    action = db.Column(db.String(20), nullable=False)  # 'start' or 'stop'
    hour = db.Column(db.Integer, nullable=False)        # 0-23
    minute = db.Column(db.Integer, nullable=False)      # 0-59
    days_of_week = db.Column(db.String(50), default='*')  # '*' = daily, '1,3,5' = Mon/Wed/Fri
    enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    instance = db.relationship('EcsInstance', backref=db.backref('schedules', lazy='dynamic'))


class ProbeServer(db.Model):
    __tablename__ = 'probe_server'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    token = db.Column(db.String(255), unique=True, nullable=False, default=lambda: secrets.token_urlsafe(32))
    server_type = db.Column(db.String(20), default='generic', nullable=False)  # 'aliyun' / 'generic'

    ipv4 = db.Column(db.String(64), default='')
    ipv6 = db.Column(db.String(128), default='')
    cpu_name = db.Column(db.String(255), default='')
    cpu_cores = db.Column(db.Integer, default=0)
    arch = db.Column(db.String(64), default='')
    os_info = db.Column(db.String(255), default='')
    virtualization = db.Column(db.String(128), default='')

    mem_total = db.Column(db.BigInteger, default=0)
    swap_total = db.Column(db.BigInteger, default=0)
    disk_total = db.Column(db.BigInteger, default=0)

    is_online = db.Column(db.Boolean, default=False)
    last_seen = db.Column(db.DateTime, nullable=True)
    latest_report_json = db.Column(db.Text, default='')
    report_updated_at = db.Column(db.DateTime, nullable=True)

    ecs_instance_id = db.Column(db.Integer, db.ForeignKey('ecs_instance.id'), nullable=True)
    notes = db.Column(db.Text, default='')
    tag = db.Column(db.String(100), default='')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    ecs_instance = db.relationship('EcsInstance', backref=db.backref('probe_servers', lazy='dynamic'))

    def set_latest_report(self, payload: dict):
        if not isinstance(payload, dict):
            return
        try:
            self.latest_report_json = json.dumps(payload, ensure_ascii=False)
            self.report_updated_at = datetime.utcnow()
        except Exception:
            pass

    def get_latest_report(self):
        if not self.latest_report_json:
            return {}
        try:
            val = json.loads(self.latest_report_json)
            return val if isinstance(val, dict) else {}
        except Exception:
            return {}


class CloudflareConfig(db.Model):
    __tablename__ = 'cloudflare_config'

    id = db.Column(db.Integer, primary_key=True)
    api_token = db.Column(db.String(800), default='')
    zone_id = db.Column(db.String(100), default='')
    domain = db.Column(db.String(255), default='')
    tester_ip = db.Column(db.String(100), default='')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @property
    def decrypted_api_token(self):
        if not self.api_token:
            return ''
        return decrypt(self.api_token)

    def set_api_token(self, token: str):
        self.api_token = encrypt(token or '')


class DnsFailover(db.Model):
    __tablename__ = 'dns_failover'

    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), nullable=False)

    primary_server_id = db.Column(db.Integer, db.ForeignKey('probe_server.id'), nullable=False)
    backup_server_ids = db.Column(db.Text, default='[]')  # JSON list of ProbeServer IDs by priority

    check_port = db.Column(db.Integer, nullable=False, default=80)
    check_interval_minutes = db.Column(db.Integer, default=10)

    current_active_server_id = db.Column(db.Integer, db.ForeignKey('probe_server.id'), nullable=True)
    enabled = db.Column(db.Boolean, default=True)

    last_check_time = db.Column(db.DateTime, nullable=True)
    last_switch_time = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    primary_server = db.relationship('ProbeServer', foreign_keys=[primary_server_id], lazy='joined')
    current_active_server = db.relationship('ProbeServer', foreign_keys=[current_active_server_id], lazy='joined')

    @property
    def backup_ids(self):
        try:
            data = json.loads(self.backup_server_ids or '[]')
            return [int(x) for x in data if str(x).isdigit()]
        except Exception:
            return []

    def set_backup_ids(self, ids):
        cleaned = [int(x) for x in ids if str(x).isdigit()]
        self.backup_server_ids = json.dumps(cleaned)


class DnsFailoverLog(db.Model):
    __tablename__ = 'dns_failover_log'

    id = db.Column(db.Integer, primary_key=True)
    failover_id = db.Column(db.Integer, db.ForeignKey('dns_failover.id'), nullable=True)
    action = db.Column(db.String(50), default='check')  # check/switch/manual_switch/emergency
    message = db.Column(db.Text, default='')
    from_server_id = db.Column(db.Integer, db.ForeignKey('probe_server.id'), nullable=True)
    to_server_id = db.Column(db.Integer, db.ForeignKey('probe_server.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    failover = db.relationship('DnsFailover', backref=db.backref('logs', lazy='dynamic', cascade='all, delete-orphan'))
