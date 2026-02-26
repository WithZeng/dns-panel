import os
import shutil
import secrets
from datetime import timedelta, datetime
from flask import Flask
from flask_login import LoginManager
from flask_apscheduler import APScheduler
from werkzeug.security import generate_password_hash
from models import (
    db,
    User,
    EcsInstance,
    AlertConfig,
    TrafficLog,
    NotificationLog,
    ScheduleTask,
    DnsFailover,
    CloudflareConfig,
)
from monitor import check_all_instances, get_client, ecs_start, ecs_stop
from crypto_utils import encrypt
from notifier import send_alert
from probe_routes import init_probe, refresh_probe_online_statuses, evaluate_failover_rule

# 1. Dynamic path configuration
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_PATH = os.path.join(BASE_DIR, 'instance')
DB_PATH = os.environ.get('DNS_PANEL_DB_PATH', '').strip() or os.path.join(INSTANCE_PATH, 'ecs_monitor.db')
BACKUP_DIR = os.path.join(INSTANCE_PATH, 'backups')
DISABLE_SCHEDULER = os.environ.get('DNS_PANEL_DISABLE_SCHEDULER', '').strip().lower() in ('1', 'true', 'yes', 'on')

if not os.path.exists(INSTANCE_PATH):
    os.makedirs(INSTANCE_PATH)
if not os.path.exists(BACKUP_DIR):
    os.makedirs(BACKUP_DIR)


def _load_env():
    """Load .env file if present (simple parser, no external deps required)."""
    env_path = os.path.join(BASE_DIR, '.env')
    if os.path.isfile(env_path):
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                k, v = line.split('=', 1)
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                os.environ.setdefault(k, v)


_load_env()


def _get_secret_key():
    """Read SECRET_KEY from env or generate and persist one."""
    key = os.environ.get('SECRET_KEY')
    if key:
        return key
    key = secrets.token_hex(32)
    env_path = os.path.join(BASE_DIR, '.env')
    # If .env is accidentally a directory (Docker bind-mount quirk), remove it
    if os.path.exists(env_path) and not os.path.isfile(env_path):
        import shutil
        shutil.rmtree(env_path, ignore_errors=True)
    mode = 'a' if os.path.isfile(env_path) else 'w'
    with open(env_path, mode) as f:
        f.write(f"\nSECRET_KEY={key}\n")
    return key


# 2. Initialize Flask app
app = Flask(__name__, instance_path=INSTANCE_PATH)
app.config['SECRET_KEY'] = _get_secret_key()
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{DB_PATH}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SCHEDULER_API_ENABLED'] = True

# Session timeout: 30 minutes
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Data retention: keep logs for N days
DATA_RETENTION_DAYS = 90
PORT_CHECKER_TESTER_IP = os.environ.get('PORT_CHECKER_TESTER_IP', '').strip()

print(f"Database Path: {DB_PATH}")

db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = 'main.login'
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.before_request
def make_session_permanent():
    """Ensure session uses PERMANENT_SESSION_LIFETIME for timeout."""
    from flask import session
    session.permanent = True


def bootstrap_database():
    """Auto-repair database on startup."""
    with app.app_context():
        db.create_all()

        # Migrate: add missing columns to existing tables
        import sqlite3
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        try:
            # Check ecs_instance columns
            cursor.execute("PRAGMA table_info(ecs_instance)")
            existing_cols = {row[1] for row in cursor.fetchall()}

            if 'notes' not in existing_cols:
                cursor.execute("ALTER TABLE ecs_instance ADD COLUMN notes TEXT DEFAULT ''")
                print("Migration: added 'notes' column to ecs_instance.")

            if 'auto_start_enabled' not in existing_cols:
                cursor.execute("ALTER TABLE ecs_instance ADD COLUMN auto_start_enabled BOOLEAN DEFAULT 0")
                print("Migration: added 'auto_start_enabled' column to ecs_instance.")

            # Check user columns
            cursor.execute("PRAGMA table_info(user)")
            user_cols = {row[1] for row in cursor.fetchall()}
            if 'dashboard_layout' not in user_cols:
                cursor.execute("ALTER TABLE user ADD COLUMN dashboard_layout TEXT DEFAULT ''")
                print("Migration: added 'dashboard_layout' column to user.")
            if 'force_password_change' not in user_cols:
                cursor.execute("ALTER TABLE user ADD COLUMN force_password_change BOOLEAN DEFAULT 0")
                print("Migration: added 'force_password_change' column to user.")

            # Check cloudflare_config columns
            cursor.execute("PRAGMA table_info(cloudflare_config)")
            cf_cols = {row[1] for row in cursor.fetchall()}
            if 'tester_ip' not in cf_cols:
                cursor.execute("ALTER TABLE cloudflare_config ADD COLUMN tester_ip TEXT DEFAULT ''")
                print("Migration: added 'tester_ip' column to cloudflare_config.")

            # Check probe_server columns
            cursor.execute("PRAGMA table_info(probe_server)")
            probe_cols = {row[1] for row in cursor.fetchall()}
            if 'latest_report_json' not in probe_cols:
                cursor.execute("ALTER TABLE probe_server ADD COLUMN latest_report_json TEXT DEFAULT ''")
                print("Migration: added 'latest_report_json' column to probe_server.")
            if 'report_updated_at' not in probe_cols:
                cursor.execute("ALTER TABLE probe_server ADD COLUMN report_updated_at DATETIME")
                print("Migration: added 'report_updated_at' column to probe_server.")

            conn.commit()
        except Exception as e:
            print(f"Column migration note: {e}")
        finally:
            conn.close()

        # Default admin
        user_count = User.query.count()
        if user_count == 0:
            initial_password = secrets.token_urlsafe(12)
            admin = User(
                username='admin',
                password_hash=generate_password_hash(initial_password),
                force_password_change=True,
            )
            db.session.add(admin)
            db.session.commit()
            cred_path = os.path.join(INSTANCE_PATH, 'initial_admin_credentials.txt')
            with open(cred_path, 'w', encoding='utf-8') as f:
                f.write("DNS Panel 鍒濆绠＄悊鍛樿处鍙穃n")
                f.write("username=admin\n")
                f.write(f"password={initial_password}\n")
                f.write("璇风櫥褰曞悗绔嬪嵆淇敼瀵嗙爜銆俓n")
            print("Default admin created. Please check instance/initial_admin_credentials.txt")

        # Migrate: encrypt plaintext AK/SK
        try:
            instances = EcsInstance.query.filter_by(is_encrypted=False).all()
            for inst in instances:
                if inst.access_key_id and not inst.is_encrypted:
                    inst.access_key_id = encrypt(inst.access_key_id)
                    inst.access_key_secret = encrypt(inst.access_key_secret)
                    inst.is_encrypted = True
            if instances:
                db.session.commit()
                print(f"Migrated {len(instances)} instances to encrypted AK/SK.")
        except Exception as e:
            print(f"AK/SK migration note: {e}")
            db.session.rollback()


# 3. Run DB bootstrap
bootstrap_database()

# 4. Initialize Scheduler
scheduler = APScheduler()
scheduler.init_app(app)
if not DISABLE_SCHEDULER:
    scheduler.start()
else:
    print("Scheduler disabled by DNS_PANEL_DISABLE_SCHEDULER.")


@scheduler.task('interval', id='check_all_instances', minutes=5)
def scheduled_check():
    with app.app_context():
        check_all_instances()


@scheduler.task('interval', id='probe_online_refresh', minutes=1)
def probe_online_refresh():
    with app.app_context():
        refresh_probe_online_statuses()


@scheduler.task('cron', id='monthly_traffic_reset', month='*', day=1, hour=0, minute=0)
def monthly_traffic_reset():
    """Reset current_month_traffic on the 1st of every month."""
    with app.app_context():
        instances = EcsInstance.query.all()
        for inst in instances:
            inst.current_month_traffic = 0.0
        db.session.commit()
        print(f"Monthly traffic reset for {len(instances)} instances.")


@scheduler.task('cron', id='daily_report', hour=9, minute=0)
def daily_report():
    """Send daily traffic summary via webhook at 9:00 AM."""
    with app.app_context():
        try:
            alert_cfg = AlertConfig.query.first()
            if not alert_cfg or not alert_cfg.enabled or not alert_cfg.webhook_url:
                return

            instances = EcsInstance.query.all()
            if not instances:
                return

            total = len(instances)
            online = sum(1 for i in instances if i.status in ('Running', 'Starting'))
            total_traffic = sum(i.current_month_traffic or 0 for i in instances)

            lines = [f"每日流量报告 ({datetime.now().strftime('%Y-%m-%d')})"]
            lines.append(f"实例总数: {total} | 在线: {online}")
            lines.append(f"本月总流量: {total_traffic:.2f} GB")
            lines.append("-" * 20)

            for inst in instances:
                if inst.traffic_strategy == 'life':
                    limit = inst.life_total_limit or 0
                    used = inst.total_traffic_sum or 0
                else:
                    limit = inst.monthly_limit or 0
                    used = inst.current_month_traffic or 0
                pct = (used / limit * 100) if limit > 0 else 0
                status_emoji = "🟢" if inst.status in ('Running', 'Starting') else "🔴"
                lines.append(f"{status_emoji} {inst.name}: {used:.2f}/{limit:.0f} GB ({pct:.0f}%)")

            send_alert(alert_cfg.notify_type, alert_cfg.webhook_url, "\n".join(lines),
                       instance_name='daily_report')
        except Exception as e:
            print(f"Daily report error: {e}")


@scheduler.task('cron', id='data_retention_cleanup', hour=3, minute=0)
def data_retention_cleanup():
    """Delete TrafficLog and NotificationLog entries older than DATA_RETENTION_DAYS."""
    with app.app_context():
        cutoff = datetime.utcnow() - timedelta(days=DATA_RETENTION_DAYS)
        try:
            deleted_traffic = TrafficLog.query.filter(TrafficLog.timestamp < cutoff).delete()
            deleted_notif = NotificationLog.query.filter(NotificationLog.timestamp < cutoff).delete()
            db.session.commit()
            print(f"Data retention cleanup: removed {deleted_traffic} traffic logs, "
                  f"{deleted_notif} notification logs older than {DATA_RETENTION_DAYS} days.")
        except Exception as e:
            print(f"Data retention cleanup error: {e}")
            db.session.rollback()


@scheduler.task('cron', id='auto_backup_db', hour=2, minute=0)
def auto_backup_db():
    """Auto-backup SQLite database daily at 2:00 AM. Keeps last 7 backups."""
    with app.app_context():
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_file = os.path.join(BACKUP_DIR, f"ecs_monitor_{timestamp}.db")
            shutil.copy2(DB_PATH, backup_file)
            print(f"Database backed up to {backup_file}")

            # Keep only the latest 7 backups
            backups = sorted(
                [f for f in os.listdir(BACKUP_DIR) if f.endswith('.db')],
                reverse=True
            )
            for old_backup in backups[7:]:
                os.remove(os.path.join(BACKUP_DIR, old_backup))
                print(f"Removed old backup: {old_backup}")
        except Exception as e:
            print(f"Auto backup error: {e}")


@scheduler.task('cron', id='run_scheduled_tasks', minute='*')
def run_scheduled_tasks():
    """Every minute, check ScheduleTask table and execute matching tasks."""
    with app.app_context():
        now = datetime.now()
        current_hour = now.hour
        current_minute = now.minute
        current_dow = now.isoweekday()  # 1=Mon, 7=Sun

        tasks = ScheduleTask.query.filter_by(
            enabled=True, hour=current_hour, minute=current_minute
        ).all()

        for task in tasks:
            # Check day-of-week
            if task.days_of_week != '*':
                allowed_days = [int(d.strip()) for d in task.days_of_week.split(',') if d.strip().isdigit()]
                if current_dow not in allowed_days:
                    continue

            inst = EcsInstance.query.get(task.instance_id)
            if not inst:
                continue

            try:
                client = get_client(inst)
                action_name = ''
                if task.action == 'start' and inst.status == 'Stopped':
                    ecs_start(client, inst.instance_id)
                    inst.status = 'Starting'
                    action_name = '瀹氭椂鍚姩'
                elif task.action == 'stop' and inst.status == 'Running':
                    ecs_stop(client, inst.instance_id)
                    inst.status = 'Stopping'
                    action_name = '瀹氭椂鍋滄'
                else:
                    continue

                from routes import log_operation
                log_operation(task.action, f'{action_name} {inst.name}', inst.id)
                db.session.commit()
                print(f"Schedule executed: {action_name} {inst.name}")
            except Exception as e:
                print(f"Schedule error for {inst.name}: {e}")


@scheduler.task('interval', id='dns_failover_check', minutes=10)
def dns_failover_check():
    """Run DNS failover checks every 10 minutes."""
    with app.app_context():
        try:
            refresh_probe_online_statuses()
            alert_cfg = AlertConfig.query.first()
            cf_cfg = CloudflareConfig.query.first()
            tester_ip = (cf_cfg.tester_ip if cf_cfg and cf_cfg.tester_ip else PORT_CHECKER_TESTER_IP)
            rules = DnsFailover.query.filter_by(enabled=True).all()
            now = datetime.utcnow()

            for rule in rules:
                if rule.last_check_time:
                    delta = (now - rule.last_check_time).total_seconds()
                    min_interval = max(int(rule.check_interval_minutes or 10), 1) * 60
                    if delta < min_interval:
                        continue

                try:
                    evaluate_failover_rule(
                        failover=rule,
                        tester_ip=tester_ip,
                        send_alert_func=send_alert,
                        alert_cfg=alert_cfg,
                    )
                    db.session.commit()
                except Exception as e:
                    print(f"DNS failover check error for {rule.domain}: {e}")
                    db.session.rollback()
        except Exception as e:
            print(f"dns_failover_check scheduler error: {e}")


# 5. CLI commands
@app.cli.command("init-db")
def init_db_command():
    """Create all database tables."""
    with app.app_context():
        db.create_all()
    print("Initialized the database.")


@app.cli.command("create-user")
def create_user_command():
    """Create a new user."""
    import click
    username = click.prompt("Username")
    password = click.prompt("Password", hide_input=True)
    with app.app_context():
        if User.query.filter_by(username=username).first():
            print("User already exists.")
            return
        new_user = User(username=username, password_hash=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()
        print(f"User {username} created successfully.")


# 6. Register blueprints
from routes import main as main_blueprint
app.register_blueprint(main_blueprint)
init_probe(app)


if __name__ == '__main__':
    print("开发模式运行中，生产环境请使用: gunicorn -c gunicorn.conf.py app:app")
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)
