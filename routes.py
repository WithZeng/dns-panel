import io
import os
import csv
import json
import re
import zipfile
import threading
from datetime import datetime, timedelta
from flask import Blueprint, render_template, redirect, url_for, request, flash, send_file, jsonify, current_app, abort
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from models import (
    db,
    User,
    EcsInstance,
    OperationLog,
    TrafficLog,
    AlertConfig,
    NotificationLog,
    ScheduleTask,
    ProbeServer,
    DnsFailover,
    ImportJob,
)
from monitor import (
    check_and_manage_instance,
    ecs_stop,
    ecs_start,
    ecs_release,
    get_region_traffic,
    get_client,
    get_security_groups,
    describe_sg_rules,
    authorize_sg,
    revoke_sg,
    ecs_enable_ipv6,
    get_ecs_ipv6_info,
    get_cdt_three_month_billing,
    BillingQueryError,
)
from notifier import send_alert
from extensions import limiter
from route_helpers import (
    is_probe_online as _is_probe_online,
    generate_ipv6_script_token as _generate_ipv6_script_token,
    verify_ipv6_script_token as _verify_ipv6_script_token,
    build_ipv6_setup_script as _build_ipv6_setup_script,
    log_operation,
    compute_instance_stats as _compute_instance_stats,
    parse_non_negative_float as _parse_non_negative_float,
    normalize_days_of_week as _normalize_days_of_week,
    slugify_account as _slugify_account,
    safe_yaml_str as _safe_yaml_str,
    classify_import_error as _classify_import_error,
    classify_billing_error as _classify_billing_error,
    parse_account_text as _parse_account_text,
    discover_ecs_instances_all_regions as _discover_ecs_instances_all_regions,
    sync_account_to_github as _sync_account_to_github,
    new_import_job as _new_import_job,
    job_is_done as _job_is_done,
    serialize_import_job as _serialize_import_job,
    update_import_job as _update_import_job,
    cleanup_import_jobs as _cleanup_import_jobs,
    mark_stale_import_job_if_needed as _mark_stale_import_job_if_needed,
    run_account_import_job as _run_account_import_job,
    _IMPORT_TEXT_MAX_CHARS,
    _IMPORT_JOBS_LOCK,
)

main = Blueprint('main', __name__)

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 10
# 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€ Auth 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

@main.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('main.login'))


@main.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if current_user.is_authenticated:
        if getattr(current_user, 'force_password_change', False):
            return redirect(url_for('main.change_password'))
        return redirect(url_for('main.dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user:
            if user.locked_until and user.locked_until > datetime.utcnow():
                remaining = int((user.locked_until - datetime.utcnow()).total_seconds() / 60) + 1
                flash(f'账户已锁定，请 {remaining} 分钟后重试', 'danger')
                return render_template('login.html')

            if check_password_hash(user.password_hash, password):
                user.failed_login_count = 0
                user.locked_until = None
                db.session.commit()
                login_user(user)
                if getattr(user, 'force_password_change', False):
                    flash('首次登录请先修改密码。', 'warning')
                    return redirect(url_for('main.change_password'))
                return redirect(url_for('main.dashboard'))

            user.failed_login_count = (user.failed_login_count or 0) + 1
            if user.failed_login_count >= MAX_LOGIN_ATTEMPTS:
                user.locked_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
                user.failed_login_count = 0
                db.session.commit()
                flash(f'连续 {MAX_LOGIN_ATTEMPTS} 次失败，账户锁定 {LOCKOUT_MINUTES} 分钟', 'danger')
                return render_template('login.html')
            db.session.commit()

        flash('用户名或密码错误', 'danger')

    return render_template('login.html')


@main.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.login'))


@main.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    is_forced = bool(getattr(current_user, 'force_password_change', False))
    if request.method == 'POST':
        old_pw = request.form.get('old_password', '')
        new_pw = request.form.get('new_password', '')
        confirm_pw = request.form.get('confirm_password', '')

        if not check_password_hash(current_user.password_hash, old_pw):
            flash('旧密码不正确', 'danger')
        elif len(new_pw) < 6:
            flash('新密码至少 6 位', 'danger')
        elif new_pw != confirm_pw:
            flash('两次输入的密码不一致', 'danger')
        else:
            current_user.password_hash = generate_password_hash(new_pw)
            current_user.force_password_change = False
            db.session.commit()
            flash('密码修改成功，请重新登录', 'success')
            logout_user()
            return redirect(url_for('main.login'))

    return render_template('change_password.html', is_forced=is_forced)


# 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€ Dashboard 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

@main.route('/dashboard')
@login_required
def dashboard():
    tag_filter = request.args.get('tag', '')
    query = EcsInstance.query
    if tag_filter:
        query = query.filter_by(tag=tag_filter)
    instances = query.all()

    total = len(instances)
    online = sum(1 for i in instances if i.status in ('Running', 'Starting'))
    stopped = sum(1 for i in instances if i.status in ('Stopped', 'Stopping'))
    total_traffic = sum(i.current_month_traffic or 0 for i in instances)
    total_cost = sum(_compute_instance_stats(i)['cost'] for i in instances)

    probe_servers = ProbeServer.query.all()
    probe_total = len(probe_servers)
    probe_online = sum(1 for s in probe_servers if _is_probe_online(s))
    probe_offline = max(probe_total - probe_online, 0)

    dns_rules = DnsFailover.query.all()
    dns_total = len(dns_rules)
    dns_enabled = sum(1 for r in dns_rules if r.enabled)

    # All available tags for filter dropdown (avoid loading all instance rows twice)
    all_tags = sorted(t for (t,) in db.session.query(EcsInstance.tag).filter(EcsInstance.tag.isnot(None)).distinct().all() if t)

    return render_template('dashboard.html',
                           instances=instances,
                           total=total, online=online, stopped=stopped,
                           total_traffic=total_traffic, total_cost=total_cost,
                           probe_total=probe_total, probe_online=probe_online, probe_offline=probe_offline,
                           dns_total=dns_total, dns_enabled=dns_enabled,
                           all_tags=all_tags, current_tag=tag_filter)


@main.route('/api/instances')
@login_required
def api_instances():
    """JSON endpoint for AJAX dashboard refresh."""
    tag_filter = request.args.get('tag', '').strip()
    query = EcsInstance.query
    if tag_filter:
        query = query.filter_by(tag=tag_filter)
    instances = query.all()

    data = []
    for inst in instances:
        stats = _compute_instance_stats(inst)
        data.append({
            'id': inst.id,
            'name': inst.name,
            'instance_id': inst.instance_id,
            'region_id': inst.region_id,
            'status': inst.status,
            'public_ip': inst.public_ip or '-',
            'private_ip': inst.private_ip or '-',
            'ipv6_addr': inst.ipv6_addr or '-',
            'strategy': inst.traffic_strategy,
            'tag': inst.tag or '',
            'monthly_used': stats['monthly_used'],
            'monthly_limit': stats['monthly_limit'],
            'monthly_remain': stats['monthly_remain'],
            'monthly_percent': stats['monthly_percent'],
            'life_used': stats['life_used'],
            'life_limit': stats['life_limit'],
            'life_remain': stats['life_remain'],
            'life_percent': stats['life_percent'],
            'percent': stats['percent'],
            'cost': stats['cost'],
            'credential_status': (inst.credential_status or 'ok'),
            'credential_error': inst.credential_error or '',
            'credential_last_failed_at': inst.credential_last_failed_at.strftime('%Y-%m-%d %H:%M') if inst.credential_last_failed_at else '',
            'last_checked': inst.last_checked.strftime('%Y-%m-%d %H:%M') if inst.last_checked else '-',
        })

    total_count = len(data)
    online_count = sum(1 for d in data if d['status'] in ('Running', 'Starting'))
    stopped_count = sum(1 for d in data if d['status'] in ('Stopped', 'Stopping'))
    total_traffic = round(sum(d['monthly_used'] for d in data), 2)
    total_cost = round(sum(d['cost'] for d in data), 2)

    return jsonify({
        'instances': data,
        'summary': {
            'total': total_count,
            'online': online_count,
            'stopped': stopped_count,
            'total_traffic': total_traffic,
            'total_cost': total_cost,
        }
    })


@main.route('/api/dashboard_probe_overview')
@login_required
def api_dashboard_probe_overview():
    servers = ProbeServer.query.order_by(ProbeServer.created_at.desc()).all()
    online = [s for s in servers if _is_probe_online(s)]
    offline = [s for s in servers if not _is_probe_online(s)]

    rules = DnsFailover.query.all()
    enabled_rules = [r for r in rules if r.enabled]

    return jsonify({
        'probe': {
            'total': len(servers),
            'online': len(online),
            'offline': len(offline),
            'servers': [
                {
                    'id': s.id,
                    'name': s.name,
                    'server_type': s.server_type,
                    'is_online': _is_probe_online(s),
                    'ipv4': s.ipv4 or '',
                    'ipv6': s.ipv6 or '',
                }
                for s in servers[:8]
            ],
        },
        'dns': {
            'total_rules': len(rules),
            'enabled_rules': len(enabled_rules),
        }
    })


# 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€ Health Check 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

@main.route('/health')
def health_check():
    """Health check endpoint for uptime monitors."""
    try:
        db.session.execute(db.text('SELECT 1'))
        return jsonify({'status': 'ok', 'database': 'connected'}), 200
    except Exception:
        current_app.logger.exception('Health check failed')
        return jsonify({'status': 'error', 'database': 'unavailable'}), 500


# 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€ Instance CRUD 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

@main.route('/instance/add', methods=['GET', 'POST'])
@login_required
def add_instance():
    if request.method == 'POST':
        name = (request.form.get('name') or '').strip()
        region_id = (request.form.get('region_id') or '').strip()
        instance_id = (request.form.get('instance_id') or '').strip()
        ak = (request.form.get('access_key_id') or '').strip()
        sk = (request.form.get('access_key_secret') or '').strip()
        tag = request.form.get('tag', '').strip()

        traffic_strategy = (request.form.get('traffic_strategy', 'cycle') or 'cycle').strip().lower()
        if traffic_strategy not in ('cycle', 'life'):
            traffic_strategy = 'cycle'

        try:
            monthly_limit = _parse_non_negative_float(request.form.get('monthly_limit'), '月度限额')
            life_total_limit = _parse_non_negative_float(request.form.get('life_total_limit'), '生命周期总限额')
            monthly_free_allowance = _parse_non_negative_float(request.form.get('monthly_free_allowance'), '月度免费额度')
        except ValueError as e:
            flash(str(e), 'danger')
            return render_template('add_instance.html', instance=None, prefill={})

        if not all([name, region_id, instance_id, ak, sk]):
            flash('请完整填写名称、地域、实例ID、Access Key ID、Access Key Secret', 'warning')
            return render_template('add_instance.html', instance=None, prefill={})

        auto_stop_enabled = 'auto_stop_enabled' in request.form
        auto_start_enabled = 'auto_start_enabled' in request.form
        monitoring_enabled = 'monitoring_enabled' in request.form

        new_instance = EcsInstance(
            name=name,
            region_id=region_id,
            instance_id=instance_id,
            tag=tag,
            notes=request.form.get('notes', '').strip(),
            traffic_strategy=traffic_strategy,
            monthly_limit=monthly_limit,
            life_total_limit=life_total_limit,
            monthly_free_allowance=monthly_free_allowance,
            auto_stop_enabled=auto_stop_enabled,
            auto_start_enabled=auto_start_enabled,
            monitoring_enabled=monitoring_enabled
        )
        new_instance.set_ak_sk(ak, sk)

        try:
            client = get_client(new_instance)
            start_traffic = get_region_traffic(client, region_id)
            if start_traffic > 0:
                new_instance.last_api_traffic = start_traffic
                new_instance.total_traffic_sum = start_traffic
                new_instance.current_month_traffic = start_traffic
        except Exception:
            pass

        try:
            db.session.add(new_instance)
            log_operation('add', f'添加实例 {name} ({instance_id})')
            db.session.commit()
            flash('实例添加成功', 'success')
            return redirect(url_for('main.dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'添加失败: {str(e)}', 'danger')
            return render_template('add_instance.html', instance=None, prefill={})

    # If coming from discover page, pre-fill AK/SK from session
    from flask import session as flask_session
    prefill = {
        'access_key_id': flask_session.pop('discover_ak', ''),
        'access_key_secret': flask_session.pop('discover_sk', ''),
    }
    return render_template('add_instance.html', instance=None, prefill=prefill)


@main.route('/instance/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_instance(id):
    instance = db.get_or_404(EcsInstance, id)
    if request.method == 'POST':
        name = (request.form.get('name') or '').strip()
        region_id = (request.form.get('region_id') or '').strip()
        instance_id = (request.form.get('instance_id') or '').strip()
        new_ak = (request.form.get('access_key_id') or '').strip()
        new_sk = (request.form.get('access_key_secret') or '').strip()
        traffic_strategy = (request.form.get('traffic_strategy', 'cycle') or 'cycle').strip().lower()
        if traffic_strategy not in ('cycle', 'life'):
            traffic_strategy = 'cycle'

        if not all([name, region_id, instance_id]):
            flash('名称、地域、实例ID 不能为空', 'warning')
            return render_template('edit_instance.html', instance=instance)

        try:
            monthly_limit = _parse_non_negative_float(request.form.get('monthly_limit'), '月度限额')
            life_total_limit = _parse_non_negative_float(request.form.get('life_total_limit'), '生命周期总限额')
            hourly_price = _parse_non_negative_float(request.form.get('hourly_price'), '小时价格')
            monthly_free_allowance = _parse_non_negative_float(request.form.get('monthly_free_allowance'), '月度免费额度')
        except ValueError as e:
            flash(str(e), 'danger')
            return render_template('edit_instance.html', instance=instance)

        instance.name = name
        instance.region_id = region_id
        instance.instance_id = instance_id
        instance.tag = request.form.get('tag', '').strip()
        instance.notes = request.form.get('notes', '').strip()
        instance.traffic_strategy = traffic_strategy
        instance.monthly_limit = monthly_limit
        instance.life_total_limit = life_total_limit
        instance.hourly_price = hourly_price
        instance.monthly_free_allowance = monthly_free_allowance
        instance.auto_stop_enabled = 'auto_stop_enabled' in request.form
        instance.auto_start_enabled = 'auto_start_enabled' in request.form
        instance.monitoring_enabled = 'monitoring_enabled' in request.form

        # Only overwrite AK/SK when both fields are provided.
        if (new_ak and not new_sk) or (new_sk and not new_ak):
            flash('请同时填写 Access Key ID 和 Access Key Secret，或保持两项都为空以保留原密钥', 'warning')
            return render_template('edit_instance.html', instance=instance)
        if new_ak and new_sk:
            instance.set_ak_sk(new_ak, new_sk)

        try:
            log_operation('edit', f'编辑实例 {instance.name}', instance_id=instance.id)
            db.session.commit()
            flash('实例更新成功', 'success')
            return redirect(url_for('main.dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'实例更新失败: {str(e)}', 'danger')

    return render_template('edit_instance.html', instance=instance)


@main.route('/instance/delete/<int:id>', methods=['POST'])
@login_required
def delete_instance_local(id):
    instance = db.get_or_404(EcsInstance, id)
    name = instance.name
    try:
        log_operation('delete', f'删除本地实例 {name}', instance_id=id)
        db.session.delete(instance)
        db.session.commit()
        flash('本地记录已删除', 'info')
    except Exception as e:
        db.session.rollback()
        flash(f'删除失败: {str(e)}', 'danger')
    return redirect(url_for('main.dashboard'))


# 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€ Instance Actions 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

@main.route('/instance/check/<int:id>')
@login_required
def check_instance(id):
    check_and_manage_instance(id)
    log_operation('check', f'手动检查实例 ID {id}', instance_id=id)
    db.session.commit()
    flash(f'实例 {id} 检查完成', 'success')
    return redirect(url_for('main.dashboard'))


@main.route('/check_all')
@login_required
def check_all():
    instances = EcsInstance.query.filter_by(monitoring_enabled=True).all()
    for inst in instances:
        check_and_manage_instance(inst.id)
    log_operation('check_all', f'批量检查 {len(instances)} 个实例')
    db.session.commit()
    flash(f'已检查 {len(instances)} 个实例', 'success')
    return redirect(url_for('main.dashboard'))


@main.route('/stop_instance/<int:id>', methods=['POST'])
@login_required
def stop_instance(id):
    instance = db.get_or_404(EcsInstance, id)
    try:
        client = get_client(instance)
        success, msg = ecs_stop(client, instance.instance_id)
        if success:
            instance.status = 'Stopping'
            flash('停机指令已发送', 'success')
        else:
            flash(f'停机失败: {msg}', 'danger')
        log_operation('stop', f'{instance.name}: {msg}', instance_id=id)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        flash(f'停机失败: {str(e)}', 'danger')
    return redirect(url_for('main.dashboard'))


@main.route('/start_instance/<int:id>', methods=['POST'])
@login_required
def start_instance(id):
    instance = db.get_or_404(EcsInstance, id)
    try:
        client = get_client(instance)
        success, msg = ecs_start(client, instance.instance_id)
        if success:
            instance.status = 'Starting'
            flash('开机指令已发送', 'success')
        else:
            flash(f'开机失败: {msg}', 'danger')
        log_operation('start', f'{instance.name}: {msg}', instance_id=id)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        flash(f'开机失败: {str(e)}', 'danger')
    return redirect(url_for('main.dashboard'))


@main.route('/release_instance/<int:id>', methods=['POST'])
@login_required
def release_instance(id):
    instance = db.get_or_404(EcsInstance, id)
    try:
        client = get_client(instance)
        success, msg = ecs_release(client, instance.instance_id)
        if success:
            instance.status = 'Releasing'
            flash('释放指令已发送', 'success')
        else:
            flash(f'释放失败: {msg}', 'danger')
        log_operation('release', f'{instance.name}: {msg}', instance_id=id)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        flash(f'释放失败: {str(e)}', 'danger')
    return redirect(url_for('main.dashboard'))


# 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€ Instance Detail & Traffic Chart 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

@main.route('/instance/<int:id>')
@login_required
def instance_detail(id):
    instance = db.get_or_404(EcsInstance, id)
    logs = OperationLog.query.filter_by(instance_id=id).order_by(OperationLog.timestamp.desc()).limit(50).all()
    ipv6_info = {'enabled': False, 'addresses': [], 'message': ''}
    try:
        client = get_client(instance)
        ipv6_info = get_ecs_ipv6_info(client, instance)
    except Exception as e:
        ipv6_info = {'enabled': False, 'addresses': [], 'message': str(e)}

    script_token = _generate_ipv6_script_token(instance.id)
    script_url = url_for('main.public_ipv6_script', id=instance.id, token=script_token, _external=True)
    curl_command = f"curl -fsSL '{script_url}' | sudo bash"

    return render_template(
        'instance_detail.html',
        instance=instance,
        logs=logs,
        ipv6_info=ipv6_info,
        ipv6_script_url=script_url,
        ipv6_curl_command=curl_command,
        ipv6_script_token_expires_minutes=max(1, int(current_app.config.get('IPV6_SCRIPT_TOKEN_EXPIRES', 1800) / 60)),
    )


@main.route('/instance/<int:id>/enable_ipv6', methods=['POST'])
@login_required
def enable_ipv6(id):
    instance = db.get_or_404(EcsInstance, id)
    try:
        client = get_client(instance)
        success, msg, _ = ecs_enable_ipv6(client, instance)
        log_operation('enable_ipv6', f'{instance.name}: {msg}', instance_id=id)
        db.session.commit()
        flash(msg if success else f'开启 IPv6 失败: {msg}', 'success' if success else 'danger')
    except Exception as e:
        db.session.rollback()
        flash(f'开启 IPv6 失败: {str(e)}', 'danger')
    return redirect(url_for('main.instance_detail', id=id))


@main.route('/instance/<int:id>/ipv6_script.sh', methods=['GET'])
@login_required
def download_ipv6_script(id):
    instance = db.get_or_404(EcsInstance, id)
    script = _build_ipv6_setup_script(instance)

    return send_file(
        io.BytesIO(script.encode('utf-8')),
        mimetype='text/x-shellscript',
        as_attachment=True,
        download_name=f'ipv6_setup_{instance.instance_id}.sh'
    )


@main.route('/public/instance/<int:id>/ipv6_script.sh', methods=['GET'])
def public_ipv6_script(id):
    token = request.args.get('token', '').strip()
    ok, reason = _verify_ipv6_script_token(token, id)
    if not ok:
        if reason == 'expired':
            abort(403, description='IPv6 脚本链接已过期，请回到面板重新生成。')
        abort(403, description='IPv6 脚本链接无效。')

    instance = db.session.get(EcsInstance, id)
    if not instance:
        abort(403, description='实例不存在或已删除。')

    script = _build_ipv6_setup_script(instance)
    return send_file(
        io.BytesIO(script.encode('utf-8')),
        mimetype='text/x-shellscript',
        as_attachment=False,
        download_name=f'ipv6_setup_{instance.instance_id}.sh'
    )


@main.route('/api/traffic_history/<int:id>')
@login_required
def api_traffic_history(id):
    logs = TrafficLog.query.filter_by(instance_id=id).order_by(TrafficLog.timestamp.asc()).all()
    return jsonify({
        'labels': [l.timestamp.strftime('%m-%d %H:%M') for l in logs],
        'data': [round(l.traffic_gb, 2) for l in logs],
    })


# 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€ Operation Logs Page 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

@main.route('/logs')
@login_required
def operation_logs():
    page = request.args.get('page', 1, type=int)
    logs = OperationLog.query.order_by(OperationLog.timestamp.desc()).paginate(page=page, per_page=30, error_out=False)
    return render_template('logs.html', logs=logs)


# 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€ Alert Config + Test Notification 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

@main.route('/alert_config', methods=['GET', 'POST'])
@login_required
def alert_config():
    config = AlertConfig.query.first()
    if not config:
        config = AlertConfig()
        db.session.add(config)
        db.session.commit()

    if request.method == 'POST':
        config.notify_type = request.form.get('notify_type', 'wechat')
        config.webhook_url = request.form.get('webhook_url', '')
        config.enabled = 'enabled' in request.form
        db.session.commit()
        flash('告警配置已保存', 'success')
        return redirect(url_for('main.alert_config'))

    return render_template('alert_config.html', config=config)


@main.route('/api/test_notification', methods=['POST'])
@login_required
def test_notification():
    """Send a test notification via configured webhook."""
    config = AlertConfig.query.first()
    if not config or not config.webhook_url:
        return jsonify({'success': False, 'message': '请先填写 Webhook URL'}), 400

    test_msg = (
        "测试通知\n"
        "这是一条来自 ECS Monitor 的测试消息。\n"
        f"通知渠道: {config.notify_type}\n"
        f"发送时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        "如果你看到了这条消息，说明配置正确。"
    )

    try:
        success = send_alert(config.notify_type, config.webhook_url, test_msg,
                             instance_name='test')
        if success:
            return jsonify({'success': True, 'message': '测试通知发送成功'})
        else:
            return jsonify({'success': False, 'message': '发送失败，请检查 Webhook URL'}), 500
    except Exception as e:
        return jsonify({'success': False, 'message': f'发送异常: {str(e)}'}), 500


# 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€ Auto-Discovery 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

@main.route('/discover', methods=['GET', 'POST'])
@login_required
def discover_instances():
    """Scan an Alibaba Cloud account to discover all ECS instances."""
    discovered = []
    if request.method == 'POST':
        ak = request.form.get('access_key_id', '')
        sk = request.form.get('access_key_secret', '')
        region_id = request.form.get('region_id', 'cn-hangzhou')

        # Store AK/SK in session so add_instance can pre-fill them
        from flask import session as flask_session
        flask_session['discover_ak'] = ak
        flask_session['discover_sk'] = sk

        try:
            for inst in _discover_ecs_instances_all_regions(ak, sk, region_id):
                existing = EcsInstance.query.filter_by(instance_id=inst['instance_id']).first()
                discovered.append({
                    **inst,
                    'already_added': existing is not None,
                })

            if not discovered:
                flash(f'在 {region_id} 区域未发现 ECS 实例', 'warning')
            else:
                flash(f'发现 {len(discovered)} 个实例', 'success')

        except Exception as e:
            flash(f'扫描失败: {str(e)}', 'danger')

    return render_template('discover.html', discovered=discovered)


@main.route('/account/import_text', methods=['GET', 'POST'])
@login_required
def import_account_text():
    """Import Alibaba account text asynchronously with progress states."""
    if request.method == 'GET':
        _cleanup_import_jobs()
        done_job_id = request.args.get('job_done', '').strip()
        if done_job_id:
            done_job = db.session.get(ImportJob, done_job_id)
            if done_job and done_job.status == 'done':
                result = done_job.get_result() or {}
                flash(
                    f"导入完成：发现 {result.get('discovered_count', 0)} 台，新增 {result.get('imported_count', 0)}，更新 {result.get('updated_count', 0)}；GitHub 已同步 {result.get('sync_target', '-')}",
                    'success'
                )
                return render_template('import_account_text.html', result=result)
            if done_job and done_job.status == 'error':
                err_result = done_job.get_result() or {}
                err_type = err_result.get('error_type') or 'unknown_error'
                err_message = err_result.get('message') or done_job.message or '导入失败'
                err_suggestion = err_result.get('suggestion') or '请检查后重试。'
                flash(f"导入失败（{err_type}）：{err_message} 建议：{err_suggestion}", 'danger')
        return render_template('import_account_text.html')

    raw_text = request.form.get('account_text', '')
    if not raw_text.strip():
        flash('请先粘贴账号文本。', 'warning')
        return render_template('import_account_text.html', raw_text=raw_text)

    if len(raw_text) > _IMPORT_TEXT_MAX_CHARS:
        flash(f'账号文本过长（最多 {_IMPORT_TEXT_MAX_CHARS} 字符），请精简后重试。', 'warning')
        return render_template('import_account_text.html', raw_text=raw_text[:_IMPORT_TEXT_MAX_CHARS])

    scan_all_regions = 'scan_all_regions' in request.form

    _cleanup_import_jobs()
    job = _new_import_job()

    app_obj = current_app._get_current_object()

    # Tests expect deterministic completion after POST; run inline in testing mode.
    if current_app.config.get('TESTING'):
        _run_account_import_job(app_obj, job.id, raw_text, scan_all_regions)
        return redirect(url_for('main.import_account_text', job_done=job.id))

    t = threading.Thread(
        target=_run_account_import_job,
        args=(app_obj, job.id, raw_text, scan_all_regions),
        daemon=True,
    )
    t.start()

    return render_template('import_account_text.html', raw_text=raw_text, job_id=job.id)


@main.route('/api/account/import_text/status/<job_id>')
@login_required
def import_account_text_status(job_id):
    _cleanup_import_jobs()
    with _IMPORT_JOBS_LOCK:
        job = db.session.get(ImportJob, job_id)
    if not job:
        return jsonify({'ok': False, 'message': '任务不存在或已过期'}), 404

    refreshed = _mark_stale_import_job_if_needed(job)
    payload = _serialize_import_job(refreshed or job)
    return jsonify({'ok': True, 'job': payload})


# 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€ Backup & Export 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

@main.route('/download_backup')
@login_required
def download_backup():
    db_path = os.path.join(current_app.instance_path, 'ecs_monitor.db')
    if not os.path.exists(db_path):
        flash('数据库文件不存在', 'danger')
        return redirect(url_for('main.dashboard'))

    try:
        memory_file = io.BytesIO()
        with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.write(db_path, arcname='ecs_monitor.db')

            # Include encryption key file when present, so AK/SK remains decryptable after restore.
            encrypt_key_path = os.path.join(current_app.instance_path, 'encrypt.key')
            if os.path.isfile(encrypt_key_path):
                zf.write(encrypt_key_path, arcname='encrypt.key')
        memory_file.seek(0)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M")
        return send_file(memory_file, download_name=f"backup_{timestamp}.zip", as_attachment=True)
    except Exception as e:
        flash(f'备份失败: {str(e)}', 'danger')
        return redirect(url_for('main.dashboard'))


@main.route('/export_csv')
@login_required
def export_csv():
    """Export instances to CSV. Accepts ?ids=1,2,3 for selective export.
    Output format matches import_csv expectations for seamless restore."""
    ids_param = request.args.get('ids', '')
    if ids_param:
        id_list = [int(x) for x in ids_param.split(',') if x.strip().isdigit()]
        instances = EcsInstance.query.filter(EcsInstance.id.in_(id_list)).all()
    else:
        instances = EcsInstance.query.all()

    output = io.StringIO()
    writer = csv.writer(output)
    # Headers match import_csv field expectations
    writer.writerow([
        'name', 'instance_id', 'region_id', 'access_key_id', 'access_key_secret',
        'ak_format', 'is_encrypted',
        'tag', 'notes', 'traffic_strategy', 'monthly_limit', 'life_total_limit',
        'monthly_free_allowance', 'hourly_price', 'alert_threshold_pct',
        'auto_stop_enabled', 'auto_start_enabled', 'total_traffic_sum', 'current_month_traffic'
    ])
    for inst in instances:
        exported_ak = inst.decrypted_ak
        exported_sk = inst.decrypted_sk
        ak_format = 'plaintext'

        # If key mismatch prevents decrypt, keep raw ciphertext + marker for lossless migration.
        if inst.is_encrypted and (not exported_ak or not exported_sk):
            exported_ak = inst.access_key_id or ''
            exported_sk = inst.access_key_secret or ''
            if exported_ak.startswith('gAAAA') and exported_sk.startswith('gAAAA'):
                ak_format = 'fernet_encrypted'

        writer.writerow([
            inst.name,
            inst.instance_id,
            inst.region_id,
            exported_ak,
            exported_sk,
            ak_format,
            bool(inst.is_encrypted),
            inst.tag or '',
            inst.notes or '',
            inst.traffic_strategy,
            inst.monthly_limit or 0,
            inst.life_total_limit or 0,
            inst.monthly_free_allowance or 0,
            inst.hourly_price or 0,
            inst.alert_threshold_pct or 80,
            inst.auto_stop_enabled,
            inst.auto_start_enabled,
            round(inst.total_traffic_sum or 0, 2),
            round(inst.current_month_traffic or 0, 2),
        ])

    mem = io.BytesIO()
    mem.write(output.getvalue().encode('utf-8-sig'))
    mem.seek(0)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    return send_file(mem, download_name=f'instances_{timestamp}.csv', as_attachment=True, mimetype='text/csv')


# 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€ Notification History 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

@main.route('/notification_logs')
@login_required
def notification_logs():
    page = request.args.get('page', 1, type=int)
    logs = NotificationLog.query.order_by(NotificationLog.timestamp.desc()).paginate(
        page=page, per_page=20, error_out=False)
    return render_template('notification_logs.html', logs=logs)


# 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€ Batch Tag Operations 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

@main.route('/batch_action', methods=['POST'])
@login_required
def batch_action():
    """Batch start/stop/check instances selected by checkbox only."""
    action = request.form.get('action')  # start, stop, check
    instance_ids = request.form.getlist('instance_ids')  # from checkboxes
    tag_filter = request.form.get('tag', '')

    if not action:
        flash('请选择操作', 'warning')
        return redirect(url_for('main.dashboard', tag=tag_filter))

    if not instance_ids:
        flash('请先勾选至少一个实例，再执行批量操作', 'warning')
        return redirect(url_for('main.dashboard', tag=tag_filter))

    instances = EcsInstance.query.filter(EcsInstance.id.in_(instance_ids)).all()
    if not instances:
        flash('未找到已勾选的实例，请刷新页面后重试', 'warning')
        return redirect(url_for('main.dashboard', tag=tag_filter))

    tag_label = f'选中的 {len(instances)} 个'

    count = 0
    for inst in instances:
        try:
            client = get_client(inst)
            if action == 'start' and inst.status == 'Stopped':
                ecs_start(client, inst.instance_id)
                inst.status = 'Starting'
                count += 1
            elif action == 'stop' and inst.status == 'Running':
                ecs_stop(client, inst.instance_id)
                inst.status = 'Stopping'
                count += 1
            elif action == 'check':
                check_and_manage_instance(inst.id)
                count += 1
        except Exception as e:
            flash(f'{inst.name} 操作失败: {str(e)}', 'danger')

    action_names = {'start': '启动', 'stop': '停止', 'check': '检查'}
    log_operation('batch_action', f'批量{action_names.get(action, action)} {tag_label}{count}个实例')
    db.session.commit()
    flash(f'已对 {count} 个实例执行 {action_names.get(action, action)} 操作', 'success')
    return redirect(url_for('main.dashboard', tag=tag_filter))


# 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€ CSV Bulk Import 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

@main.route('/import_csv', methods=['GET', 'POST'])
@login_required
def import_csv():
    """Bulk import instances from CSV file."""
    if request.method == 'POST':
        file = request.files.get('file')
        if not file or not file.filename.endswith('.csv'):
            flash('请上传 CSV 文件', 'warning')
            return render_template('import_csv.html')

        try:
            content = file.stream.read().decode('utf-8-sig')
            reader = csv.DictReader(io.StringIO(content))
            imported = 0
            skipped = 0

            for row in reader:
                instance_id = row.get('instance_id', '').strip()
                if not instance_id:
                    skipped += 1
                    continue

                # Skip duplicates
                if EcsInstance.query.filter_by(instance_id=instance_id).first():
                    skipped += 1
                    continue

                new_inst = EcsInstance(
                    name=row.get('name', instance_id).strip(),
                    region_id=row.get('region_id', 'cn-hangzhou').strip(),
                    instance_id=instance_id,
                    tag=row.get('tag', '').strip(),
                    notes=row.get('notes', '').strip(),
                    traffic_strategy=row.get('traffic_strategy', 'cycle').strip(),
                    monthly_limit=float(row.get('monthly_limit', 0) or 0),
                    life_total_limit=float(row.get('life_total_limit', 0) or 0),
                    monthly_free_allowance=float(row.get('monthly_free_allowance', 200) or 200),
                    hourly_price=float(row.get('hourly_price', 0) or 0),
                    alert_threshold_pct=int(float(row.get('alert_threshold_pct', 80) or 80)),
                    auto_stop_enabled=str(row.get('auto_stop_enabled', 'False')).strip().lower() in ('true', '1', 'yes'),
                    auto_start_enabled=str(row.get('auto_start_enabled', 'False')).strip().lower() in ('true', '1', 'yes'),
                    total_traffic_sum=float(row.get('total_traffic_sum', 0) or 0),
                    current_month_traffic=float(row.get('current_month_traffic', 0) or 0),
                    monitoring_enabled=True,
                )
                ak = row.get('access_key_id', '').strip()
                sk = row.get('access_key_secret', '').strip()
                if (ak and not sk) or (sk and not ak):
                    skipped += 1
                    continue
                ak_format = (row.get('ak_format', '') or '').strip().lower()
                is_enc = str(row.get('is_encrypted', '')).strip().lower() in ('true', '1', 'yes')

                if ak and sk:
                    if ak_format == 'fernet_encrypted' and ak.startswith('gAAAA') and sk.startswith('gAAAA'):
                        # Keep ciphertext as-is for cross-environment restore (requires matching encrypt.key).
                        new_inst.access_key_id = ak
                        new_inst.access_key_secret = sk
                        new_inst.is_encrypted = True
                    else:
                        new_inst.set_ak_sk(ak, sk)
                        if is_enc and not new_inst.is_encrypted:
                            new_inst.is_encrypted = True
                else:
                    new_inst.access_key_id = ''
                    new_inst.access_key_secret = ''

                db.session.add(new_inst)
                imported += 1

            log_operation('import_csv', f'CSV导入 {imported} 个实例，跳过 {skipped} 个')
            db.session.commit()
            flash(f'成功导入 {imported} 个实例，跳过 {skipped} 个', 'success')
            return redirect(url_for('main.dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'导入失败: {str(e)}', 'danger')

    return render_template('import_csv.html')


# 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€ Region Traffic Comparison API 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

@main.route('/api/billing/cdt/three_months')
@login_required
def api_billing_cdt_three_months():
    """Return CDT billing traffic summary for recent 3 natural months."""
    query_instance_id = (request.args.get('instance_id') or '').strip()

    target_instance = None
    if query_instance_id:
        target_instance = EcsInstance.query.filter_by(instance_id=query_instance_id).first()
        if not target_instance:
            return jsonify({
                'success': False,
                'message': f'未找到实例：{query_instance_id}',
                'error_code': 'INSTANCE_NOT_FOUND',
            }), 404
    else:
        target_instance = EcsInstance.query.order_by(EcsInstance.id.asc()).first()
        if not target_instance:
            return jsonify({
                'success': False,
                'message': '当前无可用实例凭据，无法查询 CDT 账单数据。请先添加实例或传入 instance_id。',
                'error_code': 'NO_CREDENTIAL_SOURCE',
            }), 400

    try:
        client = get_client(target_instance)
        summary = get_cdt_three_month_billing(
            client,
            instance_id=query_instance_id,
            region_id=(target_instance.region_id if query_instance_id else ''),
        )
        return jsonify({
            'success': True,
            'instance_id': query_instance_id or None,
            'scope': summary.get('scope', 'account'),
            'months': summary.get('months', []),
            'total_traffic': summary.get('total_traffic', 0.0),
            'total_amount': summary.get('total_amount', 0.0),
            'currency': summary.get('currency', 'CNY'),
            'provider': summary.get('provider', ''),
        })
    except Exception as e:
        detail = _classify_billing_error(e)
        return jsonify({
            'success': False,
            'message': detail['message'],
            'error_code': detail['error_code'],
        }), 502


@main.route('/api/region_traffic')
@login_required
def api_region_traffic():
    """Return aggregated traffic per region for comparison chart."""
    instances = EcsInstance.query.all()
    region_data = {}
    for inst in instances:
        region = inst.region_id
        stats = _compute_instance_stats(inst)
        if region not in region_data:
            region_data[region] = {'used': 0, 'limit': 0, 'cost': 0, 'count': 0}
        region_data[region]['used'] += stats['life_used'] if inst.traffic_strategy == 'life' else stats['monthly_used']
        region_data[region]['limit'] += stats['life_limit'] if inst.traffic_strategy == 'life' else stats['monthly_limit']
        region_data[region]['cost'] += stats['cost']
        region_data[region]['count'] += 1

    result = []
    for region, d in sorted(region_data.items()):
        result.append({
            'region': region,
            'used': round(d['used'], 2),
            'limit': round(d['limit'], 2),
            'cost': round(d['cost'], 2),
            'count': d['count'],
        })
    return jsonify(result)


# 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€ Traffic Forecast API 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

@main.route('/api/traffic_forecast/<int:id>')
@login_required
def api_traffic_forecast(id):
    """Predict when the traffic quota will be exhausted based on recent usage trend."""
    instance = db.get_or_404(EcsInstance, id)
    logs = TrafficLog.query.filter_by(instance_id=id).order_by(
        TrafficLog.timestamp.asc()).all()

    if len(logs) < 2:
        return jsonify({'has_forecast': False, 'message': '历史数据不足，至少需要 2 条记录'})

    # Use last 7 days of data for trend calculation
    recent_logs = [l for l in logs if l.timestamp >= datetime.utcnow() - timedelta(days=7)]
    if len(recent_logs) < 2:
        recent_logs = logs[-10:]  # Fallback to last 10 entries

    first = recent_logs[0]
    last = recent_logs[-1]
    time_diff_hours = max((last.timestamp - first.timestamp).total_seconds() / 3600, 1)
    traffic_diff = last.traffic_gb - first.traffic_gb

    if traffic_diff <= 0:
        return jsonify({'has_forecast': False, 'message': '流量无增长，无法预测'})

    gb_per_hour = traffic_diff / time_diff_hours
    gb_per_day = gb_per_hour * 24

    # Calculate remaining quota
    stats = _compute_instance_stats(instance)
    # Use life_remain for LIFE, monthly_remain for CYCLE
    remain = stats['life_remain'] if instance.traffic_strategy == 'life' else stats['monthly_remain']

    if remain <= 0:
        return jsonify({
            'has_forecast': True,
            'exhausted': True,
            'message': '配额已用尽',
            'daily_rate': round(gb_per_day, 2),
        })

    days_remaining = remain / gb_per_day if gb_per_day > 0 else 9999
    exhaust_date = (datetime.utcnow() + timedelta(days=days_remaining)).strftime('%Y-%m-%d')

    return jsonify({
        'has_forecast': True,
        'exhausted': False,
        'daily_rate': round(gb_per_day, 2),
        'days_remaining': round(days_remaining, 1),
        'exhaust_date': exhaust_date,
        'message': f'按当前速率（{gb_per_day:.2f} GB/天），预计 {exhaust_date} 用尽配额',
    })


# 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€ Instance Notes (AJAX) 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

@main.route('/api/instance/<int:id>/notes', methods=['POST'])
@login_required
def update_notes(id):
    """Update the notes field for an instance."""
    instance = db.get_or_404(EcsInstance, id)
    data = request.get_json(silent=True) or {}
    instance.notes = data.get('notes', '').strip()
    log_operation('notes', f'更新备注 {instance.name}', instance_id=id)
    db.session.commit()
    return jsonify({'success': True, 'notes': instance.notes})


# 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€ Dashboard Layout (Removed) 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

# Dashboard uses a static, fixed widget order.

# 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€ Scheduled Tasks 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

@main.route('/instance/<int:id>/schedules', methods=['GET', 'POST'])
@login_required
def instance_schedules(id):
    """View and add scheduled start/stop tasks for an instance."""
    instance = db.get_or_404(EcsInstance, id)

    if request.method == 'POST':
        action = (request.form.get('action', 'stop') or 'stop').strip().lower()
        if action not in ('start', 'stop'):
            flash('操作类型无效，仅支持 start / stop', 'danger')
            return redirect(url_for('main.instance_schedules', id=id))

        try:
            hour = int(request.form.get('hour', 0))
            minute = int(request.form.get('minute', 0))
        except (TypeError, ValueError):
            flash('时间格式无效，请选择正确的小时和分钟', 'danger')
            return redirect(url_for('main.instance_schedules', id=id))

        if not (0 <= hour <= 23 and 0 <= minute <= 59):
            flash('时间范围无效，小时应为 0-23，分钟应为 0-59', 'danger')
            return redirect(url_for('main.instance_schedules', id=id))

        days, days_err = _normalize_days_of_week(request.form.get('days_of_week', '*'))
        if days_err:
            flash(days_err, 'danger')
            return redirect(url_for('main.instance_schedules', id=id))

        task = ScheduleTask(
            instance_id=id,
            action=action,
            hour=hour,
            minute=minute,
            days_of_week=days,
            enabled=True,
        )
        try:
            db.session.add(task)
            log_operation('schedule', f'添加定时{"启动" if action=="start" else "停止"} '
                          f'{instance.name} {hour:02d}:{minute:02d} days={days}', instance_id=id)
            db.session.commit()
            flash(f'已添加定时任务: {hour:02d}:{minute:02d} {"启动" if action=="start" else "停止"}', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'添加定时任务失败: {str(e)}', 'danger')
        return redirect(url_for('main.instance_schedules', id=id))

    schedules = ScheduleTask.query.filter_by(instance_id=id).order_by(ScheduleTask.created_at.desc()).all()
    return render_template('schedules.html', instance=instance, schedules=schedules)


@main.route('/schedule/<int:id>/toggle', methods=['POST'])
@login_required
def toggle_schedule(id):
    """Enable or disable a scheduled task."""
    task = db.get_or_404(ScheduleTask, id)
    try:
        task.enabled = not task.enabled
        db.session.commit()
        flash(f'定时任务已{"启用" if task.enabled else "禁用"}', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'更新定时任务失败: {str(e)}', 'danger')
    return redirect(url_for('main.instance_schedules', id=task.instance_id))


@main.route('/schedule/<int:id>/delete', methods=['POST'])
@login_required
def delete_schedule(id):
    """Delete a scheduled task."""
    task = db.get_or_404(ScheduleTask, id)
    inst_id = task.instance_id
    try:
        db.session.delete(task)
        db.session.commit()
        flash('定时任务已删除', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'删除定时任务失败: {str(e)}', 'danger')
    return redirect(url_for('main.instance_schedules', id=inst_id))


# 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€ Security Group (Port Management) 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

@main.route('/instance/<int:id>/security_group', methods=['GET', 'POST'])
@login_required
def security_group(id):
    """View and manage security group rules for an instance."""
    instance = db.get_or_404(EcsInstance, id)
    client = get_client(instance)
    sg_ids, sg_err = get_security_groups(client, instance.instance_id)

    if not sg_ids:
        flash(f'未找到该实例的安全组: {sg_err}' if sg_err else '未找到该实例的安全组', 'warning')
        return redirect(url_for('main.instance_detail', id=id))

    sg_id = sg_ids[0]  # Use first security group

    if request.method == 'POST':
        action = request.form.get('action', 'add')

        if action == 'add':
            protocol = request.form.get('protocol', 'tcp').lower()
            port = request.form.get('port', '').strip()
            source_cidr = request.form.get('source_cidr', '0.0.0.0/0').strip() or '0.0.0.0/0'
            desc = request.form.get('description', '').strip()

            # Build port range
            if protocol == 'all':
                port_range = '-1/-1'
            elif port == '' or port == '*':
                port_range = '1/65535'
            elif '/' in port:
                port_range = port
            else:
                port_range = f'{port}/{port}'

            if protocol == 'tcp+udp':
                # Add both TCP and UDP rules
                ok1, msg1 = authorize_sg(client, sg_id, instance.region_id, 'tcp', port_range, source_cidr, description=desc)
                ok2, msg2 = authorize_sg(client, sg_id, instance.region_id, 'udp', port_range, source_cidr, description=desc)
                if ok1 and ok2:
                    flash(f'已开放 TCP+UDP {port_range}', 'success')
                    log_operation('sg_add', f'开放端口 TCP+UDP {port_range} from {source_cidr}', instance_id=id)
                else:
                    flash(f'部分失败: TCP={msg1}, UDP={msg2}', 'warning')
            else:
                ok, msg = authorize_sg(client, sg_id, instance.region_id, protocol, port_range, source_cidr, description=desc)
                if ok:
                    flash(f'已开放 {protocol.upper()} {port_range}', 'success')
                    log_operation('sg_add', f'开放端口 {protocol.upper()} {port_range} from {source_cidr}', instance_id=id)
                else:
                    flash(f'添加失败: {msg}', 'danger')

        elif action == 'open_all':
            # Open all ports for IPv4 + IPv6, both TCP + UDP.
            ops = [
                ('tcp', '0.0.0.0/0', 'Open all TCP IPv4'),
                ('udp', '0.0.0.0/0', 'Open all UDP IPv4'),
                ('tcp', '::/0', 'Open all TCP IPv6'),
                ('udp', '::/0', 'Open all UDP IPv6'),
            ]
            errors = []
            for proto, cidr, desc in ops:
                ok, msg = authorize_sg(
                    client, sg_id, instance.region_id, proto, '1/65535', cidr, description=desc
                )
                if not ok:
                    errors.append(f'{proto.upper()} {cidr}: {msg}')

            if not errors:
                flash('已开放全部端口：IPv4/IPv6 + TCP/UDP (1-65535)', 'success')
                log_operation('sg_add', '一键开放全部端口 IPv4/IPv6 + TCP/UDP', instance_id=id)
            else:
                flash('部分失败: ' + ' | '.join(errors), 'warning')

        return redirect(url_for('main.security_group', id=id))

    # GET: list rules
    rules = describe_sg_rules(client, sg_id, instance.region_id)
    return render_template('security_group.html', instance=instance, sg_id=sg_id, rules=rules)


@main.route('/instance/<int:id>/sg_delete', methods=['POST'])
@login_required
def sg_delete_rule(id):
    """Delete a security group inbound rule."""
    instance = db.get_or_404(EcsInstance, id)
    client = get_client(instance)
    sg_ids, sg_err = get_security_groups(client, instance.instance_id)
    if not sg_ids:
        flash(f'未找到安全组: {sg_err}' if sg_err else '未找到安全组', 'warning')
        return redirect(url_for('main.instance_detail', id=id))

    sg_id = sg_ids[0]
    protocol = request.form.get('protocol', '')
    port_range = request.form.get('port_range', '')
    source_cidr = request.form.get('source_cidr', '0.0.0.0/0')
    policy = request.form.get('policy', 'accept')

    ok, msg = revoke_sg(client, sg_id, instance.region_id, protocol, port_range, source_cidr, policy)
    if ok:
        flash(f'已删除规则 {protocol.upper()} {port_range}', 'success')
        log_operation('sg_delete', f'删除规则 {protocol.upper()} {port_range} from {source_cidr}', instance_id=id)
    else:
        flash(f'删除失败: {msg}', 'danger')

    return redirect(url_for('main.security_group', id=id))

