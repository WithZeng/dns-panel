import ipaddress
import json
import secrets
import threading
from datetime import datetime, timedelta
import os
import platform
import re
import shlex
import subprocess

import requests
from flask import Blueprint, jsonify, render_template, request, flash, redirect, url_for, send_file
from flask_login import login_required
from flask_sock import Sock

from cloudflare_manager import CloudflareManager
from models import (
    db,
    ProbeServer,
    EcsInstance,
    CloudflareConfig,
    DnsFailover,
    DnsFailoverLog,
)

probe = Blueprint('probe', __name__)
sock = Sock()

PROBE_OFFLINE_SECONDS = 30
_runtime_lock = threading.Lock()
_probe_runtime_cache = {}


def init_probe(app):
    sock.init_app(app)
    app.register_blueprint(probe)


def _utcnow():
    return datetime.utcnow()


def _to_int(value, default=0):
    try:
        return int(value)
    except Exception:
        return default


def _to_bool(value):
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).lower() in ('1', 'true', 'yes', 'on')


def _normalize_ip(ip_val):
    if not ip_val:
        return ''
    raw = str(ip_val).strip()
    if not raw:
        return ''
    raw = raw.split(',')[0].strip()
    raw = raw.split('/')[0].strip()
    raw = raw.strip('[]')
    try:
        parsed = ipaddress.ip_address(raw)
        if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped:
            return str(parsed.ipv4_mapped)
        return str(parsed)
    except Exception:
        return ''


def _detect_addr_family(ip_val):
    try:
        return ipaddress.ip_address(ip_val).version
    except Exception:
        return None


def _request_ip_candidates():
    vals = []
    for key in ('CF-Connecting-IP', 'X-Forwarded-For', 'X-Real-IP'):
        hv = (request.headers.get(key) or '').strip()
        if hv:
            vals.extend([x.strip() for x in hv.split(',') if x.strip()])
    ra = (request.remote_addr or '').strip()
    if ra:
        vals.append(ra)
    out = []
    for v in vals:
        n = _normalize_ip(v)
        if n and n not in out:
            out.append(n)
    return out


def refresh_probe_online_statuses():
    now = _utcnow()
    changed = False
    for server in ProbeServer.query.all():
        online = bool(server.last_seen and (now - server.last_seen).total_seconds() <= PROBE_OFFLINE_SECONDS)
        if server.is_online != online:
            server.is_online = online
            changed = True
    if changed:
        db.session.commit()


def is_probe_online(server: ProbeServer):
    if not server or not server.last_seen:
        return False
    return (_utcnow() - server.last_seen).total_seconds() <= PROBE_OFFLINE_SECONDS


def get_probe_runtime(server_id: int):
    with _runtime_lock:
        item = _probe_runtime_cache.get(server_id)
        return item.copy() if item else {}


def _update_runtime_cache(server_id: int, report_payload: dict):
    with _runtime_lock:
        _probe_runtime_cache[server_id] = {
            'report': report_payload,
            'updated_at': _utcnow().isoformat(),
        }


def _clear_runtime_cache(server_id: int):
    with _runtime_lock:
        if server_id in _probe_runtime_cache:
            _probe_runtime_cache.pop(server_id, None)


def _parse_iso_datetime(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except Exception:
        return None


def _get_effective_report(server: ProbeServer, runtime: dict):
    runtime_report = runtime.get('report') if runtime else {}
    runtime_updated_at = _parse_iso_datetime(runtime.get('updated_at')) if runtime else None

    db_report = server.get_latest_report() if server else {}
    db_updated_at = server.report_updated_at if server else None

    runtime_has = isinstance(runtime_report, dict) and bool(runtime_report)
    db_has = isinstance(db_report, dict) and bool(db_report)

    if runtime_has and db_has and runtime_updated_at and db_updated_at:
        return runtime_report if runtime_updated_at >= db_updated_at else db_report
    if runtime_has:
        return runtime_report
    if db_has:
        return db_report
    return {}


def _serialize_server(server: ProbeServer, include_realtime=True):
    runtime = get_probe_runtime(server.id) if include_realtime else {}
    report = _get_effective_report(server, runtime) if include_realtime else {}
    online = is_probe_online(server)

    cpu_usage = float(report.get('cpu', {}).get('usage', 0) or 0)
    mem_used = int(report.get('ram', {}).get('used', 0) or 0)
    mem_total = int(server.mem_total or report.get('ram', {}).get('total', 0) or 0)
    disk_used = int(report.get('disk', {}).get('used', 0) or 0)
    disk_total = int(server.disk_total or report.get('disk', {}).get('total', 0) or 0)
    net_up = float(report.get('network', {}).get('up', 0) or 0)
    net_down = float(report.get('network', {}).get('down', 0) or 0)

    mem_percent = (mem_used / mem_total * 100.0) if mem_total > 0 else 0.0
    disk_percent = (disk_used / disk_total * 100.0) if disk_total > 0 else 0.0

    return {
        'id': server.id,
        'name': server.name,
        'token': server.token,
        'server_type': server.server_type,
        'ipv4': server.ipv4 or '',
        'ipv6': server.ipv6 or '',
        'cpu_name': server.cpu_name or '',
        'cpu_cores': server.cpu_cores or 0,
        'arch': server.arch or '',
        'os_info': server.os_info or '',
        'virtualization': server.virtualization or '',
        'mem_total': server.mem_total or 0,
        'swap_total': server.swap_total or 0,
        'disk_total': server.disk_total or 0,
        'is_online': online,
        'last_seen': server.last_seen.strftime('%Y-%m-%d %H:%M:%S') if server.last_seen else '',
        'ecs_instance_id': server.ecs_instance_id,
        'notes': server.notes or '',
        'tag': server.tag or '',
        'created_at': server.created_at.strftime('%Y-%m-%d %H:%M:%S') if server.created_at else '',
        'metrics': {
            'cpu_percent': round(cpu_usage, 2),
            'mem_used': mem_used,
            'mem_percent': round(mem_percent, 2),
            'disk_used': disk_used,
            'disk_percent': round(disk_percent, 2),
            'net_up': net_up,
            'net_down': net_down,
            'report': report,
            'updated_at': (runtime.get('updated_at') if runtime.get('updated_at') else (server.report_updated_at.isoformat() if server.report_updated_at else '')),
        },
    }


def _record_failover_log(failover_id, action, message, from_server_id=None, to_server_id=None):
    log = DnsFailoverLog(
        failover_id=failover_id,
        action=action,
        message=message,
        from_server_id=from_server_id,
        to_server_id=to_server_id,
    )
    db.session.add(log)


def _get_target_ip(server: ProbeServer, prefer_ipv6=False):
    if not server:
        return ''
    if prefer_ipv6:
        return (server.ipv6 or '').strip() or (server.ipv4 or '').strip()
    return (server.ipv4 or '').strip() or (server.ipv6 or '').strip()


def _is_ipv6(ip_val: str):
    return _detect_addr_family(ip_val) == 6


def _parse_ping_avg_ms(output_text: str):
    if not output_text:
        return None

    linux_match = re.search(r'=\s*[\d.]+/([\d.]+)/[\d.]+/[\d.]+\s*ms', output_text)
    if linux_match:
        try:
            return round(float(linux_match.group(1)), 3)
        except Exception:
            pass

    windows_avg = re.search(r'Average\s*=\s*([\d.]+)\s*ms', output_text, re.IGNORECASE)
    if windows_avg:
        try:
            return round(float(windows_avg.group(1)), 3)
        except Exception:
            pass

    windows_avg_zh = re.search(r'平均\s*=\s*([\d.]+)\s*ms', output_text, re.IGNORECASE)
    if windows_avg_zh:
        try:
            return round(float(windows_avg_zh.group(1)), 3)
        except Exception:
            pass

    samples = re.findall(r'(?:time|时间)\s*[=<]\s*([\d.]+)\s*ms', output_text, re.IGNORECASE)
    if samples:
        try:
            vals = [float(v) for v in samples]
            return round(sum(vals) / len(vals), 3)
        except Exception:
            return None
    return None


def _build_local_ping_command(host: str, packet_count: int, timeout_seconds: int):
    packet_count = max(1, min(int(packet_count or 4), 10))
    timeout_seconds = max(1, min(int(timeout_seconds or 3), 10))
    is_windows = platform.system().lower().startswith('win')
    if is_windows:
        timeout_ms = timeout_seconds * 1000
        cmd = ['ping', '-n', str(packet_count), '-w', str(timeout_ms), host]
    else:
        cmd = ['ping', '-n', '-c', str(packet_count), '-W', str(timeout_seconds), host]
    return cmd


def _ping_from_panel(host: str, packet_count: int = 4, timeout_seconds: int = 3):
    host = (host or '').strip()
    if not host:
        return {
            'ok': False,
            'reachable': False,
            'avg_ms': None,
            'message': 'missing_host',
            'command': '',
            'output': '',
            'exit_code': None,
            'source': 'panel_local',
        }

    cmd = _build_local_ping_command(host, packet_count, timeout_seconds)
    command_str = shlex.join(cmd)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max(packet_count * timeout_seconds + 5, 8),
            check=False,
        )
        output_text = ((proc.stdout or '') + (proc.stderr or '')).strip()
        if len(output_text) > 12000:
            output_text = output_text[:12000] + '\n...[truncated]'
        avg_ms = _parse_ping_avg_ms(output_text)
        return {
            'ok': True,
            'reachable': proc.returncode == 0,
            'avg_ms': avg_ms,
            'message': 'reachable' if proc.returncode == 0 else 'unreachable',
            'command': command_str,
            'output': output_text,
            'exit_code': proc.returncode,
            'source': 'panel_local',
        }
    except FileNotFoundError:
        return {
            'ok': False,
            'reachable': False,
            'avg_ms': None,
            'message': 'ping_command_not_found',
            'command': command_str,
            'output': 'ping command not found on panel host',
            'exit_code': None,
            'source': 'panel_local',
        }
    except subprocess.TimeoutExpired as e:
        out = ((e.stdout or '') + (e.stderr or '')).strip()
        return {
            'ok': False,
            'reachable': False,
            'avg_ms': None,
            'message': 'ping_timeout',
            'command': command_str,
            'output': out,
            'exit_code': None,
            'source': 'panel_local',
        }
    except Exception as e:
        return {
            'ok': False,
            'reachable': False,
            'avg_ms': None,
            'message': f'ping_failed: {e}',
            'command': command_str,
            'output': str(e),
            'exit_code': None,
            'source': 'panel_local',
        }


def _ping_via_checker(tester_ip: str, host: str, packet_count: int = 4, timeout_seconds: int = 3):
    tester_ip = (tester_ip or '').strip()
    host = (host or '').strip()
    if not host:
        return {
            'ok': False,
            'reachable': False,
            'avg_ms': None,
            'message': 'missing_host',
            'command': '',
            'output': '',
            'exit_code': None,
            'source': 'checker',
        }
    if not tester_ip:
        return {
            'ok': False,
            'reachable': False,
            'avg_ms': None,
            'message': 'missing_tester_ip',
            'command': '',
            'output': 'tester_ip is required for checker mode',
            'exit_code': None,
            'source': 'checker',
        }

    url = f'http://{tester_ip}:8888/ping'
    command_str = f"curl -s '{url}?host={host}'"
    try:
        resp = requests.get(
            url,
            params={'host': host, 'count': max(1, min(int(packet_count or 4), 10)), 'timeout': max(1, min(int(timeout_seconds or 3), 10))},
            timeout=15,
        )
        output_text = (resp.text or '').strip()
        if len(output_text) > 12000:
            output_text = output_text[:12000] + '\n...[truncated]'
        if not resp.ok:
            return {
                'ok': False,
                'reachable': False,
                'avg_ms': None,
                'message': f'checker_http_{resp.status_code}',
                'command': command_str,
                'output': output_text,
                'exit_code': resp.status_code,
                'source': 'checker',
            }

        data = resp.json() if resp.content else {}
        return {
            'ok': True,
            'reachable': bool(data.get('reachable', False)),
            'avg_ms': data.get('avg_ms'),
            'message': 'reachable' if data.get('reachable', False) else 'unreachable',
            'command': command_str,
            'output': output_text,
            'exit_code': 0,
            'source': 'checker',
        }
    except Exception as e:
        return {
            'ok': False,
            'reachable': False,
            'avg_ms': None,
            'message': f'checker_request_failed: {e}',
            'command': command_str,
            'output': str(e),
            'exit_code': None,
            'source': 'checker',
        }


def _get_failover_test_mode():
    mode = (os.environ.get('DNS_FAILOVER_TEST_MODE') or 'panel_local').strip().lower()
    return mode if mode in ('panel_local', 'checker') else 'panel_local'


def _check_reachability_via_tester(tester_ip: str, host: str, port: int = 0):
    mode = _get_failover_test_mode()
    if mode == 'checker':
        result = _ping_via_checker(tester_ip, host, packet_count=2, timeout_seconds=3)
        return bool(result.get('ok')) and bool(result.get('reachable', False))
    result = _ping_from_panel(host, packet_count=2, timeout_seconds=3)
    return bool(result.get('reachable', False))


def select_best_available_server(failover: DnsFailover, tester_ip: str):
    ids = [failover.primary_server_id] + failover.backup_ids
    for sid in ids:
        server = ProbeServer.query.get(sid)
        if not server:
            continue
        if not is_probe_online(server):
            continue
        ip_val = _get_target_ip(server)
        if not ip_val:
            continue
        if _check_reachability_via_tester(tester_ip, ip_val, 0):
            return server
    return None


def apply_dns_switch(failover: DnsFailover, target_server: ProbeServer, trigger='switch'):
    cfg = CloudflareConfig.query.first()
    if not cfg or not cfg.decrypted_api_token or not cfg.zone_id:
        raise RuntimeError('Cloudflare 配置不完整')

    target_ip = _get_target_ip(target_server)
    if not target_ip:
        raise RuntimeError('目标服务器没有可用 IP')

    record_type = 'AAAA' if _is_ipv6(target_ip) else 'A'
    cf = CloudflareManager(cfg.decrypted_api_token)
    cf.upsert_dns_record(cfg.zone_id, failover.domain, record_type, target_ip)

    old_server_id = failover.current_active_server_id
    failover.current_active_server_id = target_server.id
    failover.last_switch_time = _utcnow()

    _record_failover_log(
        failover.id,
        trigger,
        f'{failover.domain} 切换到 {target_server.name} ({target_ip})',
        from_server_id=old_server_id,
        to_server_id=target_server.id,
    )


def evaluate_failover_rule(failover: DnsFailover, tester_ip: str, send_alert_func=None, alert_cfg=None):
    failover.last_check_time = _utcnow()

    current_server = ProbeServer.query.get(failover.current_active_server_id) if failover.current_active_server_id else None
    if not current_server:
        current_server = ProbeServer.query.get(failover.primary_server_id)

    should_switch = False
    reason = ''

    if not current_server:
        should_switch = True
        reason = '当前活动服务器不存在'
    else:
        current_ip = _get_target_ip(current_server)
        if not is_probe_online(current_server):
            should_switch = True
            reason = f'节点离线: {current_server.name}'
        elif not current_ip:
            should_switch = True
            reason = f'节点无可用 IP: {current_server.name}'
        elif not _check_reachability_via_tester(tester_ip, current_ip, 0):
            should_switch = True
            reason = f'Ping 不可达: {current_server.name} ({current_ip})'

    if not should_switch:
        _record_failover_log(failover.id, 'check', f'{failover.domain} 检测正常')
        return {'switched': False, 'message': 'normal'}

    candidate_ids = failover.backup_ids[:]
    if failover.primary_server_id not in candidate_ids:
        candidate_ids.insert(0, failover.primary_server_id)

    target = None
    for sid in candidate_ids:
        srv = ProbeServer.query.get(sid)
        if not srv:
            continue
        ip_val = _get_target_ip(srv)
        if not ip_val:
            continue
        if is_probe_online(srv) and _check_reachability_via_tester(tester_ip, ip_val, 0):
            target = srv
            break

    if not target:
        msg = f'DNS 故障转移失败：{failover.domain} 所有节点不可用，原因: {reason}'
        _record_failover_log(failover.id, 'emergency', msg)
        if send_alert_func and alert_cfg and alert_cfg.enabled and alert_cfg.webhook_url:
            send_alert_func(alert_cfg.notify_type, alert_cfg.webhook_url, msg, instance_name=failover.domain)
        return {'switched': False, 'message': 'all_unavailable'}

    apply_dns_switch(failover, target, trigger='switch')

    if send_alert_func and alert_cfg and alert_cfg.enabled and alert_cfg.webhook_url:
        msg = f'DNS 故障转移: {failover.domain} -> {target.name} ({_get_target_ip(target)})，原因: {reason}'
        send_alert_func(alert_cfg.notify_type, alert_cfg.webhook_url, msg, instance_name=failover.domain)

    return {'switched': True, 'message': reason, 'target_server_id': target.id}


@sock.route('/ws/agent')
def ws_agent(ws):
    server = None

    try:
        token = request.args.get('token', '').strip()
        if token:
            server = ProbeServer.query.filter_by(token=token).first()

        while True:
            raw = ws.receive()
            if raw is None:
                break

            try:
                payload = json.loads(raw)
            except Exception:
                ws.send(json.dumps({'ok': False, 'message': 'invalid_json'}))
                continue

            if not server:
                t = (payload.get('token') or '').strip()
                if t:
                    server = ProbeServer.query.filter_by(token=t).first()

            if not server:
                ws.send(json.dumps({'ok': False, 'message': 'unauthorized'}))
                break

            now = _utcnow()
            server.is_online = True
            server.last_seen = now

            msg_type = payload.get('type', '')
            basic = payload.get('basic') or payload.get('basicInfo')
            report = payload.get('report')

            if msg_type == 'auth':
                ws.send(json.dumps({'ok': True, 'message': 'authenticated'}))
                db.session.commit()
                continue

            if msg_type == 'basic' and not basic:
                basic = payload
            if msg_type == 'report' and not report:
                report = payload

            if basic:
                server.name = basic.get('hostname') or server.name
                server.cpu_name = basic.get('cpu_name') or server.cpu_name
                server.arch = basic.get('arch') or server.arch
                server.os_info = basic.get('os_info') or server.os_info
                server.virtualization = basic.get('virtualization') or server.virtualization
                server.cpu_cores = _to_int(basic.get('cpu_cores'), server.cpu_cores or 0)
                server.mem_total = int(basic.get('mem_total') or server.mem_total or 0)
                server.swap_total = int(basic.get('swap_total') or server.swap_total or 0)
                server.disk_total = int(basic.get('disk_total') or server.disk_total or 0)

                v4 = _normalize_ip(basic.get('ipv4', ''))
                v6 = _normalize_ip(basic.get('ipv6', ''))
                if v4 and _detect_addr_family(v4) == 4:
                    server.ipv4 = v4
                if v6 and _detect_addr_family(v6) == 6:
                    server.ipv6 = v6

            if report:
                _update_runtime_cache(server.id, report)
                server.set_latest_report(report)

            if not server.ipv4 or not server.ipv6:
                for cand in _request_ip_candidates():
                    fam = _detect_addr_family(cand)
                    if fam == 4 and not server.ipv4:
                        server.ipv4 = cand
                    elif fam == 6 and not server.ipv6:
                        server.ipv6 = cand

            db.session.commit()
    except Exception:
        db.session.rollback()
    finally:
        if server and not server.last_seen:
            server.last_seen = _utcnow()
            db.session.commit()


@probe.route('/api/probe/report', methods=['POST'])
def api_probe_report():
    """Agent HTTP 上报接口（不需要登录，基于 token 鉴权）。"""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'ok': False, 'message': 'invalid_json'}), 400

    token = (data.get('token') or '').strip()
    if not token:
        return jsonify({'ok': False, 'message': 'no_token'}), 401

    server = ProbeServer.query.filter_by(token=token).first()
    if not server:
        return jsonify({'ok': False, 'message': 'unauthorized'}), 401

    now = _utcnow()
    server.is_online = True
    server.last_seen = now

    basic = data.get('basic')
    report = data.get('report')

    if basic:
        server.name = basic.get('hostname') or server.name
        server.cpu_name = basic.get('cpu_name') or server.cpu_name
        server.arch = basic.get('arch') or server.arch
        server.os_info = basic.get('os_info') or server.os_info
        server.virtualization = basic.get('virtualization') or server.virtualization
        server.cpu_cores = _to_int(basic.get('cpu_cores'), server.cpu_cores or 0)
        server.mem_total = int(basic.get('mem_total') or server.mem_total or 0)
        server.swap_total = int(basic.get('swap_total') or server.swap_total or 0)
        server.disk_total = int(basic.get('disk_total') or server.disk_total or 0)

        v4 = _normalize_ip(basic.get('ipv4', ''))
        v6 = _normalize_ip(basic.get('ipv6', ''))
        if v4 and _detect_addr_family(v4) == 4:
            server.ipv4 = v4
        if v6 and _detect_addr_family(v6) == 6:
            server.ipv6 = v6

    if report:
        _update_runtime_cache(server.id, report)
        server.set_latest_report(report)

    if not server.ipv4 or not server.ipv6:
        for cand in _request_ip_candidates():
            fam = _detect_addr_family(cand)
            if fam == 4 and not server.ipv4:
                server.ipv4 = cand
            elif fam == 6 and not server.ipv6:
                server.ipv6 = cand

    db.session.commit()
    return jsonify({'ok': True})


@probe.route('/api/probe/health', methods=['GET'])
def api_probe_health():
    """探针健康检查接口（无需登录）。"""
    return jsonify({
        'ok': True,
        'message': 'probe endpoint is available',
        'websocket_path': '/ws/agent',
        'http_fallback_path': '/api/probe/report',
    })


@probe.route('/probe/servers')
@login_required
def probe_servers_page():
    refresh_probe_online_statuses()
    servers = ProbeServer.query.order_by(ProbeServer.created_at.desc()).all()
    payload = [_serialize_server(s, include_realtime=True) for s in servers]
    ecs_instances = EcsInstance.query.order_by(EcsInstance.name.asc()).all()
    return render_template('probe_servers.html', servers=payload, ecs_instances=ecs_instances)


@probe.route('/agent/install.sh')
def serve_install_script():
    """Serve probe installer script."""
    script_path = os.path.join(os.path.dirname(__file__), 'agent', 'install.sh')
    return send_file(script_path, mimetype='text/x-shellscript')


@probe.route('/agent/agent.py')
def serve_agent_script():
    """Serve probe agent script."""
    script_path = os.path.join(os.path.dirname(__file__), 'agent', 'agent.py')
    return send_file(script_path, mimetype='text/x-python')


@probe.route('/agent/install_checker.sh')
def serve_install_checker_script():
    """Serve checker installer script."""
    script_path = os.path.join(os.path.dirname(__file__), 'agent', 'install_checker.sh')
    return send_file(script_path, mimetype='text/x-shellscript')


@probe.route('/agent/install_checker_cn.sh')
def serve_install_checker_cn_script():
    """Serve CN checker installer script."""
    script_path = os.path.join(os.path.dirname(__file__), 'agent', 'install_checker_cn.sh')
    return send_file(script_path, mimetype='text/x-shellscript')


@probe.route('/agent/install_checker_global.sh')
def serve_install_checker_global_script():
    """Serve global checker installer script."""
    script_path = os.path.join(os.path.dirname(__file__), 'agent', 'install_checker_global.sh')
    return send_file(script_path, mimetype='text/x-shellscript')


@probe.route('/agent/port_checker.py')
def serve_port_checker_script():
    """Serve port checker script."""
    script_path = os.path.join(os.path.dirname(__file__), 'agent', 'port_checker.py')
    return send_file(script_path, mimetype='text/x-python')


@probe.route('/probe/server/<int:server_id>')
@login_required
def probe_server_detail_page(server_id):
    refresh_probe_online_statuses()
    server = ProbeServer.query.get_or_404(server_id)
    data = _serialize_server(server, include_realtime=True)
    ecs_instance = server.ecs_instance if server.server_type == 'aliyun' else None
    ecs_instances = EcsInstance.query.order_by(EcsInstance.name.asc()).all()
    return render_template('probe_server_detail.html', server=data, ecs_instance=ecs_instance, ecs_instances=ecs_instances)


@probe.route('/dns/failover')
@login_required
def dns_failover_page():
    refresh_probe_online_statuses()
    cfg = CloudflareConfig.query.first()
    if not cfg:
        cfg = CloudflareConfig()
        db.session.add(cfg)
        db.session.commit()

    rules = DnsFailover.query.order_by(DnsFailover.created_at.desc()).all()
    servers = ProbeServer.query.order_by(ProbeServer.name.asc()).all()
    server_map = {s.id: s for s in servers}
    logs = DnsFailoverLog.query.order_by(DnsFailoverLog.created_at.desc()).limit(100).all()
    auto_test_mode = _get_failover_test_mode()

    return render_template(
        'dns_failover.html',
        cfg=cfg,
        rules=rules,
        servers=servers,
        logs=logs,
        server_map=server_map,
        auto_test_mode=auto_test_mode,
    )


@probe.route('/dns/failover/checker-deploy')
@login_required
def checker_deploy_page():
    panel_url = (os.environ.get('PUBLIC_PANEL_URL') or request.url_root).rstrip('/')
    install_cmd_cn = (
        f"curl -fsSL {panel_url}/agent/install_checker_cn.sh -o /tmp/install_checker_cn.sh && "
        f"PANEL_BASE_URL={panel_url} bash /tmp/install_checker_cn.sh"
    )
    install_cmd_global = (
        f"curl -fsSL {panel_url}/agent/install_checker_global.sh -o /tmp/install_checker_global.sh && "
        f"PANEL_BASE_URL={panel_url} bash /tmp/install_checker_global.sh"
    )
    install_cmd_legacy = (
        f"curl -fsSL {panel_url}/agent/install_checker.sh -o /tmp/install_checker.sh && "
        f"PANEL_BASE_URL={panel_url} bash /tmp/install_checker.sh"
    )
    verify_cmd = "curl -s 'http://127.0.0.1:8888/ping?host=1.1.1.1'"
    return render_template(
        'checker_deploy.html',
        panel_url=panel_url,
        install_cmd_cn=install_cmd_cn,
        install_cmd_global=install_cmd_global,
        install_cmd_legacy=install_cmd_legacy,
        verify_cmd=verify_cmd,
    )


@probe.route('/api/probe/servers', methods=['GET'])
@login_required
def api_probe_servers():
    refresh_probe_online_statuses()
    servers = ProbeServer.query.order_by(ProbeServer.created_at.desc()).all()
    return jsonify({'servers': [_serialize_server(s, include_realtime=True) for s in servers]})


@probe.route('/api/probe/server/<int:server_id>', methods=['GET'])
@login_required
def api_probe_server_detail(server_id):
    refresh_probe_online_statuses()
    server = ProbeServer.query.get_or_404(server_id)
    return jsonify({'server': _serialize_server(server, include_realtime=True)})


@probe.route('/api/probe/servers', methods=['POST'])
@login_required
def api_create_probe_server():
    data = request.get_json(silent=True) or request.form
    name = (data.get('name') or '').strip()
    server_type = (data.get('server_type') or 'generic').strip()
    ecs_instance_id = data.get('ecs_instance_id')
    notes = (data.get('notes') or '').strip()
    tag = (data.get('tag') or '').strip()

    if not name:
        return jsonify({'success': False, 'message': 'name 涓嶈兘涓虹┖'}), 400
    if server_type not in ('aliyun', 'generic'):
        return jsonify({'success': False, 'message': 'server_type 闈炴硶'}), 400

    token = secrets.token_urlsafe(32)
    server = ProbeServer(
        name=name,
        token=token,
        server_type=server_type,
        ecs_instance_id=_to_int(ecs_instance_id, 0) or None,
        notes=notes,
        tag=tag,
    )

    db.session.add(server)
    db.session.commit()

    from routes import log_operation
    log_operation('probe_add', f'娣诲姞鎺㈤拡鏈嶅姟鍣?{name}')
    db.session.commit()

    return jsonify({'success': True, 'server': _serialize_server(server, include_realtime=False)})


@probe.route('/api/probe/servers/<int:server_id>', methods=['DELETE'])
@login_required
def api_delete_probe_server(server_id):
    server = ProbeServer.query.get_or_404(server_id)
    name = server.name
    _clear_runtime_cache(server.id)
    db.session.delete(server)

    from routes import log_operation
    log_operation('probe_delete', f'鍒犻櫎鎺㈤拡鏈嶅姟鍣?{name}')

    db.session.commit()
    return jsonify({'success': True})


@probe.route('/api/probe/servers/<int:server_id>', methods=['POST'])
@login_required
def api_update_probe_server(server_id):
    server = ProbeServer.query.get_or_404(server_id)
    data = request.get_json(silent=True) or request.form

    server.name = (data.get('name') or server.name).strip()
    server.server_type = (data.get('server_type') or server.server_type).strip()
    server.notes = (data.get('notes') or server.notes or '').strip()
    server.tag = (data.get('tag') or server.tag or '').strip()

    ecs_instance_id = data.get('ecs_instance_id')
    server.ecs_instance_id = _to_int(ecs_instance_id, 0) or None

    db.session.commit()

    from routes import log_operation
    log_operation('probe_edit', f'缂栬緫鎺㈤拡鏈嶅姟鍣?{server.name}', instance_id=server.ecs_instance_id)
    db.session.commit()

    return jsonify({'success': True, 'server': _serialize_server(server, include_realtime=False)})


@probe.route('/api/probe/servers/<int:server_id>/reset-token', methods=['POST'])
@login_required
def api_reset_probe_token(server_id):
    server = ProbeServer.query.get_or_404(server_id)
    server.token = secrets.token_urlsafe(32)
    db.session.commit()

    from routes import log_operation
    log_operation('probe_reset_token', f'閲嶇疆鎺㈤拡 Token: {server.name}')
    db.session.commit()

    return jsonify({'success': True, 'token': server.token})


@probe.route('/dns/failover/cloudflare', methods=['POST'])
@login_required
def save_cloudflare_config():
    cfg = CloudflareConfig.query.first()
    if not cfg:
        cfg = CloudflareConfig()
        db.session.add(cfg)

    api_token = request.form.get('api_token', '').strip()
    zone_id = request.form.get('zone_id', '').strip()
    domain = request.form.get('domain', '').strip()
    tester_ip = request.form.get('tester_ip', '').strip()

    if api_token:
        cfg.set_api_token(api_token)
    cfg.zone_id = zone_id
    cfg.domain = domain
    cfg.tester_ip = tester_ip

    db.session.commit()

    from routes import log_operation
    log_operation('dns_cf_config', '更新 Cloudflare 配置')
    db.session.commit()

    flash('Cloudflare 配置已保存', 'success')
    return redirect(url_for('probe.dns_failover_page'))


@probe.route('/api/dns/failover/manual-test', methods=['POST'])
@login_required
def api_dns_manual_test():
    data = request.get_json(silent=True) or request.form
    host = (data.get('host') or '').strip()
    packet_count = _to_int(data.get('packet_count'), 4)
    test_mode = (data.get('mode') or 'panel_local').strip()
    if test_mode not in ('panel_local', 'checker'):
        test_mode = 'panel_local'
    tester_ip = (data.get('tester_ip') or '').strip()

    if not host:
        return jsonify({'success': False, 'message': '请填写目标主机/IP', 'source': 'panel_local'}), 400

    if test_mode == 'checker':
        if not tester_ip:
            cfg = CloudflareConfig.query.first()
            tester_ip = (cfg.tester_ip or '').strip() if cfg else ''
        result = _ping_via_checker(tester_ip, host, packet_count=packet_count, timeout_seconds=3)
    else:
        result = _ping_from_panel(host, packet_count=packet_count, timeout_seconds=3)

    if not result.get('ok'):
        return jsonify({
            'success': False,
            'reachable': False,
            'avg_ms': None,
            'host': host,
            'packet_count': packet_count,
            'source': result.get('source', 'panel_local' if test_mode != 'checker' else 'checker'),
            'tester_ip': tester_ip,
            'command': result.get('command', ''),
            'output': result.get('output', ''),
            'exit_code': result.get('exit_code'),
            'message': result.get('message') or '测试失败',
        }), 502

    return jsonify({
        'success': True,
        'reachable': bool(result.get('reachable', False)),
        'avg_ms': result.get('avg_ms'),
        'host': host,
        'packet_count': packet_count,
        'source': result.get('source', 'panel_local' if test_mode != 'checker' else 'checker'),
        'tester_ip': tester_ip,
        'command': result.get('command', ''),
        'output': result.get('output', ''),
        'exit_code': result.get('exit_code'),
        'message': 'reachable' if result.get('reachable', False) else 'unreachable',
    })


@probe.route('/dns/failover/rule', methods=['POST'])
@login_required
def create_dns_failover_rule():
    domain = request.form.get('domain', '').strip()
    primary_server_id = _to_int(request.form.get('primary_server_id'), 0)
    backup_server_ids = request.form.getlist('backup_server_ids')
    check_port = 0
    check_interval_minutes = _to_int(request.form.get('check_interval_minutes'), 10)

    if not domain or not primary_server_id:
        flash('鍩熷悕鍜屼富鐢ㄦ湇鍔″櫒涓哄繀濉」', 'danger')
        return redirect(url_for('probe.dns_failover_page'))

    rule = DnsFailover(
        domain=domain,
        primary_server_id=primary_server_id,
        check_port=check_port,
        check_interval_minutes=check_interval_minutes,
        current_active_server_id=primary_server_id,
        enabled=True,
    )
    rule.set_backup_ids(backup_server_ids)

    db.session.add(rule)

    from routes import log_operation
    log_operation('dns_rule_add', f'娣诲姞鏁呴殰杞Щ瑙勫垯 {domain}')

    db.session.commit()
    flash('故障转移规则已创建', 'success')
    return redirect(url_for('probe.dns_failover_page'))


@probe.route('/dns/failover/rule/<int:rule_id>/edit', methods=['POST'])
@login_required
def edit_dns_failover_rule(rule_id):
    rule = DnsFailover.query.get_or_404(rule_id)

    domain = request.form.get('domain', '').strip()
    primary_server_id = _to_int(request.form.get('primary_server_id'), 0)
    backup_server_ids = request.form.getlist('backup_server_ids')
    check_interval_minutes = _to_int(request.form.get('check_interval_minutes'), 10)

    if domain:
        rule.domain = domain
    if primary_server_id:
        rule.primary_server_id = primary_server_id
    rule.check_interval_minutes = check_interval_minutes
    rule.set_backup_ids(backup_server_ids)

    from routes import log_operation
    log_operation('dns_rule_edit', f'缂栬緫鏁呴殰杞Щ瑙勫垯 {rule.domain}')
    db.session.commit()

    flash('规则已更新', 'success')
    return redirect(url_for('probe.dns_failover_page'))


@probe.route('/dns/failover/rule/<int:rule_id>/toggle', methods=['POST'])
@login_required
def toggle_dns_failover_rule(rule_id):
    rule = DnsFailover.query.get_or_404(rule_id)
    rule.enabled = not rule.enabled

    _record_failover_log(rule.id, 'toggle', f'规则 {rule.domain} 已{"启用" if rule.enabled else "禁用"}')

    from routes import log_operation
    log_operation('dns_rule_toggle', f'{rule.domain} -> {"启用" if rule.enabled else "禁用"}')

    db.session.commit()
    return jsonify({'success': True, 'enabled': rule.enabled})


@probe.route('/dns/failover/rule/<int:rule_id>/switch', methods=['POST'])
@login_required
def manual_switch_dns(rule_id):
    rule = DnsFailover.query.get_or_404(rule_id)
    target_server_id = _to_int(request.form.get('target_server_id') or (request.get_json(silent=True) or {}).get('target_server_id'), 0)
    target = ProbeServer.query.get(target_server_id)
    if not target:
        return jsonify({'success': False, 'message': '鐩爣鏈嶅姟鍣ㄤ笉瀛樺湪'}), 400

    try:
        apply_dns_switch(rule, target, trigger='manual_switch')

        from routes import log_operation
        log_operation('dns_manual_switch', f'{rule.domain} -> {target.name}')

        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


@probe.route('/dns/failover/rule/<int:rule_id>/delete', methods=['POST'])
@login_required
def delete_dns_failover_rule(rule_id):
    rule = DnsFailover.query.get_or_404(rule_id)
    domain = rule.domain
    db.session.delete(rule)

    from routes import log_operation
    log_operation('dns_rule_delete', f'鍒犻櫎鏁呴殰杞Щ瑙勫垯 {domain}')

    db.session.commit()
    flash('规则已删除', 'success')
    return redirect(url_for('probe.dns_failover_page'))


@probe.route('/api/dns/failover/summary', methods=['GET'])
@login_required
def api_dns_failover_summary():
    rules = DnsFailover.query.all()
    enabled_rules = [r for r in rules if r.enabled]
    total = len(rules)
    enabled = len(enabled_rules)

    active = 0
    for rule in enabled_rules:
        cur = ProbeServer.query.get(rule.current_active_server_id) if rule.current_active_server_id else None
        if cur and is_probe_online(cur):
            active += 1

    return jsonify({
        'total_rules': total,
        'enabled_rules': enabled,
        'healthy_rules': active,
    })


@probe.route('/api/dns/failover/logs', methods=['GET'])
@login_required
def api_dns_failover_logs():
    logs = DnsFailoverLog.query.order_by(DnsFailoverLog.created_at.desc()).limit(100).all()
    payload = [
        {
            'id': l.id,
            'action': l.action,
            'message': l.message,
            'created_at': l.created_at.strftime('%Y-%m-%d %H:%M:%S') if l.created_at else '',
        }
        for l in logs
    ]
    return jsonify({'logs': payload})


