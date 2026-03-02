import io
import os
import csv
import json
import re
import base64
import shutil
import subprocess
import unicodedata
import zipfile
import threading
import uuid
from datetime import datetime, timedelta
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask import Blueprint, render_template, redirect, url_for, request, flash, send_file, jsonify, current_app, abort, has_request_context
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
from monitor import check_and_manage_instance, ecs_stop, ecs_start, ecs_release, get_region_traffic, get_client, get_security_groups, describe_sg_rules, authorize_sg, revoke_sg, ecs_enable_ipv6, get_ecs_ipv6_info
from notifier import send_alert

main = Blueprint('main', __name__)

# 鈹€鈹€ Config 鈹€鈹€
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 10

_IMPORT_JOBS_LOCK = threading.RLock()
_IMPORT_JOB_KEEP_HOURS = 24
_IMPORT_JOB_TIMEOUT_MINUTES = 60
_IMPORT_TEXT_MAX_CHARS = 20000


def _is_probe_online(server):
    if not server or not server.last_seen:
        return False
    return (datetime.utcnow() - server.last_seen).total_seconds() <= 30


IPV6_SCRIPT_TOKEN_SALT = 'ipv6-script-download-v1'


def _ipv6_script_serializer():
    return URLSafeTimedSerializer(current_app.config['SECRET_KEY'], salt=IPV6_SCRIPT_TOKEN_SALT)


def _generate_ipv6_script_token(instance_id):
    return _ipv6_script_serializer().dumps({'instance_id': instance_id})


def _verify_ipv6_script_token(token, instance_id):
    max_age = int(current_app.config.get('IPV6_SCRIPT_TOKEN_EXPIRES', 1800))
    try:
        payload = _ipv6_script_serializer().loads(token or '', max_age=max_age)
    except SignatureExpired:
        return False, 'expired'
    except BadSignature:
        return False, 'invalid'

    if not isinstance(payload, dict) or payload.get('instance_id') != instance_id:
        return False, 'invalid'
    return True, 'ok'


def _build_ipv6_setup_script(instance):
    ipv6_candidates = []
    try:
        client = get_client(instance)
        info = get_ecs_ipv6_info(client, instance)
        ipv6_candidates = info.get('addresses', []) if isinstance(info, dict) else []
    except Exception:
        ipv6_candidates = []

    target_ipv6 = ipv6_candidates[0] if ipv6_candidates else ''
    return f'''#!/usr/bin/env bash
set -euo pipefail

TARGET_IPV6="{target_ipv6}"

echo "[1/5] 启用内核 IPv6 开关"
cat >/etc/sysctl.d/99-enable-ipv6.conf <<'EOF'
net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.default.disable_ipv6 = 0
net.ipv6.conf.lo.disable_ipv6 = 0
EOF
sysctl --system >/dev/null

echo "[2/5] 识别主网卡"
IFACE=$(ip -4 route show default 2>/dev/null | awk '{{print $5}}' | head -n1)
if [[ -z "$IFACE" ]]; then
    IFACE=$(ip -o link show | awk -F': ' '{{print $2}}' | grep -E '^(eth|ens|enp)' | head -n1 || true)
fi
if [[ -z "$IFACE" ]]; then
    echo "[ERROR] 无法识别网卡，请手动配置"
    exit 1
fi
echo "网卡: $IFACE"

echo "[3/5] 打开 IPv6 自动配置"
sysctl -w net.ipv6.conf."$IFACE".accept_ra=2 >/dev/null || true
sysctl -w net.ipv6.conf."$IFACE".autoconf=1 >/dev/null || true

echo "[4/5] 尝试通过网络管理器刷新"
if command -v nmcli >/dev/null 2>&1; then
    CONN=$(nmcli -t -f NAME,DEVICE con show --active | awk -F: -v d="$IFACE" '$2==d {{print $1; exit}}')
    if [[ -n "$CONN" ]]; then
        nmcli con mod "$CONN" ipv6.method auto || true
        nmcli con up "$CONN" || true
    fi
fi

if command -v netplan >/dev/null 2>&1; then
    NETPLAN_FILE="/etc/netplan/99-ipv6-auto.yaml"
    cat >"$NETPLAN_FILE" <<EOF
network:
    version: 2
    ethernets:
        $IFACE:
            dhcp6: true
            accept-ra: true
EOF
    netplan apply || true
fi

if [[ -n "$TARGET_IPV6" ]] && ! ip -6 addr show dev "$IFACE" | grep -q "$TARGET_IPV6"; then
    echo "[5/5] 添加云端分配的 IPv6 地址: $TARGET_IPV6"
    ip -6 addr add "$TARGET_IPV6/128" dev "$IFACE" || true
fi

if ! ip -6 route show default | grep -q '^default'; then
    echo "[extra] 未检测到默认 IPv6 路由，尝试添加 default via fe80::1 dev $IFACE"
    ip -6 route replace default via fe80::1 dev "$IFACE" metric 1024 || true
fi

echo "完成，当前 IPv6 地址如下："
ip -6 addr show dev "$IFACE"
echo "当前 IPv6 路由如下："
ip -6 route show
echo "开始连通性测试（国内优先目标）..."
TEST_TARGETS=("2400:3200::1" "2400:3200:baba::1" "240c::6666" "240c::6644")
for target in "${{TEST_TARGETS[@]}}"; do
    echo "- ping6 $target"
    if ping -6 -c 3 -W 2 "$target" >/dev/null 2>&1; then
        echo "  ✅ 可达"
    else
        echo "  ❌ 不可达"
    fi
done
echo "你也可以测试业务域名: ping -6 -c 3 <你的域名>"
'''


# 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€ Helpers 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

def log_operation(action, detail='', instance_id=None, operator='system'):
    """Write an entry to the operation log.

    Safe for background threads without request/login context.
    """
    resolved_operator = operator
    if has_request_context():
        try:
            if getattr(current_user, 'is_authenticated', False):
                resolved_operator = current_user.username
        except Exception:
            resolved_operator = operator

    op = OperationLog(
        instance_id=instance_id,
        action=action,
        detail=detail,
        operator=resolved_operator or 'system'
    )
    db.session.add(op)


def _compute_instance_stats(inst):
    """Compute traffic stats for an instance.
    Returns a dict with:
      monthly_used, monthly_limit, monthly_remain, monthly_percent  (CYCLE only)
      life_used, life_limit, life_remain, life_percent              (LIFE only)
      percent  (overall)
      cost
    """
    monthly_used = inst.current_month_traffic or 0

    if inst.traffic_strategy == 'life':
        # LIFE: total_traffic_sum is compared directly against life_total_limit
        life_consumed = inst.total_traffic_sum or 0
        life_limit = inst.life_total_limit or 0
        life_remain = max(life_limit - life_consumed, 0) if life_limit > 0 else 0
        life_pct = (life_consumed / life_limit) * 100 if life_limit > 0 else 0
        monthly_limit = monthly_remain = monthly_pct = 0
        percent = life_pct
    else:
        # CYCLE: monthly quota
        monthly_limit = inst.monthly_limit or 0
        monthly_remain = max(monthly_limit - monthly_used, 0) if monthly_limit > 0 else 0
        monthly_pct = (monthly_used / monthly_limit) * 100 if monthly_limit > 0 else 0
        life_consumed = life_limit = life_remain = life_pct = 0
        percent = monthly_pct

    # Cost estimation
    price = inst.hourly_price or 0
    if price > 0 and inst.created_at:
        hours = max((datetime.utcnow() - inst.created_at).total_seconds() / 3600, 0)
        cost = round(price * hours, 2)
    else:
        cost = 0.0

    return {
        'monthly_used': round(monthly_used, 2),
        'monthly_limit': round(monthly_limit, 2),
        'monthly_remain': round(monthly_remain, 2),
        'monthly_percent': round(monthly_pct, 1),
        'life_used': round(life_consumed, 2),
        'life_limit': round(life_limit, 2),
        'life_remain': round(life_remain, 2),
        'life_percent': round(life_pct, 1),
        'percent': round(percent, 1),
        'cost': cost,
    }


def _parse_non_negative_float(value, field_label):
    try:
        num = float(value or 0)
    except (TypeError, ValueError):
        raise ValueError(f'{field_label} 必须是数字')
    if num < 0:
        raise ValueError(f'{field_label} 不能为负数')
    return num


def _normalize_days_of_week(value):
    raw = (value or '*').strip()
    if not raw or raw == '*':
        return '*', None

    parts = [p.strip() for p in raw.split(',') if p.strip()]
    if not parts:
        return '*', None

    normalized = []
    for p in parts:
        if not p.isdigit():
            return None, '日期格式无效，请使用 * 或 1-7 的逗号分隔值'
        day = int(p)
        if day < 1 or day > 7:
            return None, '日期范围无效，请使用 1-7（1=周一，7=周日）'
        if str(day) not in normalized:
            normalized.append(str(day))

    return ','.join(normalized), None


def _slugify_account(value):
    text = (value or '').strip().lower()
    if not text:
        return ''
    text = unicodedata.normalize('NFKD', text)
    text = text.encode('ascii', 'ignore').decode('ascii')
    text = re.sub(r'[^a-z0-9]+', '-', text)
    text = re.sub(r'-{2,}', '-', text).strip('-')
    return text[:80]


def _safe_yaml_str(value):
    s = '' if value is None else str(value)
    s = s.replace('\\', '\\\\').replace('"', '\\"')
    return f'"{s}"'


def _classify_import_error(err):
    raw_error = str(err or '').strip() or '未知错误'
    text = raw_error.lower()

    if any(k in text for k in ['task_interrupted', '任务中断', '进程中断']):
        return {
            'error_type': 'task_interrupted',
            'error_code': 'TASK_INTERRUPTED',
            'message': '导入任务中断，未能完成。',
            'suggestion': '请重新发起导入；若频繁发生，请检查服务稳定性与后台日志。',
            'raw_error': raw_error,
        }

    def _meta(error_type, error_code, message, suggestion):
        return {
            'error_type': error_type,
            'error_code': error_code,
            'message': message,
            'suggestion': suggestion,
            'raw_error': raw_error,
        }

    github_keywords = ['github', 'gh cli', 'gh auth', '仓库', 'repo']
    github_failure_hints = ['同步', 'sync', 'fail', '失败', 'error', 'token', 'forbidden', 'permission', '权限']
    if any(k in text for k in github_keywords) and any(k in text for k in github_failure_hints):
        return _meta(
            'github_sync_failed',
            'GITHUB_SYNC_FAILED',
            'GitHub 同步失败，请检查登录状态与仓库权限。',
            '请先执行 gh auth status/gh auth login，确认仓库可写后重试。',
        )

    if any(k in text for k in [
        'invalidaccesskeyid', 'signaturedoesnotmatch', 'incomplete signatures',
        'access key id is not valid', 'accesskey secret', 'ak/sk', '认证失败', '鉴权失败',
        '未识别到 accesskey', '未识别到 accesskey id/secret'
    ]):
        return _meta(
            'auth_failed',
            'AUTH_FAILED',
            '认证失败（AK/SK 可能错误或格式不正确）。',
            '请核对 AccessKey ID/Secret 是否完整、未过期，并确认粘贴内容正确。',
        )

    if any(k in text for k in [
        'forbidden', 'unauthorized', 'no permission', 'permission denied',
        'ram', 'accessdenied', 'operationdenied', '权限不足'
    ]):
        return _meta(
            'permission_denied',
            'PERMISSION_DENIED',
            '权限不足（RAM 权限不满足）。',
            '请为该 AK 分配 ECS 只读/管理所需权限（如 ecs:Describe*）后重试。',
        )

    if any(k in text for k in [
        'throttl', 'ratelimit', 'rate limit', 'too many requests',
        'requestlimitexceeded', 'frequency', '限流', '频率限制'
    ]):
        return _meta(
            'api_rate_limited',
            'API_RATE_LIMITED',
            'API 调用过于频繁，已被限流。',
            '请稍后重试，或降低并发/调用频率。',
        )

    if any(k in text for k in [
        'timeout', 'timed out', 'connection', 'max retries exceeded',
        'name or service not known', 'temporarily unavailable', '网络错误', '连接失败'
    ]):
        return _meta(
            'network_error',
            'NETWORK_ERROR',
            '网络连接异常（超时或连接失败）。',
            '请检查当前网络、DNS/代理设置，稍后重试。',
        )

    return _meta(
        'unknown_error',
        'UNKNOWN_ERROR',
        '未知错误，导入未完成。',
        '请重试一次；若仍失败，请联系管理员并提供错误时间与账号标识。',
    )


def _parse_account_text(raw_text):
    """Parse AK/SK and optional metadata from free-form text (CN/EN labels)."""
    text = (raw_text or '').replace('\r\n', '\n')
    lines = [ln.strip() for ln in text.split('\n') if ln.strip()]

    key_map = {
        'login_name': ['登录名称', '登录名', '账号', '账户', '用户名', 'login name', 'username', 'account'],
        'login_password': ['登录密码', '密码', 'login password', 'passwd', 'password'],
        'access_key_secret': ['accesskey secret', 'access key secret', 'accesskeysecret', 'secret key', 'sk'],
        'access_key_id': ['accesskey id', 'access key id', 'accesskeyid', 'key id', 'akid', 'ak'],
        'security_email': ['安全邮箱', '邮箱', 'email', 'mail'],
        'security_phone': ['安全手机', '手机', 'phone', 'mobile', 'tel'],
        'remark': ['备注', '说明', 'note', 'notes', 'remark', 'memo'],
        'region_id': ['区域', '地域', 'region id', 'region_id', 'region'],
    }

    parsed = {}
    for line in lines:
        normalized = line.replace('：', ':')
        if ':' not in normalized:
            continue
        left, right = normalized.split(':', 1)
        key = left.strip().lower()
        key_nospace = re.sub(r'\s+', '', key)
        value = right.strip()
        if not value:
            continue
        for target, aliases in key_map.items():
            matched = False
            for alias in aliases:
                alias_l = alias.lower()
                alias_nospace = re.sub(r'\s+', '', alias_l)
                if key == alias_l or key_nospace == alias_nospace or alias_l in key:
                    matched = True
                    break
            if matched:
                parsed[target] = value
                break

    ak = (parsed.get('access_key_id') or '').strip()
    sk = (parsed.get('access_key_secret') or '').strip()

    if not ak:
        m = re.search(r'\b(LTAI[a-zA-Z0-9]{8,})\b', text)
        if m:
            ak = m.group(1)
    if not sk:
        candidates = re.findall(r'\b[a-zA-Z0-9+/=]{24,64}\b', text)
        for cand in candidates:
            if cand != ak and not cand.startswith('LTAI'):
                sk = cand
                break

    login_name = (parsed.get('login_name') or '').strip()
    remark = (parsed.get('remark') or '').strip()
    region_id = (parsed.get('region_id') or '').strip() or 'cn-hangzhou'
    if not re.match(r'^[a-z0-9-]+$', region_id):
        region_id = 'cn-hangzhou'

    account_slug_seed = login_name or remark or (f'account-{ak[-6:].lower()}' if ak else '')
    account_slug = _slugify_account(account_slug_seed) or (f'account-{datetime.utcnow().strftime("%Y%m%d%H%M%S")}')

    return {
        'login_name': login_name,
        'remark': remark,
        'access_key_id': ak,
        'access_key_secret': sk,
        'region_id': region_id,
        'account_slug': account_slug,
    }


def _discover_ecs_instances_all_regions(ak, sk, default_region='cn-hangzhou', scan_all_regions=True):
    """Discover ECS instances.
    scan_all_regions=True 时仅扫描国内常用区域（北京/广州/上海/杭州/深圳），避免全区域慢请求。"""
    from aliyunsdkcore.client import AcsClient
    from aliyunsdkecs.request.v20140526.DescribeRegionsRequest import DescribeRegionsRequest
    from aliyunsdkecs.request.v20140526.DescribeInstancesRequest import DescribeInstancesRequest

    client = AcsClient(ak, sk, default_region)
    client.add_endpoint(default_region, 'Ecs', f'ecs.{default_region}.aliyuncs.com')

    region_ids = [default_region]
    if scan_all_regions:
        preferred_regions = ['cn-beijing', 'cn-guangzhou', 'cn-shanghai', 'cn-hangzhou', 'cn-shenzhen']
        # Keep deterministic preferred order and include default region if user entered another cn-* region.
        region_ids = []
        for rid in preferred_regions + [default_region]:
            if rid and rid not in region_ids:
                region_ids.append(rid)

    discovered = []
    seen_ids = set()

    for region_id in region_ids:
        try:
            rc = AcsClient(ak, sk, region_id)
            rc.add_endpoint(region_id, 'Ecs', f'ecs.{region_id}.aliyuncs.com')
            req = DescribeInstancesRequest()
            req.set_PageSize(100)
            req.set_accept_format('json')
            response = rc.do_action_with_exception(req)
            result = json.loads(response)
            for inst in result.get('Instances', {}).get('Instance', []):
                iid = inst.get('InstanceId')
                if not iid or iid in seen_ids:
                    continue
                seen_ids.add(iid)

                public_ips = inst.get('PublicIpAddress', {}).get('IpAddress', []) or []
                eip = inst.get('EipAddress', {}).get('IpAddress', '')
                if eip:
                    public_ips.append(eip)
                private_ips = inst.get('VpcAttributes', {}).get('PrivateIpAddress', {}).get('IpAddress', []) or []
                ipv6_ips = inst.get('VpcAttributes', {}).get('Ipv6Addresses', {}).get('Ipv6Address', []) or []

                discovered.append({
                    'instance_id': iid,
                    'name': inst.get('InstanceName', iid),
                    'region_id': inst.get('RegionId', region_id),
                    'status': inst.get('Status', 'Unknown'),
                    'public_ip': public_ips[0] if public_ips else '',
                    'private_ip': private_ips[0] if private_ips else '',
                    'ipv6_addr': ipv6_ips[0] if ipv6_ips else '',
                })
        except Exception:
            continue

    return discovered


def _sync_account_to_github(repo, account_slug, payload):
    """Sync account payload to GitHub private repo using gh CLI (overwrite update)."""
    if not shutil.which('gh'):
        return False, '未检测到 gh CLI，请先安装并 gh auth login'

    check = subprocess.run(['gh', 'repo', 'view', repo], capture_output=True, text=True)
    if check.returncode != 0:
        created = subprocess.run(['gh', 'repo', 'create', repo, '--private', '--confirm'], capture_output=True, text=True)
        if created.returncode != 0:
            return False, f'创建 GitHub 仓库失败: {(created.stderr or created.stdout).strip()}'

    file_path = f'accounts/{account_slug}/account.yaml'
    payload_yaml = [
        f'account_slug: {_safe_yaml_str(payload.get("account_slug", ""))}',
        f'account_identifier: {_safe_yaml_str(payload.get("account_identifier", ""))}',
        f'login_name: {_safe_yaml_str(payload.get("login_name", ""))}',
        f'remark: {_safe_yaml_str(payload.get("remark", ""))}',
        f'access_key_id: {_safe_yaml_str(payload.get("access_key_id", ""))}',
        f'access_key_secret: {_safe_yaml_str(payload.get("access_key_secret", ""))}',
        f'region: {_safe_yaml_str(payload.get("region", ""))}',
        f'discovered_at: {_safe_yaml_str(payload.get("discovered_at", ""))}',
        'instances:',
    ]
    for inst in payload.get('instances', []):
        payload_yaml.extend([
            f'  - instance_id: {_safe_yaml_str(inst.get("instance_id", ""))}',
            f'    name: {_safe_yaml_str(inst.get("name", ""))}',
            f'    region: {_safe_yaml_str(inst.get("region_id", ""))}',
            f'    status: {_safe_yaml_str(inst.get("status", ""))}',
            f'    public_ip: {_safe_yaml_str(inst.get("public_ip", ""))}',
            f'    private_ip: {_safe_yaml_str(inst.get("private_ip", ""))}',
            f'    ipv6: {_safe_yaml_str(inst.get("ipv6_addr", ""))}',
        ])
    content_b64 = base64.b64encode(('\n'.join(payload_yaml) + '\n').encode('utf-8')).decode('utf-8')

    sha = None
    get_res = subprocess.run(
        ['gh', 'api', f'repos/{repo}/contents/{file_path}', '--jq', '.sha'],
        capture_output=True,
        text=True,
    )
    if get_res.returncode == 0:
        sha = (get_res.stdout or '').strip() or None

    cmd = [
        'gh', 'api', '--method', 'PUT', f'repos/{repo}/contents/{file_path}',
        '-f', f'message=chore(account-sync): update {account_slug}',
        '-f', f'content={content_b64}',
        '-f', 'branch=main',
    ]
    if sha:
        cmd += ['-f', f'sha={sha}']

    put_res = subprocess.run(cmd, capture_output=True, text=True)
    if put_res.returncode != 0:
        return False, f'GitHub 同步失败: {(put_res.stderr or put_res.stdout).strip()}'
    return True, f'{repo}/{file_path}'


def _new_import_job():
    with _IMPORT_JOBS_LOCK:
        job_id = uuid.uuid4().hex
        now = datetime.utcnow()
        job = ImportJob(
            id=job_id,
            status='queued',
            step='排队中',
            message='任务已创建，等待开始',
            progress=0,
            created_at=now,
            updated_at=now,
        )
        db.session.add(job)
        db.session.commit()
        return job


def _job_is_done(job):
    if not job:
        return False
    if hasattr(job, 'status'):
        return job.status in ('done', 'error')
    return job.get('status') in ('done', 'error')


def _serialize_import_job(job):
    if isinstance(job, ImportJob):
        payload = {
            'id': job.id,
            'status': job.status,
            'step': job.step,
            'message': job.message,
            'progress': job.progress,
            'error': job.error or '',
            'result': job.get_result(),
            'created_at': job.created_at.strftime('%Y-%m-%dT%H:%M:%SZ') if job.created_at else '',
            'updated_at': job.updated_at.strftime('%Y-%m-%dT%H:%M:%SZ') if job.updated_at else '',
            'finished_at': job.finished_at.strftime('%Y-%m-%dT%H:%M:%SZ') if job.finished_at else '',
        }
    else:
        payload = {
            'id': job.get('id'),
            'status': job.get('status'),
            'step': job.get('step'),
            'message': job.get('message'),
            'progress': job.get('progress'),
            'error': job.get('error', ''),
            'result': job.get('result'),
            'created_at': job.get('created_at').strftime('%Y-%m-%dT%H:%M:%SZ') if job.get('created_at') else '',
            'updated_at': job.get('updated_at').strftime('%Y-%m-%dT%H:%M:%SZ') if job.get('updated_at') else '',
            'finished_at': job.get('finished_at').strftime('%Y-%m-%dT%H:%M:%SZ') if job.get('finished_at') else '',
        }

    error_type = ''
    error_code = ''
    suggestion = ''

    if payload.get('status') == 'error':
        result = payload.get('result') or {}
        if isinstance(result, dict) and result.get('error_type'):
            error_type = result.get('error_type') or ''
            error_code = result.get('error_code') or ''
            suggestion = result.get('suggestion') or ''
            if result.get('message'):
                payload['message'] = result.get('message')
        else:
            meta = _classify_import_error(payload.get('error') or payload.get('message') or '')
            error_type = meta.get('error_type', '')
            error_code = meta.get('error_code', '')
            suggestion = meta.get('suggestion', '')
            payload['message'] = meta.get('message') or payload.get('message')

    payload.update({
        'error_type': error_type,
        'error_code': error_code,
        'suggestion': suggestion,
    })
    return payload


def _update_import_job(job_id, **updates):
    with _IMPORT_JOBS_LOCK:
        job = db.session.get(ImportJob, job_id)
        if not job:
            return None

        if _job_is_done(job):
            return job

        for k, v in updates.items():
            if k == 'result':
                job.set_result(v)
            elif hasattr(job, k):
                setattr(job, k, v)

        progress = getattr(job, 'progress', 0)
        try:
            progress = int(progress)
        except (TypeError, ValueError):
            progress = 0
        job.progress = max(0, min(100, progress))
        job.updated_at = datetime.utcnow()
        db.session.commit()
        return job


def _cleanup_import_jobs():
    cutoff = datetime.utcnow() - timedelta(hours=_IMPORT_JOB_KEEP_HOURS)
    with _IMPORT_JOBS_LOCK:
        try:
            ImportJob.query.filter(
                ImportJob.status.in_(['done', 'error']),
                ImportJob.finished_at < cutoff
            ).delete()
            db.session.commit()
        except Exception:
            db.session.rollback()


def _mark_stale_import_job_if_needed(job):
    if not job or _job_is_done(job):
        return job

    if not getattr(job, 'updated_at', None):
        return job

    timeout_cutoff = datetime.utcnow() - timedelta(minutes=_IMPORT_JOB_TIMEOUT_MINUTES)
    if job.updated_at >= timeout_cutoff:
        return job

    elapsed_minutes = int((datetime.utcnow() - job.updated_at).total_seconds() // 60)
    timeout_msg = (
        f'任务长时间未更新（约 {max(elapsed_minutes, _IMPORT_JOB_TIMEOUT_MINUTES)} 分钟），'
        '可能因进程中断导致。请重新发起导入。'
    )
    return _update_import_job(
        job.id,
        status='error',
        step='中断',
        message='导入任务中断，请重新发起。',
        error=timeout_msg,
        result={
            'error_type': 'task_interrupted',
            'error_code': 'TASK_INTERRUPTED',
            'suggestion': '请重新发起导入；若频繁发生，请检查服务稳定性与后台日志。',
            'message': '导入任务中断，未能完成。',
        },
        finished_at=datetime.utcnow(),
    )


def _run_account_import_job(app_obj, job_id, raw_text, scan_all_regions):
    with app_obj.app_context():
        try:
            _update_import_job(job_id, status='running', step='解析中', message='正在解析账号文本', progress=5)
            parsed = _parse_account_text(raw_text)
            ak = parsed.get('access_key_id', '')
            sk = parsed.get('access_key_secret', '')
            if not ak or not sk:
                raise ValueError('解析失败：未识别到 AccessKey ID/Secret，请检查粘贴内容。')

            account_slug = parsed['account_slug']
            default_region = parsed.get('region_id') or 'cn-hangzhou'
            note_parts = [part for part in [parsed.get('remark', '').strip(), f'account:{account_slug}'] if part]
            merged_note = ' | '.join(note_parts)

            _update_import_job(job_id, step='扫描中', message='正在扫描实例（国内常用区域）', progress=35)
            discovered = _discover_ecs_instances_all_regions(ak, sk, default_region, scan_all_regions=scan_all_regions)

            _update_import_job(job_id, step='写入中', message='正在写入数据库并更新实例', progress=65)
            imported = 0
            updated = 0
            for inst in discovered:
                existing = EcsInstance.query.filter_by(instance_id=inst['instance_id']).first()
                if existing:
                    existing.name = (inst.get('name') or existing.name or inst['instance_id']).strip()
                    existing.region_id = inst.get('region_id') or existing.region_id
                    existing.status = inst.get('status') or existing.status or 'Unknown'
                    existing.public_ip = inst.get('public_ip', '')
                    existing.private_ip = inst.get('private_ip', '')
                    existing.ipv6_addr = inst.get('ipv6_addr', '')
                    existing.notes = merged_note or (existing.notes or '')
                    existing.traffic_strategy = 'life'
                    existing.life_total_limit = 500
                    existing.auto_stop_enabled = False
                    existing.auto_start_enabled = True
                    existing.monitoring_enabled = True
                    existing.set_ak_sk(ak, sk)
                    updated += 1
                else:
                    new_instance = EcsInstance(
                        name=(inst.get('name') or inst['instance_id']).strip(),
                        region_id=inst.get('region_id') or default_region,
                        instance_id=inst['instance_id'],
                        status=inst.get('status', 'Unknown'),
                        public_ip=inst.get('public_ip', ''),
                        private_ip=inst.get('private_ip', ''),
                        ipv6_addr=inst.get('ipv6_addr', ''),
                        notes=merged_note,
                        traffic_strategy='life',
                        life_total_limit=500,
                        auto_stop_enabled=False,
                        auto_start_enabled=True,
                        monitoring_enabled=True,
                    )
                    new_instance.set_ak_sk(ak, sk)
                    db.session.add(new_instance)
                    imported += 1

            db.session.flush()

            _update_import_job(job_id, step='同步GitHub中', message='正在同步到 GitHub 私有仓库', progress=85)
            payload = {
                'account_slug': account_slug,
                'account_identifier': parsed.get('login_name') or account_slug,
                'login_name': parsed.get('login_name', ''),
                'remark': parsed.get('remark', ''),
                'access_key_id': ak,
                'access_key_secret': sk,
                'region': default_region,
                'discovered_at': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
                'instances': discovered,
            }
            ok, sync_info = _sync_account_to_github('WithZeng/aliyun-accounts', account_slug, payload)
            if not ok:
                raise RuntimeError(sync_info)

            log_operation('account_import_text', f'文本导入账号 {account_slug}，新增 {imported}，更新 {updated}')
            db.session.commit()

            _update_import_job(
                job_id,
                status='done',
                step='完成',
                message='导入完成',
                progress=100,
                result={
                    'account_slug': account_slug,
                    'discovered_count': len(discovered),
                    'imported_count': imported,
                    'updated_count': updated,
                    'sync_target': sync_info,
                    'instances': discovered,
                },
                finished_at=datetime.utcnow(),
            )
        except Exception as e:
            db.session.rollback()
            meta = _classify_import_error(e)
            _update_import_job(
                job_id,
                status='error',
                step='失败',
                message=meta.get('message', '导入失败'),
                error=meta.get('raw_error', str(e)),
                result={
                    'error_type': meta.get('error_type', ''),
                    'error_code': meta.get('error_code', ''),
                    'suggestion': meta.get('suggestion', ''),
                    'message': meta.get('message', '导入失败'),
                },
                finished_at=datetime.utcnow(),
            )


# 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€ Auth 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€

@main.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('main.login'))


@main.route('/login', methods=['GET', 'POST'])
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
    """Batch start/stop/check instances 鈥?selected by checkbox or tag."""
    action = request.form.get('action')  # start, stop, check
    instance_ids = request.form.getlist('instance_ids')  # from checkboxes
    tag_filter = request.form.get('tag', '')

    if not action:
        flash('请选择操作', 'warning')
        return redirect(url_for('main.dashboard'))

    # If specific instances were selected via checkbox, use those
    if instance_ids:
        instances = EcsInstance.query.filter(EcsInstance.id.in_(instance_ids)).all()
        tag_label = f'选中的 {len(instances)} 个'
    else:
        # Fall back to tag filter
        query = EcsInstance.query
        if tag_filter:
            query = query.filter_by(tag=tag_filter)
        instances = query.all()
        tag_label = f'标签 [{tag_filter}] 下的' if tag_filter else '所有'

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

