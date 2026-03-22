"""
Extracted helper functions for routes.py.

Validators, parsers, error classifiers, import job management,
ECS discovery, GitHub sync, and IPv6 script generation.
"""

import io
import os
import re
import json
import base64
import shutil
import subprocess
import unicodedata
import threading
import uuid
from datetime import datetime, timedelta
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask import current_app, has_request_context
from flask_login import current_user
from models import db, EcsInstance, OperationLog, ImportJob
from monitor import get_client, get_ecs_ipv6_info, BillingQueryError


# ── Probe online check ──

def is_probe_online(server):
    if not server or not server.last_seen:
        return False
    return (datetime.utcnow() - server.last_seen).total_seconds() <= 30


# ── IPv6 Script Token ──

IPV6_SCRIPT_TOKEN_SALT = 'ipv6-script-download-v1'


def ipv6_script_serializer():
    return URLSafeTimedSerializer(current_app.config['SECRET_KEY'], salt=IPV6_SCRIPT_TOKEN_SALT)


def generate_ipv6_script_token(instance_id):
    return ipv6_script_serializer().dumps({'instance_id': instance_id})


def verify_ipv6_script_token(token, instance_id):
    max_age = int(current_app.config.get('IPV6_SCRIPT_TOKEN_EXPIRES', 1800))
    try:
        payload = ipv6_script_serializer().loads(token or '', max_age=max_age)
    except SignatureExpired:
        return False, 'expired'
    except BadSignature:
        return False, 'invalid'

    if not isinstance(payload, dict) or payload.get('instance_id') != instance_id:
        return False, 'invalid'
    return True, 'ok'


def build_ipv6_setup_script(instance):
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


# ── Logging ──

def log_operation(action, detail='', instance_id=None, operator='system'):
    """Write an entry to the operation log. Safe for background threads."""
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


# ── Instance Stats ──

def compute_instance_stats(inst):
    """Compute traffic stats for an instance."""
    monthly_used = inst.current_month_traffic or 0

    if inst.traffic_strategy == 'life':
        life_consumed = inst.total_traffic_sum or 0
        life_limit = inst.life_total_limit or 0
        life_remain = max(life_limit - life_consumed, 0) if life_limit > 0 else 0
        life_pct = (life_consumed / life_limit) * 100 if life_limit > 0 else 0
        monthly_limit = monthly_remain = monthly_pct = 0
        percent = life_pct
    else:
        monthly_limit = inst.monthly_limit or 0
        monthly_remain = max(monthly_limit - monthly_used, 0) if monthly_limit > 0 else 0
        monthly_pct = (monthly_used / monthly_limit) * 100 if monthly_limit > 0 else 0
        life_consumed = life_limit = life_remain = life_pct = 0
        percent = monthly_pct

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


# ── Validators ──

def parse_non_negative_float(value, field_label):
    try:
        num = float(value or 0)
    except (TypeError, ValueError):
        raise ValueError(f'{field_label} 必须是数字')
    if num < 0:
        raise ValueError(f'{field_label} 不能为负数')
    return num


def normalize_days_of_week(value):
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


def slugify_account(value):
    text = (value or '').strip().lower()
    if not text:
        return ''
    text = unicodedata.normalize('NFKD', text)
    text = text.encode('ascii', 'ignore').decode('ascii')
    text = re.sub(r'[^a-z0-9]+', '-', text)
    text = re.sub(r'-{2,}', '-', text).strip('-')
    return text[:80]


def safe_yaml_str(value):
    s = '' if value is None else str(value)
    s = s.replace('\\', '\\\\').replace('"', '\\"')
    return f'"{s}"'


# ── Error Classifiers ──

def classify_import_error(err):
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


def classify_billing_error(err):
    raw_error = str(err or '').strip() or '未知错误'
    text = raw_error.lower()

    if isinstance(err, BillingQueryError):
        return {
            'error_code': err.error_code,
            'message': err.message,
            'raw_error': err.raw_error or raw_error,
        }

    if any(k in text for k in [
        'invalidaccesskeyid', 'signaturedoesnotmatch', 'access key id is not valid',
        'accesskey secret', 'ak/sk', '认证失败', '鉴权失败'
    ]):
        return {
            'error_code': 'AUTH_FAILED',
            'message': '认证失败：AK/SK 无效或签名不正确，请核对后重试。',
            'raw_error': raw_error,
        }

    if any(k in text for k in [
        'forbidden', 'unauthorized', 'no permission', 'permission denied',
        'ram', 'accessdenied', 'operationdenied', '权限不足'
    ]):
        return {
            'error_code': 'PERMISSION_DENIED',
            'message': '权限不足：当前 RAM 权限无法查询账单/CDT 数据。',
            'raw_error': raw_error,
        }

    if any(k in text for k in [
        'throttl', 'ratelimit', 'rate limit', 'too many requests',
        'requestlimitexceeded', 'frequency', '限流', '频率限制'
    ]):
        return {
            'error_code': 'API_RATE_LIMITED',
            'message': '请求过于频繁，账单接口已限流，请稍后重试。',
            'raw_error': raw_error,
        }

    if any(k in text for k in [
        'timeout', 'timed out', 'connection', 'max retries exceeded',
        'name or service not known', 'temporarily unavailable', '网络错误', '连接失败'
    ]):
        return {
            'error_code': 'NETWORK_ERROR',
            'message': '网络连接异常，无法访问阿里云账单接口，请稍后重试。',
            'raw_error': raw_error,
        }

    return {
        'error_code': 'UNKNOWN_ERROR',
        'message': '查询 CDT 账单数据失败，请稍后重试。',
        'raw_error': raw_error,
    }


# ── Account Text Parser ──

def parse_account_text(raw_text):
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
    account_slug = slugify_account(account_slug_seed) or (f'account-{datetime.utcnow().strftime("%Y%m%d%H%M%S")}')

    return {
        'login_name': login_name,
        'remark': remark,
        'access_key_id': ak,
        'access_key_secret': sk,
        'region_id': region_id,
        'account_slug': account_slug,
    }


# ── ECS Discovery ──

def discover_ecs_instances_all_regions(ak, sk, default_region='cn-hangzhou', scan_all_regions=True):
    """Discover ECS instances across regions."""
    from aliyunsdkcore.client import AcsClient
    from aliyunsdkecs.request.v20140526.DescribeRegionsRequest import DescribeRegionsRequest
    from aliyunsdkecs.request.v20140526.DescribeInstancesRequest import DescribeInstancesRequest

    client = AcsClient(ak, sk, default_region)
    client.add_endpoint(default_region, 'Ecs', f'ecs.{default_region}.aliyuncs.com')

    region_ids = [default_region]
    if scan_all_regions:
        req = DescribeRegionsRequest()
        req.set_accept_format('json')
        response = client.do_action_with_exception(req)
        payload = response.decode('utf-8') if isinstance(response, (bytes, bytearray)) else response
        result = json.loads(payload)
        region_ids = []
        for region in result.get('Regions', {}).get('Region', []) or []:
            rid = (region.get('RegionId') or '').strip()
            if rid and rid not in region_ids:
                region_ids.append(rid)
        if default_region and default_region not in region_ids:
            region_ids.insert(0, default_region)

    discovered = []
    seen_ids = set()

    for region_id in region_ids:
        try:
            rc = AcsClient(ak, sk, region_id)
            rc.add_endpoint(region_id, 'Ecs', f'ecs.{region_id}.aliyuncs.com')
            page_number = 1
            while True:
                req = DescribeInstancesRequest()
                req.set_PageSize(100)
                req.set_PageNumber(page_number)
                req.set_accept_format('json')
                response = rc.do_action_with_exception(req)
                payload = response.decode('utf-8') if isinstance(response, (bytes, bytearray)) else response
                result = json.loads(payload)
                instances = result.get('Instances', {}).get('Instance', []) or []
                for inst in instances:
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
                if len(instances) < 100:
                    break
                page_number += 1
        except Exception:
            continue

    return discovered


# ── GitHub Sync ──

def sync_account_to_github(repo, account_slug, payload):
    """Sync account payload to GitHub private repo using gh CLI."""
    if not shutil.which('gh'):
        return False, '未检测到 gh CLI，请先安装并 gh auth login'

    check = subprocess.run(['gh', 'repo', 'view', repo], capture_output=True, text=True)
    if check.returncode != 0:
        created = subprocess.run(['gh', 'repo', 'create', repo, '--private', '--confirm'], capture_output=True, text=True)
        if created.returncode != 0:
            return False, f'创建 GitHub 仓库失败: {(created.stderr or created.stdout).strip()}'

    file_path = f'accounts/{account_slug}/account.yaml'
    payload_yaml = [
        f'account_slug: {safe_yaml_str(payload.get("account_slug", ""))}',
        f'account_identifier: {safe_yaml_str(payload.get("account_identifier", ""))}',
        f'login_name: {safe_yaml_str(payload.get("login_name", ""))}',
        f'remark: {safe_yaml_str(payload.get("remark", ""))}',
        f'access_key_id: {safe_yaml_str(payload.get("access_key_id", ""))}',
        f'access_key_secret: {safe_yaml_str(payload.get("access_key_secret", ""))}',
        f'region: {safe_yaml_str(payload.get("region", ""))}',
        f'discovered_at: {safe_yaml_str(payload.get("discovered_at", ""))}',
        'instances:',
    ]
    for inst in payload.get('instances', []):
        payload_yaml.extend([
            f'  - instance_id: {safe_yaml_str(inst.get("instance_id", ""))}',
            f'    name: {safe_yaml_str(inst.get("name", ""))}',
            f'    region: {safe_yaml_str(inst.get("region_id", ""))}',
            f'    status: {safe_yaml_str(inst.get("status", ""))}',
            f'    public_ip: {safe_yaml_str(inst.get("public_ip", ""))}',
            f'    private_ip: {safe_yaml_str(inst.get("private_ip", ""))}',
            f'    ipv6: {safe_yaml_str(inst.get("ipv6_addr", ""))}',
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


# ── Import Job Management ──

_IMPORT_JOBS_LOCK = threading.RLock()
_IMPORT_JOB_KEEP_HOURS = 24
_IMPORT_JOB_TIMEOUT_MINUTES = 60
_IMPORT_TEXT_MAX_CHARS = 20000


def new_import_job():
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


def job_is_done(job):
    if not job:
        return False
    if hasattr(job, 'status'):
        return job.status in ('done', 'error')
    return job.get('status') in ('done', 'error')


def serialize_import_job(job):
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
            meta = classify_import_error(payload.get('error') or payload.get('message') or '')
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


def update_import_job(job_id, **updates):
    with _IMPORT_JOBS_LOCK:
        job = db.session.get(ImportJob, job_id)
        if not job:
            return None

        if job_is_done(job):
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


def cleanup_import_jobs():
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


def mark_stale_import_job_if_needed(job):
    if not job or job_is_done(job):
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
    return update_import_job(
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


def run_account_import_job(app_obj, job_id, raw_text, scan_all_regions):
    with app_obj.app_context():
        try:
            update_import_job(job_id, status='running', step='解析中', message='正在解析账号文本', progress=5)
            parsed = parse_account_text(raw_text)
            ak = parsed.get('access_key_id', '')
            sk = parsed.get('access_key_secret', '')
            if not ak or not sk:
                raise ValueError('解析失败：未识别到 AccessKey ID/Secret，请检查粘贴内容。')

            account_slug = parsed['account_slug']
            default_region = parsed.get('region_id') or 'cn-hangzhou'
            note_parts = [part for part in [parsed.get('remark', '').strip(), f'account:{account_slug}'] if part]
            merged_note = ' | '.join(note_parts)

            scan_scope_text = '全部可用区域（含香港/海外）' if scan_all_regions else f'默认区域 {default_region}'
            update_import_job(job_id, step='扫描中', message=f'正在扫描实例（{scan_scope_text}）', progress=35)
            discovered = discover_ecs_instances_all_regions(ak, sk, default_region, scan_all_regions=scan_all_regions)

            update_import_job(job_id, step='写入中', message='正在写入数据库并更新实例', progress=65)
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

            update_import_job(job_id, step='同步GitHub中', message='正在同步到 GitHub 私有仓库', progress=85)
            gh_payload = {
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
            github_repo = os.environ.get('GITHUB_SYNC_REPO', '').strip()
            if not github_repo:
                raise RuntimeError('环境变量 GITHUB_SYNC_REPO 未配置，无法同步到 GitHub')
            ok, sync_info = sync_account_to_github(github_repo, account_slug, gh_payload)
            if not ok:
                raise RuntimeError(sync_info)

            log_operation('account_import_text', f'文本导入账号 {account_slug}，新增 {imported}，更新 {updated}')
            db.session.commit()

            update_import_job(
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
            meta = classify_import_error(e)
            update_import_job(
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
