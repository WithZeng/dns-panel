import json
import os
import logging
import datetime
import tempfile
from sqlalchemy import text
from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.request import CommonRequest
from aliyunsdkecs.request.v20140526.DescribeInstancesRequest import DescribeInstancesRequest
from aliyunsdkecs.request.v20140526.StopInstanceRequest import StopInstanceRequest
from aliyunsdkecs.request.v20140526.StartInstanceRequest import StartInstanceRequest
from aliyunsdkecs.request.v20140526.DeleteInstanceRequest import DeleteInstanceRequest
from models import db, EcsInstance, TrafficLog, AlertConfig, ProbeServer, NotificationLog
from notifier import send_alert

# ================== 1. Configure Logging ==================
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

AUTO_START_ELIGIBLE_STATUSES = {'Stopped', 'Stopping'}

try:
    import fcntl  # type: ignore
except ImportError:
    fcntl = None

# Anomaly detection: alert if traffic increases by more than this % in a single check
ANOMALY_INCREASE_PCT = 20.0
_TRAFFIC_LOCK_ACQUIRED_SQL = "SELECT pg_try_advisory_lock(922337001)"
_TRAFFIC_LOCK_RELEASE_SQL = "SELECT pg_advisory_unlock(922337001)"


class BillingQueryError(Exception):
    """Raised when querying billing APIs fails with user-facing metadata."""

    def __init__(self, message, error_code='UNKNOWN_ERROR', raw_error=''):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.raw_error = raw_error


def _update_credential_status(instance, status='ok', error_msg=''):
    """Persist explicit credential/auth state for dashboard alerts."""
    normalized = (status or 'ok').strip().lower()
    if normalized not in ('ok', 'invalid_access_key', 'unauthorized'):
        normalized = 'ok'

    instance.credential_status = normalized
    if normalized == 'ok':
        instance.credential_error = ''
        instance.credential_last_failed_at = None
    else:
        instance.credential_error = (error_msg or '')[:500]
        instance.credential_last_failed_at = datetime.datetime.utcnow()


def _credential_status_from_billing_error(err):
    code = (getattr(err, 'error_code', '') or '').upper()
    if code == 'AUTH_FAILED':
        return 'invalid_access_key'
    if code == 'PERMISSION_DENIED':
        return 'unauthorized'
    return 'ok'


def _is_probe_online(server):
    if not server or not server.last_seen:
        return False
    return (datetime.datetime.utcnow() - server.last_seen).total_seconds() <= 30


def _scheduler_lock_file_path():
    return os.environ.get('DNS_PANEL_SCHEDULER_LOCK_FILE', os.path.join(tempfile.gettempdir(), 'dns-panel-scheduler.lock'))


def _instance_lock_file_path(instance_id):
    base_dir = os.environ.get('DNS_PANEL_INSTANCE_LOCK_DIR', tempfile.gettempdir())
    return os.path.join(base_dir, f'dns-panel-instance-{instance_id}.lock')


def _flock_exclusive_nonblocking(lock_handle):
    if not fcntl:
        return True
    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    return True


def _flock_unlock(lock_handle):
    if not fcntl:
        return
    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)


def _try_acquire_instance_lock(instance_id):
    lock_handle = None
    try:
        lock_handle = open(_instance_lock_file_path(instance_id), 'a+')
        _flock_exclusive_nonblocking(lock_handle)
        return lock_handle
    except Exception:
        if lock_handle:
            try:
                lock_handle.close()
            except Exception:
                pass
        return None


def _release_instance_lock(lock_handle):
    if not lock_handle:
        return
    try:
        _flock_unlock(lock_handle)
    except Exception:
        pass
    try:
        lock_handle.close()
    except Exception:
        pass


def _try_acquire_run_lock():
    """Best-effort cross-process lock to prevent duplicate scheduled runs."""
    lock_handle = None
    db_locked = False
    file_locked = False
    try:
        lock_handle = open(_scheduler_lock_file_path(), 'a+')
        _flock_exclusive_nonblocking(lock_handle)
        file_locked = True

        # Optional DB advisory lock (effective on PostgreSQL; ignored on SQLite)
        try:
            lock_result = db.session.execute(text(_TRAFFIC_LOCK_ACQUIRED_SQL)).scalar()
            db_locked = bool(lock_result)
            if not db_locked:
                _flock_unlock(lock_handle)
                lock_handle.close()
                return None, 'db_lock_busy'
        except Exception:
            # SQLite / unsupported backend: file lock alone is sufficient for single-host deployment
            db_locked = False

        return {'fh': lock_handle, 'db_locked': db_locked, 'file_locked': file_locked}, 'ok'
    except Exception:
        if lock_handle:
            try:
                lock_handle.close()
            except Exception:
                pass
        return None, 'file_lock_busy'


def _release_run_lock(lock_ctx):
    if not lock_ctx:
        return
    try:
        if lock_ctx.get('db_locked'):
            try:
                db.session.execute(text(_TRAFFIC_LOCK_RELEASE_SQL))
            except Exception:
                pass
        fh = lock_ctx.get('fh')
        if fh:
            try:
                _flock_unlock(fh)
            except Exception:
                pass
            try:
                fh.close()
            except Exception:
                pass
    except Exception:
        pass


# ================== 2. Init Client (Dynamic Endpoint) ==================
def get_client(instance):
    client = AcsClient(
        instance.decrypted_ak,
        instance.decrypted_sk,
        instance.region_id
    )
    ecs_endpoint = f"ecs.{instance.region_id}.aliyuncs.com"
    client.add_endpoint(instance.region_id, 'Ecs', ecs_endpoint)
    return client


# ================== 3. Basic ECS Operations ==================
def ecs_start(client, instance_id):
    try:
        request = StartInstanceRequest()
        request.set_InstanceId(instance_id)
        client.do_action_with_exception(request)
        logger.info(f"[Start] Command sent: {instance_id}")
        return True, "start command sent"
    except Exception as e:
        logger.error(f"Start failed {instance_id}: {e}")
        return False, str(e)


def ecs_stop(client, instance_id):
    try:
        request = StopInstanceRequest()
        request.set_InstanceId(instance_id)
        client.do_action_with_exception(request)
        logger.info(f"[Stop] Command sent: {instance_id}")
        return True, "stop command sent"
    except Exception as e:
        logger.error(f"Stop failed {instance_id}: {e}")
        return False, str(e)


def ecs_release(client, instance_id):
    try:
        request = DeleteInstanceRequest()
        request.set_InstanceId(instance_id)
        request.set_Force(True)
        client.do_action_with_exception(request)
        logger.info(f"[Release] Command sent: {instance_id}")
        return True, "instance release success"
    except Exception as e:
        logger.error(f"Release failed {instance_id}: {e}")
        return False, str(e)


# ================== 4. Get ECS Runtime Status ==================
def get_ecs_info(client, instance_id):
    """Fetch instance status and IP addresses."""
    try:
        request = DescribeInstancesRequest()
        request.set_InstanceIds(json.dumps([instance_id]))
        response = client.do_action_with_exception(request)
        response_json = json.loads(response)
        if response_json.get('Instances') and response_json['Instances'].get('Instance'):
            inst = response_json['Instances']['Instance'][0]
            status = inst.get('Status', 'Unknown')
            
            public_ips = inst.get('PublicIpAddress', {}).get('IpAddress', [])
            eip = inst.get('EipAddress', {}).get('IpAddress', '')
            if eip: public_ips.append(eip)
            
            private_ips = inst.get('VpcAttributes', {}).get('PrivateIpAddress', {}).get('IpAddress', [])
            
            # Simple IPv6 extraction from instance info
            ipv6_ips = inst.get('VpcAttributes', {}).get('Ipv6Addresses', {}).get('Ipv6Address', [])
            if not ipv6_ips:
                for ni in inst.get('NetworkInterfaces', {}).get('NetworkInterface', []):
                    for i6 in ni.get('Ipv6Sets', {}).get('Ipv6Set', []):
                        if i6.get('Ipv6Address'): ipv6_ips.append(i6['Ipv6Address'])
            
            return {
                'status': status,
                'public_ip': public_ips[0] if public_ips else '',
                'private_ip': private_ips[0] if private_ips else '',
                'ipv6_addr': ipv6_ips[0] if ipv6_ips else ''
            }
        return None
    except Exception as e:
        logger.error(f"Failed to get info for {instance_id}: {e}")
        return None

def get_ecs_status(client, instance_id):
    info = get_ecs_info(client, instance_id)
    return info['status'] if info else "Unknown"


def _collect_ipv6_from_items(item, addresses):
    if not item:
        return
    
    if isinstance(item, str):
        if ':' in item:
            ip = item.split('/')[0].strip()
            if ip not in addresses: addresses.append(ip)
        return

    if isinstance(item, list):
        for sub in item:
            _collect_ipv6_from_items(sub, addresses)
        return

    if isinstance(item, dict):
        # Specific known keys
        for k in ['Ipv6Address', 'Ipv6AddressSet', 'Ipv6Set', 'Ipv6Sets', 'Ipv6Addresses']:
            val = item.get(k)
            if val:
                _collect_ipv6_from_items(val, addresses)
        
        # General search for other Strukturen
        for k, v in item.items():
             if k not in ['Ipv6Address', 'Ipv6AddressSet', 'Ipv6Set', 'Ipv6Sets', 'Ipv6Addresses']:
                 if isinstance(v, (dict, list)):
                     _collect_ipv6_from_items(v, addresses)

def get_ecs_ipv6_info(client, instance):
    """Fetch instance IPv6 addresses and primary ENI information."""
    try:
        request = DescribeInstancesRequest()
        request.set_InstanceIds(json.dumps([instance.instance_id]))
        response = client.do_action_with_exception(request)
        data = json.loads(response)
        instances = data.get('Instances', {}).get('Instance', [])
        if not instances:
            return {
                'enabled': False,
                'addresses': [],
                'primary_eni_id': '',
                'message': '实例不存在或无权限读取',
            }

        inst = instances[0]
        addresses = []
        _collect_ipv6_from_items(inst, addresses)

        eni_id = ''
        ni_list = inst.get('NetworkInterfaces', {}).get('NetworkInterface', [])
        if isinstance(ni_list, list) and ni_list:
            eni_id = (ni_list[0].get('NetworkInterfaceId') or '').strip()

        if eni_id and not addresses:
            try:
                from aliyunsdkecs.request.v20140526.DescribeNetworkInterfacesRequest import DescribeNetworkInterfacesRequest
                req = DescribeNetworkInterfacesRequest()
                req.set_NetworkInterfaceId(eni_id)
                req.set_RegionId(instance.region_id)
                eni_resp = client.do_action_with_exception(req)
                eni_data = json.loads(eni_resp.decode('utf-8') if isinstance(eni_resp, (bytes, bytearray)) else eni_resp)
                _collect_ipv6_from_items(eni_data, addresses)
            except Exception:
                try:
                    # CommonRequest fallback if typed request fails
                    req = CommonRequest()
                    req.set_domain(f'ecs.{instance.region_id}.aliyuncs.com')
                    req.set_version('2014-05-26')
                    req.set_action_name('DescribeNetworkInterfaces')
                    req.set_method('POST')
                    req.set_protocol_type('https')
                    req.add_query_param('RegionId', instance.region_id)
                    req.add_query_param('NetworkInterfaceId.1', eni_id)
                    eni_resp = client.do_action_with_exception(req)
                    eni_data = json.loads(eni_resp.decode('utf-8') if isinstance(eni_resp, (bytes, bytearray)) else eni_resp)
                    _collect_ipv6_from_items(eni_data, addresses)
                except Exception as sub_e2:
                    logger.warning(f"DescribeNetworkInterfaces fallback failed for {instance.instance_id}: {sub_e2}")

        unique = []
        for ip in addresses:
            if ip and isinstance(ip, str) and ip.strip() and ip not in unique:
                if ':' in ip:
                    unique.append(ip.strip())

        return {
            'enabled': len(unique) > 0,
            'addresses': unique,
            'primary_eni_id': eni_id,
            'message': 'ok',
        }
    except Exception as e:
        logger.error(f"Failed to get IPv6 info for {instance.instance_id}: {e}")
        return {
            'enabled': False,
            'addresses': [],
            'primary_eni_id': '',
            'message': str(e),
        }


def ecs_enable_ipv6(client, instance):
    """Assign one IPv6 address to the primary ENI if not enabled."""
    info = get_ecs_ipv6_info(client, instance)
    if info.get('enabled'):
        addr = ', '.join(info.get('addresses', []))
        return True, f'IPv6 已开启: {addr}', info.get('addresses', [])

    eni_id = (info.get('primary_eni_id') or '').strip()
    if not eni_id:
        return False, f'未找到主网卡，无法分配 IPv6（{info.get("message", "")})', []

    try:
        req = CommonRequest()
        req.set_domain(f'ecs.{instance.region_id}.aliyuncs.com')
        req.set_version('2014-05-26')
        req.set_action_name('AssignIpv6Addresses')
        req.set_method('POST')
        req.set_protocol_type('https')
        req.add_query_param('RegionId', instance.region_id)
        req.add_query_param('NetworkInterfaceId', eni_id)
        req.add_query_param('Ipv6AddressCount', 1)

        resp = client.do_action_with_exception(req)
        payload = json.loads(resp.decode('utf-8') if isinstance(resp, (bytes, bytearray)) else resp)

        new_ips = []
        _collect_ipv6_from_items(payload, new_ips)

        refresh = get_ecs_ipv6_info(client, instance)
        final_ips = refresh.get('addresses', []) or new_ips
        if final_ips:
            logger.info(f"IPv6 enabled for {instance.instance_id}: {final_ips}")
            return True, f'IPv6 开启成功: {", ".join(final_ips)}', final_ips

        logger.info(f"AssignIpv6Addresses sent for {instance.instance_id}, awaiting sync")
        return True, '已发送 IPv6 分配请求，请稍后刷新查看', []
    except Exception as e:
        raw_err = str(e)
        lower_err = raw_err.lower()

        if 'invalidvswitch.ipv6notturnon' in lower_err:
            msg = (
                '当前实例所在 vSwitch 未开通 IPv6，无法直接分配。'
                '请在阿里云创建支持 IPv6 的 VPC/交换机，并将实例迁移到该交换机后重试。'
            )
        elif 'operationdenied' in lower_err and 'ipv6' in lower_err:
            msg = '账号或实例不满足 IPv6 开通条件（权限/地域/实例规格限制），请先在控制台确认 IPv6 能力。'
        elif 'invalidparameternetworkinterfaceid' in lower_err:
            msg = '主网卡参数无效，无法分配 IPv6，请刷新实例后重试。'
        elif 'invalidoperation.ipv6countexceeded' in lower_err:
            refresh = get_ecs_ipv6_info(client, instance)
            existing = refresh.get('addresses', [])
            if existing:
                msg = f'该实例网卡 IPv6 数量已达上限（最多1个），当前地址: {", ".join(existing)}'
                logger.info(f"IPv6 count exceeded but existing IPv6 found for {instance.instance_id}: {existing}")
                return True, msg, existing
            msg = '该实例网卡 IPv6 数量已达上限（最多1个），请在控制台查看现有 IPv6 地址。'
        else:
            msg = raw_err

        logger.error(f"Enable IPv6 failed for {instance.instance_id}: {raw_err}")
        return False, msg, []


# ================== 5. Get CDT Traffic ==================
def _decode_json_response(response):
    payload = response.decode('utf-8') if isinstance(response, (bytes, bytearray)) else response
    return json.loads(payload)


def _classify_billing_api_error(err):
    raw_error = str(err or '').strip() or '未知错误'
    text = raw_error.lower()

    if any(k in text for k in [
        'invalidaccesskeyid', 'signaturedoesnotmatch', 'incomplete signatures',
        'access key id is not valid', 'accesskey secret', 'ak/sk', '认证失败', '鉴权失败'
    ]):
        return BillingQueryError('认证失败：AK/SK 无效或签名不正确，请核对后重试。', 'AUTH_FAILED', raw_error)

    if any(k in text for k in [
        'forbidden', 'unauthorized', 'no permission', 'permission denied',
        'ram', 'accessdenied', 'operationdenied', '权限不足'
    ]):
        return BillingQueryError('权限不足：当前 RAM 权限无法查询账单/CDT 数据。', 'PERMISSION_DENIED', raw_error)

    if any(k in text for k in [
        'throttl', 'ratelimit', 'rate limit', 'too many requests',
        'requestlimitexceeded', 'frequency', '限流', '频率限制'
    ]):
        return BillingQueryError('请求过于频繁，账单接口已限流，请稍后重试。', 'API_RATE_LIMITED', raw_error)

    if any(k in text for k in [
        'timeout', 'timed out', 'connection', 'max retries exceeded',
        'name or service not known', 'temporarily unavailable', '网络错误', '连接失败'
    ]):
        return BillingQueryError('网络连接异常，无法访问阿里云账单接口，请稍后重试。', 'NETWORK_ERROR', raw_error)

    return BillingQueryError('查询 CDT 账单数据失败，请稍后重试。', 'UNKNOWN_ERROR', raw_error)


def _normalize_month_start(month_value):
    value = str(month_value or '').strip()
    if not value:
        return ''
    if len(value) == 6 and value.isdigit():  # 202603
        return f'{value[:4]}-{value[4:6]}-01'
    if len(value) >= 7 and value[4] == '-':  # 2026-03 or 2026-03-xx
        return f'{value[:7]}-01'
    return value


def _month_keys_for_recent_three(now=None):
    cursor = now or datetime.datetime.utcnow()
    cursor = datetime.datetime(cursor.year, cursor.month, 1)
    keys = []
    for _ in range(3):
        keys.append(cursor.strftime('%Y-%m'))
        if cursor.month == 1:
            cursor = datetime.datetime(cursor.year - 1, 12, 1)
        else:
            cursor = datetime.datetime(cursor.year, cursor.month - 1, 1)
    keys.reverse()
    return keys


def _normalize_billing_month(value):
    text = str(value or '').strip()
    if not text:
        return ''
    if len(text) == 6 and text.isdigit():
        return f'{text[:4]}-{text[4:6]}'
    if len(text) >= 7 and text[4] == '-':
        return text[:7]
    return ''


def _coerce_bill_items(data):
    if not isinstance(data, dict):
        return []
    items = (data.get('Data') or {}).get('Items')
    return _coerce_traffic_details(items)


def _is_cdt_like_bill_row(row):
    product_detail = str((row or {}).get('ProductDetail') or '').lower()
    product_code = str((row or {}).get('ProductCode') or '').lower()
    item = str((row or {}).get('BillItem') or '').lower()
    return ('cdt' in product_detail) or ('cdt' in product_code) or ('流量' in item) or ('traffic' in item)


def _usage_to_traffic_gb(usage, usage_unit):
    usage_value = _to_float(usage, 0.0)
    if usage_value <= 0:
        return 0.0

    unit_lower = str(usage_unit or '').lower()
    if unit_lower in ('gb', 'gbyte', 'gbytes', 'gib', 'gibibyte'):
        return usage_value
    if unit_lower in ('mb', 'mbyte', 'mbytes', 'mib', 'mibibyte'):
        return usage_value / 1024
    if unit_lower in ('kb', 'kbyte', 'kbytes', 'kib'):
        return usage_value / (1024 * 1024)
    if unit_lower in ('byte', 'bytes', 'b'):
        return usage_value / (1024 ** 3)
    if unit_lower in ('tb', 'tbyte', 'tbytes', 'tib'):
        return usage_value * 1024
    # Fallback: many billing usage fields are bytes when unit is absent
    return usage_value / (1024 ** 3)


def _build_cdt_monthly_summary(monthly_rows, instance_id=''):
    month_keys = _month_keys_for_recent_three()
    by_month = {
        m: {
            'month': m,
            'traffic': 0.0,
            'traffic_unit': 'GB',
            'amount': 0.0,
            'currency': 'CNY',
        }
        for m in month_keys
    }

    matched_scope = 'account'
    instance_key = (instance_id or '').strip().lower()

    cdt_rows = []
    saw_instance_dimension = False
    for row in (monthly_rows or []):
        if not _is_cdt_like_bill_row(row):
            continue
        cdt_rows.append(row)
        instance_no = str((row or {}).get('InstanceID') or (row or {}).get('InstanceId') or '').strip()
        if instance_no:
            saw_instance_dimension = True

    use_account_fallback = bool(instance_key) and not saw_instance_dimension

    for row in cdt_rows:
        month = _normalize_billing_month((row or {}).get('BillingCycle') or (row or {}).get('BillCycle') or (row or {}).get('BillingDate'))
        if month not in by_month:
            continue

        pretax_amount = _to_float((row or {}).get('PretaxAmount'), 0.0)
        currency = (row or {}).get('Currency') or by_month[month]['currency']

        instance_no = str((row or {}).get('InstanceID') or (row or {}).get('InstanceId') or '').strip()

        matched_row = True
        if instance_key and not use_account_fallback:
            matched_row = (instance_no.lower() == instance_key)
            if matched_row:
                matched_scope = 'instance'

        if not matched_row:
            continue

        by_month[month]['amount'] += pretax_amount
        by_month[month]['currency'] = currency or by_month[month]['currency']

        usage = (row or {}).get('Usage')
        usage_unit = (row or {}).get('UsageUnit') or (row or {}).get('UsageUnitType') or ''
        by_month[month]['traffic'] += _usage_to_traffic_gb(usage, usage_unit)

    months = []
    total_traffic = 0.0
    total_amount = 0.0
    currency = 'CNY'

    for key in month_keys:
        row = by_month[key]
        traffic = round(float(row['traffic'] or 0), 4)
        amount = round(float(row['amount'] or 0), 4)
        currency = row.get('currency') or currency
        months.append({
            'month': key,
            'traffic': traffic,
            'traffic_unit': 'GB',
            'amount': amount,
        })
        total_traffic += traffic
        total_amount += amount

    if instance_key and not saw_instance_dimension and matched_scope != 'instance':
        matched_scope = 'account'

    return {
        'months': months,
        'total_traffic': round(total_traffic, 4),
        'total_amount': round(total_amount, 4),
        'currency': currency or 'CNY',
        'scope': matched_scope,
    }


def _query_instance_bill_rows(client, month_key):
    month = _normalize_billing_month(month_key)
    if not month:
        return []

    rows = []
    page_num = 1
    page_size = 300

    while True:
        req = CommonRequest()
        req.set_domain('business.aliyuncs.com')
        req.set_version('2017-12-14')
        req.set_action_name('QueryInstanceBill')
        req.set_method('POST')
        req.set_protocol_type('https')
        req.add_query_param('ProductCode', 'cdt')
        req.add_query_param('SubscriptionType', 'PayAsYouGo')
        req.add_query_param('BillingCycle', month)
        req.add_query_param('Granularity', 'MONTHLY')
        req.add_query_param('IsBillingItem', 'true')
        req.add_query_param('PageNum', page_num)
        req.add_query_param('PageSize', page_size)

        response = client.do_action_with_exception(req)
        data = _decode_json_response(response)
        page_items = _coerce_bill_items(data)
        rows.extend(page_items)

        data_node = data.get('Data', {}) if isinstance(data, dict) else {}
        total_count = int(_to_float(data_node.get('TotalCount'), 0.0))
        if not page_items:
            break
        if total_count > 0 and len(rows) >= total_count:
            break
        if len(page_items) < page_size:
            break
        page_num += 1

    return rows


def _inject_cdt_api_fallback(summary, client, region_id=''):
    """When bill rows cannot map to instance, use CDT traffic API as last fallback.

    NOTE: ListCdtInternetTraffic is cumulative for the current period. We only patch
    the latest month's traffic to avoid fabricating historical monthly splits.
    """
    try:
        if region_id:
            traffic_gb = get_total_traffic_gb(client, region_id)
        else:
            req = CommonRequest()
            req.set_domain('cdt.aliyuncs.com')
            req.set_version('2021-08-13')
            req.set_action_name('ListCdtInternetTraffic')
            req.set_method('POST')
            req.set_protocol_type('https')
            response = client.do_action_with_exception(req)
            payload = _decode_json_response(response)
            details = _coerce_traffic_details(payload.get('TrafficDetails', []))
            traffic_gb = sum(_detail_traffic_bytes(item) for item in details) / (1024 ** 3)

        traffic_gb = _to_float(traffic_gb, 0.0)
        if traffic_gb <= 0:
            return summary

        months = summary.get('months') or []
        if not months:
            return summary

        latest = months[-1]
        latest['traffic'] = round(max(_to_float(latest.get('traffic'), 0.0), traffic_gb), 4)
        summary['months'] = months
        summary['total_traffic'] = round(sum(_to_float(m.get('traffic'), 0.0) for m in months), 4)
        summary['scope'] = 'instance_cdt_fallback' if region_id else 'account_cdt_fallback'
        summary['provider'] = f"{summary.get('provider', '')}+aliyun_cdt_list_internet_traffic".strip('+')
        return summary
    except Exception as e:
        logger.warning(f"CDT fallback traffic query failed: {e}")
        return summary


def get_cdt_three_month_billing(client, instance_id='', region_id=''):
    month_keys = _month_keys_for_recent_three()

    try:
        rows = []
        for month in month_keys:
            rows.extend(_query_instance_bill_rows(client, month))

        summary = _build_cdt_monthly_summary(rows, instance_id=instance_id)
        summary['provider'] = 'aliyun_billing_query_instance_bill'

        # 兜底：明细接口无法映射到实例时，尝试 CDT 专用流量接口做跨表聚合
        if instance_id and _to_float(summary.get('total_traffic'), 0.0) <= 0:
            summary = _inject_cdt_api_fallback(summary, client, region_id=region_id)
        return summary
    except Exception as e:
        raise _classify_billing_api_error(e)

def _coerce_traffic_details(raw_details):
    """Normalize CDT traffic details to a list across SDK payload variants."""
    if isinstance(raw_details, list):
        return raw_details
    if isinstance(raw_details, dict):
        # Some SDK responses wrap items as {'TrafficDetail': [...]} or {'Item': [...]}.
        for key in ('TrafficDetail', 'TrafficDetails', 'Items', 'Item'):
            nested = raw_details.get(key)
            if isinstance(nested, list):
                return nested
            if isinstance(nested, dict):
                return [nested]
        return [raw_details]
    return []


def _to_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _detail_traffic_bytes(detail):
    """Extract traffic bytes from a detail row (top-level or product breakdown)."""
    total = _to_float((detail or {}).get('Traffic'), 0.0)
    if total > 0:
        return total

    products = (detail or {}).get('ProductTrafficDetails')
    products = _coerce_traffic_details(products)
    for item in products:
        total += _to_float((item or {}).get('Traffic'), 0.0)
    return total


def _region_aliases(region):
    text = str(region or '').strip().lower().replace('_', '-')
    if not text:
        return set()
    aliases = {text}

    # cn-hangzhou-finance -> cn-hangzhou (match ECS region naming)
    parts = [p for p in text.split('-') if p]
    if len(parts) >= 2:
        aliases.add('-'.join(parts[:2]))
    return aliases


def _region_matches(target_region, detail_region):
    target_aliases = _region_aliases(target_region)
    detail_aliases = _region_aliases(detail_region)
    if not target_aliases or not detail_aliases:
        return False

    # Exact or prefix/suffix overlap between normalized aliases.
    for t in target_aliases:
        for d in detail_aliases:
            if t == d or t in d or d in t:
                return True
    return False


def get_total_traffic_gb(client, region_id, raise_on_error=False):
    request = CommonRequest()
    request.set_domain('cdt.aliyuncs.com')
    request.set_version('2021-08-13')
    request.set_action_name('ListCdtInternetTraffic')
    request.set_method('POST')
    request.set_protocol_type('https')

    try:
        response = client.do_action_with_exception(request)
        response_json = _decode_json_response(response)
        details = _coerce_traffic_details(response_json.get('TrafficDetails', []))

        total_bytes = 0.0
        matched_rows = 0
        for detail in details:
            biz_region = (detail or {}).get('BusinessRegionId') or (detail or {}).get('RegionId') or ''
            if _region_matches(region_id, biz_region):
                total_bytes += _detail_traffic_bytes(detail)
                matched_rows += 1

        # Fallback for single-row payloads where region metadata is empty/abnormal.
        if matched_rows == 0 and len(details) == 1:
            total_bytes = _detail_traffic_bytes(details[0])
            logger.warning(
                f"CDT region match fallback used for region={region_id}; "
                f"detail region={details[0].get('BusinessRegionId') or details[0].get('RegionId') or '<empty>'}"
            )

        return total_bytes / (1024 ** 3)
    except Exception as e:
        if raise_on_error:
            raise _classify_billing_api_error(e)
        logger.error(f"Failed to fetch CDT traffic for {region_id}: {e}")
        return None


def get_region_traffic(client, region_id):
    return get_total_traffic_gb(client, region_id)


# ================== Security Group Operations ==================
def get_security_groups(client, instance_id):
    """Get security group IDs for an instance. Returns (sg_ids, error_msg)."""
    try:
        request = DescribeInstancesRequest()
        request.set_InstanceIds(json.dumps([instance_id]))
        response = client.do_action_with_exception(request)
        data = json.loads(response)
        instances = data.get('Instances', {}).get('Instance', [])
        if instances:
            sg_ids = instances[0].get('SecurityGroupIds', {}).get('SecurityGroupId', [])
            return sg_ids, None
        return [], 'API 返回的实例列表为空，请检查 Instance ID 是否正确'
    except Exception as e:
        logger.error(f"Failed to get security groups: {e}")
        return [], str(e)


def describe_sg_rules(client, security_group_id, region_id):
    """List inbound rules for a security group."""
    try:
        req = CommonRequest()
        req.set_domain(f'ecs.{region_id}.aliyuncs.com')
        req.set_version('2014-05-26')
        req.set_action_name('DescribeSecurityGroupAttribute')
        req.set_method('POST')
        req.set_protocol_type('https')
        req.add_query_param('SecurityGroupId', security_group_id)
        req.add_query_param('Direction', 'ingress')
        req.add_query_param('RegionId', region_id)

        response = client.do_action_with_exception(req)
        data = json.loads(response)
        rules = data.get('Permissions', {}).get('Permission', [])
        return rules
    except Exception as e:
        logger.error(f"Failed to describe SG rules: {e}")
        return []


def authorize_sg(client, security_group_id, region_id, ip_protocol, port_range, source_cidr='0.0.0.0/0', policy='accept', description=''):
    """Add an inbound rule to a security group."""
    try:
        req = CommonRequest()
        req.set_domain(f'ecs.{region_id}.aliyuncs.com')
        req.set_version('2014-05-26')
        req.set_action_name('AuthorizeSecurityGroup')
        req.set_method('POST')
        req.set_protocol_type('https')
        req.add_query_param('SecurityGroupId', security_group_id)
        req.add_query_param('RegionId', region_id)
        req.add_query_param('NicType', 'intranet')  # VPC 安全组 must be intranet
        req.add_query_param('IpProtocol', ip_protocol)  # tcp, udp, icmp, all
        req.add_query_param('PortRange', port_range)      # e.g. 80/80, 1/65535, -1/-1
        if ':' in str(source_cidr):
            # IPv6 
            req.add_query_param('Ipv6SourceCidrIp', source_cidr)
        else:
            req.add_query_param('SourceCidrIp', source_cidr)
        req.add_query_param('Policy', policy)
        if description:
            req.add_query_param('Description', description)

        client.do_action_with_exception(req)
        logger.info(f"SG rule added: {ip_protocol} {port_range} from {source_cidr}")
        return True, 'ok'
    except Exception as e:
        err_text = str(e).lower()
        if 'invalidpermission.duplicate' in err_text:
            logger.info(f"SG rule already exists: {ip_protocol} {port_range} from {source_cidr}")
            return True, 'exists'
        logger.error(f"Authorize SG failed: {e}")
        return False, str(e)


def revoke_sg(client, security_group_id, region_id, ip_protocol, port_range, source_cidr='0.0.0.0/0', policy='accept'):
    """Remove an inbound rule from a security group."""
    try:
        req = CommonRequest()
        req.set_domain(f'ecs.{region_id}.aliyuncs.com')
        req.set_version('2014-05-26')
        req.set_action_name('RevokeSecurityGroup')
        req.set_method('POST')
        req.set_protocol_type('https')
        req.add_query_param('SecurityGroupId', security_group_id)
        req.add_query_param('RegionId', region_id)
        req.add_query_param('NicType', 'intranet')
        req.add_query_param('IpProtocol', ip_protocol)
        req.add_query_param('PortRange', port_range)
        if ':' in str(source_cidr):
            req.add_query_param('Ipv6SourceCidrIp', source_cidr)
        else:
            req.add_query_param('SourceCidrIp', source_cidr)
        req.add_query_param('Policy', policy)

        client.do_action_with_exception(req)
        logger.info(f"SG rule revoked: {ip_protocol} {port_range}")
        return True, 'ok'
    except Exception as e:
        logger.error(f"Revoke SG failed: {e}")
        return False, str(e)


# ================== 6. Main Logic ==================
def check_and_manage_instance(instance_id):
    instance_lock = _try_acquire_instance_lock(instance_id)
    if not instance_lock:
        logger.info(f"Skip duplicate instance check for {instance_id}: instance lock busy")
        return

    instance = db.session.get(EcsInstance, instance_id)
    if not instance:
        _release_instance_lock(instance_lock)
        return

    # Basic error handling for missing AK/SK
    if not instance.access_key_id or not instance.access_key_secret:
        logger.error(f"Missing AK/SK for instance {instance.name}")
        return

    logger.info(f"Checking: {instance.name} ({instance.instance_id})...")

    try:
        client = get_client(instance)

        # Fetch traffic (CDT reading is cumulative for the period; we persist by delta to avoid jump/reset bugs)
        previous_api_gb = instance.last_api_traffic or 0
        try:
            current_api_gb = get_total_traffic_gb(client, instance.region_id, raise_on_error=True)
            _update_credential_status(instance, 'ok')
        except BillingQueryError as billing_err:
            current_api_gb = previous_api_gb
            delta_gb = 0
            cred_state = _credential_status_from_billing_error(billing_err)
            if cred_state in ('invalid_access_key', 'unauthorized'):
                _update_credential_status(instance, cred_state, billing_err.raw_error or billing_err.message)
            else:
                # Keep prior auth alarm on transient network/rate-limit errors.
                if (instance.credential_status or 'ok') == 'ok':
                    _update_credential_status(instance, 'ok')
            logger.error(
                f"Failed to fetch CDT traffic for {instance.region_id} ({instance.name}): "
                f"{billing_err.error_code} {billing_err.raw_error or billing_err.message}"
            )

        if current_api_gb is not None:
            # If the upstream counter resets (new cycle/account reset), treat current reading as fresh delta.
            if previous_api_gb > 0 and current_api_gb < previous_api_gb:
                delta_gb = current_api_gb
            else:
                delta_gb = max(current_api_gb - previous_api_gb, 0)

            # Monthly counter is always incremental, reset by monthly scheduler.
            instance.current_month_traffic = (instance.current_month_traffic or 0) + (delta_gb or 0)
            instance.last_api_traffic = current_api_gb if current_api_gb is not None else (instance.last_api_traffic or 0)

            # LIFE accumulates forever; CYCLE keeps total aligned with current month for compatibility.
            if instance.traffic_strategy == 'life':
                instance.total_traffic_sum = (instance.total_traffic_sum or 0) + (delta_gb or 0)
            else:
                instance.total_traffic_sum = instance.current_month_traffic or 0

            # Write traffic log using displayed usage metric.
            display_usage = (instance.total_traffic_sum or 0) if instance.traffic_strategy == 'life' else (instance.current_month_traffic or 0)

            # Rate limit traffic logs to once per minute to optimize DB
            last_log = TrafficLog.query.filter_by(instance_id=instance.id).order_by(TrafficLog.timestamp.desc()).first()
            if not last_log or (datetime.datetime.utcnow() - last_log.timestamp).total_seconds() >= 60:
                traffic_log = TrafficLog(instance_id=instance.id, traffic_gb=display_usage)
                db.session.add(traffic_log)
        else:
            # Preserve previous values when API temporarily fails.
            current_api_gb = previous_api_gb
            delta_gb = 0

        # Fetch status and IPs
        try:
            ecs_info = get_ecs_info(client, instance.instance_id)
            if ecs_info:
                instance.status = ecs_info['status']
                instance.public_ip = ecs_info['public_ip']
                instance.private_ip = ecs_info['private_ip']
                if ecs_info['ipv6_addr']:
                    instance.ipv6_addr = ecs_info['ipv6_addr']
        except Exception as info_err:
            logger.error(f"Error updating instance info: {info_err}")
            if not instance.status: instance.status = "Error"
        
        current_status = instance.status

        probe_server = ProbeServer.query.filter_by(server_type='aliyun', ecs_instance_id=instance.id).first()
        probe_online = _is_probe_online(probe_server)

        # Determine the appropriate threshold per strategy
        log_api_gb = current_api_gb or 0
        log_month_traffic = instance.current_month_traffic or 0
        log_total_traffic = instance.total_traffic_sum or 0
        
        if instance.traffic_strategy == 'life':
            life_limit = instance.life_total_limit or 0
            logger.info(f"Status: {current_status} | API: {log_api_gb:.2f} GB | Month: {log_month_traffic:.2f} GB | Total: {log_total_traffic:.2f} GB | Life limit: {life_limit} GB")
        else:
            monthly_quota = instance.monthly_limit or 0
            logger.info(f"Status: {current_status} | API: {log_api_gb:.2f} GB | Month: {log_month_traffic:.2f} GB / Monthly limit: {monthly_quota} GB")

        # Check means enforcing recovery: if ECS is in a stopped/stopping state, always try to start it.
        if current_status in AUTO_START_ELIGIBLE_STATUSES:
            logger.info(f"Check detected ECS={current_status}, force start: {instance.name}")
            success, _ = ecs_start(client, instance.instance_id)
            if success:
                instance.status = 'Starting'

        # Auto start/stop logic
        if instance.auto_stop_enabled:
            if instance.traffic_strategy == 'cycle' and monthly_quota > 0:
                if (instance.current_month_traffic or 0) < monthly_quota:
                    if current_status in AUTO_START_ELIGIBLE_STATUSES and not probe_online:
                        logger.info("Traffic below threshold, try start instance.")
                        success, _ = ecs_start(client, instance.instance_id)
                        if success:
                            instance.status = 'Starting'
                else:
                    if current_status == 'Running' or probe_online:
                        logger.warning(f"Traffic exceeded ({(instance.current_month_traffic or 0):.2f} >= {monthly_quota}), try stop instance.")
                        success, _ = ecs_stop(client, instance.instance_id)
                        if success:
                            instance.status = 'Stopping'
            elif instance.traffic_strategy == 'life' and life_limit > 0:
                # For LIFE: total_traffic_sum is compared directly against life_total_limit
                life_consumed = instance.total_traffic_sum or 0
                if life_consumed >= life_limit:
                    if current_status == 'Running' or probe_online:
                        logger.warning(f"LIFE quota exhausted (consumed {life_consumed:.2f} >= {life_limit}), try stop.")
                        success, _ = ecs_stop(client, instance.instance_id)
                        if success:
                            instance.status = 'Stopping'

        try:
            limit = life_limit if instance.traffic_strategy == 'life' else monthly_quota
            alert_traffic = instance.total_traffic_sum if instance.traffic_strategy == 'life' else instance.current_month_traffic
            alert_traffic = alert_traffic or 0

            threshold_pct = instance.alert_threshold_pct or 80
            if limit and limit > 0:
                usage_pct = (alert_traffic / limit) * 100
                if usage_pct >= threshold_pct:
                    alert_cfg = AlertConfig.query.first()
                    if alert_cfg and alert_cfg.enabled and alert_cfg.webhook_url:
                        # Shared cooldown check to avoid alert storms (once per hour per instance)
                        # We use instance.id in the cooldown to distinguish alerts
                        last_notif = NotificationLog.query.filter(NotificationLog.message.like(f"%{instance.name}%")).order_by(NotificationLog.timestamp.desc()).first()
                        if not last_notif or (datetime.datetime.utcnow() - last_notif.timestamp).total_seconds() > 3600:
                            msg = (f"⚠️ [{instance.name}] 流量告警\n"
                                   f"已用: {alert_traffic:.2f} GB / 上限: {limit:.0f} GB ({usage_pct:.1f}%)\n"
                                   f"状态: {current_status}")
                            send_alert(alert_cfg.notify_type, alert_cfg.webhook_url, msg,
                                       instance_name=instance.name)
        except Exception as e:
            logger.error(f"Alert check failed: {e}")

        # Anomaly detection: alert if traffic spiked significantly
        try:
            if previous_api_gb and previous_api_gb > 0 and current_api_gb and current_api_gb > previous_api_gb:
                increase_pct = ((current_api_gb - previous_api_gb) / previous_api_gb) * 100
                if increase_pct >= ANOMALY_INCREASE_PCT:
                    alert_cfg = AlertConfig.query.first()
                    if alert_cfg and alert_cfg.enabled and alert_cfg.webhook_url:
                        # Shared cooldown check to avoid alert storms (once per 30 mins)
                        last_notif = NotificationLog.query.filter(NotificationLog.message.like(f"%{instance.name}%")).order_by(NotificationLog.timestamp.desc()).first()
                        if not last_notif or (datetime.datetime.utcnow() - last_notif.timestamp).total_seconds() > 1800:
                            msg = (f"🚨 [{instance.name}] 流量异常\n"
                                   f"API读数从 {previous_api_gb:.2f} GB 增至 {current_api_gb:.2f} GB (+{increase_pct:.1f}%)\n"
                                   f"本月累计: {(instance.current_month_traffic or 0):.2f} GB\n"
                                   f"状态: {current_status}")
                            send_alert(alert_cfg.notify_type, alert_cfg.webhook_url, msg,
                                       instance_name=instance.name)
                            logger.warning(f"Anomaly detected for {instance.name}: +{increase_pct:.1f}%")
        except Exception as e:
            logger.error(f"Anomaly check failed: {e}")

        instance.last_checked = datetime.datetime.utcnow()
        db.session.commit()

    except Exception as e:
        inst_name = instance.name if instance else instance_id
        logger.error(f"Check flow error {inst_name}: {e}")
        db.session.rollback()
    finally:
        _release_instance_lock(instance_lock)


def check_all_instances():
    logger.info("Starting scheduled check for all instances...")
    lock_ctx, lock_state = _try_acquire_run_lock()
    if not lock_ctx:
        logger.info(f"Skip duplicate scheduled round: lock not acquired ({lock_state})")
        return
    try:
        instances = EcsInstance.query.all()
        for instance in instances:
            if not instance.monitoring_enabled:
                logger.info(f"Skipping {instance.name} (monitoring disabled).")
                continue
            check_and_manage_instance(instance.id)
    except Exception as e:
        logger.error(f"Error in check_all_instances: {e}")
    finally:
        _release_run_lock(lock_ctx)
