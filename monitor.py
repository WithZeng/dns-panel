import json
import logging
import datetime
from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.request import CommonRequest
from aliyunsdkecs.request.v20140526.DescribeInstancesRequest import DescribeInstancesRequest
from aliyunsdkecs.request.v20140526.StopInstanceRequest import StopInstanceRequest
from aliyunsdkecs.request.v20140526.StartInstanceRequest import StartInstanceRequest
from aliyunsdkecs.request.v20140526.DeleteInstanceRequest import DeleteInstanceRequest
from models import db, EcsInstance, TrafficLog, AlertConfig, ProbeServer
from notifier import send_alert

# ================== 1. Configure Logging ==================
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Anomaly detection: alert if traffic increases by more than this % in a single check
ANOMALY_INCREASE_PCT = 20.0


def _is_probe_online(server):
    if not server or not server.last_seen:
        return False
    return (datetime.datetime.utcnow() - server.last_seen).total_seconds() <= 30


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
def get_ecs_status(client, instance_id):
    try:
        request = DescribeInstancesRequest()
        request.set_InstanceIds(json.dumps([instance_id]))
        response = client.do_action_with_exception(request)
        response_json = json.loads(response)
        if response_json.get('Instances') and response_json['Instances'].get('Instance'):
            return response_json['Instances']['Instance'][0].get('Status', 'Unknown')
        return "Unknown"
    except Exception as e:
        logger.error(f"Failed to get status: {e}")
        return "Unknown"


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

        def _collect_ipv6_from_items(items):
            if not isinstance(items, list):
                return
            for item in items:
                if isinstance(item, dict):
                    ip_val = (item.get('Ipv6Address') or '').strip()
                    if ip_val:
                        addresses.append(ip_val)
                elif isinstance(item, str):
                    ip_val = item.strip()
                    if ip_val:
                        addresses.append(ip_val)

        vpc_attrs = inst.get('VpcAttributes', {})
        ipv6_objs = vpc_attrs.get('Ipv6Addresses', {}).get('Ipv6Address', [])
        if isinstance(ipv6_objs, list):
            addresses.extend([str(ip).strip() for ip in ipv6_objs if str(ip).strip()])

        eni_id = ''
        enis = inst.get('NetworkInterfaces', {}).get('NetworkInterface', [])
        if isinstance(enis, list) and enis:
            eni_id = (enis[0].get('NetworkInterfaceId') or '').strip()
            for eni in enis:
                eni_ipv6 = eni.get('Ipv6Sets', {}).get('Ipv6Set', [])
                _collect_ipv6_from_items(eni_ipv6)
                eni_ipv6_alt = eni.get('Ipv6AddressSets', {}).get('Ipv6AddressSet', [])
                _collect_ipv6_from_items(eni_ipv6_alt)

        if eni_id and not addresses:
            try:
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
                eni_sets = eni_data.get('NetworkInterfaceSets', {}).get('NetworkInterfaceSet', [])
                if isinstance(eni_sets, list) and eni_sets:
                    eni0 = eni_sets[0]
                    _collect_ipv6_from_items(eni0.get('Ipv6Sets', {}).get('Ipv6Set', []))
                    _collect_ipv6_from_items(eni0.get('Ipv6AddressSets', {}).get('Ipv6AddressSet', []))
            except Exception as sub_e:
                logger.warning(f"DescribeNetworkInterfaces fallback failed for {instance.instance_id}: {sub_e}")

        unique = []
        for ip in addresses:
            if ip not in unique:
                unique.append(ip)

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
        for key in ('Ipv6Sets', 'Ipv6Set'):
            if key in payload:
                val = payload.get(key)
                if isinstance(val, dict):
                    lst = val.get('Ipv6Set', [])
                    if isinstance(lst, list):
                        for item in lst:
                            if isinstance(item, dict):
                                ip_val = (item.get('Ipv6Address') or '').strip()
                                if ip_val:
                                    new_ips.append(ip_val)
                            elif isinstance(item, str) and item.strip():
                                new_ips.append(item.strip())
                elif isinstance(val, list):
                    for item in val:
                        if isinstance(item, dict):
                            ip_val = (item.get('Ipv6Address') or '').strip()
                            if ip_val:
                                new_ips.append(ip_val)
                        elif isinstance(item, str) and item.strip():
                            new_ips.append(item.strip())

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
def get_total_traffic_gb(client, region_id):
    request = CommonRequest()
    request.set_domain('cdt.aliyuncs.com')
    request.set_version('2021-08-13')
    request.set_action_name('ListCdtInternetTraffic')
    request.set_method('POST')
    request.set_protocol_type('https')

    try:
        response = client.do_action_with_exception(request)
        response_json = json.loads(response.decode('utf-8'))
        total_bytes = 0
        for detail in response_json.get('TrafficDetails', []):
            if detail.get('BusinessRegionId') == region_id:
                total_bytes += detail.get('Traffic', 0)
        return total_bytes / (1024 ** 3)
    except Exception as e:
        logger.error(f"Failed to fetch CDT traffic: {e}")
        return 0.0


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
        req.add_query_param('IpProtocol', ip_protocol)  # tcp, udp, icmp, all
        req.add_query_param('PortRange', port_range)      # e.g. 80/80, 1/65535, -1/-1
        if ':' in str(source_cidr):
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
    instance = EcsInstance.query.get(instance_id)
    if not instance:
        return

    logger.info(f"Checking: {instance.name} ({instance.instance_id})...")

    try:
        client = get_client(instance)

        # Fetch traffic
        current_gb = get_total_traffic_gb(client, instance.region_id)
        previous_gb = instance.current_month_traffic or 0

        instance.last_api_traffic = current_gb
        instance.current_month_traffic = current_gb
        # For LIFE, total_traffic_sum accumulates across months; for CYCLE it equals current month
        if instance.traffic_strategy != 'life':
            instance.total_traffic_sum = current_gb

        # Write traffic log
        traffic_log = TrafficLog(instance_id=instance.id, traffic_gb=current_gb)
        db.session.add(traffic_log)

        # Fetch status
        current_status = get_ecs_status(client, instance.instance_id)
        instance.status = current_status

        probe_server = ProbeServer.query.filter_by(server_type='aliyun', ecs_instance_id=instance.id).first()
        probe_online = _is_probe_online(probe_server)

        # Determine the appropriate threshold per strategy
        if instance.traffic_strategy == 'life':
            monthly_quota = instance.monthly_free_allowance or 0
            life_limit = instance.life_total_limit or 0
            logger.info(f"Status: {current_status} | Traffic: {current_gb:.2f} GB | Monthly quota: {monthly_quota} GB | Life limit: {life_limit} GB")
        else:
            monthly_quota = instance.monthly_limit or 0
            logger.info(f"Status: {current_status} | Traffic: {current_gb:.2f} GB / Monthly limit: {monthly_quota} GB")

        # Auto start logic (probe-first): if probe offline and ECS appears stopped/pending, auto start when enabled.
        if instance.auto_start_enabled:
            if (not probe_online) and current_status in ('Stopped', 'Pending'):
                logger.info(f"Probe offline + ECS={current_status}, try auto-start: {instance.name}")
                success, _ = ecs_start(client, instance.instance_id)
                if success:
                    instance.status = 'Starting'

        # Auto start/stop logic
        if instance.auto_stop_enabled:
            if instance.traffic_strategy == 'cycle' and monthly_quota > 0:
                if current_gb < monthly_quota:
                    if current_status == 'Stopped' and not probe_online:
                        logger.info("Traffic below threshold, try start instance.")
                        success, _ = ecs_start(client, instance.instance_id)
                        if success:
                            instance.status = 'Starting'
                else:
                    if current_status == 'Running' or probe_online:
                        logger.warning(f"Traffic exceeded ({current_gb:.2f} >= {monthly_quota}), try stop instance.")
                        success, _ = ecs_stop(client, instance.instance_id)
                        if success:
                            instance.status = 'Stopping'
            elif instance.traffic_strategy == 'life' and life_limit > 0:
                # For LIFE: compute how much lifetime pool has been consumed
                start = instance.real_creation_time or instance.created_at
                now = instance.last_checked or instance.created_at
                running_days = max((now - start).days, 0) if start and now else 0
                running_months = (running_days // 30) + 1
                accumulated_monthly = running_months * monthly_quota
                total_traffic = instance.total_traffic_sum or 0
                life_consumed = max(total_traffic - accumulated_monthly, 0)
                if life_consumed >= life_limit:
                    if current_status == 'Running' or probe_online:
                        logger.warning(f"LIFE quota exhausted (consumed {life_consumed:.2f} >= {life_limit}), try stop.")
                        success, _ = ecs_stop(client, instance.instance_id)
                        if success:
                            instance.status = 'Stopping'

        # Alert: threshold notification
        try:
            if instance.traffic_strategy == 'life':
                limit = life_limit
                # Use life_consumed for alert percentage
                start = instance.real_creation_time or instance.created_at
                now = instance.last_checked or instance.created_at
                running_days = max((now - start).days, 0) if start and now else 0
                running_months = (running_days // 30) + 1
                accumulated_monthly = running_months * monthly_quota
                total_traffic = instance.total_traffic_sum or 0
                alert_traffic = max(total_traffic - accumulated_monthly, 0)
            else:
                limit = monthly_quota
                alert_traffic = current_gb

            threshold_pct = instance.alert_threshold_pct or 80
            if limit > 0:
                usage_pct = (alert_traffic / limit) * 100
                if usage_pct >= threshold_pct:
                    alert_cfg = AlertConfig.query.first()
                    if alert_cfg and alert_cfg.enabled and alert_cfg.webhook_url:
                        msg = (f"⚠️ [{instance.name}] 流量告警\n"
                               f"已用: {alert_traffic:.2f} GB / 上限: {limit:.0f} GB ({usage_pct:.1f}%)\n"
                               f"状态: {current_status}")
                        send_alert(alert_cfg.notify_type, alert_cfg.webhook_url, msg,
                                   instance_name=instance.name)
        except Exception as e:
            logger.error(f"Alert check failed: {e}")

        # Anomaly detection: alert if traffic spiked significantly
        try:
            if previous_gb > 0 and current_gb > previous_gb:
                increase_pct = ((current_gb - previous_gb) / previous_gb) * 100
                if increase_pct >= ANOMALY_INCREASE_PCT:
                    alert_cfg = AlertConfig.query.first()
                    if alert_cfg and alert_cfg.enabled and alert_cfg.webhook_url:
                        msg = (f"🚨 [{instance.name}] 流量异常\n"
                               f"流量从 {previous_gb:.2f} GB 突增至 {current_gb:.2f} GB (+{increase_pct:.1f}%)\n"
                               f"状态: {current_status}")
                        send_alert(alert_cfg.notify_type, alert_cfg.webhook_url, msg,
                                   instance_name=instance.name)
                        logger.warning(f"Anomaly detected for {instance.name}: +{increase_pct:.1f}%")
        except Exception as e:
            logger.error(f"Anomaly check failed: {e}")

        instance.last_checked = datetime.datetime.utcnow()
        db.session.commit()

    except Exception as e:
        logger.error(f"Check flow error {instance.name}: {e}")
        db.session.rollback()


def check_all_instances():
    logger.info("Starting scheduled check for all instances...")
    try:
        instances = EcsInstance.query.all()
        for instance in instances:
            if not instance.monitoring_enabled:
                logger.info(f"Skipping {instance.name} (monitoring disabled).")
                continue
            check_and_manage_instance(instance.id)
    except Exception as e:
        logger.error(f"Error in check_all_instances: {e}")
