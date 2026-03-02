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
def get_total_traffic_gb(client, region_id):
    request = CommonRequest()
    request.set_domain('cdt.aliyuncs.com')
    request.set_version('2021-08-13')
    request.set_action_name('ListCdtInternetTraffic')
    request.set_method('POST')
    request.set_protocol_type('https')

    try:
        response = client.do_action_with_exception(request)
        response_json = json.loads(response.decode('utf-8') if isinstance(response, (bytes, bytearray)) else response)
        total_bytes = 0
        for detail in response_json.get('TrafficDetails', []):
            if detail.get('BusinessRegionId') == region_id:
                total_bytes += detail.get('Traffic', 0)
        return total_bytes / (1024 ** 3)
    except Exception as e:
        logger.error(f"Failed to fetch CDT traffic: {e}")
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
    instance = db.session.get(EcsInstance, instance_id)
    if not instance:
        return

    # Basic error handling for missing AK/SK
    if not instance.access_key_id or not instance.access_key_secret:
        logger.error(f"Missing AK/SK for instance {instance.name}")
        return

    logger.info(f"Checking: {instance.name} ({instance.instance_id})...")

    try:
        client = get_client(instance)

        # Fetch traffic (CDT reading is cumulative for the period; we persist by delta to avoid jump/reset bugs)
        current_api_gb = get_total_traffic_gb(client, instance.region_id)
        previous_api_gb = instance.last_api_traffic or 0

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
                if (instance.current_month_traffic or 0) < monthly_quota:
                    if current_status == 'Stopped' and not probe_online:
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
