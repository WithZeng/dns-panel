#!/usr/bin/env python3
import argparse
import base64
import json
import os
import platform
import random
import socket
import ssl
import struct
import subprocess
import time
import urllib.parse
import urllib.request

import psutil


def get_cpu_name():
    name = platform.processor().strip()
    if name:
        return name

    if os.path.exists('/proc/cpuinfo'):
        try:
            with open('/proc/cpuinfo', 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if 'model name' in line.lower():
                        return line.split(':', 1)[1].strip()
        except Exception:
            pass

    return 'Unknown CPU'


def get_virtualization_type():
    try:
        out = subprocess.check_output(['systemd-detect-virt'], stderr=subprocess.DEVNULL, timeout=2)
        val = out.decode().strip()
        if val and val != 'none':
            return val
    except Exception:
        pass

    try:
        if os.path.exists('/proc/1/cgroup'):
            data = open('/proc/1/cgroup', 'r', encoding='utf-8', errors='ignore').read().lower()
            if 'docker' in data:
                return 'docker'
            if 'kubepods' in data:
                return 'kubernetes'
            if 'lxc' in data:
                return 'lxc'
    except Exception:
        pass

    return 'unknown'


def fetch_public_ip(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'dns-panel-agent/1.0'})
        with urllib.request.urlopen(req, timeout=4) as resp:
            val = resp.read().decode().strip()
            if val:
                return val
    except Exception:
        return ''
    return ''


def detect_local_ip():
    ipv4 = ''
    ipv6 = ''
    try:
        for _, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                fam = getattr(a, 'family', None)
                addr = getattr(a, 'address', '') or ''
                if fam == socket.AF_INET and addr and not addr.startswith('127.'):
                    if not ipv4:
                        ipv4 = addr
                elif fam == socket.AF_INET6 and addr and not addr.startswith('::1'):
                    pure = addr.split('%')[0]
                    if not ipv6:
                        ipv6 = pure
    except Exception:
        pass
    return ipv4, ipv6


def detect_public_ip():
    v4_services = [
        'https://api.ipify.org',
        'https://ipv4.icanhazip.com',
        'https://ifconfig.me/ip',
    ]
    v6_services = [
        'https://api6.ipify.org',
        'https://ipv6.icanhazip.com',
    ]
    ipv4 = ''
    ipv6 = ''
    for u in v4_services:
        ipv4 = fetch_public_ip(u)
        if ipv4:
            break
    for u in v6_services:
        ipv6 = fetch_public_ip(u)
        if ipv6:
            break
    return ipv4, ipv6


def collect_basic_info():
    vm = psutil.virtual_memory()
    sw = psutil.swap_memory()
    disk = psutil.disk_usage('/')
    pub4, pub6 = detect_public_ip()
    local4, local6 = detect_local_ip()

    return {
        'hostname': socket.gethostname(),
        'cpu_name': get_cpu_name(),
        'cpu_cores': psutil.cpu_count(logical=True) or 0,
        'arch': platform.machine(),
        'os_info': f"{platform.system()} {platform.release()}",
        'virtualization': get_virtualization_type(),
        'ipv4': pub4 or local4,
        'ipv6': pub6 or local6,
        'mem_total': int(vm.total),
        'swap_total': int(sw.total),
        'disk_total': int(disk.total),
    }


def collect_report(prev_net, prev_time):
    now = time.time()

    cpu = {
        'name': get_cpu_name(),
        'cores': psutil.cpu_count(logical=True) or 0,
        'arch': platform.machine(),
        'usage': float(psutil.cpu_percent(interval=None)),
    }

    vm = psutil.virtual_memory()
    ram = {'total': int(vm.total), 'used': int(vm.used)}

    sw = psutil.swap_memory()
    swap = {'total': int(sw.total), 'used': int(sw.used)}

    disk_u = psutil.disk_usage('/')
    disk = {'total': int(disk_u.total), 'used': int(disk_u.used)}

    net = psutil.net_io_counters()
    elapsed = max(now - prev_time, 1e-6)
    up_rate = max((net.bytes_sent - prev_net.bytes_sent) / elapsed, 0)
    down_rate = max((net.bytes_recv - prev_net.bytes_recv) / elapsed, 0)
    network = {
        'up': up_rate,
        'down': down_rate,
        'totalUp': int(net.bytes_sent),
        'totalDown': int(net.bytes_recv),
    }

    try:
        l1, l5, l15 = os.getloadavg()
    except Exception:
        l1, l5, l15 = 0.0, 0.0, 0.0
    load = {'load1': round(l1, 2), 'load5': round(l5, 2), 'load15': round(l15, 2)}

    tcp_count = 0
    udp_count = 0
    try:
        conns = psutil.net_connections(kind='inet')
        for c in conns:
            if c.type == socket.SOCK_STREAM and c.status == psutil.CONN_ESTABLISHED:
                tcp_count += 1
            elif c.type == socket.SOCK_DGRAM:
                udp_count += 1
    except Exception:
        pass

    uptime = max(int(time.time() - psutil.boot_time()), 0)

    report = {
        'cpu': cpu,
        'ram': ram,
        'swap': swap,
        'disk': disk,
        'network': network,
        'load': load,
        'connections': {'tcp': tcp_count, 'udp': udp_count},
        'uptime': uptime,
        'process_count': len(psutil.pids()),
    }

    return report, net, now


class SimpleWebSocketClient:
    def __init__(self, server_url):
        self.server_url = server_url
        self.sock = None

    def connect(self):
        parsed = urllib.parse.urlparse(self.server_url)
        if parsed.scheme not in ('ws', 'wss'):
            raise ValueError('server url must start with ws:// or wss://')

        host = parsed.hostname
        if not host:
            raise ValueError('invalid websocket host')

        port = parsed.port
        if not port:
            port = 443 if parsed.scheme == 'wss' else 80

        path = parsed.path or '/'
        if parsed.query:
            path += '?' + parsed.query

        raw = socket.create_connection((host, port), timeout=10)
        if parsed.scheme == 'wss':
            ctx = ssl.create_default_context()
            raw = ctx.wrap_socket(raw, server_hostname=host)

        key = base64.b64encode(os.urandom(16)).decode()
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "User-Agent: dns-panel-agent/1.0\r\n\r\n"
        )
        raw.sendall(req.encode())

        resp = b''
        while b'\r\n\r\n' not in resp:
            chunk = raw.recv(4096)
            if not chunk:
                raise ConnectionError('websocket handshake failed: empty response')
            resp += chunk
            if len(resp) > 65535:
                raise ConnectionError('websocket handshake failed: response too large')

        header = resp.split(b'\r\n\r\n', 1)[0].decode(errors='ignore')
        if ' 101 ' not in header:
            raise ConnectionError(f'websocket handshake failed: {header.splitlines()[0] if header else "invalid response"}')

        self.sock = raw

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def _send_frame(self, payload: bytes, opcode=0x1):
        if self.sock is None:
            raise ConnectionError('socket not connected')

        first = 0x80 | (opcode & 0x0F)
        length = len(payload)

        if length < 126:
            header = bytes([first, 0x80 | length])
        elif length < (1 << 16):
            header = bytes([first, 0x80 | 126]) + struct.pack('!H', length)
        else:
            header = bytes([first, 0x80 | 127]) + struct.pack('!Q', length)

        mask = os.urandom(4)
        masked = bytes(payload[i] ^ mask[i % 4] for i in range(length))
        self.sock.sendall(header + mask + masked)

    def send_text(self, text: str):
        self._send_frame(text.encode('utf-8'), opcode=0x1)


def _derive_http_url(ws_url):
    """从 WebSocket URL 推导 HTTP 上报地址"""
    url = ws_url.replace('wss://', 'https://').replace('ws://', 'http://')
    if '/ws/agent' in url:
        url = url.split('/ws/agent')[0]
    url = url.rstrip('/')
    return f'{url}/api/probe/report'


def http_report(http_url, token, payload):
    """HTTP POST 回退上报"""
    payload['token'] = token
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(
        http_url,
        data=data,
        headers={
            'Content-Type': 'application/json',
            'User-Agent': 'dns-panel-agent/1.0',
        },
        method='POST',
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode()
            result = json.loads(body)
            return result.get('ok', False)
    except Exception as e:
        print(f'[agent] HTTP report failed: {e}')
        return False


def run_agent(server_url, token, interval):
    sep = '&' if '?' in server_url else '?'
    ws_url = f'{server_url}{sep}token={token}'
    http_url = _derive_http_url(server_url)

    ws_fail_count = 0
    MAX_WS_FAILS = 3
    backoff = 1
    basic_upload_interval = max(interval * 20, 60.0)
    next_basic_upload_at = 0.0

    # Prime cpu_percent baseline so each sample reflects recent usage.
    psutil.cpu_percent(interval=None)

    while True:
        if ws_fail_count < MAX_WS_FAILS:
            ws = SimpleWebSocketClient(ws_url)
            try:
                print(f'[agent] connecting WebSocket: {server_url}')
                ws.connect()
                print('[agent] WebSocket connected')

                ws.send_text(json.dumps({'type': 'auth', 'token': token}))
                ws.send_text(json.dumps({
                    'type': 'basic', 'token': token,
                    'basic': collect_basic_info(),
                }))
                next_basic_upload_at = time.time() + basic_upload_interval

                prev_net = psutil.net_io_counters()
                prev_time = time.time()
                backoff = 1
                ws_fail_count = 0

                while True:
                    now_ts = time.time()
                    if now_ts >= next_basic_upload_at:
                        ws.send_text(json.dumps({
                            'type': 'basic', 'token': token,
                            'basic': collect_basic_info(),
                        }))
                        next_basic_upload_at = now_ts + basic_upload_interval
                    report, prev_net, prev_time = collect_report(prev_net, prev_time)
                    ws.send_text(json.dumps({
                        'type': 'report', 'token': token,
                        'report': report,
                    }))
                    time.sleep(interval)

            except KeyboardInterrupt:
                ws.close()
                raise
            except Exception as e:
                ws.close()
                ws_fail_count += 1
                wait_s = min(backoff, 60)
                jitter = random.uniform(0, 0.3 * wait_s)
                print(f'[agent] WebSocket failed ({ws_fail_count}/{MAX_WS_FAILS}): {e}; retry in {wait_s + jitter:.1f}s')
                time.sleep(wait_s + jitter)
                backoff = min(backoff * 2, 60)
                continue

        print(f'[agent] WebSocket failed {MAX_WS_FAILS} times, falling back to HTTP POST: {http_url}')

        try:
            basic = collect_basic_info()
            http_report(http_url, token, {'basic': basic})
            next_basic_upload_at = time.time() + basic_upload_interval

            prev_net = psutil.net_io_counters()
            prev_time = time.time()

            http_round = 0
            while http_round < 20:
                now_ts = time.time()
                if now_ts >= next_basic_upload_at:
                    http_report(http_url, token, {'basic': collect_basic_info()})
                    next_basic_upload_at = now_ts + basic_upload_interval
                report, prev_net, prev_time = collect_report(prev_net, prev_time)
                ok = http_report(http_url, token, {'report': report})
                if ok:
                    print(f'[agent] HTTP report OK')
                time.sleep(interval)
                http_round += 1

            ws_fail_count = 0
            backoff = 1
            print('[agent] switching back to WebSocket mode')

        except KeyboardInterrupt:
            raise
        except Exception as e:
            print(f'[agent] HTTP mode error: {e}')
            time.sleep(min(backoff, 60))
            backoff = min(backoff * 2, 60)
            ws_fail_count = 0


def main():
    parser = argparse.ArgumentParser(description='DNS Panel lightweight probe agent')
    parser.add_argument('--server', required=True, help='WebSocket server URL, e.g. wss://panel/ws/agent')
    parser.add_argument('--token', required=True, help='Probe token')
    parser.add_argument('--interval', type=float, default=3.0, help='Report interval in seconds (default: 3)')

    args = parser.parse_args()
    run_agent(args.server, args.token, max(args.interval, 1.0))


if __name__ == '__main__':
    main()
