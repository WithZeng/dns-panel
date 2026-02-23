#!/usr/bin/env python3
"""
国内 Ping 测试微服务
部署在国内测试机上，提供 HTTP API 供面板调用
检测目标 IP 是否可以从国内 ping 通
"""
import subprocess
import platform
import re
from flask import Flask, request, jsonify

app = Flask(__name__)


def ping_host(host, count=3, timeout=5):
    """ICMP ping 检测，返回是否可达和平均延迟"""
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'

    try:
        result = subprocess.run(
            ['ping', param, str(count), timeout_param, str(timeout), host],
            capture_output=True, text=True, timeout=timeout + 5
        )
        reachable = result.returncode == 0

        avg_ms = None
        if reachable:
            output = result.stdout
            match = re.search(r'(?:avg|平均)\s*=?\s*(\d+\.?\d*)', output)
            if not match:
                match = re.search(r'/(\d+\.?\d*)/', output)
            if match:
                avg_ms = float(match.group(1))

        return reachable, avg_ms
    except Exception:
        return False, None


@app.route('/ping', methods=['GET'])
def check_ping():
    host = request.args.get('host', '').strip()
    if not host:
        return jsonify({'error': 'missing host parameter'}), 400

    reachable, avg_ms = ping_host(host)
    return jsonify({
        'host': host,
        'reachable': reachable,
        'avg_ms': avg_ms,
    })


@app.route('/check', methods=['GET'])
def check_compat():
    host = request.args.get('host', '').strip()
    _ = request.args.get('port', '')
    if not host:
        return jsonify({'error': 'missing host parameter'}), 400

    reachable, avg_ms = ping_host(host)
    return jsonify({'reachable': reachable, 'avg_ms': avg_ms})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8888)
