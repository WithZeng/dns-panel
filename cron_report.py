
import os
import sys
from datetime import datetime

# 模拟 dns-panel 环境
sys.path.append('/root/.openclaw/workspace/dns-panel')
from app import app, db
from models import EcsInstance
from monitor import check_all_instances

def report_status():
    with app.app_context():
        # 执行监控核心函数（包含修复后的代码）
        check_all_instances()
        
        # 获取结果
        instances = EcsInstance.query.all()
        report = []
        for inst in instances:
            report.append(f"📡 实例: {inst.name}\n流量: {inst.total_traffic_sum:.4f} GB\n时间: {datetime.now().strftime('%H:%M:%S')}")
        
        return "\n\n".join(report)

if __name__ == "__main__":
    print(report_status())
