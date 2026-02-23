# Docker 一键部署说明

## 1. Linux 服务器一键部署（推荐）
在项目根目录执行：

```bash
chmod +x deploy.sh
./deploy.sh
```

脚本会按中文步骤自动完成：
1. 检查项目文件完整性
2. 检查 Docker 和 docker compose
3. 生成 `.env`（首次）
4. 检查端口占用与防火墙提示
5. 构建并启动容器
6. 访问 `/health` 做健康检查

默认访问地址：

```text
http://<服务器IP>:5000
```

## 2. Windows 一键部署

```powershell
powershell -ExecutionPolicy Bypass -File .\deploy.ps1
```

## 3. 常用运维命令

```bash
# 容器状态
docker compose ps

# 实时日志
docker compose logs -f dns-panel

# 重建并启动
docker compose up -d --build

# 停止服务
docker compose down
```

## 4. 端口与防火墙
- 默认端口：`5000`，可在 `.env` 修改 `PANEL_PORT`
- **部署脚本会自动一键放行防火墙（IPv4 + IPv6）**，无需手动操作：
  - Linux：自动检测并配置 UFW / firewalld / iptables+ip6tables
  - Windows：自动创建 Windows 防火墙入站规则（AddressFamily Any，同时覆盖 IPv4 与 IPv6）
- 云服务器**安全组**仍需在控制台手动放行 `PANEL_PORT/tcp`（安全组独立于系统防火墙）
- 手动放行示例（UFW）：

```bash
ufw allow 5000/tcp
```

## 5. 国内/国外测试机一键部署（可选）
说明：面板默认使用“面板机本地 Ping”。如需独立测试机校验，可部署 checker。

国内机器（推荐）：

```bash
curl -fsSL http://你的面板域名或IP:5000/agent/install_checker_cn.sh -o /tmp/install_checker_cn.sh && PANEL_BASE_URL=http://你的面板域名或IP:5000 bash /tmp/install_checker_cn.sh
```

国外机器：

```bash
curl -fsSL http://你的面板域名或IP:5000/agent/install_checker_global.sh -o /tmp/install_checker_global.sh && PANEL_BASE_URL=http://你的面板域名或IP:5000 bash /tmp/install_checker_global.sh
```

部署后验证：

```bash
systemctl status dns-panel-checker --no-pager
curl -s 'http://127.0.0.1:8888/ping?host=1.1.1.1'
journalctl -u dns-panel-checker -f
```

## 6. 关键环境变量
`.env` 中可配置：

- `PANEL_PORT`: 面板对外端口
- `PUBLIC_PANEL_URL`: 反代/NAT 场景下用于生成外网部署命令（例如 `https://panel.example.com`）
- `DNS_FAILOVER_TEST_MODE`: 自动故障转移检测模式，`panel_local` 或 `checker`
- `DNS_PANEL_DISABLE_SCHEDULER`: 测试时可设为 `1` 关闭调度器
