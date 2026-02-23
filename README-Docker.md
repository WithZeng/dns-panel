# Docker 一键部署说明

> 所有操作统一使用 `panel.sh`（Linux）或 `panel.ps1`（Windows）一个脚本完成。

## 1. Linux 一键部署（推荐）

```bash
chmod +x panel.sh
bash panel.sh deploy
```

## 2. Windows 一键部署

```powershell
powershell -ExecutionPolicy Bypass -File .\panel.ps1 deploy
```

部署脚本自动完成：检测 Docker → 生成 `.env` → 端口检查 → IPv4/IPv6 防火墙放行 → 构建容器 → 健康检查。

默认访问地址：

```text
http://<服务器IP>:5000
```

首次登录凭据见 `instance/initial_admin_credentials.txt`。

## 3. 一键更新

```bash
# Linux
bash panel.sh update

# Windows
.\panel.ps1 update
```

更新流程：**备份数据库 → git pull → 重建镜像 → 重启容器 → 健康检查**。

可选参数：

| Linux              | Windows          | 说明                        |
| ------------------- | ---------------- | --------------------------- |
| `--skip-backup`     | `-SkipBackup`    | 跳过数据库备份              |
| `--skip-pull`       | `-SkipPull`      | 跳过 git pull（仅重新构建） |

> 数据库备份位置：`instance/backups/`，自动清理 14 天前旧备份。

## 4. 更多管理命令

| 命令                         | 说明           |
| ---------------------------- | -------------- |
| `bash panel.sh status`       | 查看容器状态   |
| `bash panel.sh logs`         | 实时查看日志   |
| `bash panel.sh restart`      | 重启容器       |
| `bash panel.sh stop`         | 停止服务       |
| `bash panel.sh backup`       | 手动备份数据库 |
| `bash panel.sh help`         | 查看帮助       |

Windows 对应：`.\panel.ps1 status` / `.\panel.ps1 logs` 等。

## 5. 端口与防火墙
- 默认端口：`5000`，可在 `.env` 修改 `PANEL_PORT`
- **部署脚本会自动一键放行防火墙（IPv4 + IPv6）**，无需手动操作：
  - Linux：自动检测并配置 UFW / firewalld / iptables+ip6tables
  - Windows：自动创建 Windows 防火墙入站规则（AddressFamily Any，同时覆盖 IPv4 与 IPv6）
- 云服务器**安全组**仍需在控制台手动放行 `PANEL_PORT/tcp`（安全组独立于系统防火墙）
- 手动放行示例（UFW）：

```bash
ufw allow 5000/tcp
```

## 6. 国内/国外测试机一键部署（可选）
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

## 7. 关键环境变量
`.env` 中可配置：

- `PANEL_PORT`: 面板对外端口
- `PUBLIC_PANEL_URL`: 反代/NAT 场景下用于生成外网部署命令（例如 `https://panel.example.com`）
- `DNS_FAILOVER_TEST_MODE`: 自动故障转移检测模式，`panel_local` 或 `checker`
- `DNS_PANEL_DISABLE_SCHEDULER`: 测试时可设为 `1` 关闭调度器
