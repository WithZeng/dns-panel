# DNS Panel — 阿里云 ECS 流量监控 & DNS 故障转移面板

> 一站式管理阿里云 ECS 实例流量、定时开关机、Cloudflare DNS 故障自动切换，支持 Docker 一键部署。

---

## 功能概览

| 模块 | 说明 |
|------|------|
| **流量监控** | 5 分钟轮询阿里云 API，按月/生命周期两种计量模式统计流量，超限自动停机 |
| **Dashboard** | 实例状态总览、流量占比图表、自定义面板布局 |
| **定时任务** | 按星期/小时/分钟维度定时开关 ECS 实例 |
| **DNS 故障转移** | 结合 Cloudflare DNS，通过 Ping/端口探测自动切换 A/AAAA 记录 |
| **探针/Checker** | 可在国内/国外部署独立探测节点，WebSocket 实时上报 |
| **通知告警** | 支持企业微信、钉钉、Telegram Webhook；含每日流量报告 |
| **安全组管理** | 在线查看/编辑阿里云安全组规则，一键开启 IPv6 |
| **AK/SK 加密** | Fernet 对称加密存储阿里云密钥 |
| **自动备份** | 每日凌晨本地备份 SQLite，可选 Google Drive 远程备份 |

---

## 项目文件结构

> **仅以下为本项目代码**，`komari-1.1.7/` 为第三方无关项目，已在 `.gitignore` 中排除。

```
dns-panel/
│
├── app.py                  # Flask 主入口，调度器、数据库初始化、定时任务注册
├── models.py               # SQLAlchemy 数据模型（User / EcsInstance / DnsFailover …）
├── routes.py               # Web 路由（登录、Dashboard、实例管理、安全组、日志…）
├── probe_routes.py         # 探针 & DNS 故障转移路由（WebSocket、Checker API）
├── monitor.py              # 阿里云 ECS API 封装（流量查询、开/关/释放、安全组操作）
├── cloudflare_manager.py   # Cloudflare DNS API 封装（CRUD、Upsert）
├── notifier.py             # 告警通知（企业微信 / 钉钉 / Telegram）
├── crypto_utils.py         # AK/SK Fernet 加解密
├── backup_utils.py         # Google Drive 远程备份
├── gunicorn.conf.py        # Gunicorn 生产配置（gevent worker）
├── requirements.txt        # Python 依赖
│
├── templates/              # Jinja2 HTML 模板
│   ├── base.html           #   公共布局
│   ├── login.html          #   登录页
│   ├── dashboard.html      #   Dashboard 总览
│   ├── instance_detail.html#   实例详情
│   ├── dns_failover.html   #   DNS 故障转移配置
│   ├── probe_servers.html  #   探针节点管理
│   ├── schedules.html      #   定时任务
│   ├── security_group.html #   安全组管理
│   ├── alert_config.html   #   告警配置
│   ├── logs.html           #   操作日志
│   └── ...                 #   其他页面
│
├── agent/                  # 远程探针 Agent
│   ├── agent.py            #   Agent 主程序
│   ├── port_checker.py     #   端口探测服务
│   ├── install.sh          #   Agent 安装脚本
│   ├── install_checker.sh  #   Checker 安装脚本
│   ├── install_checker_cn.sh   # 国内加速安装脚本
│   └── install_checker_global.sh # 国际线路安装脚本
│
├── tests/                  # 单元测试
│   ├── test_auth_force_password_change.py
│   └── test_dns_failover_api.py
│
├── tools/                  # 辅助工具
│   ├── check_text_encoding.py
│   └── security_audit.sh
│
├── Dockerfile              # Docker 镜像定义
├── docker-compose.yml      # Docker Compose 编排
├── install.sh              # 远程一键部署/更新引导脚本（curl 直接调用）
├── panel.sh                # Linux 统一管理脚本（deploy/update/restart/stop/…）
├── panel.ps1               # Windows 统一管理脚本
├── README-Docker.md        # Docker 部署详细文档
├── .gitignore              # Git 忽略规则
└── .env                    # 环境变量（不入库）
```

---

## 快速开始

### 前置条件

- Docker 20+ & Docker Compose
- 阿里云 AccessKey（需 ECS 读写权限）
- *(可选)* Cloudflare API Token（DNS 故障转移功能）

### 一键部署（推荐）

服务器上执行一条命令即可部署，无需手动 clone：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/WithZeng/dns-panel/main/install.sh)
```

更新已有部署：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/WithZeng/dns-panel/main/install.sh) update
```

其他子命令（restart / stop / status / logs / backup）同理：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/WithZeng/dns-panel/main/install.sh) restart
```

> 默认安装目录 `/opt/dns-panel`，可通过 `INSTALL_DIR=/your/path` 环境变量自定义。

<details>
<summary>手动 clone 部署（备选）</summary>

**Linux：**
```bash
git clone https://github.com/WithZeng/dns-panel.git
cd dns-panel
bash panel.sh deploy
```

**Windows：**
```powershell
git clone https://github.com/WithZeng/dns-panel.git
cd dns-panel
.\panel.ps1 deploy
```
</details>

脚本自动完成：环境检查 → 生成 `.env` → 放行防火墙（IPv4+IPv6）→ 构建容器 → 健康检查。

### 默认访问

```
http://<服务器IP>:5000
```

首次登录凭据见 `instance/initial_admin_credentials.txt`，登录后会**强制修改密码**。

---

## 一键更新

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/WithZeng/dns-panel/main/install.sh) update
```

或在项目目录内直接执行：

```bash
bash panel.sh update
```

流程：备份 DB → `git pull` → `docker compose build --no-cache` → 重启 → 健康检查。

可选参数：`--skip-backup` / `--skip-pull`（Linux），`-SkipBackup` / `-SkipPull`（Windows）。

---

## 环境变量

在 `.env` 中配置（首次部署自动生成）：

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `SECRET_KEY` | Flask Session 密钥 | 自动生成 |
| `ENCRYPT_KEY` | AK/SK 加密密钥 | 自动生成 |
| `PANEL_PORT` | 面板对外端口 | `5000` |
| `PUBLIC_PANEL_URL` | 反代/NAT 场景的外网地址 | *(空)* |
| `TZ` | 时区 | `Asia/Shanghai` |
| `DNS_FAILOVER_TEST_MODE` | 故障检测模式（`panel_local` / `checker`） | `panel_local` |
| `DNS_PANEL_DISABLE_SCHEDULER` | 禁用定时任务（测试用） | `0` |

---

## 技术栈

- **后端**：Python 3.11 / Flask / SQLAlchemy / APScheduler / gevent
- **前端**：Jinja2 + Bootstrap（服务端渲染）
- **数据库**：SQLite（通过 Volume 持久化至 `instance/`）
- **容器**：Docker + Gunicorn（gevent worker）
- **云 API**：阿里云 ECS SDK / Cloudflare REST API

---

## 常用运维

```bash
bash panel.sh status      # 容器状态
bash panel.sh logs        # 实时日志
bash panel.sh restart     # 重启容器
bash panel.sh stop        # 停止服务
bash panel.sh backup      # 手动备份数据库
bash panel.sh help        # 查看所有命令
```

更多细节请参阅 [README-Docker.md](README-Docker.md)。

---

## 探针部署（可选）

国内机器：
```bash
curl -fsSL http://<面板IP>:5000/agent/install_checker_cn.sh -o /tmp/install_checker_cn.sh \
  && PANEL_BASE_URL=http://<面板IP>:5000 bash /tmp/install_checker_cn.sh
```

国外机器：
```bash
curl -fsSL http://<面板IP>:5000/agent/install_checker_global.sh -o /tmp/install_checker_global.sh \
  && PANEL_BASE_URL=http://<面板IP>:5000 bash /tmp/install_checker_global.sh
```

---

## License

Private project — all rights reserved.
