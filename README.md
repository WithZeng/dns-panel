# DNS Panel — 阿里云 ECS 流量监控 & DNS 故障转移面板

> 一站式管理阿里云 ECS 实例流量、定时开关机、Cloudflare DNS 故障自动切换，支持 Docker 一键部署。

---

## 功能概览

| 模块 | 说明 |
|------|------|
| **流量监控** | 5 分钟轮询阿里云 CDT/账单 API，按月/生命周期两种计量模式统计流量，超限自动停机 |
| **Dashboard** | 实例状态总览、流量占比图表、3 个月 CDT 流量账单卡片 |
| **定时任务** | 按星期/小时/分钟维度定时开关 ECS 实例 |
| **DNS 故障转移** | 结合 Cloudflare DNS，通过 Ping/端口探测自动切换 A/AAAA 记录 |
| **探针/Checker** | 可在国内/国外部署独立探测节点，WebSocket 实时上报 |
| **通知告警** | 支持企业微信、钉钉、Telegram Webhook；含每日流量报告与异常检测 |
| **安全组管理** | 在线查看/编辑阿里云安全组规则，一键开启 IPv6 |
| **AK/SK 加密** | Fernet 对称加密存储阿里云密钥，丢失检测与告警 |
| **自动备份** | 每日凌晨本地备份 SQLite，可选 Google Drive 远程备份 |
| **批量导入** | 支持 CSV 和文本批量导入实例，后台异步处理，断点续传 |
| **凭证状态** | 实时检测 AK/SK 有效性，Dashboard 显示凭证失效告警 |

---

## 分支说明

| 分支 | 语言 | 状态 |
|------|------|------|
| `main` | Python (Flask) | 当前稳定版，功能完整 |
| `go-rewrite` | Go (Gin) | 全新重写版，单二进制部署，性能更优 |

> Go 版本已完成全部核心功能迁移（监控、调度、通知、探针、DNS 故障转移、安全组），采用原生阿里云 API 签名无需 SDK 依赖。稳定后将合入 main。

---

## 项目文件结构

```
dns-panel/
├── app.py                  # Flask 主入口，调度器、数据库初始化
├── models.py               # SQLAlchemy 数据模型
├── routes.py               # Web 路由（登录、Dashboard、实例管理）
├── route_helpers.py         # 路由辅助函数（安全组、导入、发现等）
├── probe_routes.py         # 探针 & DNS 故障转移路由（WebSocket）
├── monitor.py              # 阿里云 ECS API（流量查询、启停、安全组）
├── cloudflare_manager.py   # Cloudflare DNS API 封装
├── notifier.py             # 告警通知（企业微信 / 钉钉 / Telegram）
├── crypto_utils.py         # AK/SK Fernet 加解密（含丢失检测）
├── extensions.py           # Flask 扩展初始化
├── backup_utils.py         # Google Drive 远程备份
├── gunicorn.conf.py        # Gunicorn 生产配置（gevent worker）
├── requirements.txt        # Python 依赖
│
├── templates/              # Jinja2 HTML 模板
├── static/                 # 前端静态资源
├── agent/                  # 远程探针 Agent & Checker
├── tests/                  # 单元测试
├── tools/                  # 辅助运维工具
│
├── Dockerfile              # Docker 镜像定义
├── docker-compose.yml      # Docker Compose 编排
├── install.sh              # 远程一键部署/更新脚本
├── panel.sh                # Linux 管理脚本
├── panel.ps1               # Windows 管理脚本
└── .env                    # 环境变量（不入库）
```

---

## 快速开始

### 前置条件

- Docker 20+ & Docker Compose
- 阿里云 AccessKey（需 ECS 读写权限）
- *(可选)* Cloudflare API Token（DNS 故障转移功能）

### 一键部署（推荐）

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

> 新安装默认目录为 `/opt/dns-panel`；远程更新脚本会自动识别已有安装目录并原地升级，也可通过 `INSTALL_DIR=/your/path` 强制指定。

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
| `DNS_PANEL_DISABLE_SCHEDULER` | 强制禁用定时任务（测试用） | `0` |
| `DNS_PANEL_ROLE` | 进程角色（`web`/`scheduler`/`all`） | `all` |
| `DATA_RETENTION_DAYS` | 日志保留天数 | `90` |

---

## 技术栈

- **后端**：Python 3.11 / Flask 3.0 / SQLAlchemy / APScheduler / gevent
- **前端**：Jinja2 + Tailwind CSS（服务端渲染）
- **数据库**：SQLite（WAL 模式，Volume 持久化至 `instance/`）
- **容器**：Docker + Gunicorn（gevent worker）
- **云 API**：阿里云 ECS/CDT/Billing SDK / Cloudflare REST API

---

## 常用运维

```bash
bash panel.sh status      # 容器状态
bash panel.sh logs        # 实时日志
bash panel.sh restart     # 重启容器
bash panel.sh stop        # 停止服务
bash panel.sh backup      # 手动备份数据库
bash panel.sh restore     # 一键恢复到最新备份
bash panel.sh help        # 查看所有命令
```

### 数据备份与恢复

数据库文件位于 `instance/ecs_monitor.db`，每次 `update` 前会自动备份到 `instance/backups/`。

```bash
# 手动备份
bash panel.sh backup

# 一键恢复到最新备份
bash panel.sh restore

# 指定某个备份恢复
bash panel.sh restore instance/backups/ecs_monitor_20260223_120000.db
```

### 重置管理员密码

```bash
# 查看初始密码（仅首次部署未改密码时有效）
cat instance/initial_admin_credentials.txt

# 进容器重置密码
cat > /tmp/reset_pw.py << 'EOF'
from app import app, db
from models import User
from werkzeug.security import generate_password_hash
with app.app_context():
    u = User.query.filter_by(username='admin').first()
    u.password_hash = generate_password_hash('你的新密码')
    u.force_password_change = False
    db.session.commit()
    print('密码已重置')
EOF
docker cp /tmp/reset_pw.py dns-panel:/app/reset_pw.py
docker exec dns-panel python /app/reset_pw.py
docker exec dns-panel rm /app/reset_pw.py
rm /tmp/reset_pw.py
```

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

## 更新日志

### v0.3.0 (2026-03-22)

**关键修复**
- 修复 VPS 更新后数据丢失和密码被重置的问题
- SQLite 并发保护：bootstrap 阶段文件锁 + WAL 模式
- 加密密钥丢失检测，防止静默重新生成导致 AK/SK 不可读
- `.dockerignore` 排除 `instance/` 目录，避免数据被 Docker 镜像覆盖

**新功能**
- 3 个月 CDT 流量账单卡片（QueryInstanceBill + CDT API 双通道）
- AK/SK 凭证状态实时检测与 Dashboard 告警展示
- 批量操作前强制勾选实例
- 停机检测自动启动
- 路由代码拆分重构（route_helpers.py）
- 添加 CI 工作流

**Go 重写分支**
- `go-rewrite` 分支完成全部功能迁移（Go/Gin/GORM）
- 单二进制部署，无需 Python 环境
- 原生阿里云 API 签名，无 SDK 依赖

---

## License

MIT
