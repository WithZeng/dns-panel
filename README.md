# ECS Monitor Panel

轻量级阿里云 ECS 流量监控与 DNS 故障转移面板，使用 Go 开发。

> 本项目最初使用 Python/Flask 开发，后使用 Go/Gin 全面重写。旧版 Python 代码保留在 `main` 分支。

## 为什么从 Python 切到 Go

| 对比项 | Python (Flask) | Go (Gin) |
|--------|---------------|----------|
| **部署** | 需要 Python 运行时 + pip 依赖 + venv | 编译为单二进制文件，零依赖 |
| **Docker 镜像** | ~800MB (Python + pip 依赖) | ~15MB (Alpine + 静态编译) |
| **内存占用** | ~120MB (Flask + Gunicorn) | ~12MB |
| **启动速度** | 3-5 秒 | <0.5 秒 |
| **并发能力** | GIL 限制，需 Gunicorn 多进程 | 原生 Goroutine，轻松万级并发 |
| **依赖管理** | requirements.txt + 版本冲突频繁 | go.mod 内置，编译时锁定 |
| **加密方案** | Fernet (AES-128-CBC) | AES-256-GCM (更强更快) |
| **CGO 依赖** | SQLite 需要 C 编译器 | 纯 Go SQLite 驱动，无 CGO |
| **类型安全** | 运行时类型错误 | 编译期类型检查 |
| **跨平台** | 需要目标平台安装 Python | 交叉编译一行命令 |

**核心收益**：部署从「安装运行时 → 安装依赖 → 配置 WSGI → 启动」简化为「下载二进制 → 启动」，Docker 镜像体积缩小 98%，内存占用降低 90%。

## 特性

- **ECS 流量监控** — 阿里云 CDT 流量自动采集，支持月流量/生命周期两种策略
- **自动启停** — 流量超限自动停机，低于阈值自动恢复
- **告警通知** — 企业微信 / 钉钉 / Telegram Webhook 推送
- **DNS 故障转移** — 基于 Cloudflare API 的自动 DNS 切换
- **探针系统** — WebSocket 长连接实时上报服务器状态
- **安全组管理** — 在线查看/添加/删除阿里云安全组规则
- **定时任务** — 自定义 ECS 启停时间表
- **一键 IPv6** — 自动开启并配置 ECS IPv6 地址
- **账户导入** — 粘贴 AK/SK 文本自动扫描全区域实例，支持 GitHub 私有仓库同步备份
- **数据备份** — ZIP 打包（含加密密钥）、CSV 导出/导入、数据库导入（兼容 Python 版）
- **版本管理** — 面板内检查更新、一键升级、密码重置

## 一键部署

```bash
bash <(curl -sL https://raw.githubusercontent.com/WithZeng/dns-panel/go-rewrite/install.sh)
```

首次启动后查看 `data/initial_admin_credentials.txt` 获取默认管理员密码。

## 一键更新

```bash
bash <(curl -sL https://raw.githubusercontent.com/WithZeng/dns-panel/go-rewrite/install.sh) update
```

更新前会自动备份数据库，数据不会丢失。

## 管理命令

```bash
cd /opt/dns-panel

bash panel.sh deploy      # 首次部署
bash panel.sh update      # 更新到最新版本
bash panel.sh start       # 启动
bash panel.sh stop        # 停止
bash panel.sh restart     # 重启
bash panel.sh status      # 查看状态
bash panel.sh logs        # 查看实时日志
bash panel.sh build       # 重新构建
bash panel.sh backup      # 手动备份数据库
bash panel.sh restore     # 恢复数据库
bash panel.sh shell       # 进入容器 Shell
```

远程执行：

```bash
bash <(curl -sL https://raw.githubusercontent.com/WithZeng/dns-panel/go-rewrite/install.sh) <命令>
```

## 密码重置

```bash
docker exec dns-panel /app/dns-panel reset-password
# 默认重置为 admin / admin123
# 指定密码：
docker exec dns-panel /app/dns-panel reset-password myNewPass
```

## 配置

| 环境变量 | 默认值 | 说明 |
|---------|--------|------|
| `PANEL_PORT` | 5000 | 监听端口 |
| `SECRET_KEY` | 自动生成 | Session 密钥 |
| `ENCRYPT_KEY` | 自动生成 | AES-256-GCM 加密密钥 |
| `DNS_PANEL_DB_PATH` | data/panel.db | SQLite 数据库路径 |
| `DNS_PANEL_ROLE` | all | 角色: all / web / scheduler |
| `GITHUB_SYNC_REPO` | 空 | 账户导入自动同步的 GitHub 私有仓库 |
| `PUBLIC_PANEL_URL` | 空 | 公网访问地址（用于 IPv6 脚本下载链接） |

## 技术栈

- **后端**: Go 1.26 + Gin + GORM + SQLite (WAL)
- **前端**: Tailwind CSS + 原生 JS + Chart.js
- **加密**: AES-256-GCM + bcrypt
- **调度**: robfig/cron/v3
- **API**: 阿里云 OpenAPI (HMAC-SHA1 自实现签名) + Cloudflare v4 + GitHub API

## 项目结构

```
├── main.go                    # 入口 + 路由 + 模板引擎
├── install.sh                 # 一键部署/更新脚本
├── panel.sh                   # 本地管理脚本
├── internal/
│   ├── config/                # 配置加载 (.env)
│   ├── crypto/                # AES-256-GCM + Fernet 兼容解密
│   ├── database/              # GORM + SQLite + 自动迁移
│   ├── models/                # 数据模型
│   ├── middleware/             # 认证/限流/日志
│   ├── handler/               # HTTP 处理器
│   └── service/
│       ├── aliyun/            # 阿里云 ECS/CDT/安全组 API
│       ├── cloudflare.go      # Cloudflare DNS
│       ├── github_sync.go     # GitHub 仓库同步
│       ├── monitor.go         # ECS 监控 + 自动启停
│       ├── notifier.go        # 通知推送
│       └── scheduler.go       # 定时调度
├── templates/                 # Go html/template 模板
├── static/                    # JS/CSS 静态资源
├── Dockerfile                 # 多阶段构建
└── docker-compose.yml
```

## License

MIT
