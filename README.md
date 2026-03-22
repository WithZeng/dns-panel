# DNS Panel (Go)

轻量级 ECS 流量监控与 DNS 故障转移面板，使用 Go 重写，替代原 Python/Flask 版本。

## 特性

- **ECS 流量监控** — 阿里云 CDT 流量自动采集，支持月流量/终身流量两种策略
- **自动启停** — 流量超限自动停机，低于阈值自动恢复
- **告警通知** — 企业微信 / 钉钉 / Telegram Webhook 推送
- **DNS 故障转移** — 基于 Cloudflare API 的自动 DNS 切换
- **探针系统** — WebSocket 长连接实时上报服务器状态
- **安全组管理** — 在线查看/添加/删除阿里云安全组规则
- **定时任务** — 自定义 ECS 启停时间表
- **数据导出** — CSV 导出实例数据

## 一键部署

在 VPS 上执行以下命令即可完成部署：

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

如果已经部署过，进入项目目录后可以使用 `panel.sh` 管理：

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

也可以用远程脚本直接执行任意命令：

```bash
bash <(curl -sL https://raw.githubusercontent.com/WithZeng/dns-panel/go-rewrite/install.sh) <命令>
```

支持的命令: `deploy` `update` `restart` `stop` `status` `logs` `backup` `restore`

## 手动部署

### Docker

```bash
git clone https://github.com/WithZeng/dns-panel.git
cd dns-panel
git checkout go-rewrite
cp .env.example .env
docker-compose up -d
```

### 编译运行

```bash
# 需要 Go 1.21+
go build -o dns-panel .
./dns-panel
```

## 配置

| 环境变量 | 默认值 | 说明 |
|---------|--------|------|
| `PANEL_PORT` | 5000 | 监听端口 |
| `SECRET_KEY` | 自动生成 | Session 密钥 |
| `ENCRYPT_KEY` | 自动生成 | AES 加密密钥 |
| `DNS_PANEL_DB_PATH` | data/panel.db | SQLite 数据库路径 |
| `DNS_PANEL_ROLE` | all | 角色: all / web / scheduler |

## 技术栈

- **后端**: Go + Gin + GORM + SQLite (WAL)
- **前端**: Tailwind CSS + 原生 JS
- **加密**: AES-256-GCM + bcrypt
- **调度**: robfig/cron
- **API**: 阿里云 OpenAPI (自实现签名) + Cloudflare v4

## 项目结构

```
├── main.go                    # 入口 + 路由
├── install.sh                 # 一键部署/更新脚本
├── panel.sh                   # 本地管理脚本
├── internal/
│   ├── config/                # 配置加载
│   ├── crypto/                # AES-256-GCM 加密
│   ├── database/              # GORM + SQLite
│   ├── models/                # 数据模型
│   ├── middleware/             # 认证/限流/日志
│   ├── handler/               # HTTP 处理器
│   └── service/
│       ├── aliyun/            # 阿里云 API 客户端
│       ├── cloudflare.go      # Cloudflare DNS
│       ├── monitor.go         # ECS 监控逻辑
│       ├── notifier.go        # 通知推送
│       └── scheduler.go       # 定时调度
├── templates/                 # HTML 模板
├── static/                    # 静态资源
├── Dockerfile
└── docker-compose.yml
```

## License

MIT
