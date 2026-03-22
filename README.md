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

## 快速部署

### Docker (推荐)

```bash
# 克隆仓库
git clone https://github.com/WithZeng/dns-panel.git
cd dns-panel
git checkout go-rewrite

# 创建环境变量文件
cp .env.example .env

# 启动
docker-compose up -d
```

### 编译运行

```bash
# 需要 Go 1.21+
go build -o dns-panel .
./dns-panel
```

首次启动后查看 `data/initial_admin_credentials.txt` 获取默认管理员密码。

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
