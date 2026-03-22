#!/usr/bin/env bash
# DNS Panel (Go) - 本地管理脚本
# 在项目目录内使用: bash panel.sh <command>
set -euo pipefail

cd "$(dirname "$0")"

compose() {
    if docker compose version &>/dev/null 2>&1; then
        docker compose "$@"
    else
        docker-compose "$@"
    fi
}

case "${1:-help}" in
    deploy)
        bash install.sh deploy
        ;;
    update)
        shift 2>/dev/null || true
        bash install.sh update "$@"
        ;;
    restart)
        compose restart
        echo "[OK] 已重启"
        ;;
    stop)
        compose down
        echo "[OK] 已停止"
        ;;
    start)
        compose up -d
        echo "[OK] 已启动"
        ;;
    status)
        compose ps
        ;;
    logs)
        compose logs -f --tail=100
        ;;
    backup)
        bash install.sh backup
        ;;
    restore)
        shift 2>/dev/null || true
        bash install.sh restore "${1:-}"
        ;;
    build)
        compose build --no-cache
        compose up -d
        echo "[OK] 已重建"
        ;;
    shell)
        docker exec -it dns-panel-go sh
        ;;
    help|--help|*)
        cat <<EOF
DNS Panel (Go) 管理脚本

用法: bash panel.sh <命令>

  deploy      首次部署
  update      更新到最新版本
  start       启动容器
  stop        停止容器
  restart     重启容器
  status      查看容器状态
  logs        查看实时日志
  build       重新构建并启动
  backup      备份数据库
  restore     恢复数据库
  shell       进入容器 Shell
  help        显示此帮助
EOF
        ;;
esac
