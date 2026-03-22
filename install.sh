#!/usr/bin/env bash
set -euo pipefail

REPO="https://github.com/WithZeng/dns-panel.git"
BRANCH="go-rewrite"
DEFAULT_DIR="/opt/dns-panel"
CONTAINER="dns-panel-go"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

detect_install_dir() {
    for d in "$DEFAULT_DIR" "/root/dns-panel" "$(pwd)"; do
        [ -d "$d/.git" ] && echo "$d" && return
    done
    echo ""
}

is_python_version() {
    local dir="$1"
    { [ -f "$dir/app.py" ] || [ -f "$dir/requirements.txt" ]; } && [ ! -f "$dir/go.mod" ]
}

ensure_deps() {
    for cmd in git docker; do
        if ! command -v "$cmd" &>/dev/null; then
            error "$cmd 未安装，请先安装后重试"
            exit 1
        fi
    done
    if ! docker compose version &>/dev/null 2>&1; then
        if ! docker-compose version &>/dev/null 2>&1; then
            error "docker compose 未安装"
            exit 1
        fi
    fi
}

compose() {
    if docker compose version &>/dev/null 2>&1; then
        docker compose "$@"
    else
        docker-compose "$@"
    fi
}

open_firewall() {
    local port="${1:-5000}"
    if command -v firewall-cmd &>/dev/null; then
        firewall-cmd --permanent --add-port="${port}/tcp" 2>/dev/null || true
        firewall-cmd --reload 2>/dev/null || true
    elif command -v ufw &>/dev/null; then
        ufw allow "${port}/tcp" 2>/dev/null || true
    fi
    if command -v ip6tables &>/dev/null; then
        ip6tables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || \
            ip6tables -I INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || true
    fi
}

generate_env() {
    local dir="$1"
    if [ ! -f "$dir/.env" ]; then
        info "生成 .env 文件..."
        local secret_key=$(head -c 32 /dev/urandom | xxd -p -c 64 | head -1)
        cat > "$dir/.env" <<EOF
SECRET_KEY=${secret_key}
PANEL_PORT=5000
TZ=Asia/Shanghai
EOF
        info ".env 已生成"
    fi
}

backup_db() {
    local dir="$1"
    local db=""
    for p in "$dir/data/panel.db" "$dir/instance/panel.db" "$dir/panel.db"; do
        [ -f "$p" ] && db="$p" && break
    done
    if [ -n "$db" ]; then
        local bak_dir="$dir/data/backups"
        mkdir -p "$bak_dir"
        local ts=$(date +%Y%m%d_%H%M%S)
        cp "$db" "$bak_dir/panel_${ts}.db"
        info "数据库已备份: $(basename $db) → backups/panel_${ts}.db"
    else
        warn "未找到数据库文件，跳过备份"
    fi
}

health_check() {
    local port="${1:-5000}"
    local max_wait=30
    info "健康检查中..."
    for i in $(seq 1 $max_wait); do
        if curl -sf "http://127.0.0.1:${port}/health" &>/dev/null; then
            info "面板已启动 ✓"
            return 0
        fi
        sleep 1
    done
    warn "健康检查超时（${max_wait}s），请手动检查日志"
    return 1
}

migrate_from_python() {
    local dir="$1"
    info "检测到旧版 Python 安装，开始迁移到 Go 版本..."

    info "停止旧版容器..."
    cd "$dir"
    compose down 2>/dev/null || true
    docker stop dns-panel 2>/dev/null || true
    docker rm dns-panel 2>/dev/null || true

    backup_db "$dir"

    if [ -f "$dir/.env" ]; then
        cp "$dir/.env" "$dir/.env.bak_python"
        info "旧版 .env 已备份为 .env.bak_python"
    fi

    local old_db=""
    for db_path in "$dir/data/panel.db" "$dir/instance/panel.db" "$dir/panel.db"; do
        if [ -f "$db_path" ]; then
            old_db="$db_path"
            break
        fi
    done

    info "切换到 Go 分支..."
    git fetch origin "$BRANCH"
    git checkout -f "$BRANCH" 2>/dev/null || git checkout -B "$BRANCH" "origin/$BRANCH"
    git reset --hard "origin/$BRANCH"

    mkdir -p "$dir/data"
    if [ -n "$old_db" ] && [ -f "$old_db" ] && [ "$old_db" != "$dir/data/panel.db" ]; then
        cp "$old_db" "$dir/data/panel.db"
        info "数据库已迁移到 data/panel.db"
    fi

    info "Python → Go 迁移完成"
}

do_deploy() {
    local dir="${INSTALL_DIR:-}"
    if [ -z "$dir" ]; then
        dir=$(detect_install_dir)
        [ -z "$dir" ] && dir="$DEFAULT_DIR"
    fi

    info "部署目录: $dir"
    ensure_deps

    if [ -d "$dir/.git" ]; then
        cd "$dir"
        if is_python_version "$dir"; then
            migrate_from_python "$dir"
        else
            local current_branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
            if [ "$current_branch" != "$BRANCH" ]; then
                info "切换到 $BRANCH 分支..."
                git fetch origin "$BRANCH"
                git checkout -f "$BRANCH" 2>/dev/null || git checkout -B "$BRANCH" "origin/$BRANCH"
                git reset --hard "origin/$BRANCH"
            fi
        fi
    else
        info "克隆仓库..."
        git clone -b "$BRANCH" "$REPO" "$dir"
    fi

    cd "$dir"
    generate_env "$dir"

    local port=$(grep -oP 'PANEL_PORT=\K\d+' .env 2>/dev/null || echo "5000")
    open_firewall "$port"

    info "构建容器..."
    compose build --no-cache
    compose up -d

    health_check "$port"

    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════${NC}"
    echo -e "${CYAN} DNS Panel (Go) 部署完成${NC}"
    echo -e "${CYAN} 访问: http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo '<IP>'):${port}${NC}"
    echo -e "${CYAN} 初始密码: cat ${dir}/data/initial_admin_credentials.txt${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════${NC}"
}

do_update() {
    local dir="${INSTALL_DIR:-}"
    if [ -z "$dir" ]; then
        dir=$(detect_install_dir)
    fi
    if [ -z "$dir" ]; then
        error "未找到已有安装，请先执行部署: install.sh deploy"
        exit 1
    fi

    cd "$dir"
    info "更新目录: $dir"

    if is_python_version "$dir"; then
        migrate_from_python "$dir"

        generate_env "$dir"

        local port=$(grep -oP 'PANEL_PORT=\K\d+' .env 2>/dev/null || echo "5000")
        open_firewall "$port"

        info "构建 Go 版本容器..."
        compose build --no-cache
        compose up -d

        health_check "$port"

        echo ""
        echo -e "${CYAN}═══════════════════════════════════════════${NC}"
        echo -e "${CYAN} Python → Go 迁移完成${NC}"
        echo -e "${CYAN} 访问: http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo '<IP>'):${port}${NC}"
        echo -e "${CYAN}═══════════════════════════════════════════${NC}"
        return
    fi

    if [[ "${1:-}" != "--skip-backup" ]]; then
        backup_db "$dir"
    fi

    local current_branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
    if [ "$current_branch" != "$BRANCH" ]; then
        info "切换到 $BRANCH 分支..."
        git fetch origin "$BRANCH"
        git checkout -f "$BRANCH" 2>/dev/null || git checkout -B "$BRANCH" "origin/$BRANCH"
        git reset --hard "origin/$BRANCH"
    elif [[ "${1:-}" != "--skip-pull" ]]; then
        info "拉取最新代码..."
        git fetch origin "$BRANCH"
        git reset --hard "origin/$BRANCH"
    fi

    info "重新构建容器..."
    compose down 2>/dev/null || true
    compose build
    compose up -d

    local port=$(grep -oP 'PANEL_PORT=\K\d+' .env 2>/dev/null || echo "5000")
    health_check "$port"
    info "更新完成"
}

resolve_dir() {
    local dir="${INSTALL_DIR:-}"
    [ -z "$dir" ] && dir=$(detect_install_dir)
    [ -z "$dir" ] && { error "未找到安装目录，请先执行部署"; exit 1; }
    echo "$dir"
}

do_restart() {
    local dir=$(resolve_dir)
    cd "$dir"
    compose restart
    info "已重启"
}

do_stop() {
    local dir=$(resolve_dir)
    cd "$dir"
    compose down
    info "已停止"
}

do_status() {
    local dir=$(resolve_dir)
    cd "$dir"
    compose ps
}

do_logs() {
    local dir=$(resolve_dir)
    cd "$dir"
    compose logs -f --tail=100
}

do_backup() {
    local dir=$(resolve_dir)
    backup_db "$dir"
}

do_restore() {
    local dir=$(resolve_dir)

    local target="$1"
    if [ -z "$target" ]; then
        target=$(ls -t "$dir/data/backups"/panel_*.db 2>/dev/null | head -1)
        [ -z "$target" ] && { error "未找到备份文件"; exit 1; }
    fi

    backup_db "$dir"
    cp "$target" "$dir/data/panel.db"
    info "已恢复: $target"
    cd "$dir"
    compose restart
}

show_help() {
    cat <<EOF
DNS Panel (Go) 管理脚本

用法:
  install.sh [命令] [选项]

命令:
  deploy          部署（默认）
  update          更新到最新版本
  restart         重启容器
  stop            停止服务
  status          查看容器状态
  logs            查看实时日志
  backup          手动备份数据库
  restore [file]  恢复数据库
  help            显示此帮助

选项:
  --skip-backup   更新时跳过备份
  --skip-pull     更新时跳过代码拉取

环境变量:
  INSTALL_DIR     指定安装目录（默认自动检测或 /opt/dns-panel）
EOF
}

case "${1:-deploy}" in
    deploy)      do_deploy ;;
    update)      shift; do_update "$@" ;;
    restart)     do_restart ;;
    stop)        do_stop ;;
    status)      do_status ;;
    logs)        do_logs ;;
    backup)      do_backup ;;
    restore)     shift; do_restore "${1:-}" ;;
    help|--help) show_help ;;
    *)           error "未知命令: $1"; show_help; exit 1 ;;
esac
