#!/usr/bin/env bash
# =============================================================================
# dns-panel 统一管理脚本
# 用法：
#   bash panel.sh deploy              首次部署
#   bash panel.sh update              更新（备份→拉取→重建→健康检查）
#   bash panel.sh update --skip-backup --skip-pull
#   bash panel.sh restart             仅重启容器
#   bash panel.sh stop                停止服务
#   bash panel.sh status              查看容器状态
#   bash panel.sh logs                查看实时日志
#   bash panel.sh backup              手动备份数据库
#   bash panel.sh help                帮助信息
# =============================================================================
set -euo pipefail

SERVICE_NAME="dns-panel"
DEFAULT_TZ="Asia/Shanghai"
DEFAULT_PORT="5000"
DEFAULT_FAILOVER_MODE="panel_local"
BACKUP_DIR="instance/backups"
DB_CANDIDATES=("instance/ecs_monitor.db" "ecs_monitor.db")

# ── 输出函数 ─────────────────────────────────────────────────────────────────
step()  { echo ""; echo "========== $* =========="; }
info()  { echo "[信息] $*"; }
ok()    { echo "[完成] $*"; }
warn()  { echo "[警告] $*"; }
fail()  { echo "[错误] $*" >&2; exit 1; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "未找到命令: $1"
}

# ── 通用函数 ─────────────────────────────────────────────────────────────────

get_panel_port() {
  local port
  port="$(grep -E '^PANEL_PORT=' .env 2>/dev/null | head -n 1 | cut -d'=' -f2- | tr -d '[:space:]' || true)"
  [[ -n "$port" ]] || port="$DEFAULT_PORT"
  echo "$port"
}

wait_and_check_health() {
  local port="$1"
  info "等待服务就绪（端口 ${port}）..."
  for i in $(seq 1 30); do
    if curl -fsS "http://127.0.0.1:${port}/health" >/dev/null 2>&1; then
      ok "健康检查通过 ✓"
      return 0
    fi
    sleep 2
  done
  warn "健康检查未通过，请查看日志："
  echo "  docker compose logs --tail=50 ${SERVICE_NAME}"
  return 1
}

backup_db() {
  local DB_FILE=""
  for candidate in "${DB_CANDIDATES[@]}"; do
    [[ -f "$candidate" ]] && { DB_FILE="$candidate"; break; }
  done
  if [[ -z "$DB_FILE" ]]; then
    warn "未找到数据库文件，跳过备份。"
    return
  fi
  mkdir -p "$BACKUP_DIR"
  local ts
  ts="$(date +%Y%m%d_%H%M%S)"
  local dest="${BACKUP_DIR}/ecs_monitor_${ts}.db"
  cp "$DB_FILE" "$dest"
  ok "数据库已备份 → ${dest}"
  find "$BACKUP_DIR" -name "*.db" -mtime +14 -delete 2>/dev/null || true
  info "已清理 14 天前的旧备份。"
}

# ── 部署：首次全新部署 ───────────────────────────────────────────────────────

check_project_files() {
  local required=("app.py" "requirements.txt" "Dockerfile" "docker-compose.yml" "routes.py" "models.py")
  local missed=0
  for f in "${required[@]}"; do
    [[ -e "$f" ]] || { warn "缺少文件: $f"; missed=1; }
  done
  [[ -d templates ]] || { warn "缺少目录: templates"; missed=1; }
  [[ "$missed" -eq 0 ]] || fail "项目文件不完整，请先上传完整项目后再部署。"
  ok "项目文件检查通过。"
}

ensure_docker() {
  if command -v docker >/dev/null 2>&1; then
    ok "Docker 已安装。"
    return
  fi
  info "未检测到 Docker，开始自动安装..."
  require_cmd curl
  curl -fsSL https://get.docker.com | sh
  ok "Docker 安装完成。"
}

ensure_docker_service() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl enable --now docker >/dev/null 2>&1 || true
  fi
}

ensure_compose() {
  docker compose version >/dev/null 2>&1 || fail "docker compose 不可用，请升级 Docker 版本后重试。"
  ok "Docker Compose 可用。"
}

ensure_env_file() {
  if [[ -f .env ]]; then
    info ".env 已存在，保留现有配置。"
    return
  fi
  local secret
  if command -v openssl >/dev/null 2>&1; then
    secret="$(openssl rand -hex 32)"
  else
    require_cmd python3
    secret="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
  fi
  cat > .env <<EOF
SECRET_KEY=${secret}
TZ=${DEFAULT_TZ}
PANEL_PORT=${DEFAULT_PORT}
PUBLIC_PANEL_URL=
DNS_FAILOVER_TEST_MODE=${DEFAULT_FAILOVER_MODE}
DNS_PANEL_DISABLE_SCHEDULER=0
EOF
  ok "已生成 .env（默认端口 ${DEFAULT_PORT}）。"
}

check_port_in_use() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    if ss -ltn "( sport = :${port} )" | grep -q ":${port}"; then
      fail "端口 ${port} 已被占用，请修改 .env 中 PANEL_PORT 后重试。"
    fi
  elif command -v netstat >/dev/null 2>&1; then
    if netstat -lnt 2>/dev/null | grep -q ":${port} "; then
      fail "端口 ${port} 已被占用，请修改 .env 中 PANEL_PORT 后重试。"
    fi
  else
    warn "未找到 ss/netstat，跳过端口占用检查。"
  fi
  ok "端口 ${port} 可用。"
}

open_firewall() {
  local port="$1"
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi "Status: active"; then
    info "检测到 UFW，放行 IPv4+IPv6 端口 ${port}/tcp ..."
    [[ -f /etc/default/ufw ]] && sed -i 's/^IPV6=no/IPV6=yes/' /etc/default/ufw
    ufw allow "${port}/tcp" >/dev/null 2>&1 || warn "UFW 放行失败，请手动: ufw allow ${port}/tcp"
    ok "UFW 已放行 ${port}/tcp（IPv4 + IPv6）。"
    return
  fi
  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    info "检测到 firewalld，放行 ${port}/tcp ..."
    firewall-cmd --permanent --add-port="${port}/tcp" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
    ok "firewalld 已放行 ${port}/tcp。"
    return
  fi
  _open_iptables_port() {
    local ipt="$1"
    if command -v "$ipt" >/dev/null 2>&1; then
      if ! "$ipt" -C INPUT -p tcp --dport "${port}" -j ACCEPT >/dev/null 2>&1; then
        "$ipt" -I INPUT -p tcp --dport "${port}" -j ACCEPT >/dev/null 2>&1 \
          || warn "$ipt 放行 ${port}/tcp 失败"
        ok "$ipt 已放行 ${port}/tcp。"
      else
        info "$ipt 端口 ${port}/tcp 规则已存在。"
      fi
    fi
  }
  _open_iptables_port iptables
  _open_iptables_port ip6tables
  if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null 2>&1 || true
  elif command -v service >/dev/null 2>&1; then
    service iptables save >/dev/null 2>&1 || true
    service ip6tables save >/dev/null 2>&1 || true
  fi
}

cmd_deploy() {
  step "第 1 步：检查项目文件"
  check_project_files

  step "第 2 步：检查 Docker 与 Compose"
  ensure_docker
  ensure_docker_service
  ensure_compose

  step "第 3 步：准备配置与目录"
  mkdir -p instance
  ensure_env_file
  local panel_port
  panel_port="$(get_panel_port)"

  step "第 4 步：检查端口与防火墙"
  check_port_in_use "$panel_port"
  open_firewall "$panel_port"

  step "第 5 步：构建并启动容器"
  info "首次构建可能较慢..."
  docker compose up -d --build
  ok "容器已启动。"

  step "第 6 步：健康检查"
  wait_and_check_health "$panel_port"
  docker compose ps || true

  step "部署完成"
  echo "访问地址 : http://<你的服务器IP>:${panel_port}"
  echo "容器状态 : docker compose ps"
  echo "查看日志 : docker compose logs -f ${SERVICE_NAME}"
  echo "更新     : bash panel.sh update"
  echo "初始密码 : cat instance/initial_admin_credentials.txt"
}

# ── 更新：备份→拉取→重建→健康检查 ─────────────────────────────────────────

cmd_update() {
  local skip_backup=0 skip_pull=0
  for arg in "$@"; do
    case "$arg" in
      --skip-backup) skip_backup=1 ;;
      --skip-pull)   skip_pull=1 ;;
    esac
  done

  [[ -f "docker-compose.yml" ]] || fail "找不到 docker-compose.yml，请在项目根目录运行。"

  step "第 1 步：备份数据库"
  if [[ "$skip_backup" -eq 1 ]]; then
    info "已跳过备份（--skip-backup）。"
  else
    backup_db
  fi

  step "第 2 步：拉取最新代码"
  if [[ "$skip_pull" -eq 1 ]]; then
    info "已跳过 git pull（--skip-pull）。"
  else
    if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
      local before after
      before="$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
      info "当前版本：${before}"
      git pull --rebase --autostash
      after="$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
      if [[ "$before" == "$after" ]]; then
        info "代码已是最新（${after}）。"
      else
        ok "代码已更新：${before} → ${after}"
      fi
    else
      warn "不是 git 仓库或未安装 git，跳过代码拉取。"
    fi
  fi

  step "第 3 步：重建镜像并重启"
  info "停止旧容器..."
  docker compose down --remove-orphans 2>&1 | tail -5 || true
  info "重建镜像（--no-cache）..."
  docker compose build --no-cache
  docker compose up -d
  ok "容器已重启。"

  step "第 4 步：健康检查"
  local panel_port
  panel_port="$(get_panel_port)"
  wait_and_check_health "$panel_port"

  step "更新完成"
  echo "版本     : $(git rev-parse --short HEAD 2>/dev/null || echo '-')"
  echo "访问地址 : http://<你的服务器IP>:${panel_port}"
  echo "回滚     : 从 ${BACKUP_DIR}/ 恢复数据库 → git checkout <版本> → bash panel.sh update --skip-pull"
}

# ── 快捷子命令 ───────────────────────────────────────────────────────────────

cmd_restart() {
  info "重启容器..."
  docker compose restart
  ok "容器已重启。"
  wait_and_check_health "$(get_panel_port)"
}

cmd_stop() {
  info "停止服务..."
  docker compose down
  ok "服务已停止。"
}

cmd_status() {
  docker compose ps
}

cmd_logs() {
  docker compose logs -f "$SERVICE_NAME"
}

cmd_backup() {
  backup_db
}

cmd_help() {
  cat <<'HELP'
dns-panel 管理脚本

用法：bash panel.sh <命令> [选项]

命令:
  deploy                首次部署（检查环境→生成配置→构建容器→开放防火墙）
  update [选项]         更新部署（备份数据库→拉取代码→重建镜像→重启→健康检查）
      --skip-backup       跳过数据库备份
      --skip-pull         跳过 git pull
  restart               重启容器
  stop                  停止服务
  status                查看容器状态
  logs                  实时查看日志
  backup                手动备份数据库
  help                  显示此帮助信息

示例：
  bash panel.sh deploy
  bash panel.sh update
  bash panel.sh update --skip-backup
  bash panel.sh logs
HELP
}

# ── 入口 ─────────────────────────────────────────────────────────────────────

ACTION="${1:-help}"
shift 2>/dev/null || true

case "$ACTION" in
  deploy)   cmd_deploy "$@" ;;
  update)   cmd_update "$@" ;;
  restart)  cmd_restart ;;
  stop)     cmd_stop ;;
  status)   cmd_status ;;
  logs)     cmd_logs ;;
  backup)   cmd_backup ;;
  help|-h|--help) cmd_help ;;
  *)
    warn "未知命令: $ACTION"
    cmd_help
    exit 1
    ;;
esac
