#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="dns-panel"
DEFAULT_TZ="Asia/Shanghai"
DEFAULT_PORT="5000"
DEFAULT_FAILOVER_MODE="panel_local"

step() {
  echo ""
  echo "========== $* =========="
}

info() { echo "[信息] $*"; }
warn() { echo "[警告] $*"; }
ok() { echo "[完成] $*"; }
fail() { echo "[错误] $*" >&2; exit 1; }

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    fail "未找到命令: $1"
  fi
}

check_project_files() {
  local required=("app.py" "requirements.txt" "Dockerfile" "docker-compose.yml" "routes.py" "models.py")
  local missed=0
  for f in "${required[@]}"; do
    if [[ ! -e "$f" ]]; then
      warn "缺少文件: $f"
      missed=1
    fi
  done
  if [[ ! -d templates ]]; then
    warn "缺少目录: templates"
    missed=1
  fi
  if [[ "$missed" -eq 1 ]]; then
    fail "项目文件不完整，请先上传完整项目后再部署。"
  fi
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
    info "尝试启动 Docker 服务..."
    systemctl enable --now docker >/dev/null 2>&1 || true
  fi
}

ensure_compose() {
  if docker compose version >/dev/null 2>&1; then
    ok "Docker Compose 可用。"
    return
  fi
  fail "docker compose 不可用，请升级 Docker 版本后重试。"
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
    secret="$(python3 - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
)"
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

ensure_instance_dir() {
  mkdir -p instance
  ok "数据目录 instance/ 已准备。"
}

get_panel_port() {
  local port
  port="$(grep -E '^PANEL_PORT=' .env 2>/dev/null | head -n 1 | cut -d '=' -f2- | tr -d '[:space:]' || true)"
  [[ -n "$port" ]] || port="$DEFAULT_PORT"
  echo "$port"
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

  # ── UFW (Ubuntu/Debian) ──────────────────────────────────────────────────
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi "Status: active"; then
    info "检测到 UFW，自动放行 IPv4+IPv6 端口 ${port}/tcp ..."
    # 确保 /etc/default/ufw 中 IPV6=yes（UFW 默认会同时处理 ip6tables）
    if [[ -f /etc/default/ufw ]]; then
      sed -i 's/^IPV6=no/IPV6=yes/' /etc/default/ufw
    fi
    ufw allow "${port}/tcp" >/dev/null 2>&1 || warn "UFW 放行 ${port}/tcp 失败，请手动执行: ufw allow ${port}/tcp"
    ok "UFW 已放行 ${port}/tcp（IPv4 + IPv6）。"
    return
  fi

  # ── firewalld (CentOS/RHEL/Fedora) ───────────────────────────────────────
  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    info "检测到 firewalld，自动放行 ${port}/tcp ..."
    firewall-cmd --permanent --add-port="${port}/tcp" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
    ok "firewalld 已放行 ${port}/tcp。"
    return
  fi

  # ── iptables + ip6tables (通用 Linux) ───────────────────────────────────
  _open_iptables_port() {
    local ipt="$1"  # iptables 或 ip6tables
    if command -v "$ipt" >/dev/null 2>&1; then
      # 避免重复添加
      if ! "$ipt" -C INPUT -p tcp --dport "${port}" -j ACCEPT >/dev/null 2>&1; then
        "$ipt" -I INPUT -p tcp --dport "${port}" -j ACCEPT >/dev/null 2>&1 \
          || warn "$ipt 放行 ${port}/tcp 失败，请手动执行: $ipt -I INPUT -p tcp --dport ${port} -j ACCEPT"
        ok "$ipt 已放行 ${port}/tcp。"
      else
        info "$ipt 端口 ${port}/tcp 规则已存在，跳过。"
      fi
    fi
  }
  _open_iptables_port iptables   # IPv4
  _open_iptables_port ip6tables  # IPv6

  # 持久化（如果系统有 iptables-save / netfilter-persistent）
  if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null 2>&1 || true
  elif command -v service >/dev/null 2>&1; then
    service iptables save >/dev/null 2>&1 || true
    service ip6tables save >/dev/null 2>&1 || true
  fi
}

deploy_container() {
  info "开始构建并启动容器（首次可能较慢）..."
  docker compose up -d --build
  ok "容器启动命令执行完成。"
}

wait_and_check_health() {
  local port="$1"
  info "等待服务就绪并检查 /health ..."
  for i in $(seq 1 30); do
    if curl -fsS "http://127.0.0.1:${port}/health" >/dev/null 2>&1; then
      ok "健康检查通过。"
      return
    fi
    sleep 2
  done
  warn "健康检查暂未通过，可执行: docker compose logs -f ${SERVICE_NAME}"
}

show_result() {
  local port="$1"
  step "部署完成"
  echo "访问地址: http://<你的服务器IP>:${port}"
  echo "容器状态: docker compose ps"
  echo "查看日志: docker compose logs -f ${SERVICE_NAME}"
  echo "停止服务: docker compose down"
  echo "一键更新: bash update.sh"
}

main() {
  step "第 1 步：检查项目文件"
  check_project_files

  step "第 2 步：检查 Docker 与 Compose"
  ensure_docker
  ensure_docker_service
  ensure_compose

  step "第 3 步：准备配置与目录"
  ensure_instance_dir
  ensure_env_file
  local panel_port
  panel_port="$(get_panel_port)"

  step "第 4 步：检查端口与防火墙"
  check_port_in_use "$panel_port"
  open_firewall "$panel_port"

  step "第 5 步：启动服务"
  deploy_container

  step "第 6 步：验证运行状态"
  wait_and_check_health "$panel_port"
  docker compose ps || true

  show_result "$panel_port"
}

main "$@"
