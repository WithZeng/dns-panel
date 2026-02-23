#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/dns-panel-checker"
SERVICE_NAME="dns-panel-checker.service"
CHECKER_PORT="8888"
CHECKER_PROFILE="${CHECKER_PROFILE:-global}"

log() { echo "[checker] $*"; }
warn() { echo "[checker][warn] $*"; }
die() { echo "[checker][error] $*" >&2; exit 1; }

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  die "请使用 root 执行此脚本。"
fi

install_python_env() {
  log "步骤 1/6：安装 Python 运行环境（profile=${CHECKER_PROFILE}）..."
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    if command -v fuser >/dev/null 2>&1; then
      local wait_sec=0
      while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || \
            fuser /var/lib/apt/lists/lock >/dev/null 2>&1; do
        if (( wait_sec == 0 )); then
          warn "检测到 apt 正被其他进程占用，等待释放锁..."
        fi
        sleep 2
        wait_sec=$((wait_sec + 2))
        if (( wait_sec >= 180 )); then
          die "apt 锁等待超过 180 秒，请检查是否有自动更新进程在运行。"
        fi
      done
    fi

    log "正在执行 apt-get update（可能需要 10~60 秒）..."
    local apt_update_cmd=("apt-get" "update")
    if [[ "${CHECKER_PROFILE}" == "cn" ]]; then
      apt_update_cmd=("apt-get" "-o" "Acquire::ForceIPv4=true" "update")
      log "已启用国内机优化参数：Acquire::ForceIPv4=true"
    fi
    if command -v timeout >/dev/null 2>&1; then
      timeout 300 "${apt_update_cmd[@]}"
    else
      "${apt_update_cmd[@]}"
    fi

    log "正在安装依赖 python3/python3-pip/curl/ca-certificates/iputils-ping ..."
    apt-get install -y python3 python3-pip curl ca-certificates iputils-ping
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y python3 python3-pip curl ca-certificates iputils
  elif command -v yum >/dev/null 2>&1; then
    yum install -y python3 python3-pip curl ca-certificates iputils
  else
    die "不支持的发行版，请手动安装 python3/python3-pip/curl。"
  fi
}

install_flask() {
  log "步骤 2/6：安装 Flask..."
  python3 -m pip install --break-system-packages flask >/dev/null 2>&1 || \
    python3 -m pip install flask >/dev/null 2>&1 || \
    die "Flask 安装失败。"
}

resolve_panel_base_url() {
  if [[ -n "${PANEL_BASE_URL:-}" ]]; then
    echo "${PANEL_BASE_URL%/}"
    return
  fi
  warn "未设置 PANEL_BASE_URL，将尝试从本地脚本目录读取 port_checker.py。"
  echo ""
}

install_checker_code() {
  log "步骤 3/6：部署 checker 程序..."
  mkdir -p "${APP_DIR}"

  local script_dir panel_base
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  panel_base="$(resolve_panel_base_url)"

  if [[ -f "${script_dir}/port_checker.py" ]]; then
    cp -f "${script_dir}/port_checker.py" "${APP_DIR}/port_checker.py"
  elif [[ -n "${panel_base}" ]]; then
    curl -fsSL "${panel_base}/agent/port_checker.py" -o "${APP_DIR}/port_checker.py" || \
      die "下载 port_checker.py 失败，请检查 PANEL_BASE_URL=${panel_base} 是否可访问。"
  else
    die "未找到 port_checker.py。请设置 PANEL_BASE_URL 后重试。"
  fi
}

install_systemd_service() {
  log "步骤 4/6：注册并启动 systemd 服务..."
  cat > "/etc/systemd/system/${SERVICE_NAME}" <<EOF
[Unit]
Description=DNS Panel Ping Checker
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/env python3 ${APP_DIR}/port_checker.py
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable "${SERVICE_NAME}" >/dev/null 2>&1
  systemctl restart "${SERVICE_NAME}"
}

verify_checker() {
  log "步骤 5/6：执行本机健康检查..."
  sleep 1
  if ! systemctl is-active --quiet "${SERVICE_NAME}"; then
    systemctl status "${SERVICE_NAME}" --no-pager || true
    die "checker 服务未成功启动。"
  fi

  local health_json
  health_json="$(curl -fsS "http://127.0.0.1:${CHECKER_PORT}/ping?host=1.1.1.1" || true)"
  if [[ -z "${health_json}" ]]; then
    warn "本机 API 校验失败，请检查端口 ${CHECKER_PORT} 与服务日志。"
  else
    log "本机 API 校验通过：${health_json}"
  fi
}

show_done_message() {
  log "步骤 6/6：部署完成。"
  echo "----------------------------------------"
  echo "checker 服务名：${SERVICE_NAME}"
  echo "监听端口：${CHECKER_PORT}"
  echo "查看状态：systemctl status ${SERVICE_NAME} --no-pager"
  echo "查看日志：journalctl -u ${SERVICE_NAME} -f"
  echo "防火墙：请放行 ${CHECKER_PORT}/tcp（仅允许面板机访问）"
  echo "当前 profile：${CHECKER_PROFILE}"
  echo "----------------------------------------"
}

install_python_env
install_flask
install_checker_code
install_systemd_service
verify_checker
show_done_message
