#!/usr/bin/env bash
set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

APP_DIR='/opt/dns-panel-agent'
SERVICE_NAME='dns-panel-agent.service'
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}"
ENV_FILE='/etc/dns-panel-agent.env'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-/tmp}")" 2>/dev/null && pwd || echo /tmp)"

CLI_SERVER_URL=""
CLI_TOKEN=""
CLI_INTERVAL=""

info() { echo -e "${BLUE}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err() { echo -e "${RED}[ERR]${NC} $*"; }

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    err "请使用 root 运行: sudo bash install.sh"
    exit 1
  fi
}

parse_cli_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --server)
        CLI_SERVER_URL="${2:-}"
        shift 2
        ;;
      --token)
        CLI_TOKEN="${2:-}"
        shift 2
        ;;
      --interval)
        CLI_INTERVAL="${2:-}"
        shift 2
        ;;
      --help|-h)
        echo "Usage: bash install.sh [--server <ws_url>] [--token <token>] [--interval <seconds>]"
        exit 0
        ;;
      *)
        warn "忽略未知参数: $1"
        shift
        ;;
    esac
  done
}

derive_http_origin_from_ws() {
  local ws_url="$1"
  local origin
  origin="$(echo "${ws_url}" | sed -E 's#^ws://#http://#; s#^wss://#https://#')"
  origin="${origin%%/ws/agent*}"
  origin="${origin%%/}"
  echo "${origin}"
}

install_python_env() {
  info '安装 Python3 运行环境...'
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y python3 python3-psutil 2>/dev/null || {
      apt-get install -y python3 python3-pip
      python3 -m pip install --break-system-packages psutil 2>/dev/null \
        || python3 -m pip install psutil
    }
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y python3 python3-psutil 2>/dev/null || {
      dnf install -y python3 python3-pip
      python3 -m pip install psutil
    }
  elif command -v yum >/dev/null 2>&1; then
    yum install -y python3 python3-psutil 2>/dev/null || {
      yum install -y python3 python3-pip
      python3 -m pip install psutil
    }
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache python3 py3-psutil
  else
    err '未识别包管理器，请手动安装 python3 和 psutil'
    exit 1
  fi

  if ! python3 -c 'import psutil' 2>/dev/null; then
    warn 'psutil 未检测到，尝试 pip 安装...'
    python3 -m pip install --break-system-packages psutil 2>/dev/null \
      || python3 -m pip install psutil 2>/dev/null \
      || { err 'psutil 安装失败，请手动运行: apt install python3-psutil 或 pip3 install psutil'; exit 1; }
  fi
  success 'Python 运行环境准备完成'
}

write_service() {
  cat > "${SERVICE_PATH}" <<'SERVICEEOF'
[Unit]
Description=DNS Panel Probe Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/dns-panel-agent.env
ExecStart=/usr/bin/env python3 /opt/dns-panel-agent/agent.py --server $SERVER_URL --token $TOKEN --interval $INTERVAL
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
SERVICEEOF

  systemctl daemon-reload
  systemctl enable "${SERVICE_NAME}"
}

configure_env() {
  local server_url token interval

  if [[ -n "${CLI_SERVER_URL}" ]]; then
    server_url="${CLI_SERVER_URL}"
    info "使用命令行传入 SERVER_URL"
  else
    read -r -p '请输入面板 WebSocket 地址（如 wss://panel.example.com/ws/agent）: ' server_url
  fi

  if [[ -n "${CLI_TOKEN}" ]]; then
    token="${CLI_TOKEN}"
    info "使用命令行传入 TOKEN"
  else
    read -r -p '请输入 Probe Token: ' token
  fi

  if [[ -n "${CLI_INTERVAL}" ]]; then
    interval="${CLI_INTERVAL}"
    info "使用命令行传入 INTERVAL=${interval}"
  elif [[ -n "${CLI_SERVER_URL}" ]]; then
    interval="3"
  else
    read -r -p '上报间隔秒数（默认 3）: ' interval
  fi

  interval="${interval:-3}"

  cat > "${ENV_FILE}" <<EOF
SERVER_URL=${server_url}
TOKEN=${token}
INTERVAL=${interval}
EOF

  chmod 600 "${ENV_FILE}"
  success "环境变量写入 ${ENV_FILE}"
}

prepare_agent_file() {
  local local_agent="${SCRIPT_DIR}/agent.py"
  if [[ -f "${local_agent}" ]]; then
    cp -f "${local_agent}" "${APP_DIR}/agent.py"
    chmod +x "${APP_DIR}/agent.py"
    return
  fi

  local ws_url="${CLI_SERVER_URL}"
  if [[ -z "${ws_url}" && -f "${ENV_FILE}" ]]; then
    ws_url="$(grep -E '^SERVER_URL=' "${ENV_FILE}" | head -n1 | cut -d'=' -f2- || true)"
  fi

  if [[ -z "${ws_url}" ]]; then
    read -r -p '未检测到本地 agent.py，请输入面板 WebSocket 地址用于下载 agent.py: ' ws_url
  fi

  local origin
  origin="$(derive_http_origin_from_ws "${ws_url}")"
  local url="${origin}/agent/agent.py"

  info "从 ${url} 下载 agent.py ..."
  curl -fsSL "${url}" -o "${APP_DIR}/agent.py"
  chmod +x "${APP_DIR}/agent.py"
  success 'agent.py 下载完成'
}

install_agent() {
  require_root
  install_python_env

  mkdir -p "${APP_DIR}"
  prepare_agent_file

  configure_env
  write_service

  local server_url
  server_url="$(grep -E '^SERVER_URL=' "${ENV_FILE}" | head -n1 | cut -d'=' -f2- || true)"
  local origin
  origin="$(derive_http_origin_from_ws "${server_url}")"

  systemctl restart "${SERVICE_NAME}"
  success '安装完成，服务已启动'
  systemctl --no-pager --full status "${SERVICE_NAME}" || true

  info '--- 诊断命令 ---'
  echo ""
  echo "  查看 Agent 日志:    journalctl -u ${SERVICE_NAME} -f --no-pager"
  echo "  检查服务状态:       systemctl status ${SERVICE_NAME}"
  echo "  测试面板连通性:     curl -s ${origin}/api/probe/health"
  echo ""
}

upgrade_agent() {
  require_root
  if [[ ! -f "${APP_DIR}/agent.py" ]]; then
    warn '检测到未安装，将执行安装流程'
    install_agent
    return
  fi

  prepare_agent_file

  if [[ ! -f "${ENV_FILE}" ]]; then
    configure_env
  fi

  write_service
  systemctl restart "${SERVICE_NAME}"
  success '升级完成，服务已重启'
}

uninstall_agent() {
  require_root
  systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
  systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
  rm -f "${SERVICE_PATH}"
  systemctl daemon-reload

  rm -rf "${APP_DIR}"
  rm -f "${ENV_FILE}"
  success '卸载完成'
}

show_menu() {
  echo -e "${GREEN}=====================================${NC}"
  echo -e "${GREEN} DNS Panel Agent 安装脚本${NC}"
  echo -e "${GREEN}=====================================${NC}"
  echo '1) 安装'
  echo '2) 升级'
  echo '3) 卸载'
  echo '4) 退出'
  read -r -p '请选择 [1-4]: ' choice

  case "${choice}" in
    1) install_agent ;;
    2) upgrade_agent ;;
    3) uninstall_agent ;;
    4) exit 0 ;;
    *) err '无效选项'; exit 1 ;;
  esac
}

parse_cli_args "$@"

if [[ -n "${CLI_SERVER_URL}" && -n "${CLI_TOKEN}" ]]; then
  info '检测到命令行参数，执行非交互安装流程'
  install_agent
else
  show_menu
fi
