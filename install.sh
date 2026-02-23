#!/usr/bin/env bash
# =============================================================================
# dns-panel 远程一键部署/更新脚本
#
# 首次部署：
#   bash <(curl -fsSL https://raw.githubusercontent.com/WithZeng/dns-panel/main/install.sh)
#
# 更新已有部署：
#   bash <(curl -fsSL https://raw.githubusercontent.com/WithZeng/dns-panel/main/install.sh) update
#
# 指定安装目录：
#   INSTALL_DIR=/opt/dns-panel bash <(curl -fsSL https://raw.githubusercontent.com/WithZeng/dns-panel/main/install.sh)
#
# 所有子命令（deploy/update/restart/stop/status/logs/backup/help）均可直接传入
# =============================================================================
set -euo pipefail

REPO_URL="https://github.com/WithZeng/dns-panel.git"
DEFAULT_INSTALL_DIR="/opt/dns-panel"
INSTALL_DIR="${INSTALL_DIR:-$DEFAULT_INSTALL_DIR}"

# ── 输出 ─────────────────────────────────────────────────────────────────────
info()  { echo "[信息] $*"; }
ok()    { echo "[完成] $*"; }
warn()  { echo "[警告] $*"; }
fail()  { echo "[错误] $*" >&2; exit 1; }
step()  { echo ""; echo "========== $* =========="; }

# ── 检查 root / sudo ────────────────────────────────────────────────────────
ensure_root() {
  if [[ "$EUID" -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then
      info "非 root 用户，使用 sudo 重新执行..."
      exec sudo bash "$0" "$@"
    else
      fail "请使用 root 用户运行此脚本。"
    fi
  fi
}

# ── 安装 git ─────────────────────────────────────────────────────────────────
ensure_git() {
  if command -v git >/dev/null 2>&1; then
    return
  fi
  info "未检测到 git，自动安装..."
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq && apt-get install -y -qq git
  elif command -v yum >/dev/null 2>&1; then
    yum install -y -q git
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q git
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache git
  else
    fail "无法自动安装 git，请手动安装后重试。"
  fi
  ok "git 已安装。"
}

# ── 克隆或拉取仓库 ──────────────────────────────────────────────────────────
sync_repo() {
  if [[ -d "$INSTALL_DIR/.git" ]]; then
    step "更新代码仓库"
    cd "$INSTALL_DIR"
    git fetch --all --prune
    git reset --hard origin/main
    ok "代码已更新到最新版本。"
  else
    step "首次克隆代码仓库"
    mkdir -p "$(dirname "$INSTALL_DIR")"
    git clone "$REPO_URL" "$INSTALL_DIR"
    ok "仓库已克隆到 $INSTALL_DIR"
    cd "$INSTALL_DIR"
  fi
}

# ── 主逻辑 ───────────────────────────────────────────────────────────────────
main() {
  local action="${1:-}"
  # 没有参数时：如果目录已存在则 update，否则 deploy
  if [[ -z "$action" ]]; then
    if [[ -d "$INSTALL_DIR/.git" ]]; then
      action="update"
    else
      action="deploy"
    fi
    info "未指定命令，自动选择: $action"
  fi

  ensure_root "$@"
  ensure_git

  # 对于不需要代码的命令（stop/status/logs/restart），直接进目录执行
  case "$action" in
    stop|status|logs|restart|backup|help|-h|--help)
      if [[ ! -f "$INSTALL_DIR/panel.sh" ]]; then
        fail "未找到 $INSTALL_DIR/panel.sh，请先执行首次部署。"
      fi
      cd "$INSTALL_DIR"
      exec bash panel.sh "$action"
      ;;
  esac

  # deploy / update 需要同步代码
  sync_repo

  # 传递所有参数给 panel.sh
  exec bash panel.sh "$@"
}

main "$@"
