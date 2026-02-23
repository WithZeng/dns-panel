#!/usr/bin/env bash
# =============================================================================
# dns-panel 一键更新部署脚本（Linux）
# 功能：备份数据库 → 拉取最新代码 → 重建镜像 → 重启容器 → 健康检查
# 用法：bash update.sh [--skip-backup] [--skip-pull]
# =============================================================================
set -euo pipefail

SERVICE_NAME="dns-panel"
BACKUP_DIR="instance/backups"
DB_CANDIDATES=("instance/ecs_monitor.db" "ecs_monitor.db")

# ── 颜色输出 ─────────────────────────────────────────────────────────────────
step()  { echo ""; echo "========== $* =========="; }
info()  { echo "[信息] $*"; }
ok()    { echo "[完成] $*"; }
warn()  { echo "[警告] $*"; }
fail()  { echo "[错误] $*" >&2; exit 1; }

# ── 参数解析 ─────────────────────────────────────────────────────────────────
SKIP_BACKUP=0
SKIP_PULL=0
for arg in "$@"; do
  case "$arg" in
    --skip-backup) SKIP_BACKUP=1 ;;
    --skip-pull)   SKIP_PULL=1 ;;
    *) warn "未知参数: $arg，已忽略" ;;
  esac
done

# ── 确认在项目根目录 ─────────────────────────────────────────────────────────
[[ -f "docker-compose.yml" ]] || fail "请在项目根目录运行此脚本（找不到 docker-compose.yml）。"

# ── 读取面板端口 ─────────────────────────────────────────────────────────────
get_panel_port() {
  local port
  port="$(grep -E '^PANEL_PORT=' .env 2>/dev/null | head -n 1 | cut -d'=' -f2- | tr -d '[:space:]' || true)"
  [[ -n "$port" ]] || port="5000"
  echo "$port"
}

# ─────────────────────────────────────────────────────────────────────────────
step "第 1 步：备份数据库"
# ─────────────────────────────────────────────────────────────────────────────
if [[ "$SKIP_BACKUP" -eq 1 ]]; then
  info "已跳过备份（--skip-backup）。"
else
  DB_FILE=""
  for candidate in "${DB_CANDIDATES[@]}"; do
    if [[ -f "$candidate" ]]; then
      DB_FILE="$candidate"
      break
    fi
  done

  if [[ -z "$DB_FILE" ]]; then
    warn "未找到数据库文件，跳过备份。"
  else
    mkdir -p "$BACKUP_DIR"
    TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
    BACKUP_FILE="${BACKUP_DIR}/ecs_monitor_before_update_${TIMESTAMP}.db"
    cp "$DB_FILE" "$BACKUP_FILE"
    ok "数据库已备份 → ${BACKUP_FILE}"

    # 清理超过 14 天的本地备份
    find "$BACKUP_DIR" -name "*.db" -mtime +14 -delete 2>/dev/null || true
    info "已清理 14 天前的旧备份。"
  fi
fi

# ─────────────────────────────────────────────────────────────────────────────
step "第 2 步：拉取最新代码"
# ─────────────────────────────────────────────────────────────────────────────
if [[ "$SKIP_PULL" -eq 1 ]]; then
  info "已跳过 git pull（--skip-pull）。"
else
  if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    BEFORE_HASH="$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
    info "当前版本：${BEFORE_HASH}"
    git pull --rebase --autostash
    AFTER_HASH="$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
    if [[ "$BEFORE_HASH" == "$AFTER_HASH" ]]; then
      info "代码已是最新，无变更（${AFTER_HASH}）。"
    else
      ok "代码已更新：${BEFORE_HASH} → ${AFTER_HASH}"
    fi
  else
    warn "当前目录不是 git 仓库或未安装 git，跳过代码拉取。"
  fi
fi

# ─────────────────────────────────────────────────────────────────────────────
step "第 3 步：重建镜像并重启容器"
# ─────────────────────────────────────────────────────────────────────────────
info "停止旧容器..."
docker compose down --remove-orphans 2>&1 | tail -5 || true

info "重建镜像并启动（首次构建可能较慢）..."
docker compose build --no-cache
docker compose up -d
ok "容器已重启。"

# ─────────────────────────────────────────────────────────────────────────────
step "第 4 步：健康检查"
# ─────────────────────────────────────────────────────────────────────────────
PANEL_PORT="$(get_panel_port)"
info "等待服务就绪（端口 ${PANEL_PORT}）..."
HEALTHY=0
for i in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:${PANEL_PORT}/health" >/dev/null 2>&1; then
    HEALTHY=1
    break
  fi
  sleep 2
done

if [[ "$HEALTHY" -eq 1 ]]; then
  ok "健康检查通过 ✓"
else
  warn "健康检查未通过，请查看日志："
  echo "  docker compose logs --tail=50 ${SERVICE_NAME}"
fi

# ─────────────────────────────────────────────────────────────────────────────
step "更新完成"
# ─────────────────────────────────────────────────────────────────────────────
echo "当前版本  : $(git rev-parse --short HEAD 2>/dev/null || echo '-')"
echo "访问地址  : http://<你的服务器IP>:${PANEL_PORT}"
echo "容器状态  : docker compose ps"
echo "实时日志  : docker compose logs -f ${SERVICE_NAME}"
echo "回滚提示  : 如需回滚，从 ${BACKUP_DIR}/ 恢复数据库并 git checkout <旧版本> 后重新运行此脚本"
