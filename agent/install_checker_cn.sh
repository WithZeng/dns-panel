#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${PANEL_BASE_URL:-}" ]]; then
  echo "[checker-cn][error] 请先设置 PANEL_BASE_URL，例如: PANEL_BASE_URL=http://1.2.3.4:5000" >&2
  exit 1
fi

PANEL_BASE_URL="${PANEL_BASE_URL%/}"
TMP_CORE="/tmp/install_checker_core.sh"

echo "[checker-cn] downloading core installer from ${PANEL_BASE_URL}/agent/install_checker.sh"
curl -fsSL "${PANEL_BASE_URL}/agent/install_checker.sh" -o "${TMP_CORE}"
chmod +x "${TMP_CORE}"

echo "[checker-cn] running with CHECKER_PROFILE=cn"
CHECKER_PROFILE=cn PANEL_BASE_URL="${PANEL_BASE_URL}" bash "${TMP_CORE}"
