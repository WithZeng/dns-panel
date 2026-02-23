#!/usr/bin/env bash
set -euo pipefail

if ! command -v pip-audit >/dev/null 2>&1; then
  echo "pip-audit 未安装，先执行: pip install pip-audit"
  exit 1
fi

pip-audit -r requirements.txt
