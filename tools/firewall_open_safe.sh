#!/usr/bin/env bash
set -euo pipefail

# Safe firewall opener for Linux hosts.
# Default is plan mode (no changes). Use --apply to execute.

APPLY=0
PORTS=""
PROTO="tcp"
SOURCE="0.0.0.0/0"

usage() {
  cat <<USAGE
Usage:
  $0 --ports 80,443,5000 [--proto tcp|udp] [--source CIDR] [--plan|--apply]

Examples:
  $0 --ports 5000 --plan
  $0 --ports 80,443 --proto tcp --apply
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ports) PORTS="$2"; shift 2 ;;
    --proto) PROTO="$2"; shift 2 ;;
    --source) SOURCE="$2"; shift 2 ;;
    --apply) APPLY=1; shift ;;
    --plan) APPLY=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1"; usage; exit 1 ;;
  esac
done

if [[ -z "$PORTS" ]]; then
  echo "[ERR] --ports is required"
  usage
  exit 1
fi

IFS=',' read -r -a PORT_ARR <<< "$PORTS"

echo "[INFO] Mode: $([[ $APPLY -eq 1 ]] && echo APPLY || echo PLAN)"
echo "[INFO] Ports: ${PORTS}"
echo "[INFO] Proto: ${PROTO}"
echo "[INFO] Source: ${SOURCE}"

run_cmd() {
  if [[ $APPLY -eq 1 ]]; then
    eval "$1"
  else
    echo "PLAN> $1"
  fi
}

if command -v ufw >/dev/null 2>&1; then
  echo "[INFO] firewall backend: ufw"
  for p in "${PORT_ARR[@]}"; do
    run_cmd "ufw allow proto ${PROTO} from ${SOURCE} to any port ${p}"
  done
elif command -v firewall-cmd >/dev/null 2>&1; then
  echo "[INFO] firewall backend: firewalld"
  for p in "${PORT_ARR[@]}"; do
    run_cmd "firewall-cmd --add-rich-rule='rule family=ipv4 source address=${SOURCE} port protocol=${PROTO} port=${p} accept' --permanent"
  done
  run_cmd "firewall-cmd --reload"
else
  echo "[WARN] No ufw/firewalld detected; fallback to iptables"
  for p in "${PORT_ARR[@]}"; do
    run_cmd "iptables -I INPUT -p ${PROTO} --dport ${p} -s ${SOURCE} -j ACCEPT"
  done
fi

echo "[OK] done"
