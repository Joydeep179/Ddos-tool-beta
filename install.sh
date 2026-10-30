#!/usr/bin/env bash
# Killora installer
# bash <(curl -s https://raw.githubusercontent.com/Joydeep179/Ddos-tool-beta/main/install.sh)
set -euo pipefail

REPO_RAW="${KILLORA_REPO:-https://raw.githubusercontent.com/Joydeep179/Ddos-tool-beta/main}"
DIR="/opt/killora"
BIN="/usr/local/bin/killora"

C_R="\033[0m"; C_G="\033[1;32m"; C_Y="\033[1;33m"; C_C="\033[1;36m"; C_RD="\033[1;31m"
say(){ printf "${C_C}[*]${C_R} %s\n" "$*"; }
ok(){ printf "${C_G}[+]${C_R} %s\n" "$*"; }
warn(){ printf "${C_Y}[!]${C_R} %s\n" "$*"; }
die(){ printf "${C_RD}[x]${C_R} %s\n" "$*"; exit 1; }

clear
cat <<'EOF'
  ██╗  ██╗██╗██╗     ██╗      ██████╗ ██████╗  █████╗
  ██║ ██╔╝██║██║     ██║     ██╔═══██╗██╔══██╗██╔══██╗
  █████╔╝ ██║██║     ██║     ██║   ██║██████╔╝███████║
  ██╔═██╗ ██║██║     ██║     ██║   ██║██╔══██╗██╔══██║
  ██║  ██╗██║███████╗███████╗╚██████╔╝██║  ██║██║  ██║
  ╚═╝  ╚═╝╚═╝╚══════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
                 installer v1.0.0  |  made by BrokenCodeZ
EOF

[[ $EUID -eq 0 ]] || die "root chahiye. sudo -i karke chalao."
command -v curl >/dev/null || die "curl nahi hai: apt install curl"

say "dependencies install ho rahi hain..."
if command -v apt-get >/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y -qq
  apt-get install -y -qq python3 python3-venv python3-pip curl git screen jq iproute2 dnsutils ca-certificates >/dev/null
elif command -v dnf >/dev/null; then
  dnf install -y -q python3 python3-pip curl git screen jq iproute bind-utils >/dev/null
elif command -v yum >/dev/null; then
  yum install -y -q python3 python3-pip curl git screen jq iproute bind-utils >/dev/null
elif command -v apk >/dev/null; then
  apk add --no-cache python3 py3-pip curl git screen jq bind-tools >/dev/null
else
  die "package manager detect nahi hua."
fi

ok "system packages done"
mkdir -p "$DIR"
cd "$DIR"

say "python venv ban raha hai..."
python3 -m venv "$DIR/venv" || die "venv fail"
# shellcheck disable=SC1091
source "$DIR/venv/bin/activate"

say "python libs install..."
pip install -q --upgrade pip
pip install -q aiohttp dnspython httpx certifi || warn "kuch lib fail hui, core chalega"

say "killora.py download ho raha hai..."
curl -fsSL --retry 3 "$REPO_RAW/killora.py" -o "$DIR/killora.py" || die "download fail. repo/branch check karo."
[[ -s "$DIR/killora.py" ]] || die "killora.py khali hai"
python3 -c "import ast,sys; ast.parse(open('$DIR/killora.py').read())" || die "killora.py syntax galat hai"

cat > "$BIN" <<EOF
#!/usr/bin/env bash
cd "$DIR" || exit 1
source "$DIR/venv/bin/activate"
ulimit -n 1048576 2>/dev/null
exec python3 "$DIR/killora.py" "\$@"
EOF
chmod +x "$BIN"; chmod +x "$DIR/killora.py"

say "kernel tuning..."
cat > /etc/sysctl.d/99-killora.conf <<'EOF'
net.core.somaxconn=65535
net.core.netdev_max_backlog=65535
net.ipv4.tcp_max_syn_backlog=65535
net.ipv4.tcp_fin_timeout=10
net.ipv4.tcp_tw_reuse=1
net.ipv4.ip_local_port_range=1024 65535
fs.file-max=2097152
EOF
sysctl -p /etc/sysctl.d/99-killora.conf >/dev/null 2>&1 || warn "sysctl partial fail"

ok "installed: $DIR"
ok "chalane ke liye: killora"
printf "${C_G}Killora v1.0.0 ready.${C_R}\n"