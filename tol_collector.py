"""Live TOL collector for Linux: real TCP connections, owning processes and byte counters.

Reads the kernel's sock_diag netlink interface (what `ss` uses) for every TCP socket, with
tcp_info for per-connection byte counters, then maps socket inodes to processes via /proc.
No root needed for your own processes; run as root to see every process.

What it can and cannot see:
  sees    remote IP/port, bytes each way per connection, owning process, reverse-DNS name
  misses  payload content (encrypted anyway), UDP/QUIC (HTTP/3), connections that open and
          close between two polls, and bytes sent in the last interval before a close
"""
import ipaddress
import os
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from datetime import datetime, timezone

from tol_registry import build_tol_session_log, lookup_company

NETLINK_SOCK_DIAG = 4
SOCK_DIAG_BY_FAMILY = 20
NLM_F_REQUEST, NLM_F_DUMP = 0x1, 0x300
NLMSG_ERROR, NLMSG_DONE = 2, 3
INET_DIAG_INFO = 2
TCP_ESTABLISHED, TCP_LISTEN = 1, 10
ALL_STATES = 0xFFF
# struct tcp_info offsets (include/uapi/linux/tcp.h, stable since Linux 4.1)
OFF_BYTES_ACKED, OFF_BYTES_RECEIVED = 120, 128

PORT_PROTOCOLS = {443: "HTTPS", 8443: "HTTPS", 80: "HTTP", 8080: "HTTP", 53: "DNS", 22: "SSH",
                  853: "DNS-over-TLS", 25: "SMTP", 465: "SMTPS", 587: "SMTP", 993: "IMAPS"}


def _protocol(proto: str, port: int) -> str:
    if proto == "udp":
        return {443: "QUIC", 53: "DNS"}.get(port, "UDP")
    return PORT_PROTOCOLS.get(port, "TCP")


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _diag_request(family: int, seq: int) -> bytes:
    sockid = b"\x00" * 48
    body = struct.pack("=BBBBI", family, socket.IPPROTO_TCP, 1 << (INET_DIAG_INFO - 1), 0, ALL_STATES) + sockid
    return struct.pack("=IHHII", 16 + len(body), SOCK_DIAG_BY_FAMILY, NLM_F_REQUEST | NLM_F_DUMP, seq, 0) + body


def _parse_diag(data: bytes, family: int):
    off = 0
    while off + 16 <= len(data):
        length, mtype = struct.unpack_from("=IH", data, off)
        if length < 16:
            return
        if mtype == NLMSG_DONE:
            return
        if mtype == NLMSG_ERROR:
            raise OSError("sock_diag error: " + str(struct.unpack_from("=i", data, off + 16)[0]))
        msg = data[off + 16:off + length]
        _, state = struct.unpack_from("=BB", msg, 0)
        sport, dport = struct.unpack_from("!HH", msg, 4)
        alen = 4 if family == socket.AF_INET else 16
        src = socket.inet_ntop(family, msg[8:8 + alen])
        dst = socket.inet_ntop(family, msg[24:24 + alen])
        uid, inode = struct.unpack_from("=II", msg, 64)
        acked = received = None
        pos = 72
        while pos + 4 <= len(msg):
            alen_, atype = struct.unpack_from("=HH", msg, pos)
            if alen_ < 4:
                break
            if atype == INET_DIAG_INFO and alen_ - 4 >= OFF_BYTES_RECEIVED + 8:
                payload = msg[pos + 4:pos + alen_]
                acked, received = struct.unpack_from("=QQ", payload, OFF_BYTES_ACKED)
            pos += (alen_ + 3) & ~3
        yield {"family": family, "state": state, "src": src, "sport": sport, "dst": dst, "dport": dport,
               "uid": uid, "inode": inode, "bytes_sent": acked, "bytes_received": received}
        off += (length + 3) & ~3


def read_tcp_sockets() -> list:
    out = []
    for family in (socket.AF_INET, socket.AF_INET6):
        s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_SOCK_DIAG)
        try:
            s.settimeout(5)
            s.send(_diag_request(family, 1))
            done = False
            while not done:
                data = s.recv(1 << 16)
                out.extend(_parse_diag(data, family))
                done = _is_done(data)
        finally:
            s.close()
    return out


def _is_done(data: bytes) -> bool:
    off = 0
    while off + 16 <= len(data):
        length, mtype = struct.unpack_from("=IH", data, off)
        if mtype == NLMSG_DONE:
            return True
        if length < 16:
            return True
        off += (length + 3) & ~3
    return False


def inode_to_process() -> dict:
    """socket inode -> (pid, process name), for every process we are allowed to inspect."""
    owners = {}
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            for fd in os.listdir(f"/proc/{pid}/fd"):
                link = os.readlink(f"/proc/{pid}/fd/{fd}")
                if link.startswith("socket:["):
                    if int(link[8:-1]) not in owners:
                        with open(f"/proc/{pid}/comm") as f:
                            owners[int(link[8:-1])] = (int(pid), f.read().strip())
        except (OSError, ValueError):
            continue
    return owners


class Resolver:
    """Cached reverse DNS with a hard timeout, forward-confirmed.

    The owner of an IP controls its PTR record, so a bare reverse lookup can claim any name
    ("github.com"). A name is only returned if resolving it forward yields the same IP;
    otherwise the IP itself is returned and no hostname is trusted.
    """

    def __init__(self, timeout=1.5, reverse=socket.gethostbyaddr, forward=socket.gethostbyname_ex):
        self.timeout, self.cache = timeout, {}
        self._reverse, self._forward = reverse, forward
        self._pool = ThreadPoolExecutor(max_workers=4)

    def _confirmed(self, ip):
        name = self._reverse(ip)[0]
        addrs = self._forward(name)[2]
        want = ipaddress.ip_address(ip)
        return name if any(ipaddress.ip_address(a) == want for a in addrs) else ip

    def __call__(self, ip: str) -> str:
        if ip not in self.cache:
            fut = self._pool.submit(self._confirmed, ip)
            try:
                self.cache[ip] = fut.result(self.timeout)
            except (OSError, FutureTimeout):
                self.cache[ip] = ip
        return self.cache[ip]


class Collector:
    def __init__(self, include_loopback=False, resolver=None, registry=None, reader=read_tcp_sockets,
                 owners=inode_to_process, labeler=None, presence_only=False):
        """labeler(ip, hostname_or_None) -> {"company", "trust_level", optional "source", "confidence"}.
        Defaults to the registry file; tol_app.labeler.Labeler adds layered automatic labelling."""
        self.include_loopback = include_loopback
        self.resolver = resolver or (lambda ip: ip)
        self.registry = registry
        self.labeler = labeler or (lambda ip, host: lookup_company(ip, host, self.registry))
        self._reader, self._owners = reader, owners
        # presence_only: the platform cannot give byte counts (Windows). One entry per newly seen established
        # connection, amounts 0, flagged bytes_known=False so nothing downstream mistakes 0 for "nothing sent".
        self.presence_only = presence_only
        self.bytes_known = not presence_only
        self._seen = None  # None until the baseline poll

    def _is_local(self, ip: str) -> bool:
        a = ipaddress.ip_address(ip.split("%")[0])
        return a.is_loopback or a.is_unspecified

    def poll(self, now=None) -> list:
        """Entries for traffic since the previous poll. The first poll only sets the baseline."""
        now = time.time() if now is None else now
        owners = self._owners() if self._owners else {}
        current, entries = {}, []
        for s in self._reader():
            if s["state"] == TCP_LISTEN or s["bytes_sent"] is None:
                continue
            if not self.include_loopback and self._is_local(s["dst"]):
                continue
            key = (s["src"], s["sport"], s["dst"], s["dport"], s["inode"])
            current[key] = (s["bytes_sent"], s["bytes_received"])
            if self.presence_only:      # connections already open at the first poll count too: that is the picture
                if s["state"] == TCP_ESTABLISHED and key not in (self._seen or {}):
                    entries.append(self._entry(now, s, 0, 0, s.get("pid"), s.get("process", "unknown")))
                continue
            if self._seen is None:
                continue
            prev = self._seen.get(key, (0, 0))   # connection new since last poll: count all of it
            sent, recv = s["bytes_sent"] - prev[0], s["bytes_received"] - prev[1]
            if sent > 0 or recv > 0:
                if "process" in s:
                    pid, name = s.get("pid"), s["process"]
                else:
                    pid, name = owners.get(s["inode"], (None, "unknown"))
                entries.append(self._entry(now, s, sent, recv, pid, name))
        self._seen = current
        return entries

    @staticmethod
    def _is_public(ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip.split("%")[0]).is_global
        except ValueError:
            return False

    def _entry(self, now, s, sent, recv, pid, name) -> dict:
        # Names are looked up only for public addresses. Asking about devices on the home network would send queries
        # onto that network (and makes macOS ask for "local network" permission) and gains nothing.
        host = self.resolver(s["dst"]) if self._is_public(s["dst"]) else s["dst"]
        info = self.labeler(s["dst"], host if host != s["dst"] else None)
        return {
            "entry_id": f"live-{s['inode']}-{int(now * 1000)}",
            "source": "live",
            "timestamp": _iso(now),
            "company_name": info["company"],
            "label_source": info.get("source", "registry"),
            "label_confidence": info.get("confidence", "verified" if info["company"] != "UNKNOWN" else "none"),
            "endpoint_ip": s["dst"],
            "endpoint_port": s["dport"],
            "endpoint_country": "??",            # no GeoIP database bundled; do not guess
            "protocol": _protocol(s.get("proto", "tcp"), s["dport"]),
            "direction": "outbound" if sent > 0 else "inbound",
            "bytes_sent": sent,
            "bytes_received": recv,
            "bytes_known": self.bytes_known,
            "hostname": host,
            "process_name": name,
            "pid": pid,
            "tls_certificate_subject": None,     # not captured: we do not see handshakes
            "tls_certificate_issuer": None,
            "tls_certificate_sha256": None,
        }

    def run(self, seconds: float, interval: float = 1.0, session_id=None) -> dict:
        """Watch for `seconds`, polling every `interval` (keep it <= the correlation window)."""
        start = time.time()
        self.poll(start)
        entries = []
        while time.time() - start < seconds:
            time.sleep(interval)
            entries += self.poll()
        return build_tol_session_log(session_id or f"live-{int(start)}", _iso(start), _iso(time.time()), entries)
