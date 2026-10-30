import os
import socket
import sys
import threading
import time

import pytest

from tol_collector import Collector, TCP_ESTABLISHED, TCP_LISTEN, read_tcp_sockets
from tol_registry import lookup_company

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only")


def sock(dst="93.184.216.34", dport=443, sent=0, recv=0, inode=1, state=TCP_ESTABLISHED, src="10.0.0.5"):
    return {"family": 2, "state": state, "src": src, "sport": 50000 + inode, "dst": dst, "dport": dport,
            "uid": 0, "inode": inode, "bytes_sent": sent, "bytes_received": recv}


class Feed:
    """Scripted socket snapshots, one per poll."""

    def __init__(self, *snapshots):
        self.snaps = list(snapshots)

    def __call__(self):
        return self.snaps.pop(0)


def collector(*snaps, **kw):
    return Collector(reader=Feed(*snaps), owners=lambda: {1: (4242, "curl"), 2: (4243, "python")}, **kw)


def test_first_poll_is_baseline_then_deltas_reported():
    c = collector([sock(sent=1000, recv=500)], [sock(sent=1300, recv=900)], [sock(sent=1300, recv=900)])
    assert c.poll(1000.0) == []                       # historical bytes are not attributed to the window
    (e,) = c.poll(1001.0)
    assert (e["bytes_sent"], e["bytes_received"], e["direction"]) == (300, 400, "outbound")
    assert (e["process_name"], e["pid"], e["endpoint_port"], e["protocol"]) == ("curl", 4242, 443, "HTTPS")
    assert e["source"] == "live" and e["tls_certificate_issuer"] is None and e["endpoint_country"] == "??"
    assert c.poll(1002.0) == []                       # idle connection: nothing reported


def test_connection_opened_between_polls_counts_all_its_bytes():
    c = collector([sock(inode=1)], [sock(inode=1), sock(inode=2, dst="1.2.3.4", sent=777)])
    c.poll(1.0)
    (e,) = c.poll(2.0)
    assert e["endpoint_ip"] == "1.2.3.4" and e["bytes_sent"] == 777 and e["process_name"] == "python"


def test_listeners_loopback_and_unknown_counters_are_skipped():
    snap = [sock(state=TCP_LISTEN, sent=5), sock(dst="127.0.0.1", sent=9, inode=2),
            {**sock(inode=3), "bytes_sent": None}]
    c = collector([], snap)
    c.poll(1.0)
    assert c.poll(2.0) == []
    c2 = collector([], [sock(dst="127.0.0.1", sent=9, inode=2)], include_loopback=True)
    c2.poll(1.0)
    assert len(c2.poll(2.0)) == 1


def test_inbound_only_traffic_is_marked_inbound():
    c = collector([], [sock(sent=0, recv=64)])
    c.poll(1.0)
    assert c.poll(2.0)[0]["direction"] == "inbound"


def test_company_from_reverse_dns_suffix_not_invented_for_unknown_ips():
    c = collector([], [sock(dst="52.1.2.3", sent=10)], resolver=lambda ip: "ec2-52-1-2-3.compute.amazonaws.com",
                  registry={".amazonaws.com": {"company": "Amazon Web Services", "trust_level": "medium"}})
    c.poll(1.0)
    assert c.poll(2.0)[0]["company_name"] == "Amazon Web Services"
    c = collector([], [sock(dst="35.192.1.1", sent=10)], registry={})   # no registry entry: UNKNOWN, never a guess
    c.poll(1.0)
    assert c.poll(2.0)[0]["company_name"] == "UNKNOWN"


def test_registry_suffix_matching_is_label_aligned():
    reg = {".stripe.com": {"company": "Stripe", "trust_level": "high"}}
    assert lookup_company("1.1.1.1", "api.stripe.com", reg)["company"] == "Stripe"
    assert lookup_company("1.1.1.1", "stripe.com", reg)["company"] == "Stripe"
    assert lookup_company("1.1.1.1", "notstripe.com", reg)["company"] == "UNKNOWN"
    assert lookup_company("1.1.1.1", "stripe.com.evil.example", reg)["company"] == "UNKNOWN"


# --- against the real kernel -------------------------------------------------
def test_real_sockets_byte_counts_and_owner():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    port = srv.getsockname()[1]
    got = bytearray()

    def serve():
        conn, _ = srv.accept()
        while chunk := conn.recv(65536):
            got.extend(chunk)
        conn.close()

    t = threading.Thread(target=serve)
    t.start()
    cli = socket.create_connection(("127.0.0.1", port))
    try:
        c = Collector(include_loopback=True)
        c.poll()                                      # baseline
        cli.sendall(b"x" * 123_456)
        time.sleep(0.3)                               # let the peer ACK
        entries = [e for e in c.poll() if e["endpoint_port"] == port]
    finally:
        cli.close()
        t.join()
        srv.close()
    (sent,) = [e for e in entries if e["bytes_sent"] > 0]
    assert sent["bytes_sent"] == 123_456
    assert sent["pid"] == os.getpid() and sent["source"] == "live"
    assert len(got) == 123_456


def test_real_kernel_listing_works():
    socks = read_tcp_sockets()
    assert socks and all(s["bytes_sent"] is not None for s in socks if s["state"] == TCP_ESTABLISHED)


def test_names_are_only_looked_up_for_public_addresses():
    asked = []
    rows = [{"family": 4, "state": 1, "src": "192.168.1.5", "sport": 5000 + i, "dst": ip, "dport": 443, "uid": None,
             "inode": i, "bytes_sent": 0, "bytes_received": 0} for i, ip in
            enumerate(["192.168.1.20", "10.0.0.7", "169.254.3.4", "fe80::1", "93.184.216.34"])]
    later = [dict(r, bytes_sent=100) for r in rows]
    seq = iter([rows, later])
    c = Collector(include_loopback=True, resolver=lambda ip: asked.append(ip) or ip, owners=lambda: {},
                  reader=lambda: next(seq), labeler=lambda ip, host: {"company": "UNKNOWN"})
    c.poll(1.0)
    c.poll(2.0)
    assert asked and set(asked) == {"93.184.216.34"}
