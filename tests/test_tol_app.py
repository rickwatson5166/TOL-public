import types
import http.client
import json
import sys
import threading
import time

import pytest

from tol_app import cli
from tol_app.engine import Engine
from tol_app.labeler import Labeler, classify_local, parse_rdap
from tol_app.server import COOKIE, load_or_create_token, make_server
from tol_collector import Collector, Resolver, TCP_ESTABLISHED

RDAP_GOOGLE = {
    "startAddress": "34.149.0.0", "endAddress": "34.149.255.255", "name": "GOOGLE-CLOUD",
    "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                                                      ["fn", {}, "text", "Google LLC"]]]}],
}
REG = {"104.18.0.0/16": {"company": "Acme Pay", "category": "payment", "trust_level": "high"},
       ".github.com": {"company": "GitHub", "category": "developer", "trust_level": "medium"}}


# --- labeler -----------------------------------------------------------------
def test_local_addresses_never_reach_lookups():
    calls = []
    lab = Labeler(registry={}, lookups=True, fetch=lambda ip: calls.append(ip))
    for ip, name in (("127.0.0.1", "This device"), ("192.168.1.5", "Local network"), ("10.0.0.2", "Local network"),
                     ("100.64.1.1", "Local network"), ("fe80::1", "Local network")):
        assert lab.label(ip)["company"] == name
    lab.wait()
    assert calls == [] and classify_local("8.8.8.8") is None


def test_layers_and_confidence():
    lab = Labeler(registry=REG, lookups=False)
    ip_hit = lab.label("104.18.0.9")
    assert (ip_hit["company"], ip_hit["confidence"], ip_hit["source"]) == ("Acme Pay", "verified", "registry")
    host_hit = lab.label("140.82.1.1", "lb-1.github.com")
    assert (host_hit["company"], host_hit["confidence"]) == ("GitHub", "likely")
    dns_only = lab.label("45.33.0.4", "api.example.org")
    assert (dns_only["company"], dns_only["confidence"]) == ("api.example.org", "hostname")
    nothing = lab.label("45.33.0.4")
    assert (nothing["company"], nothing["confidence"]) == ("UNKNOWN", "none")


def test_rdap_parse_and_network_owner_is_not_presented_as_vendor(tmp_path):
    assert parse_rdap(RDAP_GOOGLE) == ("Google LLC", ["34.149.0.0/16"])
    lab = Labeler(registry={}, lookups=True, cache_path=tmp_path / "owners.json", fetch=lambda ip: RDAP_GOOGLE)
    assert lab.label("34.149.66.165")["confidence"] == "none"      # first sight: lookup queued
    lab.wait()
    got = lab.label("34.149.7.7")                                   # whole /16 now resolved from cache
    assert (got["company"], got["confidence"], got["source"]) == ("Google LLC", "network-only", "network-owner")
    assert got["trust_level"] == "unknown" and "vendor unconfirmed" in got["notes"]
    again = Labeler(registry={}, lookups=False, cache_path=tmp_path / "owners.json")
    assert again.label("34.149.1.1")["company"] == "Google LLC"      # survives restart


def test_failed_lookups_are_negatively_cached_and_lookups_can_be_off():
    calls = []
    lab = Labeler(registry={}, lookups=True, fetch=lambda ip: calls.append(ip))   # returns None = failure
    lab.label("45.33.0.1")
    lab.wait()
    lab.label("45.33.0.1")
    lab.wait()
    assert calls == ["45.33.0.1"]
    off = Labeler(registry={}, lookups=False, fetch=lambda ip: calls.append("off"))
    off.label("45.33.0.2")
    off.wait()
    assert "off" not in calls


def test_spoofed_reverse_dns_is_not_trusted():
    spoof = Resolver(reverse=lambda ip: ("lb.github.com", [], [ip]), forward=lambda n: (n, [], ["140.82.1.1"]))
    assert spoof("45.33.0.66") == "45.33.0.66"
    lab = Labeler(registry=REG, lookups=False)
    host = spoof("45.33.0.66")
    got = lab.label("45.33.0.66", None if host == "45.33.0.66" else host)
    assert got["company"] != "GitHub"


# --- engine ------------------------------------------------------------------
def make_engine(snaps, clock, **kw):
    it = iter(snaps)
    coll = Collector(reader=lambda: next(it), owners=lambda: {1: (10, "curl"), 2: (11, "python")},
                     labeler=Labeler(registry=REG, lookups=False).label)
    return Engine(coll, clock=clock, **kw)


def sock(dst, sent, recv=0, inode=1, dport=443):
    return {"family": 2, "state": TCP_ESTABLISHED, "src": "10.0.0.5", "sport": 40000 + inode, "dst": dst,
            "dport": dport, "uid": 0, "inode": inode, "bytes_sent": sent, "bytes_received": recv}


class Clock:
    t = 1000.0

    def __call__(self):
        return self.t


def test_engine_aggregates_by_destination_and_process():
    clk = Clock()
    eng = make_engine([[sock("104.18.0.9", 0)], [sock("104.18.0.9", 500, 100)], [sock("104.18.0.9", 900, 150)]], clk)
    for _ in range(3):
        eng.tick(clk.t)
        clk.t += 1
    st = eng.state(clk.t)
    (row,) = st["rows"]
    assert (row["name"], row["process"], row["total_sent"], row["total_received"]) == ("Acme Pay", "curl", 900, 150)
    assert row["confidence"] == "verified" and st["totals"] == {"sent": 900, "received": 150}


def test_unidentified_upload_alert_once_per_cooldown():
    clk = Clock()
    snaps = [[sock("45.33.0.7", 0)]] + [[sock("45.33.0.7", 300_000 * i)] for i in range(1, 5)]
    eng = make_engine(snaps, clk, unidentified_upload=256 * 1024)
    for _ in snaps:
        eng.tick(clk.t)
        clk.t += 1
    kinds = [a["kind"] for a in eng.state(clk.t)["alerts"]]
    assert kinds.count("UNIDENTIFIED_UPLOAD") == 1                  # cooldown stops repeats


def test_large_upload_alert_and_new_destination_after_warmup():
    clk = Clock()
    snaps = [[sock("104.18.0.9", 0)], [sock("104.18.0.9", 40 * 1024 * 1024)],
             [sock("104.18.0.9", 40 * 1024 * 1024), sock("45.33.0.8", 10, inode=2)]]
    eng = make_engine(snaps, clk)
    eng.tick(clk.t)
    clk.t += 40                                                      # past warm-up
    eng.tick(clk.t)
    clk.t += 1
    eng.tick(clk.t)
    got = {a["kind"] for a in eng.state(clk.t)["alerts"]}
    assert {"LARGE_UPLOAD", "NEW_DESTINATION"} <= got


def test_engine_writes_activity_log_and_survives_collector_failure(tmp_path):
    clk = Clock()
    it = iter([[sock("104.18.0.9", 0)], [sock("104.18.0.9", 50)]])
    coll = Collector(reader=lambda: next(it), owners=lambda: {}, labeler=Labeler(registry=REG, lookups=False).label)
    eng = Engine(coll, data_dir=tmp_path, clock=clk)
    eng.tick(clk.t)
    clk.t += 1
    eng.tick(clk.t)
    (line,) = (tmp_path / "activity.jsonl").read_text(encoding="utf-8").splitlines()
    assert json.loads(line)["bytes_sent"] == 50
    coll._reader = lambda: (_ for _ in ()).throw(OSError("netlink gone"))
    assert eng.tick(clk.t + 1) == [] and eng.errors == 1


# --- server security ---------------------------------------------------------
@pytest.fixture
def served(tmp_path):
    clk = Clock()
    eng = make_engine([[sock("104.18.0.9", 0)], [sock("104.18.0.9", 700, 5)]], clk)
    eng.tick(clk.t)
    clk.t += 1
    eng.tick(clk.t)
    token = load_or_create_token(tmp_path)
    srv = make_server(eng, token, 0, lambda: ["a notice"])
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1], token
    srv.shutdown()
    srv.server_close()


def req(port, path, headers=None, host=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.putrequest("GET", path, skip_host=True)
    c.putheader("Host", host or f"127.0.0.1:{port}")
    for k, v in (headers or {}).items():
        c.putheader(k, v)
    c.endheaders()
    r = c.getresponse()
    return r.status, dict(r.getheaders()), r.read()


def test_token_cookie_and_host_checks(served):
    port, token = served
    assert req(port, "/")[0] == 403 and req(port, "/api/state")[0] == 403
    status, hdrs, _ = req(port, f"/?t={token}")
    assert status == 302 and "HttpOnly" in hdrs["Set-Cookie"] and "SameSite=Strict" in hdrs["Set-Cookie"]
    cookie = {"Cookie": f"{COOKIE}={token}"}
    assert req(port, "/", cookie)[0] == 200
    assert req(port, "/api/state", {"Cookie": f"{COOKIE}=wrong"})[0] == 403
    assert req(port, "/?t=wrong")[0] == 403
    assert req(port, "/api/state", cookie, host="evil.example")[0] == 403         # DNS rebinding
    assert req(port, "/api/state", cookie, host=f"localhost:{port}")[0] == 200
    assert req(port, "/nope", cookie)[0] == 404


def test_state_payload_and_security_headers(served):
    port, token = served
    status, hdrs, body = req(port, "/api/state", {"Cookie": f"{COOKIE}={token}"})
    state = json.loads(body)
    assert status == 200 and state["notices"] == ["a notice"]
    assert state["rows"][0]["name"] == "Acme Pay" and state["rows"][0]["total_sent"] == 700
    assert "default-src 'none'" in hdrs["Content-Security-Policy"] and hdrs["Cache-Control"] == "no-store"
    c = http.client.HTTPConnection("127.0.0.1", port)
    c.request("POST", "/api/state")
    assert c.getresponse().status == 403            # unauthenticated writes are rejected


@pytest.mark.skipif(sys.platform == "win32", reason="Windows has no Unix file modes")
def test_token_is_stable_and_private(tmp_path):
    t1 = load_or_create_token(tmp_path)
    assert load_or_create_token(tmp_path) == t1 and len(t1) >= 32
    assert oct((tmp_path / "token").stat().st_mode & 0o777) == "0o600"


def test_dashboard_never_injects_untrusted_html():
    html = (__import__("pathlib").Path(cli.__file__).parent / "static" / "dashboard.html").read_text(encoding="utf-8")
    assert "innerHTML" not in html and "insertAdjacentHTML" not in html and "document.write" not in html


# --- launcher ----------------------------------------------------------------
def test_autostart_unit_and_notices():
    unit = cli.autostart_unit(8731, "/usr/bin/python3")
    assert "ExecStart=/usr/bin/python3 -m tol_app --no-browser --port 8731" in unit
    assert any("lookups are ON" in n for n in cli.notices(True)) and any("OFF" in n for n in cli.notices(False))


# --- macOS ---------------------------------------------------------------------
def test_notices_and_launchd_plist_per_platform():
    assert "UDP/QUIC" in " ".join(cli.notices(True, "linux"))
    assert "UDP/QUIC" not in " ".join(cli.notices(True, "darwin"))
    plist = cli.autostart_plist(8731, "/usr/local/bin/python3")
    assert "<string>/usr/local/bin/python3</string>" in plist and "RunAtLoad" in plist and "8731" in plist
    import plistlib
    assert plistlib.loads(plist.encode())["Label"] == "com.tol.agent"


# --- shareable-app behaviour -----------------------------------------------------
def test_quit_endpoint_requires_auth_header_and_host(tmp_path):
    clk = Clock()
    eng = make_engine([[sock("104.18.0.9", 0)]], clk)
    token = load_or_create_token(tmp_path)
    srv = make_server(eng, token, 0)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    port = srv.server_address[1]

    def post(path="/api/quit", cookie=True, header=True, host=None):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.putrequest("POST", path, skip_host=True)
        c.putheader("Host", host or f"127.0.0.1:{port}")
        if cookie:
            c.putheader("Cookie", f"{COOKIE}={token}")
        if header:
            c.putheader("X-TOL", "1")
        c.putheader("Content-Length", "0")
        c.endheaders()
        return c.getresponse().status

    assert post(cookie=False) == 403 and post(header=False) == 403 and post(host="evil.example") == 403
    assert t.is_alive()                                           # none of the above stopped it
    assert post() == 200
    t.join(timeout=5)
    assert not t.is_alive()                                       # authorised quit stops the server
    srv.server_close()


def test_already_running_detection(served):
    port, token = served
    assert cli.already_running(port, token) is True
    assert cli.already_running(port, "wrong-token") is False
    assert cli.already_running(1, token) is False                 # nothing listening


def test_finder_launch_argument_is_ignored(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli.sys, "platform", "freebsd")
    assert cli.main(["-psn_0_12345"]) == 2                        # parsed fine; stops at the platform gate


def test_lookups_are_off_by_default_and_nothing_leaves_the_machine():
    calls = []
    lab = Labeler(registry={}, fetch=lambda ip: calls.append(ip))      # library default
    assert lab.label("45.33.0.9")["confidence"] == "none"
    lab.wait()
    assert calls == []
    notes = " ".join(cli.notices(False))
    assert "OFF (default)" in notes and "--lookup" in notes
    assert cli.build_parser().parse_args([]).lookup is False            # CLI default: off
    assert cli.build_parser().parse_args(["--lookup"]).lookup is True
    assert cli.build_parser().parse_args(["--no-lookup"]).lookup is False   # old flag still accepted


# --- recording -------------------------------------------------------------------
def test_recording_writes_json_and_csv_with_only_the_recorded_window(tmp_path):
    clk = Clock()
    snaps = [[sock("104.18.0.9", 0)], [sock("104.18.0.9", 100)], [sock("104.18.0.9", 400, 20)],
             [sock("104.18.0.9", 900, 20)]]
    it = iter(snaps)
    coll = Collector(reader=lambda: next(it), owners=lambda: {1: (10, "curl")},
                     labeler=Labeler(registry=REG, lookups=False).label)
    eng = Engine(coll, data_dir=tmp_path, clock=clk)
    eng.tick(clk.t)
    clk.t += 1
    eng.tick(clk.t)                                    # before recording: must not appear
    assert eng.start_recording(clk.t) is True and eng.start_recording(clk.t) is False
    for _ in range(2):
        clk.t += 1
        eng.tick(clk.t)
    assert eng.recording_state()["active"] and eng.recording_state()["events"] >= 1
    out = eng.stop_recording(clk.t)
    report = json.loads(open(out["json"], encoding="utf-8").read())
    assert report["destinations"][0]["destination"] == "Acme Pay"
    assert report["totals"]["sent_bytes"] == 800        # 300 + 500, not the 100 before recording
    rows = open(out["csv"], encoding="utf-8").read().splitlines()
    assert rows[0].startswith("destination,process") and "Acme Pay" in rows[1]
    assert eng.stop_recording(clk.t) is None and not eng.recording_state()["active"]


def test_recording_endpoints_need_auth_and_download_only_last_recording(tmp_path):
    clk = Clock()
    eng = make_engine([[sock("104.18.0.9", 0)], [sock("104.18.0.9", 50)]], clk)
    eng.data_dir = tmp_path
    token = load_or_create_token(tmp_path)
    srv = make_server(eng, token, 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]

    def post(path, cookie=True):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.putrequest("POST", path, skip_host=True)
        c.putheader("Host", f"127.0.0.1:{port}")
        if cookie:
            c.putheader("Cookie", f"{COOKIE}={token}")
        c.putheader("X-TOL", "1")
        c.putheader("Content-Length", "0")
        c.endheaders()
        r = c.getresponse()
        return r.status, r.read()

    cookie = {"Cookie": f"{COOKIE}={token}"}
    assert post("/api/record/start", cookie=False)[0] == 403
    assert req(port, "/api/recording/download")[0] == 403
    assert req(port, "/api/recording/download", cookie)[0] == 404          # nothing recorded yet
    assert json.loads(post("/api/record/start")[1])["active"] is True
    eng.tick(clk.t)
    clk.t += 1
    eng.tick(clk.t)
    assert json.loads(post("/api/record/stop")[1])["active"] is False
    status, hdrs, body = req(port, "/api/recording/download?kind=csv", cookie)
    assert status == 200 and "attachment" in hdrs["Content-Disposition"] and b"Acme Pay" in body
    assert req(port, "/api/recording/download?kind=../../etc/passwd", cookie)[0] == 404
    assert json.loads(req(port, "/api/state", cookie)[2])["recording"]["last"]["events"] >= 1
    srv.shutdown()
    srv.server_close()


def test_recording_auto_stops_and_saves(tmp_path):
    clk = Clock()
    snaps = [[sock("104.18.0.9", n * 10)] for n in range(5)]
    it = iter(snaps)
    coll = Collector(reader=lambda: next(it), owners=lambda: {1: (10, "curl")},
                     labeler=Labeler(registry=REG, lookups=False).label)
    eng = Engine(coll, data_dir=tmp_path, clock=clk)
    eng.tick(clk.t)
    eng.start_recording(clk.t, minutes=1)
    clk.t += 10
    eng.tick(clk.t)
    assert eng.recording_state()["active"]
    clk.t += 60
    eng.tick(clk.t)
    assert not eng.recording_state()["active"] and eng.last_recording["json"]


# --- receipts ----------------------------------------------------------------------
from tol_app.receipts import Receipts, verify as verify_receipts

RDAP_RAW = json.dumps({**RDAP_GOOGLE, "handle": "NET-34-149-0-0-1", "country": "US",
                       "events": [{"eventAction": "registration", "eventDate": "2018-01-01T00:00:00Z"}]}).encode()


def make_receipts(tmp_path, fetch=lambda ip: (RDAP_RAW, "https://rdap.arin.net/registry/ip/" + ip), labeler=None):
    return Receipts(tmp_path, labeler=labeler, fetch=fetch, clock=lambda: 1_700_000_000,
                    reverse=lambda ip: ("host.example.net", [], [ip]),
                    forward=lambda n: (n, [], ["34.149.66.165"]))


def test_receipt_records_evidence_hash_and_chain(tmp_path):
    rc = make_receipts(tmp_path)
    r = rc.create("34.149.66.165")
    assert r["status"] == "ok" and r["rdap"]["registrant"] == "Google LLC" and r["rdap"]["cidrs"] == ["34.149.0.0/16"]
    import hashlib
    assert r["rdap"]["sha256"] == hashlib.sha256(RDAP_RAW).hexdigest() and r["rdap"]["raw"].encode() == RDAP_RAW
    assert r["reverse_dns"] == {"name": "host.example.net", "forward_confirmed": True, "addresses": ["34.149.66.165"]}
    assert r["queried_at_iso"] == "2023-11-14T22:13:20Z" and "not independently verified" in r["clock"]
    assert rc.create("34.149.66.165") is rc.items["34.149.66.165"]                 # no second lookup
    rc2 = Receipts(tmp_path, fetch=lambda ip: None)                                  # survives restart
    assert rc2.items["34.149.66.165"]["rdap"]["sha256"] == r["rdap"]["sha256"] and rc2.export()["chain_ok"]


def test_receipt_tampering_is_detected(tmp_path):
    rc = make_receipts(tmp_path)
    rc.create("34.149.66.165")
    rc.create("8.8.8.8")
    chain = [json.loads(line) for line in (tmp_path / "receipts.jsonl").read_text(encoding="utf-8").splitlines()]
    assert verify_receipts(chain)[0]
    chain[0]["rdap"]["registrant"] = "Someone Else"
    assert not verify_receipts(chain)[0]                                             # link to receipt 2 breaks
    chain = [json.loads(line) for line in (tmp_path / "receipts.jsonl").read_text(encoding="utf-8").splitlines()]
    chain[1]["rdap"]["raw"] = chain[1]["rdap"]["raw"].replace("GOOGLE", "XOOGLE")
    assert "does not match its hash" in verify_receipts(chain)[1]
    assert not verify_receipts(chain[1:])[0]                                         # deleting the first one


def test_receipt_refuses_local_addresses_and_teaches_the_labeler(tmp_path):
    lab = Labeler(registry={}, lookups=False)
    rc = make_receipts(tmp_path, labeler=lab)
    for ip in ("127.0.0.1", "192.168.1.5", "not-an-ip"):
        with pytest.raises(ValueError):
            rc.create(ip)
    assert lab.label("34.149.7.7")["confidence"] == "none"
    rc.create("34.149.66.165")
    got = lab.label("34.149.7.7")
    assert (got["company"], got["confidence"]) == ("Google LLC", "network-only")      # not presented as the vendor
    assert make_receipts(tmp_path / "x", fetch=lambda ip: None).create("8.8.4.4")["status"] == "no-record"


def test_receipt_endpoint_only_for_observed_public_ips(tmp_path):
    clk = Clock()
    eng = make_engine([[sock("45.33.0.8", 0)], [sock("45.33.0.8", 900)]], clk)
    eng.receipts = make_receipts(tmp_path)
    for _ in range(2):
        eng.tick(clk.t)
        clk.t += 1
    token = load_or_create_token(tmp_path)
    srv = make_server(eng, token, 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]

    def post(path, cookie=True, header=True):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.putrequest("POST", path, skip_host=True)
        c.putheader("Host", f"127.0.0.1:{port}")
        if cookie:
            c.putheader("Cookie", f"{COOKIE}={token}")
        if header:
            c.putheader("X-TOL", "1")
        c.putheader("Content-Length", "0")
        c.endheaders()
        r = c.getresponse()
        return r.status, r.read()

    assert post("/api/receipt?ip=45.33.0.8", cookie=False)[0] == 403
    assert post("/api/receipt?ip=45.33.0.8", header=False)[0] == 403
    assert post("/api/receipt?ip=8.8.8.8")[0] == 400                       # never talked to it: no open lookup proxy
    assert post("/api/receipt?ip=192.168.1.1")[0] == 400
    status, body = post("/api/receipt?ip=45.33.0.8")
    got = json.loads(body)
    assert status == 200 and got["rdap"]["registrant"] == "Google LLC" and got["activity"]["bytes_sent"] == 900
    cookie = {"Cookie": f"{COOKIE}={token}"}
    assert json.loads(req(port, "/api/state", cookie)[2])["receipts"]["45.33.0.8"]["owner"] == "Google LLC"
    status, hdrs, body = req(port, "/api/receipts.json", cookie)
    assert status == 200 and json.loads(body)["chain_ok"] and "attachment" in hdrs["Content-Disposition"]
    assert req(port, "/api/receipts.json")[0] == 403
    srv.shutdown()
    srv.server_close()


# --- evidence package ----------------------------------------------------------------
def _record_session(tmp_path):
    clk = Clock()
    eng = make_engine([[sock("45.33.0.8", 0)], [sock("45.33.0.8", 700, 50)], [sock("45.33.0.8", 900, 60)]], clk)
    eng.data_dir = tmp_path
    eng.receipts = make_receipts(tmp_path)
    eng.tick(clk.t)
    eng.start_recording(clk.t)
    for _ in range(2):
        clk.t += 1
        eng.tick(clk.t)
    eng.receipts.create("45.33.0.8")
    eng.stop_recording(clk.t)
    return eng


def test_evidence_package_contents_and_standalone_verifier(tmp_path):
    import subprocess
    import sys
    eng = _record_session(tmp_path)
    zip_path = eng.build_evidence()
    folder = tmp_path / "evidence" / __import__("pathlib").Path(eng.last_recording["package_folder"]).name
    for rel in ("README.md", "verify.py", "MANIFEST.sha256", "device/device-info.json", "network-flows/flow-summary.csv",
                "network-flows/events.chain.jsonl", "network-flows/flow-root-hash.txt",
                "destination-verification/receipts.json", "destination-verification/rdap-45.33.0.8.json"):
        assert (folder / rel).is_file(), rel
    assert zip_path.endswith(".zip") and "does NOT prove" in (folder / "README.md").read_text(encoding="utf-8")
    run = lambda: subprocess.run([sys.executable, str(folder / "verify.py"), str(folder)], capture_output=True, text=True)
    ok = run()
    assert ok.returncode == 0 and "ALL CHECKS PASSED" in ok.stdout, ok.stdout
    # change one recorded event: both the manifest and the chain must catch it
    ev = folder / "network-flows" / "events.chain.jsonl"
    ev.write_text(ev.read_text(encoding="utf-8").replace('"bytes_sent": 200', '"bytes_sent": 999'), encoding="utf-8")
    bad = run()
    assert bad.returncode == 1 and "CHANGED: network-flows/events.chain.jsonl" in bad.stdout
    # an extra file slipped into the package is also reported
    (folder / "network-flows" / "events.chain.jsonl").write_text(ev.read_text(encoding="utf-8"), encoding="utf-8")
    (folder / "note.txt").write_text("added later", encoding="utf-8")
    assert "extra file not in manifest" in run().stdout


def test_evidence_endpoint_and_download(tmp_path):
    eng = _record_session(tmp_path)
    token = load_or_create_token(tmp_path)
    srv = make_server(eng, token, 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    cookie = {"Cookie": f"{COOKIE}={token}"}
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.putrequest("POST", "/api/evidence", skip_host=True)
    c.putheader("Host", f"127.0.0.1:{port}")
    c.putheader("Cookie", f"{COOKIE}={token}")
    c.putheader("X-TOL", "1")
    c.putheader("Content-Length", "0")
    c.endheaders()
    assert c.getresponse().status == 200
    status, hdrs, body = req(port, "/api/recording/download?kind=zip", cookie)
    assert status == 200 and hdrs["Content-Type"] == "application/zip" and body[:2] == b"PK"
    srv.shutdown()
    srv.server_close()


def test_tol_app_needs_only_the_standard_library_and_its_chain_matches_the_verifiers_copy():
    """tol_app must stay free of outside libraries (one of them once crashed the packaged Intel app), and the chain rules in
    tol_app must agree with the copy that ships inside every evidence package."""
    import ast
    import pathlib
    import sys
    from tol_app import chainhash, evidence_verify
    for f in pathlib.Path(cli.__file__).parent.glob("*.py"):
        for node in ast.walk(ast.parse(f.read_text(encoding="utf-8"))):
            mods = ([a.name for a in node.names] if isinstance(node, ast.Import)
                    else [node.module or ""] if isinstance(node, ast.ImportFrom) and node.level == 0 else [])
            for mod in mods:
                top = mod.split(".")[0]
                assert top in sys.stdlib_module_names or top.startswith("tol") or top == "certifi", f"{f.name} imports {top}"   # certifi: optional, inside a try
    c = chainhash.HashChain()
    for body in ({"x": 1, "y": "é"}, {"z": [None, True, {"k": "v"}]}):
        c.append(body)
    assert c.entries[-1]["previous_hash"] == "d8ebd4492e1dcf7ffd0c61ac08ed5110676c727eb92ad4d18dfd095b3c3ab61f"
    assert c.root() == "0f049377f7d817e277e4d9c0576890c1c91a73ce3b4f7090faf4931fd751ac3f"            # a fixed known answer
    assert evidence_verify.entry_hash(c.entries[-1]) == c.root()


# --- proof in the window, recording as a log of it ----------------------------------
def test_block_receipt_covers_other_addresses_and_flows_into_recording(tmp_path):
    from tol_app.receipts import attach
    clk = Clock()
    snaps = [[sock("34.149.66.165", 0), sock("34.149.7.7", 0, inode=2), sock("45.33.0.8", 0, inode=3)]] + \
            [[sock("34.149.66.165", 100, inode=1), sock("34.149.7.7", 50, inode=2), sock("45.33.0.8", 9, inode=3)]] * 2
    it = iter(snaps)
    lab = Labeler(registry={}, lookups=False)
    coll = Collector(reader=lambda: next(it), owners=lambda: {1: (10, "curl"), 2: (11, "python"), 3: (12, "ruby")},
                     labeler=lab.label)
    eng = Engine(coll, data_dir=tmp_path, clock=clk)
    eng.receipts = make_receipts(tmp_path, labeler=lab)
    eng.tick(clk.t)
    eng.start_recording(clk.t)
    clk.t += 1
    eng.tick(clk.t)
    eng.receipts.create("34.149.66.165")                      # one lookup...
    assert eng.receipts.find("34.149.7.7")["ip"] == "34.149.66.165"   # ...covers its whole /16
    assert eng.receipts.find("45.33.0.8") is None
    eng.stop_recording(clk.t)
    rep = json.loads(open(eng.last_recording["json"], encoding="utf-8").read())
    by = {d["endpoints"][0]: d for d in rep["destinations"]}
    assert by["34.149.7.7:443"]["registered_holder"] == "Google LLC" and by["34.149.7.7:443"]["receipt_seq"] == 0
    assert by["34.149.66.165:443"]["network_block"] == "34.149.0.0/16" and len(by["34.149.66.165:443"]["record_sha256"]) == 64
    assert by["45.33.0.8:443"]["registered_holder"] is None
    assert [r["ip"] for r in rep["receipts"]] == ["34.149.66.165"]
    header, *rows = open(eng.last_recording["csv"], encoding="utf-8").read().splitlines()
    assert "registered_holder" in header and sum("Google LLC" in r for r in rows) == 2
    # identified AFTER stop but before packaging: the package picks it up, the saved recording is untouched
    eng.receipts.create("45.33.0.8")
    eng.build_evidence()
    pkg = __import__("pathlib").Path(eng.last_recording["package_folder"])
    in_pkg = json.loads((pkg / "network-flows" / "recording.json").read_text(encoding="utf-8"))
    assert {d["endpoints"][0]: d["registered_holder"] for d in in_pkg["destinations"]}["45.33.0.8:443"] == "Google LLC"
    assert json.loads(open(eng.last_recording["json"], encoding="utf-8").read())["destinations"][0].get("registered_holder") is not None
    assert {r["ip"] for r in in_pkg["receipts"]} == {"34.149.66.165", "45.33.0.8"}


def test_state_rows_point_at_their_covering_receipt(tmp_path):
    clk = Clock()
    eng = make_engine([[sock("34.149.7.7", 0)], [sock("34.149.7.7", 10)]], clk)
    eng.receipts = make_receipts(tmp_path)
    eng.receipts.create("34.149.66.165")
    for _ in range(2):
        eng.tick(clk.t)
        clk.t += 1
    token = load_or_create_token(tmp_path)
    srv = make_server(eng, token, 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    state = json.loads(req(port, "/api/state", {"Cookie": f"{COOKIE}={token}"})[2])
    assert state["rows"][0]["receipt_ip"] == "34.149.66.165" and "34.149.66.165" in state["receipts"]
    srv.shutdown()
    srv.server_close()


# --- auto-identify -------------------------------------------------------------------
from tol_app.autoid import AutoIdentifier
from tol_app.settings import Settings


def _auto_setup(tmp_path, fetch=None, per_hour=120, snaps=None):
    clk = Clock()
    snaps = snaps or [[sock("34.149.66.165", 0), sock("34.149.7.7", 0, inode=2), sock("45.33.0.8", 0, inode=3),
                       sock("104.18.0.9", 0, inode=4), sock("192.168.1.9", 0, inode=5)]] + \
        [[sock("34.149.66.165", 900), sock("34.149.7.7", 300, inode=2), sock("45.33.0.8", 50, inode=3),
          sock("104.18.0.9", 10, inode=4), sock("192.168.1.9", 5, inode=5)]] * 2
    it = iter(snaps)
    lab = Labeler(registry=REG, lookups=False)
    coll = Collector(reader=lambda: next(it), owners=lambda: {i: (i, f"p{i}") for i in range(1, 8)}, labeler=lab.label)
    eng = Engine(coll, clock=clk)
    calls = []

    def fake_fetch(ip):
        calls.append(ip)
        return (RDAP_RAW, "https://rdap.example/ip/" + ip) if ip.startswith("34.149") else None

    eng.receipts = make_receipts(tmp_path, fetch=fetch or fake_fetch, labeler=lab)
    for _ in range(3):
        eng.tick(clk.t)
        clk.t += 1
    auto = AutoIdentifier(eng, eng.receipts, Settings(tmp_path), clock=clk, per_hour=per_hour)
    return eng, auto, calls, clk


def test_auto_identify_is_off_until_consent_and_does_nothing_when_off(tmp_path):
    eng, auto, calls, clk = _auto_setup(tmp_path)
    assert auto.enabled is False and auto.step() is None and calls == []
    with pytest.raises(PermissionError):
        auto.enable(consent=False)
    assert auto.enabled is False
    auto.enable(consent=True)
    assert auto.enabled and Settings(tmp_path).get("auto_identify") is True            # survives restart
    assert Settings(tmp_path).get("auto_identify_consented_at") == int(clk.t)
    auto.disable()
    assert Settings(tmp_path).get("auto_identify") is False


def test_auto_identify_one_lookup_per_block_skips_local_and_verified(tmp_path):
    eng, auto, calls, clk = _auto_setup(tmp_path)
    auto.enable(consent=True)
    assert auto.pending() == ["34.149.66.165", "34.149.7.7", "45.33.0.8"]       # no local 192.168.x, no verified Acme
    done = []
    while (ip := auto.step()) is not None:
        done.append(ip)
    assert done == ["34.149.66.165", "45.33.0.8"]        # 34.149.7.7 was covered by the first receipt's /16
    assert calls == done and auto.total == 2 and auto.pending() == []
    assert auto.step() is None and len(calls) == 2        # nothing left: no repeat lookups


def test_auto_identify_rate_limit_and_failure_backoff(tmp_path):
    eng, auto, calls, clk = _auto_setup(tmp_path, per_hour=1)
    auto.enable(consent=True)
    assert auto.step() == "34.149.66.165"
    assert auto.step() is None and auto.status()["rate_limited"] is True             # hourly cap reached
    clk.t += 3601
    assert auto.step() == "45.33.0.8" and auto.status()["rate_limited"] is True
    boom = []

    def failing(ip):
        boom.append(ip)
        raise OSError("network down")

    eng2, auto2, _, clk2 = _auto_setup(tmp_path / "b", fetch=failing)
    auto2.enable(consent=True)
    assert auto2.step() is None and auto2.last_error and len(boom) == 3             # each tried once, none looped
    assert auto2.step() is None and len(boom) == 3                                   # backed off, not hammered
    clk2.t += 601
    auto2.step()
    assert len(boom) > 3                                                              # retried after the backoff


def test_auto_identify_endpoint_needs_auth_header_and_consent(tmp_path):
    eng, auto, calls, clk = _auto_setup(tmp_path)
    token = load_or_create_token(tmp_path)
    srv = make_server(eng, token, 0, auto=auto)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]

    def post(path, cookie=True, header=True):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.putrequest("POST", path, skip_host=True)
        c.putheader("Host", f"127.0.0.1:{port}")
        if cookie:
            c.putheader("Cookie", f"{COOKIE}={token}")
        if header:
            c.putheader("X-TOL", "1")
        c.putheader("Content-Length", "0")
        c.endheaders()
        r = c.getresponse()
        return r.status, r.read()

    assert post("/api/auto-identify?enabled=1&consent=1", cookie=False)[0] == 403
    assert post("/api/auto-identify?enabled=1&consent=1", header=False)[0] == 403
    assert post("/api/auto-identify?enabled=1")[0] == 400 and auto.enabled is False       # no consent, no enable
    status, body = post("/api/auto-identify?enabled=1&consent=1")
    assert status == 200 and json.loads(body)["enabled"] is True and auto.enabled
    state = json.loads(req(port, "/api/state", {"Cookie": f"{COOKIE}={token}"})[2])
    assert state["auto_identify"]["enabled"] is True and state["auto_identify"]["waiting"] == 3
    assert json.loads(post("/api/auto-identify?enabled=0")[1])["enabled"] is False
    srv.shutdown()
    srv.server_close()


def test_auto_identify_also_covers_likely_rows_but_not_registry_verified(tmp_path):
    clk = Clock()
    snaps = [[sock("140.82.1.1", 0), sock("104.18.0.9", 0, inode=2)]] + [[sock("140.82.1.1", 40), sock("104.18.0.9", 40, inode=2)]] * 2
    it = iter(snaps)
    lab = Labeler(registry=REG, lookups=False)
    coll = Collector(reader=lambda: next(it), owners=lambda: {1: (1, "git"), 2: (2, "pay")},
                     resolver=lambda ip: "lb-1.github.com" if ip == "140.82.1.1" else ip, labeler=lab.label)
    eng = Engine(coll, clock=clk)
    eng.receipts = make_receipts(tmp_path, labeler=lab)
    for _ in range(3):
        eng.tick(clk.t)
        clk.t += 1
    rows = {r["name"]: r["confidence"] for r in eng.state(clk.t)["rows"]}
    assert rows == {"GitHub": "likely", "Acme Pay": "verified"}
    assert eng.unidentified_ips() == ["140.82.1.1"]            # GitHub-by-hostname still needs registry proof; Acme is the user's own rule


# --- lookup failures are not evidence ---------------------------------------------------
import urllib.error
from tol_app import netutil
from tol_app.netutil import LookupFailed


def test_rdap_get_reports_why_and_treats_only_404_as_no_record(monkeypatch):
    def boom(req, timeout=None, context=None):
        raise urllib.error.URLError("certificate verify failed")
    monkeypatch.setattr(netutil.urllib.request, "urlopen", boom)
    with pytest.raises(LookupFailed, match="certificate verify failed"):
        netutil.rdap_get("8.8.8.8")

    def not_found(req, timeout=None, context=None):
        raise urllib.error.HTTPError(req.full_url, 404, "nf", {}, None)
    monkeypatch.setattr(netutil.urllib.request, "urlopen", not_found)
    assert netutil.rdap_get("8.8.8.8") is None                          # the registry answered: no record

    def server_error(req, timeout=None, context=None):
        raise urllib.error.HTTPError(req.full_url, 503, "busy", {}, None)
    monkeypatch.setattr(netutil.urllib.request, "urlopen", server_error)
    with pytest.raises(LookupFailed, match="HTTP 503"):
        netutil.rdap_get("8.8.8.8")


def test_failed_lookup_saves_nothing_and_is_retried_and_shown(tmp_path):
    calls = []

    def flaky(ip):
        calls.append(ip)
        if len(calls) <= 3:
            raise LookupFailed("URLError: certificate verify failed")
        return (RDAP_RAW, "https://rdap.example/ip/" + ip)

    eng, auto, _, clk = _auto_setup(tmp_path, fetch=flaky)
    auto.enable(consent=True)
    while auto.step() is not None:
        pass
    assert eng.receipts.chain == [] and not (tmp_path / "receipts.jsonl").exists()   # nothing filed as evidence
    st = auto.status()
    assert st["failing"] == 3 and "certificate verify failed" in st["last_error"] and st["looked_up"] == 0
    clk.t += 601                                                                       # backoff over: retried, now works
    assert auto.step() == "34.149.66.165" and eng.receipts.find("34.149.7.7") is not None


def test_early_build_no_record_receipts_are_looked_up_again(tmp_path):
    rc = make_receipts(tmp_path)
    rc.create("34.149.66.165")
    old = json.loads((tmp_path / "receipts.jsonl").read_text(encoding="utf-8").splitlines()[0])
    old.update(ip="45.33.0.8", status="no-record", seq=1, previous_hash=__import__("tol_app.chainhash", fromlist=["x"]).entry_hash(old))
    old["rdap"] = {"source_url": None, "sha256": None}                 # what early builds wrote for a failed lookup
    with open(tmp_path / "receipts.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(old, sort_keys=True) + "\n")
    rc2 = make_receipts(tmp_path)
    assert "45.33.0.8" not in rc2.items and len(rc2.chain) == 2          # kept in the chain, but not treated as an answer
    again = rc2.create("45.33.0.8")
    assert again["seq"] == 2 and rc2.items["45.33.0.8"] is again


def test_receipt_endpoint_reports_registry_failure_as_502(tmp_path):
    clk = Clock()
    eng = make_engine([[sock("45.33.0.8", 0)], [sock("45.33.0.8", 9)]], clk)

    def fail(ip):
        raise LookupFailed("URLError: certificate verify failed")

    eng.receipts = make_receipts(tmp_path, fetch=fail)
    for _ in range(2):
        eng.tick(clk.t)
        clk.t += 1
    token = load_or_create_token(tmp_path)
    srv = make_server(eng, token, 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.putrequest("POST", "/api/receipt?ip=45.33.0.8", skip_host=True)
    for k, v in (("Host", f"127.0.0.1:{port}"), ("Cookie", f"{COOKIE}={token}"), ("X-TOL", "1"), ("Content-Length", "0")):
        c.putheader(k, v)
    c.endheaders()
    r = c.getresponse()
    assert r.status == 502 and "certificate verify failed" in json.loads(r.read())["error"]
    assert eng.receipts.chain == []
    srv.shutdown()
    srv.server_close()


def test_ssl_context_never_disables_verification():
    ctx = netutil.ssl_context()
    import ssl
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname is True


def test_dashboard_goes_compact_by_itself_when_the_window_is_narrow():
    """A narrow window must switch to the compact layout without pressing anything (guards the small-window fix)."""
    html = (__import__("pathlib").Path(cli.__file__).parent / "static" / "dashboard.html").read_text(encoding="utf-8")
    assert 'matchMedia("(max-width: 760px)")' in html            # the window decides
    assert 'classList.toggle("narrow"' in html and "body.narrow #mini" in html   # no toggle to get wrong when narrow
    assert "body.compact td.n" in html and "white-space: normal" in html          # numbers wrap instead of being cut off
    assert "width=360,height=600" in html                         # pop-out opens small


# --- trusted timestamp in the evidence package ------------------------------------------
import subprocess as _sp
import sys as _sys
import pathlib as _pl

_TESTS = _pl.Path(__file__).parent
if str(_TESTS) not in _sys.path:
    _sys.path.insert(0, str(_TESTS))
from tsa_fixture import LocalTSA, openssl_has_ts


def _verify(folder, *extra):
    return _sp.run([_sys.executable, str(_pl.Path(folder) / "verify.py"), str(folder), *extra], capture_output=True, text=True)


@pytest.mark.skipif(not openssl_has_ts(), reason="OpenSSL with `ts` support is not available")
def test_timestamp_end_to_end_and_tamper_detection(tmp_path):
    tsa = LocalTSA(tmp_path / "tsa")
    try:
        eng = _record_session(tmp_path / "dev")
        eng.settings = type("S", (), {"get": lambda self, k: tsa.url if k == "tsa_url" else None})()
        eng.build_evidence()
        folder = _pl.Path(eng.last_recording["package_folder"])
        before = _verify(folder)
        assert before.returncode == 0 and "No trusted timestamp" in before.stdout            # honest about the clock
        done = eng.timestamp_evidence()
        assert done["tsa_url"] == tsa.url and done["gen_time_utc"].endswith("Z")
        assert eng.recording_state()["last"]["timestamp"]["gen_time_utc"] == done["gen_time_utc"]
        for f in ("manifest.tsq", "manifest.tsr", "tsa-certs.pem", "timestamp.json", "README.txt"):
            assert (folder / "timestamp" / f).is_file(), f
        assert (folder / "tol_timestamp.py").is_file()
        # the authority was sent a fingerprint, never any of the data
        sent = tsa.requests[-1][1]
        assert len(sent) < 100 and b"Acme" not in sent and b"curl" not in sent
        # the zip a user downloads contains the proof
        import zipfile
        assert any(n.endswith("timestamp/manifest.tsr") for n in zipfile.ZipFile(eng.last_recording["zip"]).namelist())
        ok = _verify(folder, "--cafile", str(tsa.ca))
        assert ok.returncode == 0, ok.stdout
        assert "Trusted timestamp verified" in ok.stdout and "ALL CHECKS PASSED" in ok.stdout
        # no CA known to this machine for our throwaway authority: signature is honestly reported as NOT verified
        unknown = _verify(folder, "--cafile", "/nonexistent.pem")
        assert "FAIL" in unknown.stdout or "NOT VERIFIED" in unknown.stdout or "did NOT verify" in unknown.stdout
        # an attacker edits a recorded sample AND regenerates the manifest so the file hashes agree again ...
        ev = folder / "network-flows" / "events.chain.jsonl"
        ev.write_text(ev.read_text(encoding="utf-8").replace('"bytes_sent": 700', '"bytes_sent": 7'), encoding="utf-8")
        import hashlib
        lines = []
        for p in sorted(x for x in folder.rglob("*") if x.is_file() and x.name != "MANIFEST.sha256" and "timestamp" not in x.relative_to(folder).parts[:1]):
            lines.append(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(folder).as_posix()}\n")
        (folder / "MANIFEST.sha256").write_text("".join(lines), encoding="utf-8")
        bad = _verify(folder, "--cafile", str(tsa.ca))
        # ... the timestamp catches it: the signed fingerprint belongs to the ORIGINAL manifest
        assert bad.returncode == 1 and "NOT for this package's MANIFEST.sha256" in bad.stdout
    finally:
        tsa.close()


def _verify_without_openssl(folder, *extra):
    env = dict(__import__("os").environ, PATH="")            # no openssl on the path: only TOL's own checker can decide
    return _sp.run([_sys.executable, str(_pl.Path(folder) / "verify.py"), str(folder), *extra], capture_output=True, text=True, env=env)


@pytest.mark.skipif(not openssl_has_ts(), reason="needs the openssl command to MAKE a throw-away authority")
def test_the_packages_own_checker_verifies_the_signature_with_no_openssl_and_catches_a_forgery(tmp_path):
    tsa = LocalTSA(tmp_path / "tsa")
    try:
        eng = _record_session(tmp_path / "dev")
        eng.settings = type("S", (), {"get": lambda self, k: tsa.url if k == "tsa_url" else None})()
        eng.build_evidence()
        eng.timestamp_evidence()
        folder = _pl.Path(eng.last_recording["package_folder"])
        ok = _verify_without_openssl(folder, "--cafile", str(tsa.ca))
        assert ok.returncode == 0, ok.stdout + ok.stderr
        again = _verify_without_openssl(folder, "--cafile", str(tsa.ca))                  # running it twice must not change the answer
        assert again.returncode == 0 and not list(folder.rglob("__pycache__")), again.stdout
        assert "verified by TOL's own checker" in ok.stdout and "chaining to Test Root CA" in ok.stdout
        # without a root it trusts, it says NOT VERIFIED (and does not pass it off as checked)
        unknown = _verify_without_openssl(folder, "--cafile", str(tmp_path / "missing.pem"))
        assert "SIGNATURE NOT VERIFIED" in unknown.stdout and "verified by TOL's own checker" not in unknown.stdout
        # a changed byte inside the signature is rejected by the built-in checker alone
        tsr = folder / "timestamp" / "manifest.tsr"
        raw = bytearray(tsr.read_bytes())
        raw[-20] ^= 0xFF
        tsr.write_bytes(bytes(raw))
        bad = _verify_without_openssl(folder, "--cafile", str(tsa.ca))
        assert bad.returncode == 1 and "did NOT verify" in bad.stdout
    finally:
        tsa.close()


@pytest.mark.skipif(not openssl_has_ts(), reason="OpenSSL with `ts` support is not available")
def test_forged_token_is_not_accepted_by_the_signature_check(tmp_path):
    tsa = LocalTSA(tmp_path / "tsa")
    try:
        eng = _record_session(tmp_path / "dev")
        eng.settings = type("S", (), {"get": lambda self, k: tsa.url if k == "tsa_url" else None})()
        eng.build_evidence()
        eng.timestamp_evidence()
        folder = _pl.Path(eng.last_recording["package_folder"])
        tsr = folder / "timestamp" / "manifest.tsr"
        raw = bytearray(tsr.read_bytes())
        raw[-20] ^= 0xFF                                    # flip a byte inside the signature
        tsr.write_bytes(bytes(raw))
        out = _verify(folder, "--cafile", str(tsa.ca))
        assert out.returncode == 1 and "FAIL" in out.stdout and "did NOT verify" in out.stdout
    finally:
        tsa.close()


@pytest.mark.skipif(not openssl_has_ts(), reason="OpenSSL with `ts` support is not available")
def test_timestamp_endpoint_needs_consent_a_package_and_reports_failures(tmp_path):
    tsa = LocalTSA(tmp_path / "tsa")
    try:
        eng = _record_session(tmp_path / "dev")
        eng.settings = type("S", (), {"get": lambda self, k: tsa.url if k == "tsa_url" else None})()
        token = load_or_create_token(tmp_path / "dev")
        srv = make_server(eng, token, 0)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        port = srv.server_address[1]

        def post(path, cookie=True):
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
            c.putrequest("POST", path, skip_host=True)
            for k, v in (("Host", f"127.0.0.1:{port}"), ("X-TOL", "1"), ("Content-Length", "0")) + ((("Cookie", f"{COOKIE}={token}"),) if cookie else ()):
                c.putheader(k, v)
            c.endheaders()
            r = c.getresponse()
            raw = r.read()
            try:
                return r.status, json.loads(raw or b"{}")
            except ValueError:                                                  # e.g. the plain-text "forbidden"
                return r.status, {"text": raw.decode()}

        assert post("/api/evidence/timestamp?consent=1", cookie=False)[0] == 403
        assert post("/api/evidence/timestamp")[0] == 400                        # no consent: nothing is sent
        assert tsa.requests == []
        assert post("/api/evidence/timestamp?consent=1")[0] == 400              # no package yet
        eng.build_evidence()
        tsa.mode = "garbage"
        status, body = post("/api/evidence/timestamp?consent=1")
        assert status == 502 and "could not be read" in body["error"] and "timestamp" not in (eng.last_recording or {})
        assert not (_pl.Path(eng.last_recording["package_folder"]) / "timestamp").exists()   # failure changed nothing
        tsa.mode = "ok"
        status, body = post("/api/evidence/timestamp?consent=1")
        assert status == 200 and body["last"]["timestamp"]["tsa_url"] == tsa.url and body["tsa_url"] == tsa.url
        srv.shutdown()
        srv.server_close()
    finally:
        tsa.close()


# --- small window started by TOL itself ----------------------------------------------------
from tol_app import minilaunch


def test_mini_command_is_explicit_and_uses_a_throwaway_profile():
    cmd = minilaunch.build_command("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                                   "http://127.0.0.1:8731/?t=ONCE&view=compact", "/home/u/.tol/mini-browser", 1500, 40)
    assert cmd[1] == "--app=http://127.0.0.1:8731/?t=ONCE&view=compact" and "--window-size=360,600" in cmd
    assert "--window-position=1500,40" in cmd and "--user-data-dir=/home/u/.tol/mini-browser" in cmd
    assert "--no-first-run" in cmd and "--no-default-browser-check" in cmd
    for bad in ((-1, 40), (10, "40; rm -rf /"), (10**9, 1)):
        with pytest.raises(ValueError):
            minilaunch.build_command("chrome", "http://127.0.0.1:1/", "/p", *bad)


def test_browser_discovery_only_finds_installed_chromium_family_browsers():
    chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    assert minilaunch.find_browser("darwin", exists=lambda p: p == chrome) == chrome
    assert minilaunch.find_browser("darwin", exists=lambda p: False) is None            # Safari-only Mac: fall back
    assert minilaunch.find_browser("linux", which=lambda n: "/usr/bin/chromium" if n == "chromium" else None) == "/usr/bin/chromium"
    assert minilaunch.find_browser("win32", exists=lambda p: False) is None


def test_launcher_starts_one_window_and_never_raises(tmp_path):
    started = []

    class Proc:
        def __init__(self, cmd, **kw):
            started.append((cmd, kw))

        def poll(self):
            return None                                           # still running

    ml = minilaunch.MiniLauncher(tmp_path, find=lambda: "/x/Google Chrome", popen=Proc, platform="linux")
    first = ml.launch("http://127.0.0.1:8731/?t=a&view=compact", 1500, 40)
    assert first == {"browser": "Google Chrome", "already_open": False} and (tmp_path / "mini-browser").is_dir()
    assert started[0][1].get("start_new_session") is True               # detached from TOL
    second = ml.launch("http://127.0.0.1:8731/?t=b&view=compact", 1500, 40)
    assert second["already_open"] is True and len(started) == 1       # no second browser process
    assert minilaunch.MiniLauncher(tmp_path, find=lambda: None).launch("http://127.0.0.1:1/", 0, 0) is None
    def boom(*a, **k):
        raise OSError("cannot execute")
    assert minilaunch.MiniLauncher(tmp_path, find=lambda: "/x/c", popen=boom).launch("http://127.0.0.1:1/", 0, 0) is None


def test_popout_endpoint_hands_out_a_one_time_code_not_the_real_token(tmp_path):
    clk = Clock()
    eng = make_engine([[sock("45.33.0.8", 0)]], clk)
    token = load_or_create_token(tmp_path)
    seen = []

    def fake_launch(url, x, y):
        seen.append((url, x, y))
        return {"browser": "Google Chrome", "already_open": False}

    srv = make_server(eng, token, 0, launch_mini=fake_launch)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]

    def post(path, cookie=True, header=True):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.putrequest("POST", path, skip_host=True)
        for k, v in (("Host", f"127.0.0.1:{port}"), ("Content-Length", "0")) + ((("Cookie", f"{COOKIE}={token}"),) if cookie else ()) + ((("X-TOL", "1"),) if header else ()):
            c.putheader(k, v)
        c.endheaders()
        r = c.getresponse()
        raw = r.read()
        return r.status, (json.loads(raw) if raw.startswith(b"{") else raw)

    assert post("/api/popout?x=1500&y=40", cookie=False)[0] == 403 and post("/api/popout", header=False)[0] == 403
    assert seen == []                                                          # nothing starts without auth
    status, body = post("/api/popout?x=1500&y=40")
    assert status == 200 and body["launched"] is True
    url, x, y = seen[0]
    code = url.split("?t=")[1].split("&")[0]
    assert (x, y) == (1500, 40) and "view=compact" in url and code != token and token not in url   # token never on a command line
    # the code logs in exactly once
    assert req(port, f"/?t={code}")[0] == 302
    assert req(port, f"/?t={code}")[0] == 403
    # clamping / garbage input
    post("/api/popout?x=99999999&y=abc")
    assert seen[1][1:] == (10000, 40)
    srv.shutdown()
    srv.server_close()


def test_one_time_codes_expire(tmp_path, monkeypatch):
    from tol_app import server as srvmod
    clk = Clock()
    eng = make_engine([[sock("45.33.0.8", 0)]], clk)
    token = load_or_create_token(tmp_path)
    got = []
    srv = make_server(eng, token, 0, launch_mini=lambda url, x, y: got.append(url) or {"browser": "c", "already_open": False})
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.putrequest("POST", "/api/popout", skip_host=True)
    for k, v in (("Host", f"127.0.0.1:{port}"), ("Content-Length", "0"), ("Cookie", f"{COOKIE}={token}"), ("X-TOL", "1")):
        c.putheader(k, v)
    c.endheaders()
    c.getresponse().read()
    code = got[0].split("?t=")[1].split("&")[0]
    real = srvmod.time.time
    monkeypatch.setattr(srvmod.time, "time", lambda: real() + srvmod.ONE_TIME_TTL + 5)
    assert req(port, f"/?t={code}")[0] == 403                                  # too late
    srv.shutdown()
    srv.server_close()


def test_on_a_mac_the_browser_is_started_through_open_so_it_is_its_own_app(tmp_path):
    chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    cmd = minilaunch.mac_launch_command([chrome, "--app=http://127.0.0.1:1/", "--window-size=360,600"])
    assert cmd[:5] == ["open", "-n", "-a", "/Applications/Google Chrome.app", "--args"]
    assert cmd[5:] == ["--app=http://127.0.0.1:1/", "--window-size=360,600"]
    assert minilaunch.mac_launch_command(["/usr/bin/chromium", "--x"]) == ["/usr/bin/chromium", "--x"]

    started = []

    class Proc:
        def __init__(self, c, **kw):
            started.append(c)

    ran = []

    def nothing_running(c, **kw):
        ran.append(c)
        return types.SimpleNamespace(returncode=1)            # pgrep: no match

    ml = minilaunch.MiniLauncher(tmp_path, find=lambda: chrome, popen=Proc, platform="darwin",
                                 run=nothing_running, sleep=lambda s: None)
    assert ml.launch("http://127.0.0.1:1/?t=a", 10, 40) == {"browser": "Google Chrome", "already_open": False}
    assert [c[0] for c in ran] == ["pgrep"] and "mini-browser" in ran[0][-1]
    assert started[0][0] == "open" and any(a.startswith("--user-data-dir=") for a in started[0])
    # the Mac browser keeps running after its window is closed, so the launcher never refuses; the server decides
    assert ml.launch("http://127.0.0.1:1/?t=b", 10, 40)["already_open"] is False and len(started) == 2


def test_a_leftover_small_window_browser_is_stopped_then_forced_before_the_new_window_opens(tmp_path):
    chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    calls, alive = [], {"v": True}

    def run(c, **kw):
        calls.append(c)
        if c[:2] == ["pkill", "-9"]:
            alive["v"] = False                                  # only the forced stop works: it ignores the polite one
        return types.SimpleNamespace(returncode=0 if alive["v"] else 1)

    started = []

    class Proc:
        def __init__(self, c, **kw):
            started.append(c)

    ml = minilaunch.MiniLauncher(tmp_path, find=lambda: chrome, popen=Proc, platform="darwin", run=run, sleep=lambda s: None)
    assert ml.launch("http://127.0.0.1:1/?t=a", 0, 0)["already_open"] is False
    names = [c[:2] if c[0] == "pkill" else c[:1] for c in calls]
    assert ["pkill", "-f"] in names and ["pkill", "-9"] in names and names.index(["pkill", "-f"]) < names.index(["pkill", "-9"])
    assert len(started) == 1 and started[0][0] == "open"       # opened only after the clearing


def test_popout_always_asks_the_launcher_so_a_closed_window_can_always_be_reopened(tmp_path):
    clk = Clock()
    eng = make_engine([[sock("45.33.0.8", 0)]], clk)
    token = load_or_create_token(tmp_path)
    launched = []
    srv = make_server(eng, token, 0, launch_mini=lambda url, x, y: launched.append(url) or {"browser": "c", "already_open": False})
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]

    def call(method, path):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.putrequest(method, path, skip_host=True)
        for k, v in (("Host", f"127.0.0.1:{port}"), ("Content-Length", "0"), ("Cookie", f"{COOKIE}={token}"), ("X-TOL", "1")):
            c.putheader(k, v)
        c.endheaders()
        r = c.getresponse()
        return json.loads(r.read() or b"{}")

    first = call("POST", "/api/popout")
    assert first["launched"] is True and len(launched) == 1 and "mini=1" in launched[0]
    call("GET", "/api/state")
    call("POST", "/api/popout")                            # every click goes to the launcher, which decides
    assert len(launched) == 2 and launched[0] != launched[1]   # each gets its own one-time code
    srv.shutdown()
    srv.server_close()


def test_the_login_redirect_keeps_the_small_window_marker_but_never_the_token(tmp_path):
    clk = Clock()
    eng = make_engine([[sock("45.33.0.8", 0)]], clk)
    token = load_or_create_token(tmp_path)
    got = []
    srv = make_server(eng, token, 0, launch_mini=lambda url, x, y: got.append(url) or {"browser": "c", "already_open": False})
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.putrequest("POST", "/api/popout", skip_host=True)
    for k, v in (("Host", f"127.0.0.1:{port}"), ("Content-Length", "0"), ("Cookie", f"{COOKIE}={token}"), ("X-TOL", "1")):
        c.putheader(k, v)
    c.endheaders()
    c.getresponse().read()
    code = got[0].split("?t=")[1].split("&")[0]
    c2 = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c2.putrequest("GET", f"/?t={code}&view=compact&mini=1", skip_host=True)
    c2.putheader("Host", f"127.0.0.1:{port}")
    c2.endheaders()
    r = c2.getresponse()
    r.read()
    loc = r.getheader("Location")
    assert r.status == 302 and loc == "/?view=compact&mini=1" and token not in loc and code not in loc
    srv.shutdown()
    srv.server_close()
