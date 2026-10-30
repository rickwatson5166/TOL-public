import json
import subprocess
import sys
import http.client

import pytest

from tol_app import gpc
from tol_app.engine import Engine
from tol_app.evidence import build_package
from tol_app.server import make_server


class NoCollector:
    def poll(self, now):
        return []


def net(host, label="Acme", conf="verified"):
    return {"entry_id": "x", "source": "live", "timestamp": "2026-10-21T10:00:00Z", "company_name": label,
            "label_source": "registry", "label_confidence": conf, "endpoint_ip": "104.18.0.9", "endpoint_port": 443,
            "endpoint_country": "??", "protocol": "https", "direction": "outbound", "bytes_sent": 10, "bytes_received": 5,
            "bytes_known": True, "hostname": host, "process_name": "firefox", "pid": 1}


def obs(host, ts, g=True, page="news.example", count=1):
    return {"host": host, "page": page, "ts_ms": ts, "gpc": g, "count": count}


def test_clean_accepts_exact_shape_and_refuses_anything_more():
    ok = gpc.clean(obs("ads.example", 1_800_000_000_000), now=1_800_000_000)
    assert ok["event_type"] == gpc.EVENT_TYPE and ok["gpc"] is True
    for bad in ({**obs("a.example", 1_800_000_000_000), "url": "https://a.example/x?q=1"},
                {**obs("a.example", 1_800_000_000_000), "cookie": "z"},
                obs("a.example/path", 1_800_000_000_000), obs("a.example", 1.5e12), obs("a.example", 1_800_000_000_000, g=1),
                obs("a.example", 1_800_000_000_000, count=0), "text"):
        with pytest.raises(ValueError):
            gpc.clean(bad)


def test_observations_are_kept_only_while_recording_and_never_break_the_summary(tmp_path):
    eng = Engine(NoCollector(), data_dir=tmp_path)
    assert eng.ingest_observations([obs("t.example", 1_800_000_000_000)])["recorded"] == 0     # not recording: nothing kept
    eng.start_recording()
    assert eng.ingest_observations([obs("t.example", 1_800_000_000_000), obs("u.example", 1_800_000_001_000, g=False)])["recorded"] == 2
    eng._rec["events"].append(net("t.example"))
    mixed = eng.ingest_observations([obs("t.example", 1_800_000_002_000), {"host": "x", "url": "no"}, obs("a.example.", 1_800_000_003_000)])
    assert (mixed["recorded"], mixed["rejected"]) == (2, 1) and "unexpected field" in mixed["reason"]   # a bad item no longer costs the good ones
    with pytest.raises(ValueError):
        eng.ingest_observations("not a list")
    out = eng.stop_recording()
    rep = json.loads(open(out["json"]).read())
    assert len(rep["events"]) == 5 and len(rep["destinations"]) == 1
    assert [e["host"] for e in rep["events"] if e.get("event_type")][-1] == "a.example"                    # trailing dot normalised


def test_site_report_states_what_was_seen_with_existing_labels_and_no_verdict():
    t = 1_800_000_000_000
    events = [{**gpc.clean(o), } for o in (obs("t.example", t), obs("t.example", t + 1000, count=3),
                                            obs("far.example", t + 90_000), obs("cdn.example", t + 2000, g=False))]
    events.append(net("t.example", "Tracker Co", "likely"))
    r = gpc.site_report(events, "news.example", window_seconds=30)
    by = {d["host"]: d for d in r["destinations"]}
    assert set(by) == {"t.example", "cdn.example"} and by["t.example"]["with_signal"] == 4
    assert by["t.example"]["owner"] == "Tracker Co" and by["t.example"]["confidence"] == "likely"
    assert by["cdn.example"]["confidence"] == "no label"
    text = r["text"].lower()
    assert "does not say" in text and "violat" not in text and "illegal" not in text
    assert gpc.site_report(events, "other.example") is None


def test_report_without_signal_says_so():
    r = gpc.site_report([gpc.clean(obs("t.example", 1_800_000_000_000, g=False))], "news.example")
    assert not r["signal_seen"] and "No request from this page carried" in r["text"]


def test_ingest_endpoint_needs_the_token_and_the_package_checks_pass(tmp_path):
    eng = Engine(NoCollector(), data_dir=tmp_path)
    srv = make_server(eng, "tok123", 0)
    import threading
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]

    def post(body, token):
        c = http.client.HTTPConnection("127.0.0.1", port)
        c.request("POST", "/api/observations", json.dumps(body), {"X-TOL-Ingest": token})
        r = c.getresponse()
        return r.status, r.read()
    try:
        eng.start_recording()
        assert post([obs("t.example", 1_800_000_000_000)], "wrong")[0] == 403
        assert post([obs("t.example", 1_800_000_000_000)], "tok123") == (200, b'{"recorded": 1, "rejected": 0, "reason": ""}')
        assert post([{"host": "t.example", "url": "x"}], "tok123")[0] == 200       # a rejected item is reported, not fatal
        eng.stop_recording()
    finally:
        srv.shutdown()
    pkg = build_package(json.loads(open(eng.last_recording["json"]).read()), tmp_path / "ev")
    ok = subprocess.run([sys.executable, "-I", "verify.py"], cwd=pkg["folder"], capture_output=True, text=True)
    assert "PASS  Browser-signal observations hold only host, time and signal" in ok.stdout and ok.returncode == 0
    chain = pkg["folder"] / "network-flows" / "events.chain.jsonl"
    # a forged extra field breaks the chain AND the observation rule
    lines = chain.read_text().splitlines()
    e = json.loads(lines[0]); e["url"] = "https://t.example/secret"
    chain.write_text(json.dumps(e, sort_keys=True) + "\n")
    bad = subprocess.run([sys.executable, "-I", "verify.py"], cwd=pkg["folder"], capture_output=True, text=True)
    assert bad.returncode == 1 and "FAIL  Browser-signal observations" in bad.stdout


def test_native_helper_round_trip_and_install(tmp_path, monkeypatch):
    import io
    import threading
    from tol_app import nativehost
    eng = Engine(NoCollector(), data_dir=tmp_path)
    srv = make_server(eng, "tok9", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    (tmp_path / "token").write_text("tok9")
    (tmp_path / "ingest.json").write_text(json.dumps({"port": srv.server_address[1]}))
    try:
        eng.start_recording()
        out = io.BytesIO()
        buf = io.BytesIO()
        nativehost.write_message(buf, [obs("t.example", 1_800_000_000_000)])
        buf.seek(0)
        nativehost.serve(buf, out, tmp_path)
        out.seek(0)
        assert nativehost.read_message(out) == {"recorded": 1, "rejected": 0, "reason": ""}
        bad = nativehost.forward([{"host": "x", "url": "u"}], tmp_path)
        assert bad["recorded"] == 0 and bad["rejected"] == 1 and "unexpected field" in bad["reason"]
        assert nativehost.forward([], tmp_path / "nowhere") == {"error": "TOL is not running"}
    finally:
        srv.shutdown()
    path = nativehost.install(tmp_path / "d", exe="/x/tol", platform="darwin", home=tmp_path)
    m = json.loads(path.read_text())
    assert m["allowed_extensions"] == ["tol-observer@tol.local"] and m["type"] == "stdio"
    assert path.as_posix().endswith("Mozilla/NativeMessagingHosts/org.tol.observer.json")
    launcher = (tmp_path / "d" / "tol-native-host").read_text()
    assert "PYTHONPATH=" in launcher and "-m tol_app --native-host" in launcher
    # the launcher really starts the helper from an unrelated folder and it answers
    import subprocess, sys as _s
    if _s.platform != "win32":                       # the Mac/Linux launcher is a shell script
        nativehost.install(tmp_path / "d2", exe=_s.executable, platform="darwin", home=tmp_path)
        buf = io.BytesIO(); nativehost.write_message(buf, [])
        r = subprocess.run([str(tmp_path / "d2" / "tol-native-host")], input=buf.getvalue(), capture_output=True, cwd="/")
        assert nativehost.read_message(io.BytesIO(r.stdout)) == {"error": "TOL is not running"}
    ext = json.loads(open("extension/firefox/manifest.json").read())
    assert ext["browser_specific_settings"]["gecko"]["id"] == nativehost.EXTENSION_ID
    assert "nativeMessaging" in ext["permissions"] and "webRequestBlocking" not in ext["permissions"]


def test_site_report_command_lists_pages_and_prints_a_report(tmp_path, capsys):
    from tol_app import cli
    ev = [gpc.clean(obs("t.example", 1_800_000_000_000)), gpc.clean(obs("u.example", 1_800_000_001_000, g=False))]
    f = tmp_path / "rec.json"
    f.write_text(json.dumps({"events": ev}))
    assert cli.main(["--site-report", str(f)]) == 0
    assert "news.example: 1 / 1" in capsys.readouterr().out
    assert cli.main(["--site-report", str(f), "news.example"]) == 0
    assert "t.example: 1 with the signal, 0 without" in capsys.readouterr().out
    assert cli.main(["--site-report", str(f), "nope.example"]) == 1


def test_ip_is_optional_validated_and_used_for_the_existing_label():
    t = 1_800_000_000_000
    assert "ip" not in gpc.clean(obs("a.example", t))
    assert gpc.clean({**obs("a.example", t), "ip": "104.18.0.9"})["ip"] == "104.18.0.9"
    with pytest.raises(ValueError):
        gpc.clean({**obs("a.example", t), "ip": "not-an-address"})
    events = [gpc.clean({**obs("ping.example", t), "ip": "104.18.0.9"}), net("server-9.cdn.net", "Tracker Co", "likely")]
    r = gpc.site_report(events, "news.example")
    d = r["destinations"][0]
    assert d["ip"] == "104.18.0.9" and d["owner"] == "Tracker Co" and d["confidence"] == "likely"


def test_default_report_covers_the_whole_recording_and_counts_unlabelled():
    t = 1_800_000_000_000
    events = [gpc.clean(obs("t.example", t)), gpc.clean(obs("far.example", t + 600_000, count=4)), net("t.example", "Tracker Co", "likely")]
    whole = gpc.site_report(events, "news.example")
    assert {d["host"] for d in whole["destinations"]} == {"t.example", "far.example"}
    assert whole["destinations"][0]["host"] == "far.example"                          # busiest first
    assert "5 request(s) carried" in whole["text"] and "label for 1 of the 2" in whole["text"]
    assert [d["host"] for d in gpc.site_report(events, "news.example", window_seconds=30)["destinations"]] == ["t.example"]


def test_dashboard_site_report_endpoints(tmp_path):
    import threading
    eng = Engine(NoCollector(), data_dir=tmp_path)
    srv = make_server(eng, "tok77", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]

    def get(path, cookie=True):
        c = http.client.HTTPConnection("127.0.0.1", port)
        c.request("GET", path, headers={"Cookie": "tol_token=tok77"} if cookie else {})
        r = c.getresponse()
        return r.status, r.read().decode(), r.getheader("Content-Disposition")
    try:
        assert get("/api/site-report", cookie=False)[0] == 403
        assert json.loads(get("/api/site-report")[1]) == {"pages": []}                     # nothing recorded yet
        eng.start_recording()
        eng.ingest_observations([obs("t.example", 1_800_000_000_000, count=3), obs("u.example", 1_800_000_001_000, g=False)])
        eng.stop_recording()
        pages = json.loads(get("/api/site-report")[1])["pages"]
        assert pages == [{"page": "news.example", "with_signal": 3, "without_signal": 1}]
        st, body, _ = get("/api/site-report?page=news.example")
        rep = json.loads(body)
        assert st == 200 and {d["host"] for d in rep["destinations"]} == {"t.example", "u.example"}
        st, text, disp = get("/api/site-report?page=news.example&format=text")
        assert st == 200 and "Site report: news.example" in text and "tol-site-report-news.example.txt" in disp
        assert get("/api/site-report?page=nope.example")[0] == 404
    finally:
        srv.shutdown()


def test_dashboard_script_still_runs_with_the_site_card(tmp_path):
    import re, shutil
    html = open("tol_app/static/dashboard.html", encoding="utf-8").read()
    assert 'id="site-card"' in html and "loadSitePages" in html
    node = shutil.which("node")
    if node:
        js = re.search(r"<script>(.*)</script>", html, re.S).group(1)
        check = tmp_path / "dash_check.js"
        check.write_text(js, encoding="utf-8")
        r = subprocess.run([node, "--check", str(check)], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr


def test_windows_helper_install_writes_launcher_manifest_and_registry_entry(tmp_path):
    from tol_app import nativehost
    seen = []
    path = nativehost.install(tmp_path / "d", exe=r"C:\\TOL\\TOL.exe", platform="win32", home=tmp_path, registry=seen.append)
    m = json.loads(path.read_text())
    bat = tmp_path / "d" / "tol-native-host.bat"
    assert m["path"] == str(bat) and m["allowed_extensions"] == ["tol-observer@tol.local"]
    assert seen == [path] and path.parent == tmp_path / "d"            # registry points at the manifest in TOL's folder
    text = bat.read_text()
    assert "--native-host" in text and 'set "PYTHONPATH=' in text and text.startswith("@echo off")


def test_setup_button_installs_helper_and_copies_the_extension(tmp_path, monkeypatch):
    import threading
    from tol_app import nativehost
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setattr(nativehost, "_set_registry", lambda path: None)            # never touch a real registry in a test
    monkeypatch.setattr(nativehost.Path, "home", classmethod(lambda cls: tmp_path / "home"))
    eng = Engine(NoCollector(), data_dir=tmp_path / "tol")
    srv = make_server(eng, "tokq", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    def post(headers):
        c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1])
        c.request("POST", "/api/browser-helper/install", headers=headers)
        r = c.getresponse()
        raw = r.read()
        return r.status, (json.loads(raw) if r.status == 200 else raw)
    try:
        assert post({})[0] == 403                                                   # needs the login cookie and header
        st, body = post({"Cookie": "tol_token=tokq", "X-TOL": "1"})
    finally:
        srv.shutdown()
    assert st == 200 and (tmp_path / "tol" / "extension" / "firefox" / "manifest.json").is_file()
    assert body["extension_dir"].endswith("extension/firefox") or body["extension_dir"].endswith("extension\\firefox")


def test_both_app_builds_bundle_the_extension_and_the_new_modules():
    for f in ("scripts/tol_mac.spec", "scripts/tol_win.spec"):
        spec = open(f).read()
        assert "extension" in spec and "tol_app.gpc" in spec and "tol_app.nativehost" in spec


def test_packaged_mac_launcher_survives_a_temporary_app_translocation_path(tmp_path, monkeypatch):
    from tol_app import nativehost
    monkeypatch.setattr(nativehost.sys, "frozen", True, raising=False)
    temp = "/private/var/folders/x/AppTranslocation/ABC/d/TOL.app/Contents/MacOS/TOL"
    assert nativehost.stable_app_paths(temp, home=tmp_path)[0] == "/Applications/TOL.app/Contents/MacOS/TOL"
    assert nativehost.stable_app_paths(temp, home=tmp_path)[-1] == temp               # kept only as a last resort
    assert nativehost.stable_app_paths("/Applications/TOL.app/Contents/MacOS/TOL", home=tmp_path)[0] == "/Applications/TOL.app/Contents/MacOS/TOL"
    nativehost.install(tmp_path / "d", exe=temp, platform="darwin", home=tmp_path)
    text = (tmp_path / "d" / "tol-native-host").read_text()
    assert text.index('"/Applications/TOL.app') < text.index("AppTranslocation") and "--native-host" in text
    if nativehost.sys.platform == "win32":           # the Mac launcher is a shell script; Windows has its own .bat launcher
        return
    # the launcher really picks the first program that exists, and gives up cleanly when none does
    fake = tmp_path / "TOL"
    fake.write_text('#!/bin/sh\necho started-with "$@"\n'); fake.chmod(0o755)
    nativehost.install(tmp_path / "d3", exe=str(fake), platform="darwin", home=tmp_path)
    r = subprocess.run([str(tmp_path / "d3" / "tol-native-host")], capture_output=True, text=True)
    assert "started-with --native-host --data-dir" in r.stdout


def _run_extension(mode):
    import shutil
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed")
    out = subprocess.run([node, "tests/extension_harness.js", mode], capture_output=True, text=True, timeout=30, check=True).stdout
    return json.loads(out)


def test_extension_says_hello_at_load_reports_only_hosts_and_shows_its_own_state():
    ok = _run_extension("ok")
    assert ok["native"][0]["msg"] == []                                  # contacts the helper as soon as it loads
    sent = ok["native"][1]["msg"]
    assert {(s["host"], s["gpc"]) for s in sent} == {("ads.example", True), ("cdn.example", False)}
    assert all(set(s) <= {"host", "page", "ts_ms", "gpc", "count", "ip"} for s in sent)
    assert "secret" not in json.dumps(ok) and "Cookie" not in json.dumps(ok) and "127.0.0.1" not in json.dumps(sent)
    assert ok["badge"][-1] == "2" and "Problem" not in ok["title"][-1]
    # the stand-in answers both the hello and the batch with kept 2 / turned away 1, so the totals are 4 and 2
    assert "kept 4" in ok["title"][-1] and "turned away 2" in ok["title"][-1] and "bare host names" in ok["title"][-1]
    for mode, reason in (("down", "helper not reachable"), ("refused", "TOL is not running")):
        bad = _run_extension(mode)
        assert bad["badge"][-1] == "!" and reason in bad["title"][-1]


def test_extension_manifest_has_a_toolbar_button_and_no_blocking_rights():
    m = json.loads(open("extension/firefox/manifest.json").read())
    assert m["browser_action"]["default_area"] == "navbar" and "webRequestBlocking" not in m["permissions"]


def test_odd_but_real_host_shapes_are_normalised_not_refused():
    t = 1_800_000_000_000
    for raw, want in (("Example.com.", "example.com"), ("[2001:db8::1]", "2001:db8::1"), (" CDN.Example ", "cdn.example")):
        assert gpc.clean({**obs("a.example", t), "host": raw})["host"] == want
    for bad in ("exa mple.com", "example.com/path", "a" * 70 + ".com", "-x.example"):
        with pytest.raises(ValueError):
            gpc.clean({**obs("a.example", t), "host": bad})


def test_a_reverse_dns_name_is_shown_as_an_address_name_not_as_an_owner():
    t = 1_800_000_000_000
    n = net("a23-1.deploy.static.akamaitechnologies.com", "a23-1.deploy.static.akamaitechnologies.com", "hostname")
    events = [gpc.clean({**obs("news.example", t), "ip": "104.18.0.9"}), n]
    r = gpc.site_report(events, "news.example")
    d = r["destinations"][0]
    assert d["owner"] is None and d["address_name"].startswith("a23-1.deploy") and d["confidence"] == "address name only"
    assert "label for 0 of the 1" in r["text"] and "the address's own name is a23-1" in r["text"]


def _rec(*items):
    return [gpc.clean(o) for o in items]


def test_comparison_reads_which_recording_had_the_signal_from_the_recordings_not_the_order():
    t = 1_800_000_000_000
    on = _rec(obs("t.example", t, count=3), obs("ads.example", t + 1000, count=5), obs("cdn.example", t + 2000))
    off = _rec(obs("t.example", t, g=False, count=4), obs("cdn.example", t + 2000, g=False), obs("tracker2.example", t + 3000, g=False, count=2))
    for a, b in ((on, off), (off, on)):                       # given in either order, the result is the same
        r = gpc.compare_reports(a, b, "news.example")
        assert r["ordered_by_condition"] and (r["first"], r["second"]) == ("signal on", "signal off")
        assert [d["host"] for d in r["only_first"]] == ["ads.example"]
        assert [d["host"] for d in r["only_second"]] == ["tracker2.example"]
        assert {d["host"]: (d["first"], d["second"]) for d in r["both"]} == {"t.example": (3, 4), "cdn.example": (1, 1)}
    text = r["text"].lower()
    assert "does not say why" in text and "violat" not in text and "illegal" not in text and "complian" not in text
    assert gpc.compare_reports(on, off, "other.example") is None


def test_comparison_of_two_runs_with_the_same_setting_is_labelled_as_a_baseline():
    t = 1_800_000_000_000
    a = _rec(obs("t.example", t), obs("x.example", t))
    b = _rec(obs("t.example", t), obs("y.example", t))
    r = gpc.compare_reports(a, b, "news.example")
    assert r["baseline"] and not r["ordered_by_condition"] and "varies on its own" in r["text"]
    assert [d["host"] for d in r["only_first"]] == ["x.example"] and [d["host"] for d in r["only_second"]] == ["y.example"]


def test_compare_report_command(tmp_path, capsys):
    from tol_app import cli
    t = 1_800_000_000_000
    fa, fb = tmp_path / "on.json", tmp_path / "off.json"
    fa.write_text(json.dumps({"events": _rec(obs("t.example", t), obs("ads.example", t))}))
    fb.write_text(json.dumps({"events": _rec(obs("t.example", t, g=False))}))
    assert cli.main(["--compare-report", str(fa), str(fb), "news.example"]) == 0
    out = capsys.readouterr().out
    assert "Only in signal on:" in out and "ads.example" in out and "Only in signal off:" in out
    assert cli.main(["--compare-report", str(fa), str(fb), "nope.example"]) == 1
    assert cli.main(["--compare-report", str(tmp_path / "missing.json"), str(fb), "news.example"]) == 1


def test_comparison_warns_when_the_two_visits_are_not_like_for_like():
    t = 1_800_000_000_000
    big = _rec(*[obs(f"h{i}.example", t, count=50) for i in range(10)])
    small = _rec(obs("h0.example", t, g=False, count=2))
    r = gpc.compare_reports(big, small, "news.example")
    assert not r["comparable"] and "CAUTION" in r["text"]
    even = gpc.compare_reports(_rec(obs("a.example", t, count=10)), _rec(obs("a.example", t, g=False, count=9)), "news.example")
    assert even["comparable"] and "CAUTION" not in even["text"]
