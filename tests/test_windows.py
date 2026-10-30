"""Windows reader and presence mode. The sample mimics `Get-NetTCPConnection | ConvertTo-Json` output."""
import json

import pytest

from tol_app import cli, minilaunch
from tol_app.engine import Engine
from tol_collector import Collector
from tol_collector_win import parse_connections

SAMPLE = json.dumps([
    {"la": "192.168.1.20", "lp": 50123, "ra": "142.250.80.46", "rp": 443, "st": 5, "pid": 4120, "name": "chrome"},
    {"la": "0.0.0.0", "lp": 135, "ra": "0.0.0.0", "rp": 0, "st": 2, "pid": 1032, "name": "svchost"},
    {"la": "192.168.1.20", "lp": 50200, "ra": "fe80::1%12", "rp": 443, "st": 5, "pid": 4, "name": None},
    {"la": "::1", "lp": 50300, "ra": "2607:f8b0:4004::200e", "rp": 443, "st": 5, "pid": 9, "name": "msedge"},
    {"la": "bad", "lp": "x"},
])


def test_parse_connections_keeps_connected_rows_only():
    socks = parse_connections(SAMPLE)
    assert [(s["process"], s["dst"], s["dport"]) for s in socks] == [
        ("chrome", "142.250.80.46", 443), ("System", "fe80::1", 443), ("msedge", "2607:f8b0:4004::200e", 443)]
    assert socks[0]["state"] == 1 and socks[0]["bytes_sent"] == 0 and socks[2]["family"] == 6


def test_single_connection_object_and_empty_output():
    one = json.dumps({"la": "10.0.0.2", "lp": 1, "ra": "93.184.216.34", "rp": 80, "st": 5, "pid": 7, "name": "curl"})
    assert len(parse_connections("\ufeff" + one)) == 1
    assert parse_connections("") == [] and parse_connections("  \n") == []


def test_presence_mode_reports_each_new_established_connection_once():
    state = {"rows": parse_connections(SAMPLE)}
    c = Collector(reader=lambda: state["rows"], owners=None, labeler=lambda ip, host: {"company": "UNKNOWN"},
                  presence_only=True)
    first = c.poll(100.0)                       # connections already open at start are reported
    assert {e["process_name"] for e in first} == {"chrome", "System", "msedge"}
    assert all(e["bytes_sent"] == 0 and e["bytes_known"] is False for e in first)
    assert c.poll(101.0) == []                  # nothing new, nothing reported
    state["rows"] = state["rows"] + parse_connections(json.dumps(
        [{"la": "10.0.0.2", "lp": 7, "ra": "93.184.216.34", "rp": 443, "st": 5, "pid": 7, "name": "curl"}]))
    assert [e["process_name"] for e in c.poll(102.0)] == ["curl"]


def test_engine_flags_bytes_unknown_and_alerts_on_first_connection():
    rows = parse_connections(SAMPLE)
    state = {"rows": rows[:1]}
    clock = {"t": 1000.0}
    c = Collector(reader=lambda: state["rows"], owners=None, labeler=lambda ip, host: {"company": "UNKNOWN"},
                  presence_only=True)
    eng = Engine(c, clock=lambda: clock["t"])
    eng.started = 0
    eng.tick(clock["t"])
    state["rows"] = rows
    clock["t"] += 5
    eng.tick(clock["t"])
    snap = eng.snapshot(clock["t"]) if hasattr(eng, "snapshot") else eng.state(clock["t"])
    assert snap["bytes_known"] is False
    assert any("First connection to" in a["message"] for a in snap["alerts"])


def test_find_browser_on_windows_uses_edge_or_chrome(monkeypatch):
    monkeypatch.setenv("PROGRAMFILES(X86)", r"C:\Program Files (x86)")
    edge = r"C:\Program Files (x86)" + "\\" + r"Microsoft\Edge\Application\msedge.exe"
    found = minilaunch.find_browser("win32", exists=lambda p: p == edge)
    assert found == edge
    assert minilaunch.find_browser("win32", exists=lambda p: False) is None


def test_notices_explain_windows_limits_and_do_not_need_geteuid():
    text = " ".join(cli.notices(False, platform="win32"))
    assert "n/a" in text and "Windows" in text


def test_a_slow_powershell_reading_is_skipped_not_fatal(monkeypatch):
    """A PowerShell call that outlasts its time limit must look like any other failed reading (OSError), which the
    engine counts and survives. Before, subprocess.TimeoutExpired escaped and the collector thread died silently."""
    import subprocess
    import tol_collector_win as win

    monkeypatch.setattr(win.shutil, "which", lambda name: "powershell.exe")

    def slow(*a, **k):
        raise subprocess.TimeoutExpired(cmd="powershell", timeout=30)
    monkeypatch.setattr(win.subprocess, "run", slow)
    with pytest.raises(OSError, match="longer than 30 seconds"):
        win.run_powershell()

    class Slow:
        def poll(self, now):
            return win.run_powershell() and []
    eng = Engine(Slow())
    assert eng.tick() == [] and eng.errors == 1                  # counted, and the next tick can try again
    assert eng.tick() == [] and eng.errors == 2
