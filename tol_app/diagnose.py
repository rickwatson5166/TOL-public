"""`tol --diagnose`: show exactly what this machine's network tools return and what TOL parsed."""
import platform
import shutil
import sys


def diagnose(out=print) -> bool:
    out(f"TOL diagnose | {platform.platform()} | {platform.machine()} | python {platform.python_version()}")
    if sys.platform == "darwin":
        from tol_collector_mac import NETTOP_CMD, parse_nettop, run_nettop
        out(f"nettop: {shutil.which('nettop') or 'NOT FOUND'}")
        try:
            raw = run_nettop()
        except Exception as e:  # noqa: BLE001 - this is a diagnostic; show whatever happened
            out(f"FAILED running {' '.join(NETTOP_CMD)}: {e}")
            return False
        lines = raw.splitlines()
        out(f"nettop returned {len(lines)} lines. First 12:")
        for ln in lines[:12]:
            out("  | " + ln[:160])
        socks = parse_nettop(raw)
        out(f"parsed {len(socks)} connections with byte counters; first 5:")
        for s in socks[:5]:
            out(f"  {s['process']}({s['pid']}) {s['proto']} {s['dst']}:{s['dport']} "
                f"out={s['bytes_sent']} in={s['bytes_received']}")
        ok = bool(socks)
    elif sys.platform.startswith("linux"):
        from tol_collector import read_tcp_sockets
        socks = read_tcp_sockets()
        out(f"sock_diag returned {len(socks)} TCP sockets")
        ok = bool(socks)
    elif sys.platform == "win32":
        from tol_collector_win import CMD, parse_connections, run_powershell
        out(f"powershell: {shutil.which('powershell') or 'NOT FOUND'}")
        try:
            raw = run_powershell()
        except Exception as e:  # noqa: BLE001 - this is a diagnostic; show whatever happened
            out(f"FAILED running {' '.join(CMD[:6])} ...: {e}")
            return False
        out(f"PowerShell returned {len(raw)} characters. First 300:")
        out("  | " + raw[:300].replace("\n", " "))
        socks = parse_connections(raw)
        out(f"parsed {len(socks)} connections (Windows gives no byte counts); first 5:")
        for s in socks[:5]:
            out(f"  {s['process']}({s['pid']}) {s['dst']}:{s['dport']} state={s['state']}")
        ok = bool(socks)
    else:
        out("unsupported platform")
        return False
    out(registry_check())
    out("RESULT: " + ("OK, live data is readable." if ok else
                      "NO CONNECTIONS PARSED. Send this whole output to the developer."))
    out("Note: the lines above name programs and addresses your machine connected to. Review before sharing.")
    return ok


def registry_check() -> str:
    """Can this machine reach the public registry used by Identify? Uses a well-known public test address, not yours."""
    from .netutil import LookupFailed, rdap_get, ssl_context
    stats = ssl_context().cert_store_stats().get("x509_ca", 0)
    try:
        got = rdap_get("1.1.1.1")
    except LookupFailed as e:
        return f"registry lookup (rdap.org): FAILED, {e}  [CA certificates loaded: {stats}]"
    return f"registry lookup (rdap.org): {'OK' if got else 'reachable, no record'}  [CA certificates loaded: {stats}]"


def save_sample(path: str) -> None:
    """Write raw nettop output so a parser fix can be built from your Mac's real format."""
    from tol_collector_mac import run_nettop
    with open(path, "w", encoding="utf-8") as f:
        f.write(run_nettop())
    print(f"Saved raw nettop output to {path}. It lists programs and addresses; review before sharing.")
