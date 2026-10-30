"""`tol`: start live monitoring and open the dashboard."""
import argparse
import json
import os
import sys
import threading
import webbrowser
from pathlib import Path

from . import __version__

DEFAULT_PORT = 8731
UNIT = """[Unit]
Description=TOL live network transparency

[Service]
ExecStart={exe} -m tol_app --no-browser --port {port}
Restart=on-failure

[Install]
WantedBy=default.target
"""


def autostart_unit(port=DEFAULT_PORT, exe=None) -> str:
    return UNIT.format(exe=exe or sys.executable, port=port)


PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.tol.agent</string>
  <key>ProgramArguments</key><array>
    <string>{exe}</string><string>-m</string><string>tol_app</string>
    <string>--no-browser</string><string>--port</string><string>{port}</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict></plist>
"""


def autostart_plist(port=DEFAULT_PORT, exe=None) -> str:
    return PLIST.format(exe=exe or sys.executable, port=port)


def notices(lookups: bool, platform=None) -> list:
    platform = platform or sys.platform
    out = []
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        out.append("Some processes owned by other users may show as 'unknown'. Run with sudo to see them all.")
    out.append("Public network-owner lookups are ON: destination IPs are sent to public registries (RDAP) "
               "to name the network owner. Restart without --lookup to turn this off." if lookups else
               "Network-owner lookups are OFF (default): no destination IPs leave this machine, so "
               "unrecognised destinations stay 'Unidentified'. Start with --lookup to name network owners; "
               "that sends destination IPs to public registries.")
    out.append("Know a vendor? Add its IP range or hostname to ~/.tol/registry.json and it shows as Verified.")
    if platform.startswith("win"):
        limit = ("On Windows it lists connections and the program that opened each one, but not how much data each "
                 "carried (Windows does not share that), so amounts show as n/a. It misses connections that open and "
                 "close between two checks, and UDP/QUIC.")
    elif platform.startswith("linux"):
        limit = "It does not see UDP/QUIC traffic or connections shorter than one second."
    else:
        limit = "Connections that open and close between two checks (a few seconds) can be missed."
    out.append("TOL sees who your device sends data to and how much, not what the data contains. " + limit)
    return out


def already_running(port: int, token: str) -> bool:
    """True if a TOL for this user is already serving on `port` (token proves it is ours)."""
    import http.client
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=1.5)
        c.request("GET", "/api/state", headers={"Cookie": f"tol_token={token}"})
        return c.getresponse().status == 200
    except OSError:
        return False


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="tol", description=__doc__)
    ap.add_argument("--version", action="version", version=f"TOL {__version__}")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--lookup", action="store_true",
                    help="name network owners by sending destination IPs to public registries (RDAP); off by default")
    ap.add_argument("--no-lookup", action="store_true", help=argparse.SUPPRESS)   # old flag; lookups are off by default
    ap.add_argument("--loopback", action="store_true", help="also show traffic to this device")
    ap.add_argument("--data-dir", default=str(Path.home() / ".tol"))
    ap.add_argument("--install-autostart", action="store_true", help="start TOL at login (systemd / launchd)")
    ap.add_argument("--native-host", action="store_true", help=argparse.SUPPRESS)       # started by the browser extension
    ap.add_argument("--install-browser-helper", action="store_true",
                    help="let the TOL Firefox extension pass its observations to TOL (writes one small file in Firefox's helper folder)")
    ap.add_argument("--site-report", nargs="+", metavar=("RECORDING.json", "PAGE"),
                    help="print what a recording shows for one page (PAGE is a host such as example.com); with no PAGE, list the pages seen")
    ap.add_argument("--compare-report", nargs=3, metavar=("RECORDING_A.json", "RECORDING_B.json", "PAGE"),
                    help="set two recordings of one page side by side (for example signal off and signal on)")
    ap.add_argument("--diagnose", action="store_true", help="show what this machine's network tools return")
    ap.add_argument("--save-sample", metavar="FILE", help="macOS: save raw nettop output for debugging")
    return ap


def main(argv=None) -> int:
    argv = [a for a in (sys.argv[1:] if argv is None else argv) if not a.startswith("-psn_")]  # Finder launch
    args = build_parser().parse_args(argv)

    if args.site_report:
        from . import gpc
        try:
            events = json.loads(Path(args.site_report[0]).read_text(encoding="utf-8"))["events"]
        except (OSError, ValueError, KeyError) as e:
            print(f"cannot read that recording: {e}", file=sys.stderr)
            return 1
        pages = {}
        for e in events:
            if gpc.is_observation(e):
                p = pages.setdefault(e["page"], [0, 0])
                p[0 if e["gpc"] else 1] += e["count"]
        if len(args.site_report) < 2:
            print("Pages seen (requests with the signal / without):" if pages else "No browser observations in this recording.")
            for name, (w, wo) in sorted(pages.items(), key=lambda kv: -sum(kv[1])):
                print(f"  {name}: {w} / {wo}")
            return 0
        r = gpc.site_report(events, args.site_report[1])
        print(r["text"] if r else "That page does not appear in this recording.")
        return 0 if r else 1
    if args.compare_report:
        from . import gpc
        try:
            ev = [json.loads(Path(f).read_text(encoding="utf-8"))["events"] for f in args.compare_report[:2]]
        except (OSError, ValueError, KeyError) as e:
            print(f"cannot read a recording: {e}", file=sys.stderr)
            return 1
        r = gpc.compare_reports(ev[0], ev[1], args.compare_report[2])
        print(r["text"] if r else "That page does not appear in both recordings.")
        return 0 if r else 1
    if args.native_host:
        from . import nativehost
        return nativehost.main(args.data_dir)
    if args.install_browser_helper:
        from . import nativehost
        try:
            print("Installed:", nativehost.install(args.data_dir))
        except OSError as e:
            print(e, file=sys.stderr)
            return 1
        return 0

    if args.diagnose:
        from .diagnose import diagnose
        return 0 if diagnose() else 1
    if args.save_sample:
        from .diagnose import save_sample
        save_sample(args.save_sample)
        return 0

    if args.install_autostart and sys.platform == "darwin":
        agent = Path.home() / "Library" / "LaunchAgents" / "com.tol.agent.plist"
        agent.parent.mkdir(parents=True, exist_ok=True)
        agent.write_text(autostart_plist(args.port), encoding="utf-8")
        print(f"Wrote {agent}\nStart it now with: launchctl load {agent}")
        return 0
    if args.install_autostart:
        unit = Path.home() / ".config" / "systemd" / "user" / "tol.service"
        unit.parent.mkdir(parents=True, exist_ok=True)
        unit.write_text(autostart_unit(args.port), encoding="utf-8")
        print(f"Wrote {unit}\nEnable it with: systemctl --user enable --now tol")
        return 0

    if not (sys.platform.startswith("linux") or sys.platform in ("darwin", "win32")):
        print("TOL's live collector supports Windows, macOS and Linux.", file=sys.stderr)
        return 2

    from tol_registry import load_registry
    from tol_collector import Collector, Resolver
    from .engine import Engine
    from .labeler import Labeler
    from .server import load_or_create_token, make_server, run_ticker

    data_dir = Path(args.data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    reg_path = data_dir / "registry.json"
    if not reg_path.exists():
        reg_path.write_text("{}\n", encoding="utf-8")
    labeler = Labeler(registry=load_registry(reg_path), lookups=args.lookup,
                      cache_path=data_dir / "owners.json")
    if sys.platform == "darwin":
        from tol_collector_mac import read_mac_sockets
        collector = Collector(include_loopback=args.loopback, resolver=Resolver(), labeler=labeler.label,
                              reader=read_mac_sockets, owners=None)
    elif sys.platform == "win32":
        from tol_collector_win import read_windows_sockets
        collector = Collector(include_loopback=args.loopback, resolver=Resolver(), labeler=labeler.label,
                              reader=read_windows_sockets, owners=None, presence_only=True)
    else:
        collector = Collector(include_loopback=args.loopback, resolver=Resolver(), labeler=labeler.label)
    engine = Engine(collector, data_dir=args.data_dir)
    from .receipts import Receipts
    engine.receipts = Receipts(data_dir, labeler=labeler)
    from . import autoid
    from .settings import Settings
    auto_stop = threading.Event()
    from .minilaunch import MiniLauncher
    mini = MiniLauncher(data_dir)
    engine.settings = Settings(data_dir)
    auto = autoid.AutoIdentifier(engine, engine.receipts, engine.settings)
    token = load_or_create_token(args.data_dir)
    if already_running(args.port, token):
        url = f"http://127.0.0.1:{args.port}/?t={token}"
        print(f"TOL is already running. Opening {url}", flush=True)
        if not args.no_browser:
            webbrowser.open(url)
        return 0
    try:
        server = make_server(engine, token, args.port, lambda: notices(args.lookup), auto=auto, launch_mini=mini.launch)
    except OSError:
        server = make_server(engine, token, 0, lambda: notices(args.lookup), auto=auto, launch_mini=mini.launch)
    url = f"http://127.0.0.1:{server.server_address[1]}/?t={token}"
    (data_dir / "ingest.json").write_text(json.dumps({"port": server.server_address[1]}), encoding="utf-8")
    stop = threading.Event()
    run_ticker(engine, stop)
    threading.Thread(target=auto.run, args=(auto_stop,), daemon=True, name="tol-auto-identify").start()
    print(f"TOL is watching this machine's connections.\nOpen: {url}\nPress Ctrl+C to stop.", flush=True)
    if not args.no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        auto_stop.set()
        server.server_close()
    return 0
