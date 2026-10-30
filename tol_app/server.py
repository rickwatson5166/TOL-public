"""Local dashboard server. Bound to 127.0.0.1 only and protected by a per-install token.

Two guards because the page shows sensitive activity: a token (so other local users and
processes cannot read it) and a Host-header check (so a malicious website cannot reach it
through DNS rebinding).
"""
import hmac
import json
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import __version__

STATIC = Path(__file__).with_name("static")
COOKIE = "tol_token"
CSP = ("default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
       "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


def load_or_create_token(data_dir) -> str:
    path = Path(data_dir) / "token"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_text(encoding="utf-8").strip():
        return path.read_text(encoding="utf-8").strip()
    token = secrets.token_urlsafe(24)
    path.write_text(token, encoding="utf-8")
    path.chmod(0o600)
    return token


ONE_TIME_TTL = 60



def make_server(engine, token, port=0, notices=lambda: [], auto=None, launch_mini=None):
    once, once_lock = {}, threading.Lock()          # one-time login codes: code -> expiry

    def issue_code() -> str:
        code = secrets.token_urlsafe(16)
        with once_lock:
            now = time.time()
            for k in [k for k, v in once.items() if v < now]:
                del once[k]
            if len(once) >= 8:                      # never let these pile up
                once.pop(next(iter(once)))
            once[code] = now + ONE_TIME_TTL
        return code

    def redeem_code(code: str) -> bool:
        with once_lock:
            return once.pop(code, 0) >= time.time()

    class Handler(BaseHTTPRequestHandler):
        server_version = "TOL"

        def log_message(self, *args):
            pass

        def _send(self, code, body, ctype="text/plain; charset=utf-8", extra=()):
            data = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("Referrer-Policy", "no-referrer")
            for k, v in extra:
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def _host_ok(self):
            port_ = self.server.server_address[1]
            return self.headers.get("Host") in (f"127.0.0.1:{port_}", f"localhost:{port_}")

        def _authed(self):
            for part in (self.headers.get("Cookie") or "").split(";"):
                k, _, v = part.strip().partition("=")
                if k == COOKIE and hmac.compare_digest(v, token):
                    return True
            return False

        def do_GET(self):
            if not self._host_ok():
                return self._send(403, "forbidden host")
            url = urlparse(self.path)
            if url.path == "/":
                supplied = parse_qs(url.query).get("t", [""])[0]
                if supplied and (hmac.compare_digest(supplied, token) or redeem_code(supplied)):
                    mini = parse_qs(url.query).get("mini", [""])[0] == "1"
                    return self._send(302, "", extra=[
                        ("Location", "/?view=compact&mini=1" if mini else "/"),
                        ("Set-Cookie", f"{COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/")])
                if not self._authed():
                    return self._send(403, "Open TOL using the link it printed when it started.")
                return self._send(200, (STATIC / "dashboard.html").read_bytes(), "text/html; charset=utf-8")
            if url.path == "/api/state":
                if not self._authed():
                    return self._send(403, "forbidden")
                state = engine.state()
                state["version"] = __version__
                state["notices"] = notices()
                state["recording"] = engine.recording_state()
                state["auto_identify"] = auto.status() if auto else None
                state["receipts"] = engine.receipts.summaries() if engine.receipts else {}
                if engine.receipts:
                    for row in state["rows"]:      # which receipt (own or same network block) backs this row
                        found = row["endpoints"] and engine.receipts.find(row["endpoints"][0].rsplit(":", 1)[0])
                        row["receipt_ip"] = found["ip"] if found else None
                return self._send(200, json.dumps(state), "application/json")
            if url.path == "/api/receipts.json":
                if not self._authed() or engine.receipts is None:
                    return self._send(403, "forbidden")
                return self._send(200, json.dumps(engine.receipts.export(), indent=2), "application/json", extra=[
                    ("Content-Disposition", 'attachment; filename="tol-receipts.json"')])
            if url.path == "/api/site-report":
                if not self._authed():
                    return self._send(403, "forbidden")
                q = parse_qs(url.query)
                page = q.get("page", [""])[0]
                if not page:
                    return self._send(200, json.dumps({"pages": engine.site_pages()}), "application/json")
                report = engine.site_report(page)
                if report is None:
                    return self._send(404, json.dumps({"error": "that page is not in the last recording"}), "application/json")
                if q.get("format", [""])[0] == "text":
                    safe = "".join(c for c in page if c.isalnum() or c in ".-")[:60]
                    return self._send(200, report["text"], "text/plain; charset=utf-8", extra=[
                        ("Content-Disposition", f'attachment; filename="tol-site-report-{safe}.txt"')])
                return self._send(200, json.dumps(report), "application/json")
            if url.path == "/api/recording/download":
                if not self._authed():
                    return self._send(403, "forbidden")
                kind = parse_qs(url.query).get("kind", ["json"])[0]
                last = engine.last_recording
                path = last.get(kind) if last and kind in ("json", "csv", "zip") else None
                if not path or not Path(path).is_file():
                    return self._send(404, "no recording yet")
                ctype = {"json": "application/json", "csv": "text/csv; charset=utf-8", "zip": "application/zip"}[kind]
                return self._send(200, Path(path).read_bytes(), ctype, extra=[
                    ("Content-Disposition", f'attachment; filename="{Path(path).name}"')])
            self._send(404, "not found")

        def do_POST(self):
            if urlparse(self.path).path == "/api/observations":
                # the browser extension reaches us only through TOL's native helper, which holds the token file
                if not self._host_ok() or not hmac.compare_digest(self.headers.get("X-TOL-Ingest", ""), token):
                    return self._send(403, "forbidden")
                try:
                    n = int(self.headers.get("Content-Length", "0"))
                    if not 0 < n <= 512 * 1024:
                        raise ValueError("body size")
                    result = engine.ingest_observations(json.loads(self.rfile.read(n)))
                except (ValueError, UnicodeDecodeError) as e:
                    return self._send(400, json.dumps({"error": str(e)}), "application/json")
                return self._send(200, json.dumps(result), "application/json")
            # cookie is SameSite=Strict; the custom header additionally blocks cross-site form posts
            if not self._host_ok() or not self._authed() or self.headers.get("X-TOL") != "1":
                return self._send(403, "forbidden")
            path = urlparse(self.path).path
            if path == "/api/record/start":
                try:
                    minutes = int(parse_qs(urlparse(self.path).query).get("minutes", ["0"])[0])
                except ValueError:
                    minutes = 0
                engine.start_recording(minutes=minutes if 0 < minutes <= 24 * 60 else None)
                return self._send(200, json.dumps(engine.recording_state()), "application/json")
            if path == "/api/record/stop":
                engine.stop_recording()
                return self._send(200, json.dumps(engine.recording_state()), "application/json")
            if path == "/api/auto-identify":
                q = parse_qs(urlparse(self.path).query)
                if auto is None:
                    return self._send(400, json.dumps({"error": "not available"}), "application/json")
                if q.get("enabled", ["0"])[0] == "1":
                    try:
                        auto.enable(consent=q.get("consent", ["0"])[0] == "1")
                    except PermissionError:
                        return self._send(400, json.dumps({"error": "consent required"}), "application/json")
                else:
                    auto.disable()
                return self._send(200, json.dumps(auto.status()), "application/json")
            if path == "/api/browser-helper/install":
                import sys
                from . import nativehost
                try:
                    manifest = nativehost.install(engine.data_dir, exe=sys.executable)
                    ext = nativehost.copy_extension(engine.data_dir)
                except (OSError, TypeError) as e:
                    return self._send(500, json.dumps({"error": str(e)}), "application/json")
                return self._send(200, json.dumps({"manifest": str(manifest), "extension_dir": str(ext)}), "application/json")
            if path == "/api/popout":
                q = parse_qs(urlparse(self.path).query)
                def whole(name, default):                  # each number on its own: one bad value must not spoil the other
                    try:
                        return min(max(int(q.get(name, [str(default)])[0]), 0), 10000)
                    except ValueError:
                        return default
                x, y = whole("x", 0), whole("y", 40)
                if launch_mini is None:
                    return self._send(200, json.dumps({"launched": False}), "application/json")
                url = f"http://127.0.0.1:{self.server.server_address[1]}/?t={issue_code()}&view=compact&mini=1"
                got = launch_mini(url, x, y)
                return self._send(200, json.dumps({"launched": bool(got), **(got or {})}), "application/json")
            if path == "/api/evidence/timestamp":
                from .timestamp import TimestampFailed
                if parse_qs(urlparse(self.path).query).get("consent", ["0"])[0] != "1":
                    return self._send(400, json.dumps({"error": "consent required"}), "application/json")
                try:
                    done = engine.timestamp_evidence()
                except TimestampFailed as e:           # say why, change nothing
                    return self._send(502, json.dumps({"error": str(e), "tsa_url": engine.tsa_url()}), "application/json")
                if done is None:
                    return self._send(400, json.dumps({"error": "create the evidence package first"}), "application/json")
                return self._send(200, json.dumps(engine.recording_state()), "application/json")
            if path == "/api/evidence":
                try:
                    zip_path = engine.build_evidence()
                except OSError:
                    zip_path = None
                if not zip_path:
                    return self._send(400, json.dumps({"error": "record something first"}), "application/json")
                return self._send(200, json.dumps(engine.recording_state()), "application/json")
            if path == "/api/receipt":
                ip = parse_qs(urlparse(self.path).query).get("ip", [""])[0]
                rc = engine.receipts
                # only IPs this device actually talked to: the endpoint cannot be used as an open lookup proxy
                if rc is None or not rc.valid_target(ip) or engine.ip_activity(ip) is None:
                    return self._send(400, json.dumps({"error": "unknown or non-public address"}), "application/json")
                from .netutil import LookupFailed
                try:
                    r = rc.create(ip)
                except LookupFailed as e:      # the registry could not be asked: say why, save nothing
                    return self._send(502, json.dumps({"error": str(e)}), "application/json")
                except RuntimeError:
                    return self._send(409, json.dumps({"error": "lookup already running"}), "application/json")
                r = {**r, "activity": engine.ip_activity(ip)}
                return self._send(200, json.dumps(r), "application/json")
            if path != "/api/quit":
                return self._send(404, "not found")
            self._send(200, json.dumps({"stopped": True}), "application/json")
            threading.Thread(target=self.server.shutdown, daemon=True).start()

        do_HEAD = do_PUT = do_DELETE = lambda self: self._send(405, "method not allowed")

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def run_ticker(engine, stop: threading.Event, interval=1.0):
    def loop():
        engine.tick()                       # baseline
        while not stop.wait(interval):
            engine.tick()
    t = threading.Thread(target=loop, daemon=True, name="tol-collector")
    t.start()
    return t
