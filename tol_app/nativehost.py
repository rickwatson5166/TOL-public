"""The helper a browser starts for the TOL extension (browser "native messaging"): it passes the extension's observations
to the TOL that is running on this machine, and nothing else.

The browser starts this program only for the extension named in its manifest, and speaks to it over stdin/stdout. The helper
reads TOL's token from the user's own TOL folder (a file only that user can read) and posts to 127.0.0.1. Any other program
running as the same user could do the same, so this proves the data came from this user's session, not from the extension
alone; see docs/METHOD.md.
"""
import http.client
import json
import os
import struct
import sys
from pathlib import Path

HOST_NAME = "org.tol.observer"
EXTENSION_ID = "tol-observer@tol.local"
MAX_MESSAGE = 512 * 1024


def read_message(stream):
    head = stream.read(4)
    if len(head) < 4:
        return None
    (n,) = struct.unpack("<I", head)
    if n > MAX_MESSAGE:
        raise ValueError("message too large")
    return json.loads(stream.read(n).decode("utf-8"))


def write_message(stream, obj):
    data = json.dumps(obj).encode("utf-8")
    stream.write(struct.pack("<I", len(data)) + data)
    stream.flush()


def forward(items, data_dir):
    """Post a batch to the running TOL. Returns TOL's answer, or {"error": ...}; never raises."""
    d = Path(data_dir)
    try:
        port = json.loads((d / "ingest.json").read_text(encoding="utf-8"))["port"]
        token = (d / "token").read_text(encoding="utf-8").strip()
        c = http.client.HTTPConnection("127.0.0.1", int(port), timeout=5)
        c.request("POST", "/api/observations", json.dumps(items), {"X-TOL-Ingest": token, "Content-Type": "application/json"})
        r = c.getresponse()
        body = json.loads(r.read().decode("utf-8") or "{}")
        return body if r.status == 200 else {"error": body.get("error", f"TOL answered {r.status}")}
    except (OSError, ValueError, KeyError):
        return {"error": "TOL is not running"}


def serve(stdin, stdout, data_dir):
    while True:
        msg = read_message(stdin)
        if msg is None:
            return
        write_message(stdout, forward(msg, data_dir))


def bundled_extension_dir():
    """Where the extension's files are: inside the packaged app, or the source tree."""
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
    return base / "extension" / "firefox"


def copy_extension(data_dir):
    """Put a copy of the extension in TOL's own folder, at a path that does not change when the app is updated. Returns it."""
    import shutil
    src, dest = bundled_extension_dir(), Path(data_dir) / "extension" / "firefox"
    if not (src / "manifest.json").is_file():
        raise OSError("the extension files are not part of this copy of TOL")
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(src, dest)
    return dest


def manifest(path):
    return {"name": HOST_NAME, "description": "Passes the TOL extension's observations to TOL on this machine",
            "path": str(path), "type": "stdio", "allowed_extensions": [EXTENSION_ID]}


def manifest_dir(platform=None, home=None):
    platform, home = platform or sys.platform, Path(home or Path.home())
    if platform == "darwin":
        return home / "Library/Application Support/Mozilla/NativeMessagingHosts"
    if platform.startswith("linux"):
        return home / ".mozilla/native-messaging-hosts"
    return None                                           # Windows: the manifest sits in TOL's folder and the registry points at it


def _set_registry(manifest_path):
    """Windows: tell Firefox where the helper's manifest is (current user only, no administrator rights)."""
    import winreg
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, "Software\\Mozilla\\NativeMessagingHosts\\" + HOST_NAME) as k:
        winreg.SetValueEx(k, "", 0, winreg.REG_SZ, str(manifest_path))


def stable_app_paths(exe, home=None):
    """Where a packaged Mac app can be found again later. macOS runs an app that has not been approved from a temporary
    copy (".../AppTranslocation/<random>/d/TOL.app") whose path changes at every start, so that path must not be the only
    one the launcher knows."""
    home = Path(home or Path.home())
    paths = []
    if "/AppTranslocation/" not in str(exe):
        paths.append(str(exe))
    paths += ["/Applications/TOL.app/Contents/MacOS/TOL", str(home / "Applications/TOL.app/Contents/MacOS/TOL")]
    if str(exe) not in paths:
        paths.append(str(exe))                          # last resort: the copy that is running now
    return paths


def install(data_dir, exe=None, platform=None, home=None, registry=None):
    """Write the launcher and the Firefox manifest. Returns the manifest path. Touches only the user's own folders
    (and, on Windows, the current user's registry key)."""
    platform = platform or sys.platform
    windows = platform.startswith("win")
    d = Path(data_dir)
    d.mkdir(parents=True, exist_ok=True)
    exe = exe or sys.executable
    frozen = getattr(sys, "frozen", False)                # the packaged app is TOL itself
    if windows:
        launcher = d / "tol-native-host.bat"
        run = f'"{exe}"' if frozen else f'set "PYTHONPATH={Path(__file__).resolve().parent.parent}" && "{exe}" -m tol_app'
        launcher.write_text(f'@echo off\r\n{run} --native-host --data-dir "{d}"\r\n', encoding="utf-8")
        out = d / f"{HOST_NAME}.json"
    else:
        target = manifest_dir(platform, home)
        if target is None:
            raise OSError("installing the helper is supported on macOS, Windows and Linux")
        launcher = d / "tol-native-host"
        if frozen:
            tries = " ".join(f'"{p}"' for p in stable_app_paths(exe, home))
            launcher.write_text(f'#!/bin/sh\nfor p in {tries}; do\n  [ -x "$p" ] && exec "$p" --native-host --data-dir "{d}"\ndone\nexit 1\n',
                                encoding="utf-8")
        else:
            run = f'PYTHONPATH="{Path(__file__).resolve().parent.parent}" "{exe}" -m tol_app'
            launcher.write_text(f'#!/bin/sh\nexec env {run} --native-host --data-dir "{d}"\n', encoding="utf-8")
        launcher.chmod(0o700)
        target.mkdir(parents=True, exist_ok=True)
        out = target / f"{HOST_NAME}.json"
    out.write_text(json.dumps(manifest(launcher), indent=2), encoding="utf-8")
    if windows:
        (registry or _set_registry)(out)
    return out


def main(data_dir):
    if sys.platform == "win32":                           # the browser's messages are binary; no newline translation
        import msvcrt
        msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    serve(sys.stdin.buffer, sys.stdout.buffer, data_dir)
    return 0
