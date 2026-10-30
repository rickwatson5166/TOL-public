"""Open the dashboard in its own small browser window, started by TOL itself.

Why: a web page can only *ask* the browser for a small pop-up (window.open with a size). Chrome on some Macs ignores the
request and opens a full-size window. Starting the browser ourselves with an explicit size (`--app` + `--window-size`) is
not a request, so it is honoured. The window gets its own throw-away browser profile (inside TOL's data folder), so it
never touches the user's normal Chrome profile, tabs or extensions, and so the size flags always apply.

It only starts a Chromium-family browser that is already installed (Chrome, Chromium, Brave, Edge). If none is found the
caller falls back to the in-page pop-up. Nothing leaves the machine: the URL is 127.0.0.1.
"""
import ntpath
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

SIZE = (360, 600)
MAC_BROWSERS = (
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
)
WINDOWS_BROWSERS = (
    ("PROGRAMFILES", r"Google\Chrome\Application\chrome.exe"),
    ("PROGRAMFILES(X86)", r"Google\Chrome\Application\chrome.exe"),
    ("LOCALAPPDATA", r"Google\Chrome\Application\chrome.exe"),
    ("PROGRAMFILES(X86)", r"Microsoft\Edge\Application\msedge.exe"),     # Edge ships with Windows
    ("PROGRAMFILES", r"Microsoft\Edge\Application\msedge.exe"),
    ("PROGRAMFILES", r"BraveSoftware\Brave-Browser\Application\brave.exe"),
)
LINUX_BROWSERS = ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "brave-browser", "microsoft-edge")


def find_browser(platform=None, which=shutil.which, exists=os.path.exists):
    """Path of an installed Chromium-family browser, or None."""
    platform = platform or sys.platform
    if platform == "darwin":
        return next((p for p in MAC_BROWSERS if exists(p)), None)
    if platform.startswith("win"):
        paths = [ntpath.join(os.environ[var], rest) for var, rest in WINDOWS_BROWSERS if os.environ.get(var)]
        return next((p for p in paths if exists(p)), None)
    if platform.startswith("linux"):
        return next((p for p in (which(n) for n in LINUX_BROWSERS) if p), None)
    return None


def build_command(binary, url, profile, x, y, size=SIZE, extra=()):
    w, h = size
    for n in (x, y, w, h):
        if not isinstance(n, int) or not 0 <= n <= 20000:
            raise ValueError("window position and size must be whole numbers")
    return [binary, f"--app={url}", f"--window-size={w},{h}", f"--window-position={x},{y}",
            f"--user-data-dir={profile}", "--no-first-run", "--no-default-browser-check", *extra]


def mac_launch_command(command):
    """Start a Mac browser through Launch Services (`open`) instead of running its program file directly.

    Started directly, the browser counts as part of TOL, so macOS blames TOL for what the browser does by itself, such
    as its own updater touching the browser app ("TOL was prevented from modifying apps"). Started with `open`, the
    browser is its own app."""
    binary = command[0]
    cut = binary.find(".app/Contents/MacOS/")
    if cut < 0:
        return command
    return ["open", "-n", "-a", binary[:cut + 4], "--args", *command[1:]]


class MiniLauncher:
    def __init__(self, data_dir, find=find_browser, popen=subprocess.Popen, extra_args=(), platform=None,
                 run=subprocess.run, sleep=time.sleep):
        self.profile = Path(data_dir) / "mini-browser"
        self._find, self._popen, self._extra = find, popen, tuple(extra_args)
        self._platform = platform or sys.platform
        self._run, self._sleep = run, sleep
        self._proc = None

    def _clear_leftover(self):
        """Mac: stop a leftover small-window browser (its window is gone but the process lingers and swallows the new
        launch). Ask politely, wait until it is gone, then force it. Only processes started with TOL's own small-window
        profile folder are touched."""
        pattern = "--user-data-dir=" + re.sub(r"([.^$*+?()\[\]{}|\\])", r"\\\1", str(self.profile))

        def call(*cmd):
            return self._run(list(cmd), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, timeout=5).returncode

        def gone(wait):                                  # True once nothing with our profile is running
            for _ in range(int(wait / 0.2) + 1):
                if call("pgrep", "-f", "--", pattern) != 0:
                    return True
                self._sleep(0.2)
            return False
        try:
            if call("pgrep", "-f", "--", pattern) != 0:
                return
            call("pkill", "-f", "--", pattern)
            if not gone(2.0):
                call("pkill", "-9", "-f", "--", pattern)
                gone(1.0)
            self._sleep(0.3)
        except (OSError, subprocess.SubprocessError):
            pass

    def launch(self, url: str, x: int, y: int):
        """Start the small window. Returns {"browser": name, "already_open": bool}, or None if it cannot be done."""
        mac = self._platform == "darwin"
        # On a Mac closing the window leaves the browser process running, and `open` returns at once, so there is no
        # process to ask. The server knows whether the small window is open (it keeps asking for data) and checks first.
        if not mac and self._proc is not None and self._proc.poll() is None:
            return {"browser": "already running", "already_open": True}      # one small window at a time
        binary = self._find()
        if not binary:
            return None
        try:
            self.profile.mkdir(parents=True, exist_ok=True)
            if mac:
                self._clear_leftover()
            command = build_command(binary, url, str(self.profile), x, y, extra=self._extra)
            if mac:
                command = mac_launch_command(command)
            detach = ({"creationflags": getattr(subprocess, "DETACHED_PROCESS", 0)} if self._platform == "win32"
                      else {"start_new_session": True})
            self._proc = self._popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL, **detach)
        except (OSError, ValueError):
            return None
        return {"browser": Path(binary).name, "already_open": False}
