"""Windows reader for the TOL collector, built on PowerShell's `Get-NetTCPConnection` (ships with Windows 10/11).

It lists every TCP connection with its remote address and owning program. Windows does not give per-connection byte
counts to a normal (non-administrator) program, so this reader reports `bytes_sent` and `bytes_received` as 0 and the
collector runs in presence mode: one entry per connection TOL sees, with no amounts. The dashboard says so.

When TOL runs as Administrator, `BytesReader` adds real byte counts: it switches on Windows' per-connection TCP
statistics (`SetPerTcpConnectionEStats`, data class) for each established connection and reads `DataBytesOut` /
`DataBytesIn` from `GetPerTcpConnectionEStats`. Counting starts when TOL first sees a connection, so earlier traffic on
an already-open connection is not included. Without administrator rights none of this is allowed, and the presence mode
above is used.

UNVERIFIED ON A REAL WINDOWS PC until a person has run `tol --diagnose` there; GitHub's Windows machines test it.
"""
import ctypes
import ipaddress
import json
import shutil
import socket
import struct
import subprocess
import sys

POWERSHELL_SCRIPT = (
    "$p=@{}; Get-Process | ForEach-Object { $p[[int]$_.Id]=$_.ProcessName }; "
    "Get-NetTCPConnection | ForEach-Object { [pscustomobject]@{la=[string]$_.LocalAddress;lp=[int]$_.LocalPort;"
    "ra=[string]$_.RemoteAddress;rp=[int]$_.RemotePort;st=[int]$_.State;pid=[int]$_.OwningProcess;"
    "name=$p[[int]$_.OwningProcess]} } | ConvertTo-Json -Compress"
)
CMD = ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", POWERSHELL_SCRIPT]

# Windows TCP_STATE numbers -> the Linux numbers the collector uses (1 = established, 10 = listen)
STATES = {1: 7, 2: 10, 3: 2, 4: 3, 5: 1, 6: 4, 7: 5, 8: 8, 9: 11, 10: 9, 11: 6, 12: 7}
SYSTEM_PIDS = {0: "System Idle", 4: "System"}


def run_powershell(timeout: float = 30) -> str:
    if not shutil.which("powershell"):
        raise OSError("powershell not found (this reader is for Windows)")
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        out = subprocess.run(CMD, capture_output=True, text=True, timeout=timeout, creationflags=flags)
    except subprocess.TimeoutExpired:       # a slow or busy PC: skip this reading (the engine counts it), do not stop collecting
        raise OSError(f"powershell took longer than {timeout:.0f} seconds") from None
    if out.returncode != 0 and not out.stdout.strip():
        raise OSError(f"powershell failed ({out.returncode}): {out.stderr.strip()[:200]}")
    return out.stdout


def parse_connections(text: str) -> list:
    """PowerShell JSON -> socket dicts in the shape tol_collector.Collector expects. Unconnected rows are dropped."""
    text = text.strip().lstrip("﻿")
    if not text:
        return []
    data = json.loads(text)
    if isinstance(data, dict):                    # ConvertTo-Json gives a bare object for exactly one connection
        data = [data]
    sockets = []
    for row in data:
        try:
            remote = str(row["ra"]).split("%")[0]
            addr = ipaddress.ip_address(remote)
            ipaddress.ip_address(str(row["la"]).split("%")[0])
            if addr.is_unspecified or not row["rp"]:
                continue
            pid = int(row["pid"])
            name = row.get("name") or SYSTEM_PIDS.get(pid) or "unknown"
            sockets.append({
                "family": 6 if addr.version == 6 else 4,
                "state": STATES.get(int(row["st"]), 0),
                "src": str(row["la"]).split("%")[0], "sport": int(row["lp"]), "dst": remote, "dport": int(row["rp"]),
                "uid": None, "inode": f"{pid}|{row['la']}:{row['lp']}-{remote}:{row['rp']}",
                "bytes_sent": 0, "bytes_received": 0,
                "pid": pid, "process": name, "proto": "tcp",
            })
        except (KeyError, ValueError, TypeError):
            continue
    return sockets


def read_windows_sockets() -> list:
    return parse_connections(run_powershell())


# ---- byte counts through the per-connection TCP statistics API (administrator only) -------------------------------

ESTATS_DATA = 1          # TCP_ESTATS_TYPE: TcpConnectionEstatsData
MIB_ESTABLISHED = 5      # MIB_TCP_STATE_ESTAB
NO_ERROR = 0


class _Row4(ctypes.Structure):                      # MIB_TCPROW
    _fields_ = [("state", ctypes.c_uint32), ("local_addr", ctypes.c_uint32), ("local_port", ctypes.c_uint32),
                ("remote_addr", ctypes.c_uint32), ("remote_port", ctypes.c_uint32)]


class _Row6(ctypes.Structure):                      # MIB_TCP6ROW
    _fields_ = [("state", ctypes.c_uint32), ("local_addr", ctypes.c_ubyte * 16), ("local_scope", ctypes.c_uint32),
                ("local_port", ctypes.c_uint32), ("remote_addr", ctypes.c_ubyte * 16),
                ("remote_scope", ctypes.c_uint32), ("remote_port", ctypes.c_uint32)]


class _DataRw(ctypes.Structure):                    # TCP_ESTATS_DATA_RW_v0
    _fields_ = [("enable", ctypes.c_ubyte)]


class _DataRod(ctypes.Structure):                   # TCP_ESTATS_DATA_ROD_v0
    _fields_ = [("data_bytes_out", ctypes.c_uint64), ("data_segs_out", ctypes.c_uint64),
                ("data_bytes_in", ctypes.c_uint64), ("data_segs_in", ctypes.c_uint64),
                ("segs_out", ctypes.c_uint64), ("segs_in", ctypes.c_uint64),
                ("soft_errors", ctypes.c_uint32), ("soft_error_reason", ctypes.c_uint32),
                ("snd_una", ctypes.c_uint32), ("snd_nxt", ctypes.c_uint32), ("snd_max", ctypes.c_uint32),
                ("thru_bytes_acked", ctypes.c_uint64), ("rcv_nxt", ctypes.c_uint32),
                ("thru_bytes_received", ctypes.c_uint64)]


def _port(p: int) -> int:
    return socket.htons(int(p))                      # Windows keeps the port in network byte order in a DWORD


def make_row(src: str, sport: int, dst: str, dport: int):
    """A MIB_TCPROW (IPv4) or MIB_TCP6ROW (IPv6) naming one established connection, as the statistics API wants it."""
    a, b = ipaddress.ip_address(src.split("%")[0]), ipaddress.ip_address(dst.split("%")[0])
    if a.version == 4 and b.version == 4:
        return _Row4(MIB_ESTABLISHED, struct.unpack("<I", a.packed)[0], _port(sport),
                     struct.unpack("<I", b.packed)[0], _port(dport)), 4
    if a.version == 6 and b.version == 6:
        scope = lambda t: int(t.split("%")[1]) if "%" in t and t.split("%")[1].isdigit() else 0  # noqa: E731
        return _Row6(MIB_ESTABLISHED, (ctypes.c_ubyte * 16)(*a.packed), scope(src), _port(sport),
                     (ctypes.c_ubyte * 16)(*b.packed), scope(dst), _port(dport)), 6
    raise ValueError("mixed address families")


class _Iphlpapi:
    """The four functions used, with the argument types set so 64-bit Windows passes pointers correctly."""

    def __init__(self):
        dll = ctypes.WinDLL("iphlpapi")                       # AttributeError/OSError off Windows: caller handles
        p = ctypes.c_void_p
        u32 = ctypes.c_uint32
        self.set4, self.set6 = dll.SetPerTcpConnectionEStats, dll.SetPerTcp6ConnectionEStats
        self.get4, self.get6 = dll.GetPerTcpConnectionEStats, dll.GetPerTcp6ConnectionEStats
        for f in (self.set4, self.set6):
            f.argtypes, f.restype = [p, ctypes.c_int, p, u32, u32, u32], u32
        for f in (self.get4, self.get6):
            f.argtypes, f.restype = [p, ctypes.c_int, p, u32, u32, p, u32, u32, p, u32, u32], u32


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


class BytesReader:
    """`read()` is a drop-in for `read_windows_sockets` that fills in real byte counts. A connection whose statistics
    cannot be switched on or read gets `bytes_sent` None, which the collector skips rather than showing a false 0."""

    def __init__(self, api=None, admin=None, lister=None):
        self.error = None
        self._lister = lister or read_windows_sockets
        try:
            self._api = api or _Iphlpapi()
        except (AttributeError, OSError) as e:
            self._api, self.error = None, f"Windows statistics API not available: {e}"
        self.available = self._api is not None and (is_admin() if admin is None else admin)
        if self._api is not None and not self.available:
            self.error = "not running as Administrator"
        self._enabled = set()

    def _calls(self, version):
        return (self._api.set4, self._api.get4) if version == 4 else (self._api.set6, self._api.get6)

    def _bytes(self, s):
        row, version = make_row(s["src"], s["sport"], s["dst"], s["dport"])
        setter, getter = self._calls(version)
        key = (s["src"], s["sport"], s["dst"], s["dport"])
        if key not in self._enabled:
            rw = _DataRw(1)
            if setter(ctypes.byref(row), ESTATS_DATA, ctypes.byref(rw), 0, ctypes.sizeof(rw), 0) != NO_ERROR:
                return None
            self._enabled.add(key)
        rod = _DataRod()
        if getter(ctypes.byref(row), ESTATS_DATA, None, 0, 0, None, 0, 0, ctypes.byref(rod), 0,
                  ctypes.sizeof(rod)) != NO_ERROR:
            self._enabled.discard(key)
            return None
        return rod.data_bytes_out, rod.data_bytes_in

    def read(self) -> list:
        socks = self._lister()
        for s in socks:
            if s["state"] != 1:                      # only established connections carry counters
                s["bytes_sent"] = s["bytes_received"] = None
                continue
            try:
                got = self._bytes(s)
            except ValueError:
                got = None
            if got is None:
                s["bytes_sent"] = s["bytes_received"] = None
            else:
                s["bytes_sent"], s["bytes_received"] = got
        self._enabled &= {(x["src"], x["sport"], x["dst"], x["dport"]) for x in socks}   # forget closed connections
        return socks
