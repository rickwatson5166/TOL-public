"""Windows reader for the TOL collector, built on PowerShell's `Get-NetTCPConnection` (ships with Windows 10/11).

It lists every TCP connection with its remote address and owning program. Windows does not give per-connection byte
counts to a normal (non-administrator) program, so this reader reports `bytes_sent` and `bytes_received` as 0 and the
collector runs in presence mode: one entry per connection TOL sees, with no amounts. The dashboard says so.

UNVERIFIED ON A REAL WINDOWS PC until a person has run `tol --diagnose` there; GitHub's Windows machines test it.
"""
import ipaddress
import json
import shutil
import subprocess

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
