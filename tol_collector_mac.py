"""macOS reader for the TOL collector, built on `nettop` (ships with macOS, no install needed).

`nettop -L 1 -n -x` prints one CSV sample: a header row, then for every process a row like
`curl.1234,...` followed by one row per connection like
`tcp4 192.168.1.5:50123<->93.184.216.34:443,en0,Established,<bytes_in>,<bytes_out>,...`.
Columns are located by header name, not position, so extra or reordered columns are tolerated.

UNVERIFIED ON A REAL MAC: this was written without macOS access. Run `tol --diagnose` on the
machine; it shows exactly what nettop returned and what was parsed.
"""
import csv
import io
import ipaddress
import re
import shutil
import subprocess

NETTOP_CMD = ["nettop", "-L", "1", "-n", "-x"]
CONN_RE = re.compile(r"^(?P<proto>tcp|udp)(?P<v>\d*)\s+(?P<local>\S+)<->(?P<remote>\S+)$", re.I)
PROC_RE = re.compile(r"^(?P<name>.+)\.(?P<pid>\d+)$")
STATES = {"established": 1, "listen": 10, "syn_sent": 2, "syn_received": 3, "fin_wait_1": 4,
          "fin_wait_2": 5, "time_wait": 6, "closed": 7, "close_wait": 8, "last_ack": 9, "closing": 11}
LISTEN = 10


def run_nettop(timeout: float = 20) -> str:
    if not shutil.which("nettop"):
        raise OSError("nettop not found (this reader is for macOS)")
    out = subprocess.run(NETTOP_CMD, capture_output=True, text=True, timeout=timeout)
    if out.returncode != 0 and not out.stdout:
        raise OSError(f"nettop failed ({out.returncode}): {out.stderr.strip()[:200]}")
    return out.stdout


def parse_endpoint(text: str):
    """'93.184.216.34:443', '2607:f8b0::1.443' or '*:*' -> (ip, port) or None."""
    text = text.strip()
    m = re.match(r"^(?P<host>.+)[:.](?P<port>\d+)$", text)
    if not m:
        return None
    host = m.group("host").split("%")[0]
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return None
    return host, int(m.group("port"))


def _num(value):
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def parse_nettop(text: str) -> list:
    """nettop CSV -> socket dicts in the shape tol_collector.Collector expects.
    Wildcard/unconnected rows and rows without byte counters are dropped."""
    sockets, cols, process = [], None, None
    for row in csv.reader(io.StringIO(text)):
        if not row:
            continue
        lowered = [c.strip().lower() for c in row]
        if "bytes_in" in lowered and "bytes_out" in lowered:       # header row (repeats per sample)
            cols = {name: i for i, name in enumerate(lowered) if name}
            continue
        if cols is None:
            continue
        name_idx = 1 if "time" in cols else 0                       # the unnamed label column
        if len(row) <= max(name_idx, cols["bytes_in"], cols["bytes_out"]):
            continue
        label = row[name_idx].strip()
        conn = CONN_RE.match(label)
        if not conn:
            pm = PROC_RE.match(label)
            process = (pm.group("name"), int(pm.group("pid"))) if pm else None
            continue
        local, remote = parse_endpoint(conn["local"]), parse_endpoint(conn["remote"])
        if not local or not remote or process is None:
            continue
        sent, recv = _num(row[cols["bytes_out"]]), _num(row[cols["bytes_in"]])
        if sent is None or recv is None:
            continue
        state_text = row[cols["state"]].strip().lower() if "state" in cols and len(row) > cols["state"] else ""
        sockets.append({
            "family": 6 if ":" in remote[0] else 4,
            "state": STATES.get(state_text, 1 if conn["proto"].lower() == "tcp" else 0),
            "src": local[0], "sport": local[1], "dst": remote[0], "dport": remote[1],
            "uid": None, "inode": f"{process[1]}|{label}",
            "bytes_sent": sent, "bytes_received": recv,
            "pid": process[1], "process": process[0], "proto": conn["proto"].lower(),
        })
    return sockets


def read_mac_sockets() -> list:
    return parse_nettop(run_nettop())
