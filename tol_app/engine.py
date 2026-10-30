"""Aggregation, alerts and persistence on top of the collector."""
import json
import threading
import time
from collections import deque
from pathlib import Path

WINDOW = 60                      # seconds for "recent" figures
RATE_WINDOW = 10
LARGE_UPLOAD_BYTES = 25 * 1024 * 1024
UNIDENTIFIED_UPLOAD_BYTES = 256 * 1024
ALERT_COOLDOWN = 600
WARMUP = 30                      # seconds before "new destination" alerts start
LOG_ROTATE_BYTES = 10 * 1024 * 1024
MAX_RECORDED_EVENTS = 100_000     # a recording keeps at most this many connection samples
UNIDENTIFIED = ("none", "pending", "network-owner")


def display_name(entry) -> str:
    """Unidentified destinations are named by address so each stays its own row."""
    if entry["label_confidence"] == "none":
        return entry["hostname"]
    return entry["company_name"]


class Engine:
    def __init__(self, collector, data_dir=None, clock=time.time, large_upload=LARGE_UPLOAD_BYTES,
                 unidentified_upload=UNIDENTIFIED_UPLOAD_BYTES):
        self.collector, self.clock = collector, clock
        self.large_upload, self.unidentified_upload = large_upload, unidentified_upload
        self.started = clock()
        self.rows, self.alerts = {}, deque(maxlen=200)
        self._recent = deque()                 # (ts, row_key, sent, recv)
        self._cooldown = {}
        self.totals = {"sent": 0, "received": 0}
        self.ips = {}                          # ip -> what this device did with it (feeds receipts)
        self.receipts = None                   # set by the launcher: tol_app.receipts.Receipts
        self.settings = None                   # set by the launcher: tol_app.settings.Settings
        self.lock = threading.Lock()
        self.log_path = Path(data_dir) / "activity.jsonl" if data_dir else None
        if self.log_path:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.errors = 0
        self.data_dir = Path(data_dir) if data_dir else None
        self._rec = None                       # active recording: {"started", "events", "dropped"}
        self.last_recording = None             # {"json": path, "csv": path, "started", "stopped", "events"}

    # --- ingest ---------------------------------------------------------------
    def tick(self, now=None):
        now = self.clock() if now is None else now
        try:
            entries = self.collector.poll(now)
        except OSError:
            self.errors += 1
            return []
        with self.lock:
            for e in entries:
                self._record(e, now)
            self._evaluate(now)
        if entries and self.log_path:
            self._append_log(entries)
        rec = self._rec
        if rec is not None and rec["ends"] is not None and now >= rec["ends"]:
            self.stop_recording(now)
        if entries and self._rec is not None:
            with self.lock:
                room = MAX_RECORDED_EVENTS - len(self._rec["events"])
                self._rec["events"].extend(entries[:max(room, 0)])
                self._rec["dropped"] += max(len(entries) - max(room, 0), 0)
        return entries

    def _record(self, e, now):
        name = display_name(e)
        key = (name, e["process_name"])
        new = key not in self.rows
        row = self.rows.setdefault(key, {
            "name": name, "process": e["process_name"], "pid": e.get("pid"),
            "source": e["label_source"], "confidence": e["label_confidence"],
            "category": None, "endpoints": set(), "protocols": set(), "hostnames": set(),
            "total_sent": 0, "total_received": 0, "first_seen": now, "last_seen": now})
        st = self.ips.setdefault(e["endpoint_ip"], {"sent": 0, "received": 0, "processes": set(),
                                                    "ports": set(), "first_seen": now, "last_seen": now})
        st["sent"] += e["bytes_sent"]
        st["received"] += e["bytes_received"]
        st["processes"].add(e["process_name"])
        st["ports"].add(e["endpoint_port"])
        st["last_seen"] = now
        row["endpoints"].add(f"{e['endpoint_ip']}:{e['endpoint_port']}")
        row["protocols"].add(e["protocol"])
        if e["hostname"] != e["endpoint_ip"]:
            row["hostnames"].add(e["hostname"])
        row["total_sent"] += e["bytes_sent"]
        row["total_received"] += e["bytes_received"]
        row["last_seen"] = now
        row["confidence"], row["source"] = e["label_confidence"], e["label_source"]
        self.totals["sent"] += e["bytes_sent"]
        self.totals["received"] += e["bytes_received"]
        self._recent.append((now, key, e["bytes_sent"], e["bytes_received"]))
        if new and (e["bytes_sent"] > 0 or not e.get("bytes_known", True)) and now - self.started > WARMUP:
            self._alert(now, "INFO", "NEW_DESTINATION", key,
                        (f"First time sending data to {name} (from {e['process_name']})" if e.get("bytes_known", True)
                         else f"First connection to {name} (from {e['process_name']})"), cooldown=0)

    # --- alerts ---------------------------------------------------------------
    def _recent_sums(self, now):
        while self._recent and self._recent[0][0] < now - WINDOW:
            self._recent.popleft()
        sums = {}
        for ts, key, sent, recv in self._recent:
            s = sums.setdefault(key, [0, 0, 0])
            s[0] += sent
            s[1] += recv
            if ts >= now - RATE_WINDOW:
                s[2] += sent
        return sums

    def _evaluate(self, now):
        for key, (sent, _, _) in self._recent_sums(now).items():
            row = self.rows[key]
            if sent >= self.large_upload:
                self._alert(now, "HIGH", "LARGE_UPLOAD", key,
                            f"{_fmt(sent)} sent to {row['name']} in the last minute ({row['process']})")
            elif row["confidence"] in UNIDENTIFIED and sent >= self.unidentified_upload:
                self._alert(now, "MEDIUM", "UNIDENTIFIED_UPLOAD", key,
                            f"{_fmt(sent)} sent to {row['name']}, whose vendor is not confirmed ({row['process']})")

    def _alert(self, now, severity, kind, key, message, cooldown=ALERT_COOLDOWN):
        ck = (kind, key)
        if now < self._cooldown.get(ck, 0):
            return
        self._cooldown[ck] = now + cooldown
        self.alerts.appendleft({"time": now, "severity": severity, "kind": kind,
                                "owner": key[0], "process": key[1], "message": message})

    # --- output ---------------------------------------------------------------
    def state(self, now=None):
        now = self.clock() if now is None else now
        with self.lock:
            sums = self._recent_sums(now)
            rows = []
            for key, r in self.rows.items():
                s = sums.get(key, [0, 0, 0])
                rows.append({
                    "name": r["name"], "process": r["process"], "pid": r["pid"],
                    "source": r["source"], "confidence": r["confidence"],
                    "endpoints": sorted(r["endpoints"])[:6], "endpoint_count": len(r["endpoints"]),
                    "hostnames": sorted(r["hostnames"])[:3], "protocols": sorted(r["protocols"]),
                    "sent_recent": s[0], "received_recent": s[1], "send_rate": s[2] / RATE_WINDOW,
                    "total_sent": r["total_sent"], "total_received": r["total_received"],
                    "last_seen": r["last_seen"], "active": now - r["last_seen"] <= RATE_WINDOW,
                })
            rows.sort(key=lambda r: (-r["sent_recent"], -r["total_sent"], -r["last_seen"]))
            return {"now": now, "uptime": now - self.started, "totals": dict(self.totals),
                    "rows": rows, "alerts": list(self.alerts)[:50], "collector_errors": self.errors,
                    "bytes_known": getattr(self.collector, "bytes_known", True)}

    # --- recording ------------------------------------------------------------
    def start_recording(self, now=None, minutes=None):
        """Begin capturing everything seen from now on. `minutes` auto-stops and saves it.
        Returns False if already recording."""
        now = self.clock() if now is None else now
        with self.lock:
            if self._rec is not None:
                return False
            self._rec = {"started": now, "events": [], "dropped": 0,
                         "ends": now + minutes * 60 if minutes else None}
            return True

    def stop_recording(self, now=None):
        """Stop and write the recording to <data_dir>/recordings as .json (full) and .csv (per destination)."""
        now = self.clock() if now is None else now
        with self.lock:
            rec, self._rec = self._rec, None
            if rec is None:
                return None
            alerts = [a for a in self.alerts if rec["started"] <= a["time"] <= now]
        dests = {}
        from .gpc import is_observation
        for e in rec["events"]:
            if is_observation(e):
                continue                       # browser-signal observations are chained but are not connections
            name = display_name(e)
            d = dests.setdefault((name, e["process_name"]), {
                "destination": name, "process": e["process_name"], "confidence": e["label_confidence"],
                "sent_bytes": 0, "received_bytes": 0, "endpoints": set(), "hostnames": set()})
            d["sent_bytes"] += e["bytes_sent"]
            d["received_bytes"] += e["bytes_received"]
            d["endpoints"].add(f"{e['endpoint_ip']}:{e['endpoint_port']}")
            if e["hostname"] != e["endpoint_ip"]:
                d["hostnames"].add(e["hostname"])
        summary = sorted(({**d, "endpoints": sorted(d["endpoints"]), "hostnames": sorted(d["hostnames"])}
                          for d in dests.values()), key=lambda d: -d["sent_bytes"])
        report = {
            "tol_recording": 1, "started": rec["started"], "stopped": now, "duration_seconds": now - rec["started"],
            "totals": {"sent_bytes": sum(d["sent_bytes"] for d in summary),
                       "received_bytes": sum(d["received_bytes"] for d in summary)},
            "destinations": summary, "alerts": alerts, "events": rec["events"],
            "events_dropped": rec["dropped"],
            "receipts": [],
            "note": "Shows who this device sent data to and how much, not what the data contained.",
        }
        from .receipts import attach
        attach(report, self.receipts)          # registered holder + proof pointers on each destination
        out = {"started": rec["started"], "stopped": now, "events": len(rec["events"]), "json": None, "csv": None}
        if self.data_dir is not None:
            folder = self.data_dir / "recordings"
            folder.mkdir(parents=True, exist_ok=True)
            stem = "tol-recording-" + time.strftime("%Y%m%d-%H%M%S", time.localtime(rec["started"]))
            try:
                (folder / f"{stem}.json").write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
                from .evidence import write_summary_csv
                write_summary_csv(folder / f"{stem}.csv", summary)
                out["json"], out["csv"] = str(folder / f"{stem}.json"), str(folder / f"{stem}.csv")
            except OSError:
                self.errors += 1
        self.last_recording = out
        return out

    def ingest_observations(self, items, now=None):
        """Browser-signal observations from the extension. Each one is checked on its own: a good one is recorded even if
        another in the same batch is not. Returns {"recorded": n, "rejected": m, "reason": first reason or ""}; nothing
        about a rejected item is kept except why. Observations are kept only while a recording is running.
        Raises ValueError only when the batch itself is not a list of the allowed size."""
        from .gpc import MAX_BATCH, clean
        if not isinstance(items, list) or len(items) > MAX_BATCH:
            raise ValueError(f"send a list of at most {MAX_BATCH} observations")
        now = self.clock() if now is None else now
        cleaned, rejected, reason = [], 0, ""
        for i in items:
            try:
                cleaned.append(clean(i, now))
            except ValueError as e:
                rejected += 1
                reason = reason or str(e)
        with self.lock:
            if self._rec is None:
                return {"recorded": 0, "rejected": rejected, "reason": reason}
            room = MAX_RECORDED_EVENTS - len(self._rec["events"])
            kept = cleaned[:max(room, 0)]
            self._rec["events"].extend(kept)
            self._rec["dropped"] += len(cleaned) - len(kept)
        return {"recorded": len(kept), "rejected": rejected, "reason": reason}

    def _last_events(self):
        last = self.last_recording
        if not last or not last.get("json"):
            return []
        try:
            return json.loads(Path(last["json"]).read_text(encoding="utf-8")).get("events", [])
        except (OSError, ValueError):
            return []

    def site_pages(self):
        """Pages the browser extension reported in the last finished recording, busiest first."""
        from .gpc import is_observation
        pages = {}
        for e in self._last_events():
            if is_observation(e):
                p = pages.setdefault(e["page"], {"page": e["page"], "with_signal": 0, "without_signal": 0})
                p["with_signal" if e["gpc"] else "without_signal"] += e["count"]
        return sorted(pages.values(), key=lambda p: -(p["with_signal"] + p["without_signal"]))

    def site_report(self, page, window_seconds=None):
        from .gpc import site_report
        return site_report(self._last_events(), page, window_seconds)

    def build_evidence(self):
        """Package the last finished recording (files + manifest + verifier). Returns the zip path or None."""
        last = self.last_recording
        if not last or not last.get("json") or self.data_dir is None:
            return None
        from .evidence import build_package
        from .receipts import attach
        # refresh with the receipts that exist now, so anything identified after Stop is included
        report = attach(json.loads(Path(last["json"]).read_text(encoding="utf-8")), self.receipts)
        pkg = build_package(report, self.data_dir / "evidence")
        last["zip"], last["package_folder"] = str(pkg["zip"]), str(pkg["folder"])
        return last["zip"]

    def tsa_url(self) -> str:
        from .timestamp import DEFAULT_TSA
        return (self.settings.get("tsa_url") if self.settings is not None else None) or DEFAULT_TSA

    def timestamp_evidence(self, request=None):
        """Add an independent trusted timestamp to the evidence package just built. Sends only a fingerprint of the
        package's manifest to the timestamp authority. Returns the details, or None if there is no package yet.
        Raises timestamp.TimestampFailed (with the reason) if the authority cannot be used."""
        last = self.last_recording
        if not last or not last.get("package_folder"):
            return None
        from .evidence import add_timestamp
        detail = add_timestamp(last["package_folder"], self.tsa_url(), request=request)
        last["zip"] = detail["zip"]
        last["timestamp"] = {k: detail[k] for k in ("tsa_url", "gen_time_utc", "serial", "policy")}
        return last["timestamp"]

    def recording_state(self, now=None):
        now = self.clock() if now is None else now
        with self.lock:
            rec = self._rec
            return {"active": rec is not None,
                    "started": rec["started"] if rec else None,
                    "ends": rec["ends"] if rec else None,
                    "tsa_url": self.tsa_url(),
                    "events": len(rec["events"]) if rec else 0,
                    "last": self.last_recording}

    def unidentified_ips(self):
        """Public addresses seen so far with no covering receipt, busiest first. Excludes local addresses and rows
        the user's own registry verifies. "Likely" rows (a name guessed from the hostname) are included: they have
        a label but no independent registry proof."""
        with self.lock:
            cands = {}
            for r in self.rows.values():
                if r["source"] == "local" or r["confidence"] == "verified":
                    continue
                for ep in r["endpoints"]:
                    ip = ep.rsplit(":", 1)[0]
                    cands[ip] = cands.get(ip, 0) + r["total_sent"]
        out = []
        for ip, sent in sorted(cands.items(), key=lambda kv: -kv[1]):
            if self.receipts is not None and (not self.receipts.valid_target(ip) or self.receipts.find(ip)):
                continue
            out.append(ip)
        return out

    def ip_activity(self, ip):
        """What this device observed for one IP, for attaching to its receipt."""
        with self.lock:
            st = self.ips.get(ip)
            if not st:
                return None
            return {"bytes_sent": st["sent"], "bytes_received": st["received"],
                    "processes": sorted(st["processes"]), "ports": sorted(st["ports"]),
                    "first_seen": st["first_seen"], "last_seen": st["last_seen"]}

    def _append_log(self, entries):
        try:
            if self.log_path.exists() and self.log_path.stat().st_size > LOG_ROTATE_BYTES:
                self.log_path.replace(self.log_path.with_suffix(".jsonl.1"))
            with open(self.log_path, "a", encoding="utf-8") as f:
                for e in entries:
                    f.write(json.dumps(e, sort_keys=True) + "\n")
        except OSError:
            self.errors += 1


def _fmt(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
