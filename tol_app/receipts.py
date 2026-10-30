"""Destination "receipts": a saved, hashed record of who an IP address belongs to.

A receipt joins what TOL saw (this device talked to IP x) with independent public evidence about x:
  - reverse DNS, forward-confirmed (a name only counts if it resolves back to the same IP)
  - the RDAP/WHOIS record for the IP's network block, stored verbatim with its SHA-256

Receipts are hash-chained in an append-only file (~/.tol/receipts.jsonl), so editing or deleting an
earlier one is detectable. This is tamper EVIDENCE, not a trusted timestamp: times come from this
device's clock, and the chain is not signed by a third party.

Privacy: creating a receipt sends the IP to the public RDAP service. It happens only when the user asks
for it, only for public addresses TOL actually observed, never for local ones.
"""
import hashlib
import ipaddress
import json
import socket
import threading
import time
from pathlib import Path

from .chainhash import GENESIS, entry_hash
from .labeler import classify_local, parse_rdap
from .netutil import LookupFailed, rdap_get

RDAP_URL = "https://rdap.org/ip/{ip}"
CAVEAT = ("The registered holder of an IP block is the network operator (for example a cloud provider), "
          "not necessarily the company whose service this device was using.")


def fetch_rdap_raw(ip: str):
    """(raw bytes, final URL); None if the registry says it has no record; raises LookupFailed otherwise."""
    return rdap_get(ip)


def _iso(epoch: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))


def _entities(doc):
    out = []

    def walk(ents):
        for e in ents or []:
            name = None
            for item in (e.get("vcardArray") or [None, []])[1]:
                if item and item[0] == "fn":
                    name = item[3]
            out.append({"roles": sorted(e.get("roles", [])), "name": name, "handle": e.get("handle")})
            walk(e.get("entities"))

    walk(doc.get("entities"))
    return out


class Receipts:
    def __init__(self, data_dir, labeler=None, fetch=fetch_rdap_raw, reverse=socket.gethostbyaddr,
                 forward=socket.gethostbyname_ex, clock=time.time):
        self.path = Path(data_dir) / "receipts.jsonl" if data_dir else None
        self.labeler, self._fetch, self._reverse, self._forward, self._clock = labeler, fetch, reverse, forward, clock
        self.chain, self.items = [], {}
        self._lock = threading.Lock()
        self._inflight = set()
        if self.path and self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                self.chain.append(entry)
                if entry["status"] == "no-record" and not entry["rdap"].get("answered"):
                    continue        # written by an early build when a failed lookup was filed as "no record"
                self.items[entry["ip"]] = entry
            if self.chain and labeler is not None:
                for e in self.chain:
                    self._teach(e)

    # --- public ---------------------------------------------------------------
    def valid_target(self, ip: str) -> bool:
        try:
            return classify_local(ip) is None and ipaddress.ip_address(ip).is_global
        except ValueError:
            return False

    def create(self, ip: str) -> dict:
        """Look up `ip` and append a receipt. Returns the receipt (existing one if already made)."""
        if not self.valid_target(ip):
            raise ValueError("not a public IP address")
        with self._lock:
            if ip in self.items:
                return self.items[ip]
            if ip in self._inflight:
                raise RuntimeError("lookup already running")
            self._inflight.add(ip)
        try:
            body = self._build(ip)
            with self._lock:
                entry = dict(body)
                entry["seq"] = len(self.chain)
                entry["previous_hash"] = entry_hash(self.chain[-1]) if self.chain else GENESIS
                self.chain.append(entry)
                self.items[ip] = entry
                if self.path:
                    self.path.parent.mkdir(parents=True, exist_ok=True)
                    with open(self.path, "a", encoding="utf-8") as f:
                        f.write(json.dumps(entry, sort_keys=True) + "\n")
            self._teach(entry)
            return entry
        finally:
            with self._lock:
                self._inflight.discard(ip)

    def find(self, ip: str):
        """The receipt that covers `ip`: its own, else the one for the most specific network block containing it."""
        with self._lock:
            if ip in self.items:
                return self.items[ip]
            try:
                a = ipaddress.ip_address(ip)
            except ValueError:
                return None
            best, best_len = None, -1
            for r in self.chain:
                for c in r["rdap"].get("cidrs", []):
                    net = ipaddress.ip_network(c)
                    if a in net and net.prefixlen > best_len:
                        best, best_len = r, net.prefixlen
            return best

    def summaries(self) -> dict:
        """Small per-IP view for the dashboard (no raw record)."""
        with self._lock:
            return {ip: {"seq": r["seq"], "status": r["status"], "owner": r["rdap"].get("registrant") or r["rdap"].get("name"),
                         "network": r["rdap"].get("cidrs", []), "ptr": r["reverse_dns"]["name"],
                         "ptr_confirmed": r["reverse_dns"]["forward_confirmed"],
                         "queried_at": r["queried_at_iso"], "sha256": r["rdap"].get("sha256"),
                         "caveat": r["caveat"]} for ip, r in self.items.items()}

    def export(self) -> dict:
        with self._lock:
            return {"tol_receipts": 1, "chain_ok": verify(self.chain)[0], "receipts": list(self.chain),
                    "note": CAVEAT}

    # --- internals ------------------------------------------------------------
    def _build(self, ip):
        now = int(self._clock())
        ptr, confirmed, addrs = None, False, []
        try:
            ptr = self._reverse(ip)[0]
            addrs = sorted(set(self._forward(ptr)[2]))
            confirmed = any(ipaddress.ip_address(a) == ipaddress.ip_address(ip) for a in addrs)
        except (OSError, ValueError):
            pass
        got = self._fetch(ip)
        rdap = {"source_url": None, "sha256": None, "answered": True, "http_status": 404}   # the registry replied: no record
        status = "no-record"
        if got:
            raw, url = got
            try:
                doc = json.loads(raw)
                owner, nets = parse_rdap(doc)
                ents = _entities(doc)
                registrant = next((e["name"] for e in ents if "registrant" in e["roles"] and e["name"]), None)
                rdap = {
                    "source_url": url, "sha256": hashlib.sha256(raw).hexdigest(),
                    "name": doc.get("name"), "handle": doc.get("handle"), "country": doc.get("country"),
                    "start": doc.get("startAddress"), "end": doc.get("endAddress"), "cidrs": nets,
                    "registrant": registrant, "entities": ents,
                    "events": {ev.get("eventAction"): ev.get("eventDate") for ev in doc.get("events", [])},
                    "raw": raw.decode("utf-8"),
                }
                status = "ok"
            except ValueError:
                pass
        return {
            "ip": ip, "queried_at": now, "queried_at_iso": _iso(now),
            "clock": "this device's clock; not independently verified",
            "reverse_dns": {"name": ptr, "forward_confirmed": confirmed, "addresses": addrs},
            "rdap": rdap, "status": status, "caveat": CAVEAT,
        }

    def _teach(self, entry):
        """Let the live labels use what the receipt found (network-owner level only)."""
        r = entry["rdap"]
        if self.labeler is not None and entry["status"] == "ok" and r.get("cidrs"):
            self.labeler.learn(r.get("registrant") or r.get("name"), r["cidrs"])


def holder(receipt):
    r = receipt["rdap"]
    return r.get("registrant") or r.get("name")


def attach(report: dict, receipts) -> dict:
    """Add the registered holder and proof pointers to each destination of a recording report, and put the
    receipts that back them in report["receipts"]. Works on the current receipts, so addresses identified
    after the recording stopped are included. Returns the same dict."""
    used = {}
    for d in report["destinations"]:
        found = None
        for ep in d["endpoints"]:
            r = receipts.find(ep.rsplit(":", 1)[0]) if receipts is not None else None
            if r is not None:
                found = r
                break
        d["registered_holder"] = holder(found) if found else None
        d["network_block"] = ", ".join(found["rdap"].get("cidrs", [])) if found else None
        d["receipt_seq"] = found["seq"] if found else None
        d["record_sha256"] = found["rdap"].get("sha256") if found else None
        d["reverse_dns_confirmed"] = found["reverse_dns"]["forward_confirmed"] if found else None
        d["lookup_time"] = found["queried_at_iso"] if found else None
        if found:
            used[found["seq"]] = found
    report["receipts"] = [used[k] for k in sorted(used)]
    return report


def verify(chain):
    """(ok, error). Walks the receipt chain and checks every link and each stored record's hash."""
    prev = GENESIS
    for i, e in enumerate(chain):
        if e.get("seq") != i or e.get("previous_hash") != prev:
            return False, f"receipt {i}: chain broken"
        raw = e.get("rdap", {}).get("raw")
        if raw is not None and hashlib.sha256(raw.encode()).hexdigest() != e["rdap"].get("sha256"):
            return False, f"receipt {i}: stored record does not match its hash"
        prev = entry_hash(e)
    return True, None
