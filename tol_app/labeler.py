"""Automatic labelling of "who is this IP", in layers, each tagged with how far to trust it.

  verified      your registry matched the IP/CIDR
  likely        the reverse-DNS hostname matched a registry suffix rule
  hostname      forward-confirmed reverse DNS gave a name that is not in your registry
  network-only  public RDAP records say who owns the network block. This is the NETWORK
                OPERATOR (e.g. a cloud provider), not necessarily the vendor you are talking to
  none          nothing found

Privacy: RDAP lookups send the destination IP to the public registries, so they are OFF unless
lookups=True (the app's --lookup flag). They are skipped for private/local addresses and made once
per network block (cached on disk).
"""
import ipaddress
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from tol_registry import UNKNOWN_COMPANY, load_registry, lookup_company

RDAP_URL = "https://rdap.org/ip/{ip}"
NEGATIVE_TTL = 600


def classify_local(ip: str):
    a = ipaddress.ip_address(ip.split("%")[0])
    if a.is_loopback:
        return {"company": "This device", "category": "local", "trust_level": "high",
                "source": "local", "confidence": "verified"}
    if not a.is_global:
        return {"company": "Local network", "category": "local", "trust_level": "high",
                "source": "local", "confidence": "verified"}
    return None


def parse_rdap(doc: dict):
    """RFC 9083 IP network object -> (owner name or None, [CIDR strings])."""
    owner = None

    def walk(entities):
        nonlocal owner
        for ent in entities or []:
            if "registrant" in ent.get("roles", []) and owner is None:
                for item in (ent.get("vcardArray") or [None, []])[1]:
                    if item and item[0] == "fn":
                        owner = item[3]
            walk(ent.get("entities"))

    walk(doc.get("entities"))
    owner = owner or doc.get("name")
    nets = []
    try:
        start, end = ipaddress.ip_address(doc["startAddress"]), ipaddress.ip_address(doc["endAddress"])
        nets = [str(n) for n in ipaddress.summarize_address_range(start, end)]
    except (KeyError, ValueError):
        pass
    return owner, nets


def fetch_rdap(ip: str):
    """Parsed RDAP document, or None on any failure (this path only feeds the optional --lookup labels)."""
    from .netutil import LookupFailed, rdap_get
    try:
        got = rdap_get(ip)
        return json.loads(got[0]) if got else None
    except (LookupFailed, ValueError):
        return None


class Labeler:
    def __init__(self, registry=None, lookups=False, cache_path=None, fetch=fetch_rdap, now=time.time):
        self.registry = load_registry() if registry is None else registry
        self.lookups, self._fetch, self._now = lookups, fetch, now
        self.cache_path = Path(cache_path) if cache_path else None
        self._owners = []                    # [(ip_network, owner)]
        self._inflight, self._failed = set(), {}
        self._lock = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=2)
        self._load()

    # --- public ---------------------------------------------------------------
    def label(self, ip: str, hostname=None) -> dict:
        local = classify_local(ip)
        if local:
            return local
        info = lookup_company(ip, hostname, self.registry)
        if info["company"] != UNKNOWN_COMPANY["company"]:
            by_ip = hostname is None or self._matches_ip_rule(ip)
            return {**info, "source": "registry" if by_ip else "hostname",
                    "confidence": "verified" if by_ip else "likely"}
        if hostname:    # forward-confirmed by the collector's resolver
            return {"company": hostname, "category": "unrated", "trust_level": "unknown",
                    "notes": "Hostname confirmed by DNS; vendor not in your registry",
                    "source": "dns", "confidence": "hostname"}
        owner = self._cached_owner(ip)
        if owner:
            return {"company": owner, "category": "network", "trust_level": "unknown",
                    "notes": "Network operator from public records; vendor unconfirmed",
                    "source": "network-owner", "confidence": "network-only"}
        if self.lookups:
            self._queue(ip)
        return {**UNKNOWN_COMPANY, "source": "pending" if ip in self._inflight else "none",
                "confidence": "none"}

    def learn(self, owner, cidrs):
        """Add a network block -> operator mapping (from a user-requested receipt) and remember it."""
        if not owner:
            return
        with self._lock:
            for c in cidrs:
                try:
                    self._owners.append((ipaddress.ip_network(c), owner))
                except ValueError:
                    pass
            self._save()

    def wait(self):
        """Block until queued lookups finish (tests, shutdown)."""
        self._pool.shutdown(wait=True)
        self._pool = ThreadPoolExecutor(max_workers=2)

    # --- internals ------------------------------------------------------------
    def _matches_ip_rule(self, ip):
        a = ipaddress.ip_address(ip)
        for key in self.registry:
            if key.startswith((".", "*.")):
                continue
            try:
                if a in ipaddress.ip_network(key, strict=False):
                    return True
            except ValueError:
                pass
        return False

    def _cached_owner(self, ip):
        a = ipaddress.ip_address(ip)
        with self._lock:
            hits = [(n, o) for n, o in self._owners if a in n]
        return max(hits, key=lambda h: h[0].prefixlen)[1] if hits else None

    def _queue(self, ip):
        with self._lock:
            if ip in self._inflight or self._failed.get(ip, 0) > self._now():
                return
            self._inflight.add(ip)
        self._pool.submit(self._resolve, ip)

    def _resolve(self, ip):
        try:
            doc = self._fetch(ip)
            owner, nets = parse_rdap(doc) if doc else (None, [])
            with self._lock:
                if owner and nets:
                    self._owners += [(ipaddress.ip_network(n), owner) for n in nets]
                    self._save()
                else:
                    self._failed[ip] = self._now() + NEGATIVE_TTL
        finally:
            with self._lock:
                self._inflight.discard(ip)

    def _load(self):
        if self.cache_path and self.cache_path.exists():
            try:
                self._owners = [(ipaddress.ip_network(c), o)
                                for c, o in json.loads(self.cache_path.read_text(encoding="utf-8"))]
            except (ValueError, OSError):
                self._owners = []

    def _save(self):
        if self.cache_path:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(json.dumps([[str(n), o] for n, o in self._owners]), encoding="utf-8")
