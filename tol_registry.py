"""TOL's registry: who runs an address, from a built-in list of hostname suffixes plus your own additions.

Nothing here is looked up over the network. Add your own verified entries to ~/.tol/registry.json; they show as Verified.
"""
import hashlib
import ipaddress
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path



def canonical(obj) -> str:
    """Stable JSON for hashing TOL entries (strings, ints, None only)."""
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False)

REGISTRY_PATH = Path.home() / ".tol" / "registry.json"   # your own additions; optional
# Built-in hostname-suffix rules. Deliberately no IP mappings: those must be verified by you.
DEFAULT_REGISTRY = {
    ".amazonaws.com": {"company": "Amazon Web Services", "category": "cloud", "trust_level": "medium",
                       "notes": "Reverse-DNS suffix. AWS hosts many tenants; rate trust yourself."},
    ".googleusercontent.com": {"company": "Google Cloud", "category": "cloud", "trust_level": "medium",
                               "notes": "Reverse-DNS suffix. Hosts many tenants."},
    ".1e100.net": {"company": "Google", "category": "internet-services", "trust_level": "medium",
                   "notes": "Google reverse-DNS suffix"},
    ".cloudflare.com": {"company": "Cloudflare", "category": "cdn", "trust_level": "medium",
                        "notes": "Reverse-DNS suffix"},
    ".github.com": {"company": "GitHub", "category": "developer", "trust_level": "medium",
                    "notes": "Reverse-DNS suffix"},
}
UNKNOWN_COMPANY = {
    "company": "UNKNOWN",
    "category": "unknown",
    "trust_level": "unknown",
    "notes": "IP not in local registry",
}


def load_registry(path=None) -> dict:
    """Built-in defaults overlaid with the JSON file at `path` (default ~/.tol/registry.json), if any.
    File format: {"203.0.113.0/24": {"company": ..., "category": ..., "trust_level": ...},
                  ".example.com": {...}}   # IP/CIDR keys or hostname-suffix keys"""
    registry = dict(DEFAULT_REGISTRY)
    p = Path(path or REGISTRY_PATH)
    if p.exists():
        registry.update(json.loads(p.read_text() or "{}"))
    return registry


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def generate_tol_entry(timestamp, company_name, endpoint_ip, endpoint_port, protocol,
                       direction, bytes_sent, bytes_received, hostname, process_name,
                       endpoint_country="US") -> dict:
    """SIMULATED TOL record for tests and demos (source="simulated"; TLS fields are fake).
    Live records come from tol_collector.Collector."""
    parts = hostname.split(".")
    return {
        "entry_id": str(uuid.uuid4()),
        "source": "simulated",
        "timestamp": timestamp,
        "company_name": company_name,
        "endpoint_ip": endpoint_ip,
        "endpoint_port": endpoint_port,
        "endpoint_country": endpoint_country,
        "protocol": protocol,
        "direction": direction,
        "bytes_sent": bytes_sent,
        "bytes_received": bytes_received,
        "hostname": hostname,
        "process_name": process_name,
        "tls_certificate_subject": "*." + ".".join(parts[-2:]) if len(parts) > 1 else hostname,
        "tls_certificate_issuer": "Let's Encrypt",  # mock
        "tls_certificate_sha256": hashlib.sha256(hostname.encode()).hexdigest(),
    }


def build_tol_session_log(session_id, session_start, session_end, entries) -> dict:
    return {
        "session_id": session_id,
        "session_start": session_start,
        "session_end": session_end,
        "entries": entries,
        "total_outbound_bytes": sum(e["bytes_sent"] for e in entries),
        "total_inbound_bytes": sum(e["bytes_received"] for e in entries),
        "unique_companies": len({e["company_name"] for e in entries}),
        "entries_hash": hashlib.sha256(canonical(entries).encode()).hexdigest(),
    }


def lookup_company(ip_address: str, hostname=None, registry=None) -> dict:
    """Registry lookup. Keys are IPs/CIDR blocks (most specific wins) or hostname suffixes
    written as ".example.com" or "*.example.com". IP rules take precedence over hostname rules."""
    registry = load_registry() if registry is None else registry
    ip = ipaddress.ip_address(ip_address.split("%")[0])
    best, best_len = None, -1
    for key, info in registry.items():
        if key.startswith((".", "*.")):
            continue
        try:
            net = ipaddress.ip_network(key, strict=False)
        except ValueError:
            continue
        if ip in net and net.prefixlen > best_len:
            best, best_len = info, net.prefixlen
    if best is None and hostname:
        host = hostname.lower().rstrip(".")
        matches = [(k, v) for k, v in registry.items()
                   if k.startswith((".", "*.")) and ("." + host).endswith("." + k.lstrip("*.").lstrip("."))]
        if matches:
            best = max(matches, key=lambda kv: len(kv[0]))[1]
    return best or dict(UNKNOWN_COMPANY)


def lookup_company_by_ip(ip_address: str, registry=None) -> dict:
    return lookup_company(ip_address, None, registry)
