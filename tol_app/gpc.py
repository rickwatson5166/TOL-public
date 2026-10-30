"""Browser privacy-signal observations (0.4.7): what a browser extension saw, and the site report built from it.

The extension only watches. For each request it reports the host the request went to, the host of the page that caused it,
a time, and whether the browser sent `Sec-GPC: 1`. Nothing else: no paths, no query strings, no headers other than that
one, no bodies. TOL never sends the signal; the browser does.

Everything here is a statement of what was observed. Nothing here says anyone broke a rule.
"""
import ipaddress
import re
import time

EVENT_TYPE = "gpc_observation"
FIELDS = ("host", "page", "ts_ms", "gpc", "count", "ip")    # the only fields an observation may carry (plus the TOL stamp); ip is optional
MAX_BATCH = 500
MAX_COUNT = 100_000
_HOST = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$")
_IPV6 = re.compile(r"^[0-9a-f:.]{2,45}$")


def _bare(s):
    """A host as a browser may hand it over -> the plain form: lower case, no trailing dot, no brackets round an IPv6 address."""
    if isinstance(s, str):
        s = s.strip().lower()
        if s.startswith("[") and s.endswith("]"):
            s = s[1:-1]
        if s.endswith(".") and len(s) > 1:
            s = s[:-1]
    return s


def _is_host(s) -> bool:
    return isinstance(s, str) and bool(_HOST.match(s) or ("::" in s or s.count(":") >= 2) and _IPV6.match(s))


def clean(raw, now=None):
    """One observation from the extension -> the exact event TOL records, or raises ValueError. Unknown fields are refused, not
    dropped, so an extension that starts sending more than it should is noticed."""
    if not isinstance(raw, dict):
        raise ValueError("an observation must be an object")
    extra = set(raw) - set(FIELDS)
    if extra:
        raise ValueError("unexpected field(s): " + ", ".join(sorted(map(str, extra))))
    host, page = _bare(raw.get("host")), _bare(raw.get("page"))
    ts, gpc, count = raw.get("ts_ms"), raw.get("gpc"), raw.get("count", 1)
    if not _is_host(host) or not _is_host(page):
        raise ValueError("host and page must be bare host names")
    if type(ts) is not int or not 946684800000 <= ts <= 4102444800000:
        raise ValueError("ts_ms must be whole milliseconds since 1970")
    if type(gpc) is not bool:
        raise ValueError("gpc must be true or false")
    if type(count) is not int or not 1 <= count <= MAX_COUNT:
        raise ValueError("count must be a whole number from 1")
    ip = raw.get("ip")
    if ip is not None:
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            raise ValueError("ip must be an address") from None
    now = time.time() if now is None else now
    out = {"event_type": EVENT_TYPE, "host": host, "page": page, "ts_ms": ts, "gpc": gpc, "count": count,
           "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))}      # when TOL received it, by TOL's clock
    if ip is not None:
        out["ip"] = ip                           # the server address the browser connected to for this host
    return out


def is_observation(e) -> bool:
    return isinstance(e, dict) and e.get("event_type") == EVENT_TYPE


def _owner(host, ip, network_events):
    """The ownership label TOL already has, from the device's own connections: matched by the server address the browser
    reported, else by a host name the device itself resolved. Returns the label with its confidence."""
    best = None
    for e in network_events:
        h = e.get("hostname") or ""
        by_ip = bool(ip) and e.get("endpoint_ip") == ip
        by_name = h != e.get("endpoint_ip") and (h == host or h.endswith("." + host) or host.endswith("." + h))
        if by_ip or by_name:
            if best is None or (e["label_confidence"] == "verified" and best["label_confidence"] != "verified"):
                best = e
    if best is None:
        return {"owner": None, "confidence": "no label", "note": "no connection by this device to this host was seen by the OS list"}
    if best["label_confidence"] == "hostname":            # only the address's own reverse-DNS name is known: that is not an owner
        return {"owner": None, "confidence": "address name only", "address_name": best["company_name"], "note": ""}
    return {"owner": best["company_name"] if best["label_confidence"] != "none" else None,
            "confidence": best["label_confidence"], "note": ""}


def site_report(events, page, window_seconds=None, network_events=None):
    """What a recording shows for one page. `events` is the recording's events (observations and connections mixed).

    By default the report covers the whole recording. With `window_seconds` it covers only the time from the first request
    that carried the signal (T) to T + window. Each destination host is listed with how many of the page's requests to it
    carried the signal and how many did not, and with the ownership label TOL already has for it, if any. A page that
    never sent the signal is reported as such, with the same list, so the two can be compared."""
    obs = [e for e in events if is_observation(e) and e["page"] == page]
    if not obs:
        return None
    net = network_events if network_events is not None else [e for e in events if not is_observation(e)]
    sig = [e for e in obs if e["gpc"]]
    t0 = min(e["ts_ms"] for e in sig) if sig else min(e["ts_ms"] for e in obs)
    first, last = min(e["ts_ms"] for e in obs), max(e["ts_ms"] for e in obs)
    lo, hi = (t0, t0 + int(window_seconds * 1000)) if window_seconds is not None else (first, last)
    dests = {}
    for e in obs:
        if lo <= e["ts_ms"] <= hi:
            d = dests.setdefault(e["host"], {"host": e["host"], "ip": None, "with_signal": 0, "without_signal": 0})
            d["ip"] = e.get("ip") or d["ip"]
            d["with_signal" if e["gpc"] else "without_signal"] += e["count"]
    rows = sorted(dests.values(), key=lambda d: (-(d["with_signal"] + d["without_signal"]), d["host"]))
    for d in rows:
        d.update(_owner(d["host"], d["ip"], net))
    return {"page": page, "signal_seen": bool(sig), "t_ms": t0, "first_ms": first, "last_ms": last,
            "window_seconds": window_seconds, "destinations": rows,
            "text": render(page, sig, t0, window_seconds, rows, lo, hi)}


def _utc(ms):
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ms // 1000))


def render(page, sig, t0, window, rows, lo, hi):
    with_n = sum(d["with_signal"] for d in rows)
    without_n = sum(d["without_signal"] for d in rows)
    labelled = sum(1 for d in rows if d["owner"])
    lines = [f"Site report: {page}", ""]
    if not sig:
        lines += ["No request from this page carried the Global Privacy Control signal.", ""]
    if window is None:
        lines.append(f"Covers the whole recording of this page, {_utc(lo)} to {_utc(hi)}.")
    else:
        lines.append(f"Covers {window} seconds from the first request that carried the signal ({_utc(t0)}).")
    lines.append(f"The page's requests went to {len(rows)} host(s): {with_n} request(s) carried the Global Privacy Control "
                 f"signal (Sec-GPC: 1) and {without_n} did not.")
    lines.append(f"TOL has an ownership label for {labelled} of the {len(rows)} host(s); the rest are shown as unlabelled.")
    lines.append("")
    for d in rows:
        if d["owner"]:
            who = f"{d['owner']} ({d['confidence']})"
        elif d.get("address_name"):
            who = f"no ownership label; the address's own name is {d['address_name']}"
        else:
            who = f"no ownership label ({d['confidence']})"
        lines.append(f"  {d['host']}: {d['with_signal']} with the signal, {d['without_signal']} without. {who}")
    lines += ["", "This lists what was observed. It does not say whether any request was lawful, wanted or in breach of anything.",
              "Requests are counted by host only: no content was read. Times are this device's clock."]
    return "\n".join(lines) + "\n"


def _condition(rows):
    """"signal on" / "signal off" / "mixed" for one recording of a page, from how its requests were sent."""
    w = sum(d["with_signal"] for d in rows)
    wo = sum(d["without_signal"] for d in rows)
    if w and not wo:
        return "signal on"
    if wo and not w:
        return "signal off"
    return "mixed"


def compare_reports(events_a, events_b, page):
    """Two recordings of the same page, set side by side. Returns a dict, or None if either has no such page.

    Which one had the privacy signal on is read from the recordings themselves (whether their requests carried it), not
    from the order given. Hosts are listed as seen in both, only with the signal on, or only with it off. A host being
    on one side only is an observation about these two visits. Pages change between visits (ads rotate, caches fill), so
    two recordings of the same setting are the way to see how much a page varies by itself."""
    ra, rb = site_report(events_a, page), site_report(events_b, page)
    if ra is None or rb is None:
        return None
    ca, cb = _condition(ra["destinations"]), _condition(rb["destinations"])
    on, off = (ra, rb) if (ca, cb) == ("signal on", "signal off") else (rb, ra) if (cb, ca) == ("signal on", "signal off") else (None, None)
    first, second = ra, rb
    if on is None:                                    # same setting twice (a baseline), or mixed: compare in the order given
        first_name, second_name = f"recording 1 ({ca})", f"recording 2 ({cb})"
        a_rows, b_rows = {d["host"]: d for d in ra["destinations"]}, {d["host"]: d for d in rb["destinations"]}
        baseline = ca == cb
    else:
        first_name, second_name = "signal on", "signal off"
        a_rows, b_rows = {d["host"]: d for d in on["destinations"]}, {d["host"]: d for d in off["destinations"]}
        baseline = False
    only_a = sorted((a_rows[h] for h in a_rows.keys() - b_rows.keys()), key=lambda d: -(d["with_signal"] + d["without_signal"]))
    only_b = sorted((b_rows[h] for h in b_rows.keys() - a_rows.keys()), key=lambda d: -(d["with_signal"] + d["without_signal"]))
    both = sorted(((a_rows[h], b_rows[h]) for h in a_rows.keys() & b_rows.keys()),
                  key=lambda p: -(p[0]["with_signal"] + p[0]["without_signal"] + p[1]["with_signal"] + p[1]["without_signal"]))
    n = lambda d: d["with_signal"] + d["without_signal"]
    ta, tb = sum(map(n, a_rows.values())), sum(map(n, b_rows.values()))
    comparable = min(ta, tb) * 5 >= max(ta, tb)         # one visit with under a fifth of the other's requests is not a like-for-like visit
    return {"page": page, "comparable": comparable, "first": first_name, "second": second_name, "baseline": baseline, "ordered_by_condition": on is not None,
            "only_first": only_a, "only_second": only_b, "both": [{"host": a["host"], "first": n(a), "second": n(b),
                                                                  "owner": a["owner"] or b["owner"]} for a, b in both],
            "text": render_comparison(page, first_name, second_name, baseline, on is not None, a_rows, b_rows, only_a, only_b, both, comparable)}


def render_comparison(page, name_a, name_b, baseline, by_condition, a_rows, b_rows, only_a, only_b, both, comparable=True):
    n = lambda d: d["with_signal"] + d["without_signal"]
    lines = [f"Comparison for {page}", ""]
    if by_condition:
        lines.append("Two recordings of this page, one with the browser's Global Privacy Control signal on and one with it off.")
    elif baseline:
        lines.append(f"Two recordings of this page with the same setting ({name_a.split('(')[1].rstrip(')')}). "
                     "This shows how much the page varies on its own between visits.")
    else:
        lines.append("Two recordings of this page. They are not one signal-on and one signal-off, so they are shown in the order given.")
    if not comparable:
        lines += ["", "CAUTION: the two recordings differ a lot in size, so these visits may not be like for like (for example one page "
                      "was already loaded and cached, or the browser did not report everything). Repeat the visit before reading anything into "
                      "the differences below."]
    lines += ["", f"  {name_a}: {len(a_rows)} host(s), {sum(map(n, a_rows.values()))} request(s)",
              f"  {name_b}: {len(b_rows)} host(s), {sum(map(n, b_rows.values()))} request(s)",
              f"  in both: {len(both)} host(s)", ""]
    for title, rows in ((f"Only in {name_a}:", only_a), (f"Only in {name_b}:", only_b)):
        lines.append(title)
        lines += [f"  {d['host']} ({n(d)} request(s))" + (f", {d['owner']}" if d["owner"] else "") for d in rows] or ["  none"]
        lines.append("")
    lines.append("In both (requests: " + name_a + " / " + name_b + "):")
    lines += [f"  {a['host']}: {n(a)} / {n(b)}" for a, b in both] or ["  none"]
    lines += ["", "This lists what was observed in two visits. A host seen on one side only may be there because pages change between "
                  "visits (ads rotate, caches fill, the browser blocks some requests before they are sent). It does not say why a host "
                  "appeared or did not, what any host did with a request, or whether anyone broke a rule. Repeat the visits, and "
                  "compare two runs with the same setting, before reading anything into a difference.",
              "Requests are counted by host only: no content was read. Times are this device's clock."]
    return "\n".join(lines) + "\n"
