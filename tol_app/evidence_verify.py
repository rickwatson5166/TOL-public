#!/usr/bin/env python3
"""Verify a TOL evidence package. Standard library only; needs no TOL install.

    python3 verify.py            (run from inside the package folder, or pass the folder path)

Checks, and prints PASS / FAIL for each:
  1. every file matches the SHA-256 in MANIFEST.sha256, and no file is missing or extra
  2. the recorded network events form an unbroken hash chain ending in the stated root hash
  3. each destination receipt's stored registry record matches its recorded SHA-256 (and the
     verbatim copy in destination-verification/ is byte-identical)
  4. the receipt chain links, when the package holds the complete chain

It proves the files have not changed since the package was made. It does not prove that the
device clock was right or that the capture itself was accurate; see README.md.
"""
import calendar
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.dont_write_bytecode = True      # reading a package must never add files to it (a cache file would count as "extra")
GENESIS = "0" * 64


def _ser(obj):
    if obj is None:
        return "null"
    if obj is True:
        return "true"
    if obj is False:
        return "false"
    if isinstance(obj, int):
        return str(obj)
    if isinstance(obj, str):
        return json.dumps(obj, ensure_ascii=False)
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(_ser(x) for x in obj) + "]"
    if isinstance(obj, dict):
        items = sorted(obj.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _ser(v) for k, v in items) + "}"
    raise TypeError(type(obj).__name__)


def entry_hash(entry):
    return hashlib.sha256(_ser(entry).encode("utf-8")).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def check_manifest(root):
    problems, listed = [], set()
    manifest = root / "MANIFEST.sha256"
    if not manifest.exists():
        return ["MANIFEST.sha256 is missing"]
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, _, name = line.partition("  ")
        listed.add(name)
        p = root / name
        if not p.is_file():
            problems.append(f"missing file: {name}")
        elif sha256_file(p) != digest:
            problems.append(f"CHANGED: {name}")
    for p in root.rglob("*"):
        rel = p.relative_to(root).as_posix()
        if rel.startswith("__pycache__/tol_timestamp.") and rel.endswith(".pyc"):
            continue                                                  # left by an older verify.py when it read the timestamp reader
        if p.is_file() and rel not in listed and rel != "MANIFEST.sha256" and not rel.startswith("timestamp/"):
            problems.append(f"extra file not in manifest: {rel}")      # timestamp/ signs the manifest, so it is not in it
    return problems


def check_event_chain(root):
    path = root / "network-flows" / "events.chain.jsonl"
    stated = (root / "network-flows" / "flow-root-hash.txt").read_text(encoding="utf-8").strip()
    prev, last, n = GENESIS, None, 0
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
        e = json.loads(line)
        if e.get("seq") != i or e.get("previous_hash") != prev:
            return [f"event {i}: chain broken"], n
        prev, last, n = entry_hash(e), e, i + 1
    root_hash = entry_hash(last) if last else GENESIS
    return ([] if root_hash == stated else [f"root hash {root_hash} != stated {stated}"]), n


OBS_KEYS = {"event_type", "host", "page", "ts_ms", "gpc", "count", "ip", "timestamp", "seq", "previous_hash"}


def check_observations(root):
    """Browser-signal observations may hold a host, a page host, a server address, a time, a yes/no and a count, and nothing else."""
    problems, n = [], 0
    for i, line in enumerate((root / "network-flows" / "events.chain.jsonl").read_text(encoding="utf-8").splitlines()):
        e = json.loads(line)
        if e.get("event_type") != "gpc_observation":
            continue
        n += 1
        extra = sorted(set(e) - OBS_KEYS)
        if extra:
            problems.append(f"event {i}: carries more than a host record should: {', '.join(extra)}")
        elif type(e.get("gpc")) is not bool or type(e.get("ts_ms")) is not int or not isinstance(e.get("host"), str):
            problems.append(f"event {i}: malformed browser-signal observation")
    return problems, n


def check_receipts(root):
    problems, path = [], root / "destination-verification" / "receipts.json"
    chain = json.loads(path.read_text(encoding="utf-8"))["receipts"]
    for r in chain:
        raw = r.get("rdap", {}).get("raw")
        if raw is None:
            continue
        digest = hashlib.sha256(raw.encode()).hexdigest()
        if digest != r["rdap"].get("sha256"):
            problems.append(f"receipt for {r['ip']}: stored record does not match its hash")
        f = root / "destination-verification" / f"rdap-{r['ip'].replace(':', '_')}.json"
        if not f.is_file() or sha256_file(f) != digest:
            problems.append(f"receipt for {r['ip']}: verbatim record file missing or different")
    seqs = [r["seq"] for r in chain]
    note = ""
    if chain and seqs == list(range(len(chain))):
        prev = GENESIS
        for r in chain:
            if r["previous_hash"] != prev:
                problems.append(f"receipt {r['seq']}: chain broken")
                break
            prev = entry_hash(r)
    elif chain:
        note = "(receipts are a subset of the full chain; links to receipts outside this package cannot be checked here)"
    return problems, len(chain), note


CA_BUNDLES = ("/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt",
              "/opt/homebrew/etc/openssl@3/cert.pem", "/usr/local/etc/openssl@3/cert.pem")


def find_openssl_ts():
    """An openssl that can verify timestamps (OpenSSL 1.1+; macOS's own LibreSSL cannot), or None."""
    candidates = [shutil.which("openssl"), "/opt/homebrew/bin/openssl", "/usr/local/opt/openssl@3/bin/openssl",
                  "/opt/homebrew/opt/openssl@3/bin/openssl"]
    for exe in [c for c in candidates if c and os.path.exists(c)]:
        try:
            ver = subprocess.run([exe, "version"], capture_output=True, text=True, timeout=10).stdout
            out = subprocess.run([exe, "ts", "-help"], capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.SubprocessError):
            continue
        if ver.startswith("OpenSSL") and "-verify" in (out.stdout + out.stderr):     # not LibreSSL
            return exe
    return None


def check_timestamp(root, cafile=None):
    """Returns (status, lines). status: "none" (no timestamp), "fail", "consistent" (token is for this package but its
    signature was not checked here) or "verified" (OpenSSL checked the signature and certificate chain)."""
    tdir = root / "timestamp"
    if not tdir.is_dir():
        return "none", ["No trusted timestamp in this package: its times come from the device's own clock."]
    try:
        sys.path.insert(0, str(root))
        import tol_timestamp as ts
        info = ts.parse_response((tdir / "manifest.tsr").read_bytes())
    except Exception as e:                                          # noqa: BLE001 - report whatever is wrong
        return "fail", [f"timestamp token cannot be read: {e}"]
    finally:
        if str(root) in sys.path:
            sys.path.remove(str(root))
    if not info.get("granted") or "imprint_hex" not in info:
        return "fail", ["the stored answer is not a granted timestamp"]
    manifest = root / "MANIFEST.sha256"
    want = sha256_file(manifest)
    if info["hash_oid"] != ts.OID_SHA256 or info["imprint_hex"] != want:
        return "fail", ["the timestamp is NOT for this package's MANIFEST.sha256 (the manifest was changed after it was stamped)"]
    when = info["gen_time"]
    epoch = calendar.timegm(time.strptime(when, "%Y-%m-%dT%H:%M:%SZ"))
    lines = [f"the authority's time: {when} UTC (serial {info['serial']}, policy {info['policy']})",
             "it covers exactly this package's MANIFEST.sha256"]
    builtin = ts.verify_token((tdir / "manifest.tsr").read_bytes(), cafile=cafile) if hasattr(ts, "verify_token") else None
    if builtin is not None and builtin.status == "verified":
        lines.append(f"signature and certificate chain verified by TOL's own checker: signed by {builtin.signer}, "
                     f"chaining to {builtin.root}")
        lines.append(f"(trusted root list: {builtin.roots_source}; certificate revocation is not checked)")
        return "verified", lines
    exe = find_openssl_ts()
    bundle = cafile or os.environ.get("SSL_CERT_FILE") or next((c for c in CA_BUNDLES if os.path.isfile(c)), None)
    how = (f"openssl ts -verify -data MANIFEST.sha256 -in timestamp/manifest.tsr -CAfile <CA bundle> "
           f"-untrusted timestamp/tsa-certs.pem -attime {epoch}")
    opened = None
    unreadable_roots = bool(cafile) and not os.path.isfile(cafile)       # a root file that is not there is "cannot decide", not "forged"
    if exe is not None and bundle is not None and not unreadable_roots:
        cmd = [exe, "ts", "-verify", "-data", str(manifest), "-in", str(tdir / "manifest.tsr"), "-CAfile", bundle,
               "-untrusted", str(tdir / "tsa-certs.pem"), "-attime", str(epoch)]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        text = (out.stdout + out.stderr).strip()
        opened = out.returncode == 0 and "Verification: OK" in text
        if opened:
            lines.append("signature and certificate chain verified by OpenSSL against " + bundle)
            lines.append("(certificate revocation is not checked)")
            return "verified", lines
    if builtin is not None and builtin.status == "failed" and opened is not True:
        lines.append("the authority's signature did NOT verify: " + builtin.reason)
        return "fail", lines
    if opened is False:
        lines.append("OpenSSL did NOT verify the signature: " + text.replace("\n", " | ")[:400])
        lines.append("if the authority's root is missing from that CA bundle, try --cafile with another bundle")
        return "fail", lines
    why = builtin.reason if builtin is not None and builtin.reason else "this package carries an older reader"
    lines.append(f"SIGNATURE NOT VERIFIED here (TOL's own checker could not decide: {why}).")
    if exe is None:
        lines.append("To check it with OpenSSL 3 (macOS: brew install openssl; some Macs cannot), run")
        lines.append("    " + how)
    return "consistent", lines


def main():
    args = sys.argv[1:]
    cafile = None
    if "--cafile" in args:
        i = args.index("--cafile")
        cafile = args[i + 1] if i + 1 < len(args) else None
        del args[i:i + 2]
    root = Path(args[0] if args else ".").resolve()
    ok = True

    def report(name, problems, extra=""):
        nonlocal ok
        ok &= not problems
        print(("PASS  " if not problems else "FAIL  ") + name + (f"  {extra}" if extra else ""))
        for p in problems:
            print("        - " + p)

    report("File hashes match MANIFEST.sha256", check_manifest(root))
    probs, n = check_event_chain(root)
    report("Network event chain unbroken", probs, f"({n} events)")
    probs, n = check_observations(root)
    if n or probs:
        report("Browser-signal observations hold only host, time and signal", probs, f"({n} observations)")
    probs, n, note = check_receipts(root)
    report("Destination receipts match their stored records", probs, f"({n} receipts) {note}".strip())
    status, lines = check_timestamp(root, cafile)
    ok &= status != "fail"
    label = {"none": "NOTE  ", "fail": "FAIL  ", "consistent": "NOTE  ", "verified": "PASS  "}[status]
    title = {"none": "No trusted timestamp", "fail": "Trusted timestamp", "consistent": "Trusted timestamp (signature not checked here)",
             "verified": "Trusted timestamp verified"}[status]
    print(label + title)
    for ln in lines:
        print("        - " + ln)
    print("\nALL CHECKS PASSED" if ok else "\nSOMETHING FAILED: do not rely on this package.")
    if ok and status != "verified":
        print("(the package's contents are consistent; the time is " +
              ("the device's own clock." if status == "none" else "not independently verified on this machine."))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
