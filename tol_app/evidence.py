"""Build an evidence package from a finished recording: files + hash manifest + a standalone verifier.

This makes the evidence tamper-evident and self-checking. It does not add trust that is not there:
timestamps are the device clock, and there is no raw packet capture. The README inside every package
says so plainly.
"""
import csv
import hashlib
import json
import platform
import shutil
import time
import uuid
import zipfile
from pathlib import Path

from . import __version__

from .chainhash import HashChain

VERSION = "0.2"

README = """# TOL evidence package

Created: {created} (this device's clock)
Device: {host} ({system})
Recording: {start} to {stop} ({duration:.0f} seconds), {events} connection samples
Destinations: {dests}   Receipts: {receipts}

## What this is
A record of which addresses this device sent data to, and how much, during the recording above, together
with registry records identifying who holds each address you chose to look up.

## How to check it has not been changed
Run, from inside this folder (needs Python 3, nothing else):

    python3 verify.py

It re-computes every file's SHA-256 against `MANIFEST.sha256`, re-walks the event hash chain, and checks each
receipt's stored registry record against its hash. Any change to any file makes it print FAIL.
You can also check files yourself: `shasum -a 256 -c MANIFEST.sha256` (macOS) or `sha256sum -c MANIFEST.sha256`.

## Contents
- `network-flows/` flow-summary.csv (one row per destination), events.chain.jsonl (every sample, hash-chained),
  flow-root-hash.txt (the final hash; changing any sample changes it), recording.json (full report)
- `destination-verification/` receipts.json and one verbatim registry record per address (`rdap-<ip>.json`;
  its SHA-256 is recorded in the receipt)
- `device/device-info.json` hostname, operating system, hardware address of this device.
  **Review before sharing: it identifies the device.**
- `MANIFEST.sha256`, `verify.py`

## What this does NOT prove
- **When, unless there is a `timestamp/` folder.** Times come from this device's clock, so the hashes show the files
  have not changed since packaging, not that they existed at the stated time. If the package has a `timestamp/` folder,
  an independent timestamp authority signed the fingerprint of MANIFEST.sha256, which proves the whole package
  existed by the time it names (see timestamp/README.txt; `verify.py` checks it, including the authority's signature). The
  times of the individual samples inside the recording are still the device's clock: the timestamp proves when the
  package existed, not that each sample happened at the moment it claims.
- **That the capture was complete.** TOL reads the operating system's connection tables once a second. It can
  miss connections that open and close between readings and, on macOS, short-lived ones. It does not record
  packet contents and there is no packet capture (pcap) file.
- **Who the "company" is.** A registry record names the holder of an address block, usually a network or cloud
  operator, not necessarily the service this device was using. Reverse DNS is shown as confirmed only when the
  name resolves back to the same address.
- **Legal admissibility.** Nothing here is certified by an expert or a third party. Whether it is admissible
  depends on the court, the jurisdiction and expert testimony. Have a qualified person review it first.
"""


def _device():
    mac = f"{uuid.getnode():012x}"
    return {"hostname": platform.node(), "system": platform.platform(), "machine": platform.machine(),
            "python": platform.python_version(), "hardware_address": ":".join(mac[i:i + 2] for i in range(0, 12, 2)),
            "tol_evidence_format": VERSION, "tol_version": __version__}


SUMMARY_COLUMNS = ["destination", "process", "confidence", "registered_holder", "network_block", "sent_bytes",
                   "received_bytes", "hostnames", "endpoints", "reverse_dns_confirmed", "lookup_time",
                   "record_sha256", "receipt_seq"]


def write_summary_csv(path, destinations):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(SUMMARY_COLUMNS)
        for d in destinations:
            row = []
            for c in SUMMARY_COLUMNS:
                v = d.get(c)
                row.append(" ".join(v) if isinstance(v, list) else ("" if v is None else v))
            w.writerow(row)


def _sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def build_package(recording, out_dir, clock=time.time):
    """`recording` is a report dict or the path of a saved recording. Returns {"folder", "zip", "root_hash"}."""
    report = recording if isinstance(recording, dict) else json.loads(Path(recording).read_text(encoding="utf-8"))
    created = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(clock()))
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime(report["started"]))
    host = platform.node() or "device"
    name = f"TOL-Evidence-Package-{stamp}-{''.join(c for c in host if c.isalnum() or c in '-_')[:24]}"
    folder = Path(out_dir) / name
    if folder.exists():
        shutil.rmtree(folder)
    for sub in ("network-flows", "destination-verification", "device"):
        (folder / sub).mkdir(parents=True)

    # flows: every sample in a hash chain, plus a per-destination summary
    chain = HashChain()
    for e in report["events"]:
        chain.append(e)
    (folder / "network-flows" / "events.chain.jsonl").write_text(
        "".join(json.dumps(e, sort_keys=True) + "\n" for e in chain.entries), encoding="utf-8")
    root_hash = chain.root()
    (folder / "network-flows" / "flow-root-hash.txt").write_text(root_hash + "\n", encoding="utf-8")
    write_summary_csv(folder / "network-flows" / "flow-summary.csv", report["destinations"])
    (folder / "network-flows" / "recording.json").write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    # destination receipts + the verbatim registry record for each
    receipts = report.get("receipts", [])
    (folder / "destination-verification" / "receipts.json").write_text(json.dumps(
        {"receipts": receipts, "note": "Holder of an address block is the network operator, "
         "not necessarily the vendor."}, indent=2, sort_keys=True), encoding="utf-8")
    for r in receipts:
        raw = r.get("rdap", {}).get("raw")
        if raw is not None:
            (folder / "destination-verification" / f"rdap-{r['ip'].replace(':', '_')}.json").write_bytes(raw.encode())

    (folder / "device" / "device-info.json").write_text(json.dumps(_device(), indent=2), encoding="utf-8")
    (folder / "README.md").write_text(README.format(
        created=created, host=host, system=platform.platform(),
        start=time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(report["started"])),
        stop=time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(report["stopped"])),
        duration=report["duration_seconds"], events=len(report["events"]),
        dests=len(report["destinations"]), receipts=len(receipts)), encoding="utf-8")
    shutil.copyfile(Path(__file__).with_name("evidence_verify.py"), folder / "verify.py")
    shutil.copyfile(Path(__file__).with_name("timestamp.py"), folder / "tol_timestamp.py")   # lets verify.py read tokens

    files = sorted(p for p in folder.rglob("*") if p.is_file())
    (folder / "MANIFEST.sha256").write_text("".join(
        f"{_sha(p)}  {p.relative_to(folder).as_posix()}\n" for p in files), encoding="utf-8")

    return {"folder": folder, "zip": zip_folder(folder), "root_hash": root_hash}


def zip_folder(folder) -> Path:
    """(Re)write <folder>.zip next to the folder, with every file in it."""
    folder = Path(folder)
    zip_path = folder.with_suffix(".zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(folder.rglob("*")):
            if p.is_file():
                z.write(p, Path(folder.name) / p.relative_to(folder))
    return zip_path


TIMESTAMP_README = """TRUSTED TIMESTAMP

What this is: an independent timestamp authority ({tsa}) signed a statement that the fingerprint
(SHA-256) of MANIFEST.sha256 existed at {gen_time} (UTC). MANIFEST.sha256 lists the fingerprint of every other file in
this package, so the statement covers the whole package: change any file and the manifest changes; change the manifest
and the fingerprint no longer matches the signed one.

What was sent to the authority: only that 32-byte fingerprint ({imprint}), nothing else.

Files here: manifest.tsq (the request), manifest.tsr (the signed answer), tsa-certs.pem (the authority's certificates
as returned), timestamp.json (the details).

How to check it: run `python3 verify.py` from the package folder. It checks the authority's signature and certificate
chain itself (standard Python only, nothing to install) against the trusted root list of the computer it runs on. If it
cannot decide it says "SIGNATURE NOT VERIFIED" and gives the reason; it never reports a signature as checked when it was not.

To check it independently with OpenSSL 1.1 or newer (not the LibreSSL that ships with macOS):

    openssl ts -verify -data ../MANIFEST.sha256 -in manifest.tsr -CAfile <your CA bundle> -untrusted tsa-certs.pem -attime {epoch}

Limits: this proves the package contents existed by {gen_time}. It does not prove the capture was complete or that the
device was honest, and it does not check whether the authority's certificate was revoked. A free public authority is
not a "qualified" one in the legal sense; for use in a legal proceeding, ask your lawyer which authority to use
(set "tsa_url" in ~/.tol/settings.json).
"""


def add_timestamp(folder, tsa_url=None, request=None, clock=time.time) -> dict:
    """Timestamp <folder>/MANIFEST.sha256 with an RFC 3161 authority and store the proof in <folder>/timestamp/.
    The proof files are not listed in the manifest (they sign it), and verify.py knows that. Re-zips the package.
    Raises timestamp.TimestampFailed with the reason if the authority cannot be used."""
    import calendar
    from . import timestamp as ts
    folder = Path(folder)
    manifest = folder / "MANIFEST.sha256"
    if not manifest.is_file():
        raise ts.TimestampFailed("this package has no MANIFEST.sha256")
    url = tsa_url or ts.DEFAULT_TSA
    digest = ts.sha256_file(manifest)
    got = (request or ts.request_timestamp)(digest, url)
    info = got["info"]
    tdir = folder / "timestamp"
    tdir.mkdir(exist_ok=True)
    (tdir / "manifest.tsq").write_bytes(got["request"])
    (tdir / "manifest.tsr").write_bytes(got["response"])
    (tdir / "tsa-certs.pem").write_text(ts.certs_pem(info), encoding="utf-8")
    epoch = calendar.timegm(time.strptime(info["gen_time"], "%Y-%m-%dT%H:%M:%SZ"))
    detail = {"tsa_url": url, "requested_at_device_clock": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(clock())),
              "gen_time_utc": info["gen_time"], "serial": info["serial"], "policy": info["policy"],
              "tsa_name": info.get("tsa_name"), "nonce": got["nonce"], "hash_algorithm": "sha256",
              "stamped": "MANIFEST.sha256", "imprint": digest.hex(),
              "signature_checked_by_tol": False,
              "note": "TOL checks the answer is for this fingerprint; verify.py checks the authority's signature and chain."}
    (tdir / "timestamp.json").write_text(json.dumps(detail, indent=2, sort_keys=True), encoding="utf-8")
    (tdir / "README.txt").write_text(TIMESTAMP_README.format(tsa=url, gen_time=info["gen_time"], imprint=digest.hex(), epoch=epoch), encoding="utf-8")
    detail["zip"] = str(zip_folder(folder))
    return detail

