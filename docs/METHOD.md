# TOL: how it works, what it records, and what it does not prove

This document describes TOL's method in plain terms so that a technical reviewer, an expert witness or an attorney can
judge what the tool's output is worth. It is a description of the software, not legal advice. Whether any record is
admissible or persuasive is for a court and qualified experts to decide.

## 1. What TOL does

TOL watches one computer. Every second or so it asks the operating system which network connections are open, which
program owns each one, and (on macOS and Linux) how many bytes each carried. It turns that into a live list of
**destinations**: the remote address, the program, the time, and a name for who is believed to be on the other end.

It does **not** read the contents of any traffic, install a network driver, or sit between the computer and the
internet. It only reads what the operating system already reports.

## 2. Where the data comes from

| Platform | Source | Byte counts | Notes |
|---|---|---|---|
| macOS | `nettop` (ships with macOS) | yes | A connection that opens and closes between two checks can be missed. |
| Linux | kernel `sock_diag` and `/proc` | yes | TCP only. No UDP/QUIC. |
| Windows | PowerShell `Get-NetTCPConnection` | **no** (shown as n/a) | Windows does not give per-connection counts to a normal program. TOL records that a connection existed, which program opened it, and when. |

If the source cannot be read, TOL says so and does not guess.

## 3. How a destination is named

Each destination carries a label and a confidence, never just a name:

- **Verified**: matches an entry you added yourself to `~/.tol/registry.json`.
- **Likely**: the hostname matches a built-in suffix rule and was **forward-confirmed** (see 3.1).
- **Hostname confirmed**: the reverse-DNS name resolves back to the same address.
- **Network owner only**: the public registry (RDAP/WHOIS) says which organisation holds the address block. That is the
  operator of the network, which may be a cloud or hosting company, not the business whose service was used.
- **Unidentified**: nothing reliable is known.

### 3.1 Forward confirmation
Whoever controls an address controls its reverse-DNS record and can make it claim any name. TOL therefore accepts a
name only if looking that name up forward yields the same address.

### 3.2 No lookups unless you ask
By default no address leaves the computer. Registry lookups happen only when the user presses **Identify**, or turns on
**Auto-identify** after being told what is sent. A lookup sends one public IP address to the public RDAP service
(`rdap.org`) and nothing else. Local and private addresses are never looked up.

## 4. Receipts

A **receipt** is a saved record of one registry lookup:

- the address, the time (this computer's clock), and the reverse-DNS result;
- the registry's answer **stored verbatim**, with its SHA-256 hash, and the URL it came from;
- a one-line caveat that the holder of an address block is not necessarily the vendor.

A failed lookup (network error, certificate error, timeout) is **never** stored as "no record". Only the registry's own
"not found" answer is stored as "no record". Receipts are written to an append-only file in which each entry includes
the hash of the one before it (a hash chain), so editing or deleting an earlier receipt breaks every later link.

## 5. Recordings and evidence packages

The user can start a **recording** for a period of time. When it stops, TOL can create an **evidence package**, a folder
and zip containing:

- the per-destination summary and every sample taken, in a hash chain;
- the receipts that back each named destination, with each registry record verbatim;
- device information and the TOL version;
- `MANIFEST.sha256`, the SHA-256 of every file in the package;
- a README stating what the package does not prove;
- `verify.py`, which anyone can run with plain Python 3 (no TOL needed) to confirm that no file changed and the chains
  are intact.

## 6. Trusted timestamp (optional)

The computer's clock can be wrong or changed. To show the package existed by a given time, the user can ask for a
**trusted timestamp** (RFC 3161). TOL sends **only** the 32-byte SHA-256 fingerprint of `MANIFEST.sha256` to an
independent timestamp authority (default: DigiCert). The authority returns a signed token naming the time. TOL refuses
any answer that is not for exactly that fingerprint.

`verify.py` checks that the token covers this package's manifest and verifies the authority's signature and certificate
chain itself, using only Python's standard library, against the trusted root list of the computer it runs on (or a
file named with `--cafile`). It handles RSA signatures with SHA-2; where it cannot decide (another signature type, or a
certificate that does not chain to a trusted root) it says plainly that the signature was **not** verified, and it tries
OpenSSL as a second route when one is installed. Revocation of the authority's certificate is not checked. This is a standard timestamp, not a legally
"qualified" timestamp under any particular jurisdiction's rules.

## 6.1 Browser-signal observer (optional)
An optional Firefox extension can record, per request, the destination host, the page host, a time and whether the browser sent `Sec-GPC: 1`, and nothing else. See `docs/BROWSER-SIGNAL.md` for what it records, how it reaches TOL, and what it does not prove (in particular: the chain and timestamp stop later editing, not false input at capture time).

## 7. What TOL does not prove

- **Not the content.** TOL does not see what was sent or received.
- **Not the vendor.** A network owner is not necessarily the company whose service ran; cloud and CDN addresses are
  shared by many.
- **Not completeness.** Short connections, UDP/QUIC (Linux, Windows) and anything between two checks can be missed.
- **Not the user's intent or who was at the keyboard.**
- **Not a tamper-proof device.** The hash chains show that records were not edited after being written; they do not show
  that the computer was not tampered with before. Without a trusted timestamp, times come from the computer's clock.
- **Not independently certified.** No third party has audited TOL. Packet capture and an expert certification are not
  yet part of the package.
- **Windows amounts.** On Windows, byte counts are unavailable and shown as n/a.

## 8. Privacy and security of the tool itself

- The dashboard listens only on `127.0.0.1` (this computer). It requires a secret token and checks the request host and
  a custom header on actions that change anything.
- Nothing is sent anywhere except the optional registry lookups (an IP address) and the optional timestamp request
  (a hash). TOL has no accounts, no analytics and no updates that phone home.
- Data is kept in `~/.tol` on the user's own computer.
- TOL uses only the language's standard library, so the code that runs is the code in the repository.

## 9. Checking it yourself

- Run `tol --diagnose` to see exactly what the operating system returned and what TOL read from it.
- Unzip an evidence package and run `python3 verify.py`.
- Read the code: it is short, and each module above has its own tests (`python -m pytest`).
