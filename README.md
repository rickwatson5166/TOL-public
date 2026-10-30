# TOL
A transparent, neutral window on which companies your device is sending data to. Free, open and early.

Read `docs/WHY-TRUST.md` and `docs/SCOPE.md` first: they say what TOL does, what it cannot establish, and what is not yet in place.

## Quick start (macOS, Intel or Apple silicon; Linux also works)
```
pipx install git+https://github.com/rickwatson5166/TOL-public      # or: pip3 install .
tol --diagnose      # first run: shows what your machine's network tools return
tol                 # starts watching and opens the dashboard
```
`tol` watches this machine's real connections and opens a live dashboard in your browser
(`http://127.0.0.1:8731`). Optional: `tol --install-autostart` to start at login (launchd on macOS,
systemd on Linux), `--lookup` to name network owners (sends destination IPs to public registries; **off by default**).

**macOS status:** the collector reads the system's `nettop` and was written without access to a
Mac. If `tol --diagnose` does not say `RESULT: OK`, run `tol --save-sample nettop.txt` and send that
file (it lists program names and addresses, so review it first): the parser can be fixed from your
Mac's real output.

**A standalone program (no Python needed):** on the target Mac, `pip3 install pyinstaller` then
`./scripts/build_binary.sh` builds `dist/tol` for that Mac's chip. A binary you build yourself runs
fine. A binary you *download* from somewhere is blocked by macOS Gatekeeper unless it is signed with
an Apple Developer ID and notarized, which needs a paid Apple developer account.

## Browser-signal observer (optional, 0.4.7)
A small Firefox extension (`extension/firefox/`) lets TOL record which hosts a page's requests went to and whether Firefox sent the Global Privacy Control signal. Observer only: no content, nothing blocked or changed. Read `docs/BROWSER-SIGNAL.md` first. Install the helper with `python3 -m tol_app --install-browser-helper`, load the extension from `about:debugging`, record, then `python3 -m tol_app --site-report <recording.json>`.

## Sharing the Mac app

GitHub builds `TOL.app` for both Intel and Apple silicon on every push (`.github/workflows/mac-app.yml`),
tests it on real Macs, and attaches `TOL-x86_64.dmg`/`.zip` (Intel) and `TOL-arm64.dmg`/`.zip` (Apple silicon).

- **Get the files:** repo -> Actions -> latest `mac-app` run -> Artifacts. Or tag a release
  (`git tag v0.1.0 && git push --tags`) and the dmg/zip files appear under Releases, with a public link.
- **Install:** open the dmg, drag `TOL` to Applications, double-click. The dashboard opens in the browser.
  Double-clicking again just reopens it; the **Quit TOL** button in the dashboard stops it.
- **First launch warning:** until the app is signed and notarized with an Apple Developer ID, macOS shows
  "TOL can't be opened". Recipients right-click the app -> **Open** -> **Open**, or run
  `xattr -dr com.apple.quarantine /Applications/TOL.app` once. This is expected for unsigned apps.
- **To remove that warning for everyone:** join the Apple Developer Program, then add the repo secrets
  `MACOS_SIGN_IDENTITY`, `APPLE_ID`, `APPLE_TEAM_ID`, `APPLE_APP_PASSWORD`; the workflow then signs and
  notarizes automatically (`scripts/package_mac.sh`). This path is written but has not been run.

**Pop out:** on a Mac with Chrome (or Chromium, Brave, Edge) installed, *Pop out* has TOL start its own small
360x600 browser window, so the size cannot be ignored (a web page can only *ask* for a small pop-up, and some browsers
refuse). It uses a separate throw-away browser profile in `~/.tol/mini-browser`, never your normal Chrome profile, and
logs in with a one-time code that works once for 60 seconds, so TOL's access token is never put on a command line. If no
such browser is found it falls back to asking the current browser for a pop-up.

**Mini view and recording (in the dashboard):** a window narrower than about 760 px switches to the compact side
layout by itself (and back when widened); *Mini view* forces it in a wide window, and *Pop out*
opens a small separate window to keep beside your work (its *Snap* button flips it to the other side of the screen). *● Record* starts capturing activity; *Stop recording*
(optionally auto-stopping after 5 min to 1 hour) saves `~/.tol/recordings/tol-recording-<time>.json` (full report: totals, destinations, alerts, every connection
sample) and a `.csv` per-destination summary, both downloadable from the dashboard.

**Receipts (pinpointing a destination):** each destination has an *Identify* button. It asks the public RDAP/WHOIS
service who holds that address (this sends the address, not your data, so it only happens when you click and you
confirm), and saves a *receipt* to `~/.tol/receipts.jsonl`: the registry record verbatim with its SHA-256,
forward-confirmed reverse DNS, what this device sent/received, and the lookup time. Receipts are hash-chained so
edits or deletions are detectable, are included in recordings, and can be downloaded as one file. Limits: times come
from this device's clock (no trusted timestamp), the chain is not signed by a third party, and the registered holder
of an address block is the network operator, not necessarily the vendor.

**Auto-identify:** a switch in the dashboard header. When on (it asks first, and stays off by default), TOL looks up
each new destination in the background and saves a receipt for it, so every row fills in its proof by itself. It sends
only IP addresses, makes one lookup per network block, skips local addresses and rows your own registry already verifies (rows labelled *Likely*, whose name is only a hostname guess, are looked up),
and is capped at one lookup every 1.5 s and 120 per hour. The setting is kept in `~/.tol/settings.json`.

**If lookups fail:** `tol --diagnose` (or `/Applications/TOL.app/Contents/MacOS/TOL --diagnose`) now ends with a
line that tests the registry connection and says why it failed. A lookup that cannot be made is never saved as a
receipt; the dashboard shows the reason and retries it later. "The registry has no record" is shown only when the
registry actually answered that.

**Trusted timestamp:** after building an evidence package, *Add trusted timestamp* (it asks first) sends ONE
fingerprint, the SHA-256 of the package's `MANIFEST.sha256`, never any data, to an independent timestamp authority
(RFC 3161; default `timestamp.digicert.com`, change it with `tsa_url` in `~/.tol/settings.json`). The signed answer is
stored in the package's `timestamp/` folder, so the time of the whole package no longer depends on your Mac's clock.
`python3 verify.py` re-checks that the token covers exactly this package and verifies the authority's signature and
certificate chain with its own built-in checker (standard Python only, nothing to install; RSA with SHA-2, against the
computer's trusted root list). If it cannot decide it says plainly that the signature was **not** verified, and tries
OpenSSL when one is installed. Limits: certificate revocation is
not checked; a free public authority is not a legally "qualified" one, so ask your lawyer which to use; and the
timestamp proves when the package existed, not that the capture was complete or that each sample's own time is right.

**Evidence package:** after stopping a recording, *Create evidence package* bundles it into one zip
(`~/.tol/evidence/`): the per-destination summary, every sample in a hash chain, the receipts with each registry
record verbatim, device info, a `MANIFEST.sha256`, a README that states what it does *not* prove, and `verify.py`.
Anyone can run `python3 verify.py` inside the unzipped folder (Python 3 only, no TOL needed) to confirm nothing
changed since packaging. Not included yet: packet capture (pcap), a signature on the receipt chain, expert certification.

The dashboard shows who your device is sending data to and how much, labelled by how far each name
can be trusted: **Verified** (your registry), **Likely** (forward-confirmed hostname rule),
**Hostname confirmed**, **Network owner only** (public RDAP records; the network operator, not
necessarily the vendor) or **Unidentified**. It does not read what the data contains.

## What live collection cannot see
Payload content, UDP/QUIC (HTTP/3), connections that open and close between two one-second readings, and the last interval of
bytes before a close. Country is `??` (no GeoIP) and TLS certificate fields are empty (handshakes are not captured). Company names
come only from the built-in hostname rules and `~/.tol/registry.json` (IP/CIDR or hostname-suffix rules you edit); anything
unmatched is shown as unidentified. Never add a mapping you have not verified.

## Documents
- `docs/SCOPE.md`: what TOL is and is not
- `docs/WHY-TRUST.md`: what you can check yourself, and what is not yet in place
- `docs/METHOD.md`: how it works and what it does not prove
- `docs/BROWSER-SIGNAL.md`: the optional Firefox observer and the site report
- `docs/INSTALL.md`: installing

## Tests
`python -m pytest` (standard library plus pytest; no other dependencies).

## Contact
optioncsolutions@gmail.com (Option C Solutions). Tell me what is wrong, unclear or missing: a neutral tool is only worth having if it can be corrected.

## Licence
Apache License 2.0. See `LICENSE` and `NOTICE`.
