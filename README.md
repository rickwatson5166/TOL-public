# TOL

**See who your computer is sending data to.** Free, open source and early.

TOL watches your computer's network connections and shows, in plain language, where data is going: which app, which destination, how much.
It can look up who holds an address, and it can save a record with an independent timestamp that anyone can check.

**TOL shows. It does not block, judge, or promise privacy.** Please read [what TOL can and cannot prove](docs/WHY-TRUST.md) first.

## Download (v0.4.8, pre-release)
Get the files from the [Releases page](https://github.com/rickwatson5166/TOL-public/releases): Mac (Apple silicon or Intel) and Windows 10/11.

- **The apps are not signed yet.** macOS says "can't be opened": right-click the app, choose Open, then Open. You can check each file against the SHA-256 shown on the release page,
  and everything is built in public by this repository's own workflow.
- **Honest status:** tested by hand on one Intel Mac. The Apple-silicon build passes automated tests on GitHub's machines but has not yet been
  tried by a person on that hardware. **Windows** has been run by hand on one Windows 11 PC. Per-connection amounts need TOL to be started as Administrator (right-click, Run as administrator); otherwise Windows shows each connection and program with amounts as n/a, and TOL says so on screen. Linux works from source.
- Prefer to run it yourself? See "Run from source" below, or [how to check a download](docs/INSTALL.md#check-your-download). TOL uses only Python's standard library.

## What it does
- A live view of destinations, the program using each, and the amount of data.
- Record a session and save it (JSON and CSV).
- Optional "receipts": ask the public registries who holds an address (off by default; it sends the address, never your data).
- An evidence package: every sample in a hash chain, a checker script that needs only Python, and an optional RFC 3161 trusted timestamp.
- Optional Firefox add-on that records whether your browser sent the Global Privacy Control signal. Observer only.

## What it does not do
- It does not block anything, and it cannot tell you whether anyone's use of your data is good or bad.
- It does not always know who is on the other end. It may be a company, a cloud or network provider, an individual's server, or something unidentified. Each label says how sure TOL is.
- It does not read the contents of your traffic. There is no packet capture.
- It can miss very short connections. The registry holder of an address is often a cloud provider, not the service you were using.
- A record is not legal proof by itself. Have a qualified person review it before relying on it.

## Feedback
Found a bug, a wrong label, or a claim that overreaches? Open an issue. That is the most useful thing you can do.
Contact: optioncsolutions@gmail.com. Made by Rick Watson (Option C Solutions). Licence: Apache-2.0.

## Run from source
```
pipx install git+https://github.com/rickwatson5166/TOL-public      # or: pip3 install .
tol --diagnose      # first run: shows what your machine's network tools return
tol                 # starts watching and opens the dashboard at http://127.0.0.1:8731
```
More options (start at login, receipts, recordings, evidence packages, trusted timestamps, the Firefox add-on) are in [docs/USAGE.md](docs/USAGE.md).

## Documents
- [docs/SCOPE.md](docs/SCOPE.md): what TOL is and is not
- [docs/WHY-TRUST.md](docs/WHY-TRUST.md): what you can check yourself, and what is not yet in place
- [docs/METHOD.md](docs/METHOD.md): how it works and what it does not prove
- [docs/INSTALL.md](docs/INSTALL.md): installing, and checking a download
- [docs/USAGE.md](docs/USAGE.md): every feature in detail
- [docs/BROWSER-SIGNAL.md](docs/BROWSER-SIGNAL.md): the optional Firefox observer and the site report
- [SECURITY.md](SECURITY.md): reporting a security problem

## Tests
`python -m pytest` (standard library plus pytest; no other dependencies).
