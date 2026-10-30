# Why trust this? (You shouldn't have to take our word for it.)

TOL watches what your computer's network connections show. A tool like that asks for trust, so this page says what you
can check yourself, and what is not yet in place.

## What you can check

**It is small and readable.** TOL is written in plain Python with no outside libraries (`dependencies = []` in
`pyproject.toml`; if the `certifi` certificate list happens to be installed it is used for the optional registry lookups, and
TOL works without it). The code is in this repository. Nothing is hidden in a download you cannot inspect.

**It reaches the outside in exactly two ways, and you control both.**
1. *Registry lookups*, which name the owner of an address. They are **off by default**. They send the address you looked up
   to a public registry, and only if you turn them on.
2. *A trusted timestamp*, which sends only a fingerprint of your evidence package to a timestamp authority, and only when you
   press the button and agree.

Everything else TOL does stays on your computer, and its web page listens only on `127.0.0.1`, protected by a token. To
check, search the code for network calls:

    grep -rn "urlopen\|HTTPSConnection\|create_connection" tol_app/ tol_collector*.py

You will find the registry lookup (`tol_app/netutil.py`) and the timestamp request (`tol_app/timestamp.py`), plus the helper
that talks to TOL on `127.0.0.1`. That is all.

**It never reads content.** It records which addresses a device connected to and how many bytes moved, never what the bytes
held. The optional Firefox observer keeps only a host, the page host, a time and a yes/no for the privacy signal. The
verifier refuses a package whose observations carry anything more.

**It blocks and changes nothing.** TOL only watches. It never sends the privacy signal; your browser does.

**Its records check themselves.** Every evidence package carries `verify.py`, which needs only Python. It re-checks every
file's hash, the event chain, and any timestamp signature, with no TOL installed. You do not have to trust TOL to trust
the check.

**It says how sure it is.** Every destination label carries its confidence (Network owner only, Likely, Hostname confirmed,
Verified), and a report never says anyone broke a rule. See `docs/SCOPE.md` and `docs/METHOD.md`.

## What is not in place yet (so you know)

- **No outside review.** Nobody independent has read the code or tested the method yet. That is the most important gap.
- **Unsigned apps.** The Mac and Windows downloads are not yet signed, so your system will warn you before opening them.
  A signed release and a published checksum for each download are planned. Until then, build it from source if you prefer.
- **Early software.** Tested so far on one Intel Mac with Firefox. Windows, Chrome, Edge and Apple-silicon Macs are not yet
  tested on real machines.
- **Licence.** TOL is released under the Apache License 2.0 (see `LICENSE` and `NOTICE`). The name "TOL" is not licensed for modified versions.
- **A record can be edited before it is packaged, or fed false input at capture time** by a program running as you. The
  chain and timestamp stop later editing, not that. See `docs/BROWSER-SIGNAL.md`.

If you find a problem with any of this, please say so. A neutral tool is only worth having if it can be corrected.
