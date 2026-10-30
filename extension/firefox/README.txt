TOL observer (Firefox), test build.
1. Run:  python3 -m tol_app --install-browser-helper     (once; writes one file in Firefox's helper folder)
2. Firefox: about:debugging -> This Firefox -> Load Temporary Add-on -> pick manifest.json here.
3. Start TOL, press Record, browse, Stop. The observations go into the recording's hash chain.
Observer only: it reads no content, blocks nothing, changes nothing. The extension keeps nothing; when TOL is not
recording, TOL discards what arrives.
