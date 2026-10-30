# TOL browser-signal observer (0.4.7): what it records, and what it does not prove

This is an optional add-on. TOL works without it. It is observer-only and free to use, copy and inspect.

## What it does
Some browsers send a privacy signal called Global Privacy Control (GPC): the request header `Sec-GPC: 1`.
Firefox sends it when "Tell websites not to sell or share my data" is switched on (Settings, Privacy & Security).
The TOL Firefox extension (`extension/firefox/`) watches outgoing requests and keeps, for each one:

- the host the request went to (for example `ads.example.com`), never the path or query,
- the host of the page you were on,
- the time, to the second,
- the server address Firefox connected to,
- whether `Sec-GPC: 1` was present, yes or no.

It reads no page content, no cookies, no other headers and no request or response bodies. It blocks nothing, changes
nothing and injects nothing. **TOL never sends the signal; Firefox does.** TOL only records whether it was there.

## Private windows
Firefox does not run extensions in private windows unless you allow it, and TOL does not ask you to: browsing you chose to keep
private is not watched by default. If your Firefox is set to always use private browsing, the observer sees nothing until you open
Settings, then Extensions, then TOL observer, and set **Run in Private Windows** to Allow. Leave **Run on sites with restrictions**
off. The observer's toolbar button shows a number when it is seeing requests and a red **!** (with the reason on hover) when it
cannot reach TOL's helper. Firefox's own tracking protection also blocks some known trackers before a request is sent, and the
observer can only count requests that were sent, so a host missing from a report does not show that the page never tried to reach it.

## How it reaches TOL
The extension cannot read TOL's token. It hands batches to a small helper program that Firefox starts (browser "native
messaging"), and only for this extension's id. The helper reads TOL's token from your own `~/.tol` folder and posts to
`127.0.0.1`. TOL refuses any observation that has more than the allowed fields. Install the helper with
`python3 -m tol_app --install-browser-helper`; it writes one small file in Firefox's helper folder.

Observations are kept only while a recording is running. When TOL is not recording, what arrives is discarded.
They go into the same hash chain as the network samples, as event type `gpc_observation`, and `verify.py` fails
any package whose observations carry more than the allowed fields.

## The site report
For one page, `python3 -m tol_app --site-report <recording.json> <page>` (or `--site-report <recording.json>` to list
the pages seen) prints which hosts that page's requests went to, how many carried the signal and how many did not, and
the ownership label TOL already had for each host, with its confidence (Network owner only / Likely / Hostname confirmed /
Verified). It says what was observed. It never says that anyone broke a rule.

**Read the labels carefully.** A label is usually the company that runs the servers (a cloud, network or content-delivery
operator), not necessarily the company behind the host name. That is why each label carries its confidence, and why many
hosts are shown as having no label.

## What this does NOT prove
- **That anyone acted on the signal, or failed to.** A request sent while the signal was on shows that the page contacted
  that host. It does not show what the host did with the request, what the request contained, or whether any law or
  policy applies.
- **That the capture was honest at the moment it was made.** The hash chain and the trusted timestamp stop later editing.
  They do not stop a false observation being fed in at capture time: any program running as you can pass observations to
  TOL the same way the extension does. The helper proves the data came through your account, not that it is true.
- **That the capture was complete.** The extension sees what Firefox reports. Requests made outside Firefox, or by other
  extensions, may be missed.
- **Who the "company" is.** See the note on labels above.
- **Anything from a single recording.** Two short recordings on one Mac show that the counter can tell "signal on" from
  "signal off". They are not a finding about any site.

## Privacy of the observations themselves
A list of hosts with times is browsing history. It stays on your machine, in the recording and evidence package you
create, and goes nowhere unless you send it. Read a recording before you share it: the page names show where you went.
TOL does not ship a list of known trackers. If tracker identification is added later, it will use a published list that
you supply yourself, so its own licence and age are clear.
