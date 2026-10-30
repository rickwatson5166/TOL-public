# What TOL is, and what it is not

TOL is a transparent, neutral window on what a computer's network connections and a browser's requests show. It is meant to be
free to use and free to inspect. It records what happened. It does not judge.

## What TOL does
- Shows which outside addresses a device connected to, which program opened each connection, and how much data was sent
  (never what the data contained).
- Names each destination only as far as the evidence goes, and says how sure it is: Network owner only, Likely, Hostname
  confirmed, or Verified.
- Optionally records, through a Firefox extension, which hosts a page's requests went to and whether the browser sent the Global
  Privacy Control signal (`Sec-GPC: 1`). Only the host, the page host, the time and a yes/no are kept. No content is read.
- Packages a recording so that later editing is detectable: a hash chain, a manifest, an optional independent trusted timestamp, and
  a verifier script that needs only Python.
- Prints a site report: where one page's requests went, with and without the signal, each host with its label and confidence.

## What TOL never does
- It never blocks, changes or injects anything. It never sends the privacy signal; the browser does.
- It never reads page content, passwords, cookies or message bodies.
- Nothing leaves the machine unless the user asks for it (for example, a registry lookup or a timestamp request).
- It states no verdict. A report says what was observed, never that anyone broke a rule.

## What TOL cannot establish
- **Whether a vendor complies with an opt-out.** TOL sees the device's side: that a request went to a host while the signal was on.
  What the host did with it happens on the host's servers, where TOL cannot see. A request after the signal is not by itself a
  violation; many requests are ordinary.
- **That a capture was honest when it was made.** The hash chain and timestamp stop later editing. They do not stop false input at
  capture time by a program running as the same user.
- **That a capture was complete.** TOL reads the operating system's connection tables about once a second and sees what the browser
  extension reports. It can miss short connections and requests made outside the browser.
- **Who a company is.** A label usually names who runs the servers (a cloud, network or delivery operator), not necessarily the
  company behind a host name.
- **Anything legal.** Whether a record is admissible, or what a law requires of a given vendor, is for qualified people.

## Where TOL can help a vendor that is complying
Some promises can be checked from the browser. A site that says "when your browser sends the signal, we stop loading advertising
and tracking hosts" can be tested: record the page with the signal off, then on, and compare the host lists. Anyone can repeat
that test. TOL gives a way to check this part instead of asking for trust. Promises about server-side use of data, such as "we do not
sell your data", are outside what TOL can show, and TOL must not be described as showing them.

## A repeatable test
1. Record the page with the browser's signal turned off. Stop. Save the recording.
2. Record the same page with the signal turned on. Stop. Save the recording.
3. Repeat on more than one site, more than once, and in more than one browser where supported.
4. Compare the host lists. Publish the method together with the results, including runs that show no difference.
One short run on one site shows only that the capture works. It is not a finding about the site.
