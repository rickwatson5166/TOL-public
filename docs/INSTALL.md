# Installing TOL

TOL is early software and is not yet signed with a developer certificate, so a Mac shows a warning the first
time. The steps below get past it. Nothing here installs a driver or changes your network.

## Mac (Intel or Apple silicon)

1. Download the file for your Mac: `TOL-x86_64.dmg` (Intel) or `TOL-arm64.dmg` (Apple silicon, M1 and later).
   Not sure? Apple menu > About This Mac: "Chip" says Apple M1/M2/M3, or "Processor" says Intel.
2. Open the downloaded `.dmg` and drag **TOL** into **Applications**.
3. Open **Applications**, **right-click TOL**, choose **Open**, then **Open** again.
4. If macOS still refuses: **System Settings > Privacy & Security**, scroll down, press **Open Anyway** next to TOL.
5. Your browser opens with the TOL window. To stop TOL, press **Quit TOL** in that window.

## Windows: coming soon

A Windows build exists and passes automated tests on GitHub's Windows machines, but nobody has run it on a real PC yet. It is not offered for download
until that has been done. Windows will show each connection and the program that made it, but not how much data it carried (Windows does not share
that with ordinary programs), so amounts will show as n/a.

## Linux

Run from source: `pip install .` then `tol`.

## Checking the download (optional)

Each file's SHA-256 fingerprint is listed on the release page. On a Mac: `shasum -a 256 TOL-x86_64.dmg`. The result should match the one on the release page.

## What TOL does on your computer

- Shows which companies your computer is talking to. It only watches; it blocks and changes nothing.
- Sends nothing out unless you ask. Two optional buttons send something: **Identify** sends one public address to
  a public registry (rdap.org), and **Add trusted timestamp** sends a 32-byte fingerprint to a timestamp service.
- Keeps everything it saves in a folder named `.tol` in your home folder. Delete the folder to remove it all.
- Has no accounts, no analytics and no automatic updates.

## If something goes wrong

Run `TOL --diagnose` (Mac: `/Applications/TOL.app/Contents/MacOS/TOL --diagnose`) and send the output; it lists the
programs and addresses your computer connected to, so look it over before sharing.

## Check your download
Each file on the [Releases page](https://github.com/rickwatson5166/TOL-public/releases) shows a SHA-256 fingerprint. Compare it with your copy:

- **Mac:** `shasum -a 256 ~/Downloads/TOL-arm64.dmg` (use the name of the file you downloaded)

If the long string matches, your file is the one GitHub shows. That proves it was not damaged or swapped on the way to you. It does not prove the
program is safe: for that, the source is in this repository, and the apps are built by this repository's own public workflow
(`.github/workflows/mac-app.yml`). If you would rather not trust a download at all, run it from source (see the README).

## Status, stated plainly
Tested by hand on one Intel Mac. The Apple-silicon build passes automated tests on GitHub's machines but has not yet been tried by a person on that
hardware. Windows is coming soon: its build passes automated tests but has not been run on a real PC, so it is not offered yet. If something fails for you, please open an issue and include what `tol --diagnose` prints.

