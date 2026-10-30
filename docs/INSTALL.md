# Installing TOL

TOL is early software and is not yet signed with a developer certificate, so Mac and Windows show a warning the first
time. The steps below get past it. Nothing here installs a driver or changes your network.

## Mac (Intel or Apple silicon)

1. Download the file for your Mac: `TOL-x86_64.dmg` (Intel) or `TOL-arm64.dmg` (Apple silicon, M1 and later).
   Not sure? Apple menu > About This Mac: "Chip" says Apple M1/M2/M3, or "Processor" says Intel.
2. Open the downloaded `.dmg` and drag **TOL** into **Applications**.
3. Open **Applications**, **right-click TOL**, choose **Open**, then **Open** again.
4. If macOS still refuses: **System Settings > Privacy & Security**, scroll down, press **Open Anyway** next to TOL.
5. Your browser opens with the TOL window. To stop TOL, press **Quit TOL** in that window.

## Windows 10 / 11

1. Download `TOL-windows-x64.zip`.
2. Right-click it, choose **Extract All**, and extract to a folder such as Documents.
3. Open the extracted **TOL** folder and double-click **TOL.exe**.
4. If Windows says "Windows protected your PC": press **More info**, then **Run anyway**.
5. A black window opens and stays open while TOL runs; your browser opens with the TOL window. Closing the black window
   stops TOL. **Quit TOL** in the browser does the same.

Windows shows each connection and the program that made it, but not how much data it carried (Windows does not share
that with ordinary programs), so amounts show as n/a.

## Linux

Run from source: `pip install .` then `tol`.

## Checking the download (optional)

Each file's SHA-256 fingerprint is listed on the release page. On a Mac: `shasum -a 256 TOL-x86_64.dmg`. On Windows
(PowerShell): `Get-FileHash TOL-windows-x64.zip`. The result should match the one on the release page.

## What TOL does on your computer

- Shows which companies your computer is talking to. It only watches; it blocks and changes nothing.
- Sends nothing out unless you ask. Two optional buttons send something: **Identify** sends one public address to
  a public registry (rdap.org), and **Add trusted timestamp** sends a 32-byte fingerprint to a timestamp service.
- Keeps everything it saves in a folder named `.tol` in your home folder. Delete the folder to remove it all.
- Has no accounts, no analytics and no automatic updates.

## If something goes wrong

Run `TOL --diagnose` (Mac: `/Applications/TOL.app/Contents/MacOS/TOL --diagnose`) and send the output; it lists the
programs and addresses your computer connected to, so look it over before sharing.
