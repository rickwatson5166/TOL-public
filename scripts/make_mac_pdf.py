"""Builds docs/TOL-for-Mac.pdf: the features that have been run and worked on a real Mac, and what has not."""
import sys
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

OUT = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "docs" / "TOL-for-Mac.pdf")
INK, MUTED, LINE, ACCENT, SOFT = colors.HexColor("#14202B"), colors.HexColor("#4F5D6A"), colors.HexColor("#C9D1D9"), colors.HexColor("#1F5FA8"), colors.HexColor("#EAF1F8")
GOOD = colors.HexColor("#1B6B43")

base = ParagraphStyle("base", fontName="Helvetica", fontSize=9.6, leading=13.4, textColor=INK, alignment=TA_LEFT)
H1 = ParagraphStyle("h1", parent=base, fontName="Helvetica-Bold", fontSize=22, leading=26, spaceAfter=4)
SUB = ParagraphStyle("sub", parent=base, fontSize=10.5, leading=14.5, textColor=MUTED, spaceAfter=8)
H2 = ParagraphStyle("h2", parent=base, fontName="Helvetica-Bold", fontSize=12.5, leading=16, spaceBefore=10, spaceAfter=4)
CELL = ParagraphStyle("cell", parent=base, fontSize=8.7, leading=11.5)
HEAD = ParagraphStyle("head", parent=CELL, fontName="Helvetica-Bold", textColor=colors.white)
SMALL = ParagraphStyle("small", parent=base, fontSize=8.2, leading=11, textColor=MUTED)
BUL = ParagraphStyle("bul", parent=base, leftIndent=12, bulletIndent=0, spaceAfter=2.5)
OK = f'<font color="{GOOD.hexval()}"><b>Worked</b></font>'


def p(t, s=base):
    return Paragraph(t, s)


def grid(rows, widths):
    t = Table([[p(c, HEAD if i == 0 else CELL) for c in r] for i, r in enumerate(rows)], colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), ACCENT), ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, SOFT]), ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE),
        ("BOX", (0, 0), (-1, -1), 0.6, LINE), ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 3.4), ("BOTTOMPADDING", (0, 0), (-1, -1), 3.4)]))
    return t


def footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7.6)
    canvas.setFillColor(MUTED)
    canvas.drawString(0.8 * inch, 0.5 * inch, "TOL 0.4.6 for Mac  |  Tested October 9 to 14, 2026 on an Intel Mac mini  |  Early software.")
    canvas.drawRightString(letter[0] - 0.8 * inch, 0.5 * inch, f"Page {doc.page}")
    canvas.restoreState()


bullets = lambda items: [Paragraph(t, BUL, bulletText="•") for t in items]

story = [
    p("TOL for Mac", H1),
    p("Version 0.4.6. A transparent, neutral window that shows which companies a Mac is sending data to. "
      "Below are the features that were run on a real Mac and worked. Nothing here is listed unless it was run.", SUB),

    p("Features that worked", H2),
    grid([
        ["Feature", "What it does", "On the Mac"],
        ["Live destinations", "Lists every outside connection: destination name and address, the program that opened it, data sent in the last minute, "
         "rate, total sent, total received, and when it was last seen. Updates every second.", OK],
        ["Summary tiles", "Data sent since start, data received since start, number of destinations, number of alerts.", OK],
        ["First-time alerts", "A notice the first time a program sends data to a new destination, for example \"First time sending data to Dropbox, Inc. (from Dropbox).\"", OK],
        ["Naming who owns an address", "On request (Identify all, or Auto-identify after a consent question), asks a public registry who holds each address. "
         "Each name carries a label: Network owner only, Likely, Hostname confirmed or Verified. Seen on this Mac: Anthropic, Google, Dropbox, GitHub, Apple.", OK],
        ["Receipts", "\"View receipt\" shows the saved registry answer behind each name, with its hash and the time it was looked up.", OK],
        ["Local devices", "Devices on the home network show as Local network, Verified, and are never looked up outside the Mac.", OK],
        ["Pop out and Mini view", "A small separate window to keep beside other work. Closing it and clicking Pop out again reopens it every time (three times in a row on this Mac).", OK],
        ["Recording", "Record, then stop. TOL reports how many samples were saved and keeps the recording in a folder on the Mac. "
         "Links to download the full report (JSON), the summary (CSV) and the evidence package appear after stopping.", OK],
        ["Evidence package", "One zip holding the recording, the receipts, device details, a list of every file's fingerprint, a README and a checking script.", OK],
        ["Trusted timestamp", "Optional, asks first. Sends only a fingerprint of the package to DigiCert, an independent authority, and stores the signed answer. "
         "The page then shows the authority's time and name.", OK],
        ["Checking script", "Run <font face=\"Courier\">python3 verify.py</font> in the package folder. Passed on a package made the same day: files match, event chain "
         "unbroken, receipts match, timestamp signature and certificate chain verified by TOL's own checker, with nothing extra installed. "
         "A file added to the package afterwards was rejected.", OK],
        ["Version display", "The version is shown at the bottom of the page and recorded inside every evidence package.", OK],
        ["Quit TOL", "A button that stops TOL cleanly. TOL listens only on this Mac (127.0.0.1).", OK],
    ], [1.45 * inch, 4.55 * inch, 0.9 * inch]),

    p("What it does not do", H2),
    *bullets([
        "It does not read content. It sees the destination, the program and the amount, not the words, files or pages inside.",
        "It does not block or change anything. Turning it off leaves the Mac as it was.",
        "It can miss very short connections that open and close between two checks.",
        "A named owner is not always the vendor: a registry names who holds an address block, which may be a cloud or hosting company.",
        "Times come from the Mac's clock unless the package carries a trusted timestamp. Certificate revocation is not checked.",
    ]),

    p("Opening it on a Mac", H2),
    p("TOL is not yet code-signed, so macOS shows a first-time warning. After copying TOL to Applications, one line in Terminal clears it: "
      "<font face=\"Courier\">xattr -dr com.apple.quarantine /Applications/TOL.app</font>, then open TOL. Its page appears in the browser at "
      "127.0.0.1. Quit any earlier copy of TOL first, because an old copy that is still running will be the one that opens."),

    p("Not yet tested", H2),
    *bullets([
        "The Apple-silicon (M-series) build is built and passes automated tests, but no one has run it on a real Apple-silicon Mac.",
        "Only one Mac, an Intel Mac mini, has been used. Other macOS versions are untested.",
        "The longest recording on a real Mac so far is a few minutes, not hours.",
        "No outside party has reviewed TOL or its method.",
    ]),
    Spacer(1, 4),
    p("Overview page: rickwatson5166.github.io/tol-info", SMALL),
]

OUT.parent.mkdir(parents=True, exist_ok=True)
doc = SimpleDocTemplate(str(OUT), pagesize=letter, leftMargin=0.8 * inch, rightMargin=0.8 * inch, topMargin=0.6 * inch,
                        bottomMargin=0.85 * inch, title="TOL for Mac", author="Rick Watson",
                        subject="Features of TOL 0.4.6 that were run and worked on a real Mac")
doc.build(story, onFirstPage=footer, onLaterPages=footer)
print(OUT)
