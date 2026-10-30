"""Builds docs/TOL-capabilities-mac-windows.pdf. Every claim here is tied to something that was run; see the 'How it was checked' box."""
import sys
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

OUT = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "docs" / "TOL-capabilities-mac-windows.pdf")
INK, MUTED, LINE, ACCENT, SOFT = colors.HexColor("#14202B"), colors.HexColor("#4F5D6A"), colors.HexColor("#C9D1D9"), colors.HexColor("#1F5FA8"), colors.HexColor("#EAF1F8")
GOOD, PART, NO = colors.HexColor("#1B6B43"), colors.HexColor("#8A5A00"), colors.HexColor("#A3271F")

base = ParagraphStyle("base", fontName="Helvetica", fontSize=9.6, leading=13.4, textColor=INK, alignment=TA_LEFT)
H1 = ParagraphStyle("h1", parent=base, fontName="Helvetica-Bold", fontSize=22, leading=26, spaceAfter=4)
SUB = ParagraphStyle("sub", parent=base, fontSize=10.5, leading=14.5, textColor=MUTED, spaceAfter=10)
H2 = ParagraphStyle("h2", parent=base, fontName="Helvetica-Bold", fontSize=12.5, leading=16, spaceBefore=9, spaceAfter=4)
CELL = ParagraphStyle("cell", parent=base, fontSize=8.6, leading=11.4)
HEAD = ParagraphStyle("head", parent=CELL, fontName="Helvetica-Bold", textColor=colors.white)
SMALL = ParagraphStyle("small", parent=base, fontSize=8.2, leading=11, textColor=MUTED)
BUL = ParagraphStyle("bul", parent=base, leftIndent=12, bulletIndent=0, spaceAfter=2.5)


def p(t, s=base):
    return Paragraph(t, s)


def tag(word, col):
    return f'<font color="{col.hexval()}"><b>{word}</b></font>'


YES, PARTLY, NOPE = tag("Yes", GOOD), tag("Built, not yet run on a real PC", PART), tag("No", NO)


def grid(rows, widths):
    t = Table([[p(c, HEAD if i == 0 else CELL) if isinstance(c, str) else c for c in r] for i, r in enumerate(rows)],
              colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), ACCENT), ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, SOFT]), ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE),
        ("BOX", (0, 0), (-1, -1), 0.6, LINE), ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 3.2), ("BOTTOMPADDING", (0, 0), (-1, -1), 3.2)]))
    return t


def footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7.6)
    canvas.setFillColor(MUTED)
    canvas.drawString(0.8 * inch, 0.5 * inch, "TOL 0.4.6  |  Capabilities as of October 14, 2026  |  Early software. A description of the tool, not legal advice.")
    canvas.drawRightString(letter[0] - 0.8 * inch, 0.5 * inch, f"Page {doc.page}")
    canvas.restoreState()


story = [
    p("TOL: what it can do today", H1),
    p("Version 0.4.6 for macOS and Windows. A transparent, neutral window that shows which companies a computer is "
      "sending data to. It only watches. It does not block, change or read anything.", SUB),

    p("What it does", H2),
    grid([
        ["Capability", "macOS", "Windows"],
        ["Live list of destinations: who the computer is connected to, which program opened each connection, and when",
         f"{YES}<br/>Run on a real Intel Mac.", f"{YES}<br/>Passes automated tests on Windows machines. {PARTLY.replace('Built, not yet run on a real PC', 'Not yet run on a real PC.')}"],
        ["Amount of data sent and received per destination", YES, f"{NOPE}<br/>Windows does not give ordinary programs per-connection counts. TOL shows n/a and says why on screen."],
        ["Names the owner of an address (public registry lookup, only when the user asks; one IP address is sent, nothing else)",
         YES, f"Built and tested by machine. {PARTLY.replace('Built, not yet run on a real PC', 'Not yet run on a real PC.')}"],
        ["Receipts: each lookup saved verbatim with its hash, in a chain that breaks if any entry is edited or removed", YES,
         "Built and tested by machine."],
        ["Recording, and an evidence package: the recording, the receipts, device details, a manifest of every file's fingerprint, and a checking script",
         f"{YES}<br/>Made and checked end to end on a real Mac.", "Built into the packaged app; the build is tested on Windows machines."],
        ["Checking script (verify.py): anyone can run it with plain Python and no TOL. It reports whether any file was changed or added and whether the chains are intact",
         f"{YES}<br/>Passes on a package made today. Rejected a file added afterwards.", "Same script; tested by machine."],
        ["Trusted timestamp (optional): only a fingerprint is sent to an independent authority (DigiCert). TOL's own checker verifies the authority's signature and certificate chain, with nothing extra to install",
         f"{YES}<br/>Verified on a real Mac against DigiCert.", "Same checker. It reads the Windows certificate store, a route not yet run on a real PC."],
        ["Small separate window to keep beside other work (Pop out)", f"{YES}<br/>Reopens reliably on a real Mac.", "Finds Edge or Chrome. Not yet run on a real PC."],
    ], [3.05 * inch, 1.85 * inch, 2.0 * inch]),

    p("What it does not do", H2),
    *[Paragraph(t, BUL, bulletText="•") for t in [
        "<b>It does not read content.</b> It sees the destination, the program and the amount, not the words, files or pages inside.",
        "<b>It does not block or change anything.</b> Turning it off leaves the computer exactly as it was.",
        "<b>It can miss very short connections</b> that open and close between two checks, a few seconds apart.",
        "<b>A named owner is not always the vendor.</b> A registry names who holds an address block, which may be a cloud or hosting company.",
        "<b>It is not a tamper-proof device.</b> The chains show records were not edited after they were written, not that the computer was untouched. "
        "Without a trusted timestamp, times come from the computer's own clock.",
        "<b>Timestamp limits.</b> The checker does not test whether the authority's certificate was revoked. It handles RSA signatures with SHA-2 "
        "(DigiCert and Sectigo); other signature types are reported as not verified. It is a standard timestamp, not a legally \"qualified\" one.",
    ]],

    p("How it was checked", H2),
    grid([
        ["Evidence", "What it covers"],
        ["Real Intel Mac, TOL 0.4.6", "Live view, recording, evidence package, trusted timestamp and the checking script all run on a real computer. The check passed on a package made that day."],
        ["Real timestamp answers", "Saved answers from DigiCert and Sectigo verify, including their full certificate chains. A third authority (FreeTSA) uses a different signature type and is correctly reported as not verified."],
        ["Attack tests", "Every byte of what the authority signed, the signature and the signing certificate was changed one at a time on two real answers. None of the changed answers was accepted."],
        ["Over 170 automated tests", "Run on every change, on a Mac and on Windows test machines, before a release is built. They include altered and forged packages."],
        ["Written method", "A plain-language description of what is recorded, how, and what it does not prove (docs/METHOD.md)."],
    ], [1.9 * inch, 5.0 * inch]),

    p("Not yet done", H2),
    *[Paragraph(t, BUL, bulletText="•") for t in [
        "<b>Real-PC test of the Windows version.</b> Everything marked above as not yet run on a real PC.",
        "<b>Real-computer test of the Apple-chip Mac build.</b> It is built and passes automated tests; no person has run it.",
        "<b>Code signing.</b> Both apps are unsigned, so a Mac or Windows computer shows a first-time warning, and some managed computers may not allow them.",
        "<b>Independent review.</b> No outside party has audited TOL or its method.",
        "<b>Certificate revocation checking</b> and support for more timestamp signature types.",
    ]],

    p("Using it", H2),
    p("TOL runs on the person's own computer and shows its dashboard only on that computer (address 127.0.0.1). It has no accounts and no "
      "analytics, and it does not phone home. Nothing leaves the computer except two optional actions, each started by the user: a registry "
      "lookup (one public IP address) and a timestamp request (one 32-byte fingerprint). Data is kept in a folder on the user's own computer."),
    Spacer(1, 6),
    p("Overview page: rickwatson5166.github.io/tol-info", SMALL),
]

OUT.parent.mkdir(parents=True, exist_ok=True)
doc = SimpleDocTemplate(str(OUT), pagesize=letter, leftMargin=0.8 * inch, rightMargin=0.8 * inch, topMargin=0.6 * inch,
                        bottomMargin=0.85 * inch, title="TOL: what it can do today", author="Rick Watson",
                        subject="Capabilities of TOL 0.4.6 on macOS and Windows")
doc.build(story, onFirstPage=footer, onLaterPages=footer)
print(OUT)
