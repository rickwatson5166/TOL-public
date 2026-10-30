# PyInstaller spec for the Windows build: `pyinstaller --noconfirm --clean scripts/tol_win.spec` -> dist/TOL/TOL.exe
# A console window stays open while TOL runs (closing it stops TOL); the dashboard also has a Quit button.
from pathlib import Path

root = Path(SPECPATH).parent

a = Analysis(
    [str(root / "scripts" / "app_entry.py")],
    pathex=[str(root)],
    datas=[(str(root / "tol_app" / "static"), "tol_app/static"),
           (str(root / "tol_app" / "evidence_verify.py"), "tol_app"),   # copied into evidence packages
           (str(root / "tol_app" / "timestamp.py"), "tol_app"),
           (str(root / "extension" / "firefox"), "extension/firefox")],         # the browser observer, copied out on Set up
    hiddenimports=["tol_collector_win", "tol_collector", "tol_registry", "tol_app.gpc", "tol_app.nativehost"],
)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="TOL", console=True)
coll = COLLECT(exe, a.binaries, a.datas, name="TOL")
