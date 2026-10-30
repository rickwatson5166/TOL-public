# PyInstaller spec for TOL.app. Build on a Mac: `pyinstaller --noconfirm --clean scripts/tol_mac.spec`
# The app has no Dock icon (LSUIElement); it opens the dashboard in the browser, which has a Quit button.
from pathlib import Path

root = Path(SPECPATH).parent

a = Analysis(
    [str(root / "scripts" / "app_entry.py")],
    pathex=[str(root)],
    datas=[(str(root / "tol_app" / "static"), "tol_app/static"),
           (str(root / "tol_app" / "evidence_verify.py"), "tol_app"),   # copied into evidence packages
           (str(root / "tol_app" / "timestamp.py"), "tol_app"),
           (str(root / "extension" / "firefox"), "extension/firefox")],         # the browser observer, copied out on Set up
    hiddenimports=["tol_collector_mac", "tol_collector", "tol_registry", "tol_app.gpc", "tol_app.nativehost"],
)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="TOL", console=False)
coll = COLLECT(exe, a.binaries, a.datas, name="TOL")
app = BUNDLE(
    coll,
    name="TOL.app",
    bundle_identifier="com.tol.app",
    info_plist={
        "CFBundleName": "TOL",
        "CFBundleDisplayName": "TOL",
        "CFBundleShortVersionString": "0.4.7",
        "LSUIElement": True,
        "NSHighResolutionCapable": True,
    },
)
