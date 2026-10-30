#!/usr/bin/env bash
# Build dist/TOL.app plus a .zip and .dmg for sharing. Run on a Mac.
# Optional signing + notarization (needs a paid Apple Developer account). Set:
#   MACOS_SIGN_IDENTITY   e.g. "Developer ID Application: Your Name (TEAMID)"
#   APPLE_ID, APPLE_TEAM_ID, APPLE_APP_PASSWORD   for notarization
set -euo pipefail
cd "$(dirname "$0")/.."
arch="$(uname -m)"
pyinstaller --noconfirm --clean scripts/tol_mac.spec

if [[ -n "${MACOS_SIGN_IDENTITY:-}" ]]; then
  codesign --force --deep --options runtime --timestamp --sign "$MACOS_SIGN_IDENTITY" dist/TOL.app
  codesign --verify --deep --strict dist/TOL.app
fi

ditto -c -k --keepParent dist/TOL.app "dist/TOL-${arch}.zip"

if [[ -n "${MACOS_SIGN_IDENTITY:-}" && -n "${APPLE_ID:-}" ]]; then
  xcrun notarytool submit "dist/TOL-${arch}.zip" --apple-id "$APPLE_ID" --team-id "$APPLE_TEAM_ID" \
    --password "$APPLE_APP_PASSWORD" --wait
  xcrun stapler staple dist/TOL.app
  rm "dist/TOL-${arch}.zip"
  ditto -c -k --keepParent dist/TOL.app "dist/TOL-${arch}.zip"
fi

hdiutil create -volname TOL -srcfolder dist/TOL.app -ov -format UDZO "dist/TOL-${arch}.dmg"
echo "Built dist/TOL.app, dist/TOL-${arch}.zip, dist/TOL-${arch}.dmg"
