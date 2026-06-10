#!/usr/bin/env bash
# Remove macOS Gatekeeper's quarantine bit from the unsigned Qira
# Link alpha build so it can be opened without the "cannot be
# verified" dialog.
#
# This is needed ONLY until the builds are signed with an Apple
# Developer ID certificate + notarized by Apple's notary service.
# Once that lands (see `scripts/sign-macos.sh`) the normal
# double-click flow works and this helper isn't needed.
#
# Usage:
#   bash unquarantine.sh                         # /Applications/Qira Link.app
#   bash unquarantine.sh /path/to/Qira\ Link.app # elsewhere
#
# What it does:
#   1. Locates the Qira Link.app bundle.
#   2. Recursively removes the `com.apple.quarantine` extended
#      attribute that marks files downloaded from the internet.
#   3. Prints a sanity check so you can confirm the attribute is gone.
#
# This does NOT bypass any security scan — Gatekeeper still runs
# on first launch, but the unsigned-binary dialog is suppressed
# because the OS no longer treats the app as a fresh download.
set -euo pipefail

APP_PATH="${1:-/Applications/Qira Link.app}"

if [[ ! -d "${APP_PATH}" ]]; then
  echo "!! Not a directory: ${APP_PATH}" >&2
  echo "   Drag the app to /Applications first, or pass a full path." >&2
  exit 1
fi

echo "==> Target: ${APP_PATH}"

# Show current quarantine status (no output = already clean).
QUARANTINE_LINES="$(xattr -r "${APP_PATH}" 2>/dev/null | grep -c 'com.apple.quarantine' || true)"
echo "==> Quarantine-marked entries before: ${QUARANTINE_LINES}"

if [[ "${QUARANTINE_LINES}" -eq 0 ]]; then
  echo "==> Already clean — nothing to do."
  exit 0
fi

echo "==> Removing quarantine attribute recursively"
xattr -dr com.apple.quarantine "${APP_PATH}"

QUARANTINE_AFTER="$(xattr -r "${APP_PATH}" 2>/dev/null | grep -c 'com.apple.quarantine' || true)"
echo "==> Quarantine-marked entries after: ${QUARANTINE_AFTER}"

if [[ "${QUARANTINE_AFTER}" -ne 0 ]]; then
  echo "!! Some entries still marked — likely a permission issue." >&2
  echo "   Try: sudo bash unquarantine.sh \"${APP_PATH}\"" >&2
  exit 1
fi

echo ""
echo "==> Done. Launch with:  open \"${APP_PATH}\""
