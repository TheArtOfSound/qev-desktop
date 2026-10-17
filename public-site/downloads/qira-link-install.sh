#!/usr/bin/env bash
# Qira Link one-shot installer for macOS (Apple Silicon).
#
#   curl -fsSL https://secure.imagineqira.com/downloads/qira-link-install.sh | bash
#
# What this does:
#   1. Downloads the v0.1.0-alpha DMG to /tmp.
#   2. Mounts it, copies Qira Link.app to /Applications/.
#   3. Removes the macOS "cannot be verified" quarantine flag.
#   4. Unmounts the DMG + removes the temp file.
#   5. Launches Qira Link.
#
# Prompts for your sudo password once because step 3 writes to
# /Applications which is root-owned. No other privileges are used.
#
# Source: read before running. The script is short on purpose.
set -euo pipefail

URL="https://secure.imagineqira.com/downloads/QiraLink-0.1.0-alpha.0-aarch64.dmg"
TMP_DMG="/tmp/qiralink-install-$$.dmg"
APP_NAME="Qira Link.app"
DEST="/Applications/${APP_NAME}"

cleanup() {
  # Best-effort unmount if we mounted a volume.
  if [[ -n "${MOUNT_PATH:-}" ]] && [[ -d "${MOUNT_PATH}" ]]; then
    hdiutil detach "${MOUNT_PATH}" -quiet 2>/dev/null || true
  fi
  rm -f "${TMP_DMG}"
}
trap cleanup EXIT

echo "==> Downloading Qira Link (~4 MB)"
curl -fL --progress-bar "${URL}" -o "${TMP_DMG}"

echo "==> Mounting DMG"
# hdiutil's plist output is the only reliable way to get the mount
# path — its column output is a tabs-and-spaces mess.
MOUNT_PATH="$(
  hdiutil attach "${TMP_DMG}" -nobrowse -readonly -plist \
    | python3 -c "
import plistlib, sys
p = plistlib.loads(sys.stdin.buffer.read())
for e in p.get('system-entities', []):
    mp = e.get('mount-point')
    if mp:
        print(mp)
        break
"
)"

if [[ -z "${MOUNT_PATH}" ]] || [[ ! -d "${MOUNT_PATH}" ]]; then
  echo "!! Could not determine DMG mount point." >&2
  exit 1
fi
echo "    mounted at: ${MOUNT_PATH}"

if [[ ! -d "${MOUNT_PATH}/${APP_NAME}" ]]; then
  echo "!! ${APP_NAME} not inside the DMG at ${MOUNT_PATH}" >&2
  exit 1
fi

echo "==> Installing to /Applications (requires sudo password)"
sudo rm -rf "${DEST}"
sudo cp -R "${MOUNT_PATH}/${APP_NAME}" "${DEST}"
sudo chown -R "$(id -u):$(id -g)" "${DEST}"

echo "==> Removing macOS quarantine flag"
sudo xattr -cr "${DEST}"

# Newer macOS (14+/15+) sometimes refuses unsigned binaries with a
# generic "damaged" message. Ad-hoc signing settles it — the local
# signature matches what's on disk, so Gatekeeper stops complaining.
if ! codesign --verify --strict "${DEST}" >/dev/null 2>&1; then
  echo "==> Ad-hoc re-signing (fixes 'damaged' message on Sonoma/Sequoia)"
  sudo codesign --force --deep --sign - "${DEST}" 2>/dev/null || true
fi

echo "==> Launching"
open "${DEST}"

echo ""
echo "==> Done. Qira Link is installed at ${DEST}"
echo "    You can open it any time from Spotlight or /Applications/."
