#!/usr/bin/env bash
# Deploy the public secure.imagineqira.com static site with fail-closed integrity.
#
# Invariant:
#   final release bytes → hash → sign → independently verify → deploy exact signed
#   artifact → verify live bytes
#
# Usage (from repo root):
#   export BRY_SITE_SIGNER_KEY_PATH=/absolute/path/to/site-signer.ed25519.key
#   export QEV_DEPLOY_HOST=ubuntu@52.72.26.109
#   export QEV_SSH_KEY=$HOME/.ssh/autohustle-aws.pem
#   ./scripts/deploy_secure_static_site.sh
#
# Optional:
#   QEV_REMOTE_ROOT=/var/www/secure-imagineqira
#   QEV_SOURCE_DIR=landing          # directory to deploy (default: landing)
#   QEV_SKIP_LIVE_VERIFY=1          # skip public HTTPS proof (not recommended)
#
# The private key NEVER leaves the local machine. It is never rsync'd to EC2.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

SOURCE_DIR="${QEV_SOURCE_DIR:-landing}"
REMOTE_ROOT="${QEV_REMOTE_ROOT:-/var/www/secure-imagineqira}"
DEPLOY_HOST="${QEV_DEPLOY_HOST:-ubuntu@52.72.26.109}"
SSH_KEY="${QEV_SSH_KEY:-$HOME/.ssh/autohustle-aws.pem}"
PINNED_PUB="881de4e7616992f92013b84ba1bbd08280a007b491bde28a46d8a15612d1d326"
PUBLIC_BASE="${QEV_PUBLIC_BASE:-https://secure.imagineqira.com}"

die() { echo "ERROR: $*" >&2; exit 1; }

[[ -d "$SOURCE_DIR" ]] || die "source dir missing: $SOURCE_DIR"
[[ -n "${BRY_SITE_SIGNER_KEY_PATH:-}" ]] || die "BRY_SITE_SIGNER_KEY_PATH is required"
[[ -f "$BRY_SITE_SIGNER_KEY_PATH" ]] || die "signer key not found at BRY_SITE_SIGNER_KEY_PATH"
[[ -f "$SSH_KEY" ]] || die "SSH key not found: $SSH_KEY"
[[ -f scripts/sign_site_content.py ]] || die "scripts/sign_site_content.py missing"

# Refuse to ship private material
if find "$SOURCE_DIR" -type f \( -name '*.key' -o -name '*.pem' -o -name '.env' -o -name '.env.*' \) | grep -q .; then
  die "refusing to deploy: private key/env files present under $SOURCE_DIR"
fi

echo "==> [1/6] Sign release bytes (local only)"
# sign_site_content.py always uses landing/; if SOURCE_DIR differs, require landing
if [[ "$SOURCE_DIR" != "landing" ]]; then
  die "this script currently signs landing/; set QEV_SOURCE_DIR=landing or sync content there first"
fi
python3 scripts/sign_site_content.py

MANIFEST="$SOURCE_DIR/site-integrity.json"
[[ -f "$MANIFEST" ]] || die "manifest not written"

echo "==> [2/6] Independently verify manifest before upload"
python3 - <<'PY'
import json, hashlib, os, sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

PINNED = bytes.fromhex("881de4e7616992f92013b84ba1bbd08280a007b491bde28a46d8a15612d1d326")
DOMAIN = b"BRY-NFET-SX|SITE-INTEGRITY|V2"
root = Path("landing")
m = json.loads((root / "site-integrity.json").read_text())
if m.get("schema") != "BRY-NFET-SX-SITE-INTEGRITY-V2":
    sys.exit("schema mismatch")
pub_hex = m["signature"]["public_key_hex"]
if pub_hex != PINNED.hex():
    sys.exit(f"public key mismatch: {pub_hex}")
fails = []
for rel, expected in m["files"].items():
    p = root / rel
    if not p.is_file():
        fails.append(f"missing {rel}")
        continue
    actual = hashlib.sha256(p.read_bytes()).hexdigest()
    if actual != expected:
        fails.append(f"hash {rel}")
if fails:
    print("\n".join(fails[:20]))
    sys.exit("pre-deploy hash verification failed")
body = {k: v for k, v in m.items() if k != "signature"}
msg = DOMAIN + json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
try:
    Ed25519PublicKey.from_public_bytes(PINNED).verify(
        bytes.fromhex(m["signature"]["signature_hex"]), msg
    )
except InvalidSignature:
    sys.exit("pre-deploy signature verification failed")
print(f"pre-deploy OK: files={m['file_count']} signed_at={m['signed_at']}")
PY

echo "==> [3/6] Deploy exact signed tree to $DEPLOY_HOST:$REMOTE_ROOT"
# Never include private keys, git, env, backups, or mac resource forks
rsync -az --delete \
  -e "ssh -i $SSH_KEY -o StrictHostKeyChecking=accept-new" \
  --exclude '.git/' \
  --exclude '.DS_Store' \
  --exclude '._*' \
  --exclude '*.bak*' \
  --exclude '*.before*' \
  --exclude '*.key' \
  --exclude '*.pem' \
  --exclude '.env' \
  --exclude '.env.*' \
  --exclude '*.tmp' \
  --exclude '*.swp' \
  --exclude '*~' \
  "$SOURCE_DIR/" "$DEPLOY_HOST:$REMOTE_ROOT/"

echo "==> [4/6] Harden remote: no junk in public root"
ssh -i "$SSH_KEY" "$DEPLOY_HOST" "set -euo pipefail
ROOT='$REMOTE_ROOT'
BAK=/opt/backups/qev-webroot-junk
sudo mkdir -p \"\$BAK\"
# Move any junk that snuck in
sudo find \"\$ROOT\" -type f \\( -name '*.bak*' -o -name '._*' -o -name '*.before*' -o -name '*.key' -o -name '*.pem' -o -name '.env' -o -name '.env.*' \\) -exec sudo mv -t \"\$BAK\"/ {} + 2>/dev/null || true
# Ensure public perms on integrity files
sudo chmod 644 \"\$ROOT/site-integrity.json\" \"\$ROOT/site-signer.ed25519.pub\" \"\$ROOT/site-verify.js\" 2>/dev/null || true
"

if [[ "${QEV_SKIP_LIVE_VERIFY:-0}" == "1" ]]; then
  echo "==> [5/6] SKIP live verify (QEV_SKIP_LIVE_VERIFY=1)"
  echo "==> [6/6] Deploy finished (live proof skipped)"
  exit 0
fi

echo "==> [5/6] Live public proof against $PUBLIC_BASE"
python3 - <<PY
import json, hashlib, urllib.request, ssl, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

BASE = "${PUBLIC_BASE}"
PINNED = bytes.fromhex("${PINNED_PUB}")
DOMAIN = b"BRY-NFET-SX|SITE-INTEGRITY|V2"
ctx = ssl.create_default_context()

def fetch(path: str) -> bytes:
    req = urllib.request.Request(BASE + path, headers={"User-Agent": "qev-deploy-live-proof/1.0"})
    with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
        return r.read()

def status(path: str) -> int:
    req = urllib.request.Request(BASE + path, headers={"User-Agent": "qev-deploy-live-proof/1.0"})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=15) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code

root = fetch("/")
index = fetch("/index.html")
man = fetch("/site-integrity.json")
if root != index:
    sys.exit("live / and /index.html differ")
m = json.loads(man)
if m["files"]["index.html"] != hashlib.sha256(index).hexdigest():
    sys.exit("live index hash != manifest")
if m["signature"]["public_key_hex"] != PINNED.hex():
    sys.exit("live public key != pinned")
body = {k: v for k, v in m.items() if k != "signature"}
msg = DOMAIN + json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
try:
    Ed25519PublicKey.from_public_bytes(PINNED).verify(
        bytes.fromhex(m["signature"]["signature_hex"]), msg
    )
except InvalidSignature:
    sys.exit("live signature invalid")

# Spot-check critical assets
for rel in ["site-verify.js", "site-signer.ed25519.pub", "vault/index.html"]:
    if rel in m["files"]:
        data = fetch("/" + rel)
        if hashlib.sha256(data).hexdigest() != m["files"][rel]:
            sys.exit(f"live hash mismatch: {rel}")

# Secrets must not be public
for path in ["/.env", "/.git/config", "/site-signer.ed25519.key", "/data/site-signer.ed25519.key"]:
    st = status(path)
    if st == 200:
        sys.exit(f"secret path publicly readable: {path}")

if b"qira-product-launcher" not in root and b"Qira Apps" not in root:
    # soft warning only if launcher was intentionally absent; for current product require it
    print("WARNING: Qira Apps launcher markers not found in index (confirm intentional)")

print(f"LIVE_PROOF_OK signed_at={m['signed_at']} files={m['file_count']}")
PY

echo "==> [6/6] Deploy + live proof complete"
echo "    Public: $PUBLIC_BASE/"
echo "    Manifest: $PUBLIC_BASE/site-integrity.json"
echo "    Private key remained local."
