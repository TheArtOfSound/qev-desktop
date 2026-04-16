#!/usr/bin/env python3
"""Sign the landing site content as a BRY-NFET-SX integrity bundle.

Creates a signed artifact of all landing page files so visitors can
verify that the site content has not been tampered with since signing.

Uses ed25519 asymmetric signatures so anyone with the public key can
verify the signature independently — a property HMAC-SHA256 does NOT
have (since HMAC verification requires the secret key, which by
definition the operator cannot publish). This addresses the "anyone
can verify" claim on /verify honestly.

Usage:
    uv run python scripts/sign_site_content.py

Environment:
    BRY_SITE_SIGNER_KEY_PATH — path to the ed25519 private key PEM file.
        Defaults to data/site-signer.ed25519.key. The script HARD-FAILS
        if the file does not exist — no hardcoded key fallback, no
        silent "anyone can forge" mode.

Inputs:
    data/site-signer.ed25519.key         — PEM private key (NEVER commit)
    landing/site-signer.ed25519.pub      — hex public key (committed)
    landing/<page>.html, chat/*, etc.    — files to hash

Outputs:
    landing/site-integrity.json — public verification record (hashes
                                   + ed25519 signature + public key)
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# Ensure we run from project root
project_root = Path(__file__).resolve().parent.parent
os.chdir(project_root)

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


LANDING_DIR = Path("landing")

# Signing key paths. The private key is gitignored and kept in data/.
# The public key is checked in under landing/ so the signing script can
# verify a round-trip and so the deployed site serves it alongside
# site-integrity.json for third-party verification.
PRIV_KEY_PATH = Path(
    os.getenv("BRY_SITE_SIGNER_KEY_PATH", "data/site-signer.ed25519.key")
)
PUB_KEY_PATH = Path("landing/site-signer.ed25519.pub")
SIGNATURE_SCHEME = "ed25519"
SIGNATURE_DOMAIN = b"BRY-NFET-SX|SITE-INTEGRITY|V2"

# Files to include in the integrity check.
#
# This MUST cover every file served under /var/www/bry-nfet-sx/ except:
#   - site-integrity.json itself (self-referential)
#   - site-signer.ed25519.pub (the verification key; its fingerprint is
#     bound to the manifest but it cannot sign itself)
#   - third-party verification tokens (e.g. IndexNow .txt files whose
#     content is dictated by the search engine, not by us)
#
# If you add a new file to landing/, ADD IT HERE. An unlisted file is
# silently unprotected and the /verify page's "every file" claim will
# become a lie.
SITE_FILES = [
    "index.html",
    "review.html",
    "security.html",
    "contact.html",
    "verify.html",
    "challenge.html",
    "downloads.html",
    "vault/index.html",
    "vault/gate.js",
    "vault/chat.js",
    "vault/sodium.js",
    "vault/SODIUM-VERSION.txt",
    "vault/LICENSE-libsodium.txt",
    "styles.css",
    "robots.txt",
    "sitemap.xml",
    # Public challenge bundle — previously uncovered. These are the
    # artifacts the /challenge page asks the public to evaluate; if
    # they can be silently swapped, the entire challenge is undermined.
    "challenge/challenge-meta.json",
    "challenge/bry-nfet-sx-challenge-bundle.zip",
    "challenge/bundle/artifact.json",
    "challenge/bundle/manifest.json",
    "challenge/bundle/metadata.json",
    "challenge/bundle/signature.json",
    # Android beta download page + gate script.
    "android/index.html",
    "android/gate.js",
    # Site signing public key — committed so verifiers can grab it
    # from the site itself. It is included in the manifest so a
    # tampered key swap invalidates the signature chain.
    "site-signer.ed25519.pub",
]

# Pages that contain Subresource Integrity attributes which must be
# verified before signing. Each entry maps the parent HTML file (relative
# to LANDING_DIR) to the directory the SRI src attributes are resolved
# against. The script extracts every <script src=... integrity=sha384-...>
# tag, recomputes the SHA-384 of the referenced file, and refuses to sign
# if any hash is stale.
SRI_GUARDED_PAGES = {
    "vault/index.html": "vault",
}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha384_b64(path: Path) -> str:
    digest = hashlib.sha384(path.read_bytes()).digest()
    return base64.b64encode(digest).decode("ascii")


_SRI_TAG_RE = re.compile(
    r'<script\s+[^>]*?src="(?P<src>[^"]+)"[^>]*?integrity="sha384-(?P<hash>[^"]+)"',
    re.IGNORECASE | re.DOTALL,
)
_SRI_TAG_RE_REVERSED = re.compile(
    r'<script\s+[^>]*?integrity="sha384-(?P<hash>[^"]+)"[^>]*?src="(?P<src>[^"]+)"',
    re.IGNORECASE | re.DOTALL,
)


def _extract_sri_tags(html: str) -> list[tuple[str, str]]:
    """Return list of (src, embedded_b64_hash) pairs from a page."""
    pairs: list[tuple[str, str]] = []
    for match in _SRI_TAG_RE.finditer(html):
        pairs.append((match.group("src"), match.group("hash")))
    for match in _SRI_TAG_RE_REVERSED.finditer(html):
        pair = (match.group("src"), match.group("hash"))
        if pair not in pairs:
            pairs.append(pair)
    return pairs


def verify_sri_hashes() -> None:
    """Refuse to sign if any embedded SRI hash is stale.

    For each page in SRI_GUARDED_PAGES, parse <script src=... integrity=...>
    tags, recompute the SHA-384 of the referenced file on disk, and
    compare. A mismatch means someone edited a referenced JS file without
    updating the parent HTML, which would silently break the trust chain
    on the live site (browser would refuse to execute the script). Exit
    non-zero with a clear actionable error so the operator can fix it
    before signing.
    """
    failures: list[str] = []
    for parent_rel, base_dir in SRI_GUARDED_PAGES.items():
        parent_path = LANDING_DIR / parent_rel
        if not parent_path.exists():
            failures.append(
                f"  {parent_rel}: parent HTML file does not exist"
            )
            continue
        html = parent_path.read_text(encoding="utf-8")
        pairs = _extract_sri_tags(html)
        if not pairs:
            failures.append(
                f"  {parent_rel}: no <script integrity=sha384-...> tags found"
            )
            continue
        for src, embedded_hash in pairs:
            # Strip query string and fragment if present (e.g.,
            # /chat/chat.js?v=0.28.1) before resolving to disk path. SRI
            # is computed over file bytes, not URL.
            src_clean = src.split("?", 1)[0].split("#", 1)[0]
            # Resolve src against the page directory (handle absolute /chat/foo
            # and relative foo paths).
            if src_clean.startswith("/"):
                ref_path = LANDING_DIR / src_clean.lstrip("/")
            else:
                ref_path = LANDING_DIR / base_dir / src_clean
            ref_path = ref_path.resolve()
            try:
                ref_path.relative_to((LANDING_DIR).resolve())
            except ValueError:
                failures.append(
                    f"  {parent_rel}: src {src} resolves outside LANDING_DIR"
                )
                continue
            if not ref_path.exists():
                failures.append(
                    f"  {parent_rel}: src {src} -> {ref_path} (file not found)"
                )
                continue
            actual_hash = sha384_b64(ref_path)
            if actual_hash != embedded_hash:
                failures.append(
                    f"  {parent_rel}: src {src} SRI hash mismatch\n"
                    f"      embedded: sha384-{embedded_hash}\n"
                    f"      actual:   sha384-{actual_hash}"
                )
            else:
                print(
                    f"  SRI OK: {parent_rel} -> {src} "
                    f"(sha384-{actual_hash[:16]}...)"
                )
    if failures:
        print()
        print("ERROR: SRI hash verification failed:")
        for line in failures:
            print(line)
        print()
        print("Fix: regenerate the SRI hash with")
        print("  openssl dgst -sha384 -binary <file> | openssl base64 -A")
        print("and update the integrity= attribute in the parent HTML.")
        sys.exit(1)


def canonical_manifest_bytes(manifest: dict) -> bytes:
    """Serialize the manifest with sorted keys and deterministic
    formatting so that signing and verification produce identical
    byte strings regardless of Python dict ordering or whitespace.
    The signer and any third-party verifier MUST use the same
    serialization, which this function documents and enforces.
    """
    return json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")


def load_private_key() -> Ed25519PrivateKey:
    if not PRIV_KEY_PATH.exists():
        print(
            f"ERROR: ed25519 private key not found at {PRIV_KEY_PATH}\n"
            f"\n"
            f"Generate one with:\n"
            f"\n"
            f"    uv run python -c \"\\\n"
            f"        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey; \\\n"
            f"        from cryptography.hazmat.primitives import serialization; \\\n"
            f"        k = Ed25519PrivateKey.generate(); \\\n"
            f"        open('{PRIV_KEY_PATH}', 'wb').write(k.private_bytes(\\\n"
            f"            serialization.Encoding.PEM, \\\n"
            f"            serialization.PrivateFormat.PKCS8, \\\n"
            f"            serialization.NoEncryption())); \\\n"
            f"        pub_hex = k.public_key().public_bytes(\\\n"
            f"            serialization.Encoding.Raw, \\\n"
            f"            serialization.PublicFormat.Raw).hex(); \\\n"
            f"        open('{PUB_KEY_PATH}', 'w').write(pub_hex + '\\\\n')\"\n"
            f"\n"
            f"The private key must NEVER be committed or deployed. The\n"
            f"public key at {PUB_KEY_PATH} IS committed and deployed.\n",
            file=sys.stderr,
        )
        sys.exit(2)
    pem = PRIV_KEY_PATH.read_bytes()
    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except Exception as e:
        print(f"ERROR: could not load private key from {PRIV_KEY_PATH}: {e}", file=sys.stderr)
        sys.exit(2)
    if not isinstance(key, Ed25519PrivateKey):
        print(
            f"ERROR: {PRIV_KEY_PATH} is not an ed25519 private key "
            f"(got {type(key).__name__})",
            file=sys.stderr,
        )
        sys.exit(2)
    return key


def public_key_hex(priv: Ed25519PrivateKey) -> str:
    raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return raw.hex()


def verify_committed_public_key_matches(priv: Ed25519PrivateKey) -> None:
    """Guard against silently signing with a private key whose public
    half doesn't match the one committed to landing/site-signer.ed25519.pub.
    If the two drift, third-party verifiers using the committed public
    key will reject signatures, so fail loudly here.
    """
    expected = public_key_hex(priv)
    if not PUB_KEY_PATH.exists():
        PUB_KEY_PATH.write_text(expected + "\n", encoding="utf-8")
        print(f"Wrote new public key: {PUB_KEY_PATH}")
        return
    committed = PUB_KEY_PATH.read_text().strip()
    if committed != expected:
        print(
            f"ERROR: committed public key at {PUB_KEY_PATH} does not match "
            f"the private key at {PRIV_KEY_PATH}.\n"
            f"  committed: {committed}\n"
            f"  expected:  {expected}\n"
            f"If you rotated keys intentionally, delete {PUB_KEY_PATH} and "
            f"re-run this script; it will be regenerated. Otherwise your "
            f"private key file is out of sync and should be investigated.",
            file=sys.stderr,
        )
        sys.exit(2)


def main() -> None:
    print("Verifying SRI hashes before signing...")
    verify_sri_hashes()
    print()

    # Load (and sanity-check) the ed25519 private key FIRST so we fail
    # fast if the operator forgot the key rather than re-hashing 20 files
    # and then discovering the problem.
    priv = load_private_key()
    verify_committed_public_key_matches(priv)
    pub_hex = public_key_hex(priv)
    print(f"Signing with ed25519 public key: {pub_hex}")
    print()

    print("Hashing site content...")

    # Hash every site file. Fail loudly on any missing file so an
    # unlisted-but-referenced asset doesn't silently produce a partial
    # manifest.
    file_hashes: dict[str, str] = {}
    missing: list[str] = []
    for name in SITE_FILES:
        fpath = LANDING_DIR / name
        if fpath.exists():
            file_hashes[name] = sha256_file(fpath)
            print(f"  {name}: {file_hashes[name][:16]}...")
        else:
            print(f"  {name}: MISSING")
            missing.append(name)
    if missing:
        print()
        print(
            f"ERROR: {len(missing)} file(s) in SITE_FILES do not exist on "
            f"disk. Remove them from SITE_FILES or produce them before "
            f"signing. Missing:",
            file=sys.stderr,
        )
        for m in missing:
            print(f"  - {m}", file=sys.stderr)
        sys.exit(2)

    # Build the manifest payload. The public key is included so a
    # third-party verifier can check it matches the public key they
    # fetched separately (defense against a MITM serving a different
    # public key alongside a forged manifest).
    manifest = {
        "schema": "BRY-NFET-SX-SITE-INTEGRITY-V2",
        "site": "secure.imagineqira.com",
        "signed_at": datetime.now(timezone.utc).isoformat(),
        "file_count": len(file_hashes),
        "files": file_hashes,
        "signer": {
            "scheme": SIGNATURE_SCHEME,
            "public_key_hex": pub_hex,
            "public_key_url": "https://secure.imagineqira.com/site-signer.ed25519.pub",
            "domain": SIGNATURE_DOMAIN.decode("ascii"),
        },
    }

    # Sign: ed25519(domain || canonical_manifest_bytes).
    # The domain separator prevents cross-protocol signature reuse:
    # a signature over this manifest cannot be confused with a signature
    # over a different kind of document that happened to share the same
    # byte prefix.
    manifest_bytes = canonical_manifest_bytes(manifest)
    signed_bytes = SIGNATURE_DOMAIN + manifest_bytes
    signature = priv.sign(signed_bytes)

    # Self-check: verify our own signature before writing it out.
    priv.public_key().verify(signature, signed_bytes)

    integrity_record = {
        **manifest,
        "signature": {
            "algorithm": SIGNATURE_SCHEME,
            "domain": SIGNATURE_DOMAIN.decode("ascii"),
            "public_key_hex": pub_hex,
            "signature_hex": signature.hex(),
            "canonical_json_note": (
                "The signed bytes are: "
                f"{SIGNATURE_DOMAIN.decode('ascii')} "
                "|| json.dumps(manifest_without_signature, indent=2, "
                "sort_keys=True).encode('utf-8'). The 'manifest_without_signature' "
                "object is this record with the 'signature' field removed."
            ),
        },
    }

    output_path = LANDING_DIR / "site-integrity.json"
    output_path.write_text(json.dumps(integrity_record, indent=2) + "\n", encoding="utf-8")

    print()
    print(f"Integrity record written: {output_path}")
    print(f"Files signed:             {len(file_hashes)}")
    print(f"Signature scheme:         {SIGNATURE_SCHEME}")
    print(f"Public key (hex):         {pub_hex}")
    print(f"Signature (first 32):     {signature.hex()[:32]}...")
    print()
    print("Deploy this file alongside the site content.")
    print("Verify at: https://secure.imagineqira.com/site-integrity.json")
    print("Public key: https://secure.imagineqira.com/site-signer.ed25519.pub")


if __name__ == "__main__":
    main()
