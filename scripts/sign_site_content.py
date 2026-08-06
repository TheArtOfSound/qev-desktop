#!/usr/bin/env python3
"""Create a signed integrity manifest for secure.imagineqira.com.

The manifest is signed with Ed25519 over:

    SIGNATURE_DOMAIN || canonical_json(manifest_without_signature)

Canonical JSON is UTF-8 JSON with recursively sorted object keys, no
insignificant whitespace, and non-ASCII characters emitted directly.
That contract intentionally matches landing/site-verify.js, which uses
JSON.stringify(deepSortKeys(value)).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PROJECT_ROOT = Path(__file__).resolve().parent.parent
os.chdir(PROJECT_ROOT)

LANDING_DIR = Path("landing")
PRIV_KEY_PATH = Path(
    os.getenv("BRY_SITE_SIGNER_KEY_PATH", "data/site-signer.ed25519.key")
)
PUB_KEY_PATH = LANDING_DIR / "site-signer.ed25519.pub"
MANIFEST_PATH = LANDING_DIR / "site-integrity.json"

SIGNATURE_SCHEME = "ed25519"
SIGNATURE_DOMAIN = b"BRY-NFET-SX|SITE-INTEGRITY|V2"
MANIFEST_SCHEMA = "BRY-NFET-SX-SITE-INTEGRITY-V2"
SITE_NAME = "secure.imagineqira.com"

# site-integrity.json is necessarily excluded because it contains the
# signature over the other files. Every other deployable file under
# landing/ is discovered automatically, including new Qira launcher
# JavaScript, CSS, icon, and manifest assets.
EXCLUDED_RELATIVE_PATHS = {"site-integrity.json"}
IGNORED_NAMES = {".DS_Store"}
IGNORED_SUFFIXES = {".tmp", ".swp", ".bak"}

SRI_GUARDED_PAGES = {
    "vault/index.html": "vault",
}

_SRI_TAG_RE = re.compile(
    r'<script\s+[^>]*?src="(?P<src>[^"]+)"[^>]*?integrity="sha384-(?P<hash>[^"]+)"',
    re.IGNORECASE | re.DOTALL,
)
_SRI_TAG_RE_REVERSED = re.compile(
    r'<script\s+[^>]*?integrity="sha384-(?P<hash>[^"]+)"[^>]*?src="(?P<src>[^"]+)"',
    re.IGNORECASE | re.DOTALL,
)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha384_b64(path: Path) -> str:
    return base64.b64encode(hashlib.sha384(path.read_bytes()).digest()).decode("ascii")


def canonical_manifest_bytes(manifest: dict) -> bytes:
    """Match JSON.stringify(deepSortKeys(value)) in site-verify.js."""
    return json.dumps(
        manifest,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def discover_site_files() -> list[str]:
    if not LANDING_DIR.is_dir():
        raise SystemExit(f"ERROR: landing directory not found: {LANDING_DIR}")

    discovered: list[str] = []
    for path in LANDING_DIR.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(LANDING_DIR).as_posix()
        if relative in EXCLUDED_RELATIVE_PATHS:
            continue
        if any(part.startswith(".") for part in Path(relative).parts):
            continue
        if path.name in IGNORED_NAMES:
            continue
        if path.suffix.lower() in IGNORED_SUFFIXES:
            continue
        discovered.append(relative)

    discovered.sort()
    if not discovered:
        raise SystemExit("ERROR: no deployable files found under landing/")
    return discovered


def _extract_sri_tags(html: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for matcher in (_SRI_TAG_RE, _SRI_TAG_RE_REVERSED):
        for match in matcher.finditer(html):
            pair = (match.group("src"), match.group("hash"))
            if pair not in pairs:
                pairs.append(pair)
    return pairs


def verify_sri_hashes() -> None:
    failures: list[str] = []

    for parent_rel, base_dir in SRI_GUARDED_PAGES.items():
        parent_path = LANDING_DIR / parent_rel
        if not parent_path.exists():
            failures.append(f"{parent_rel}: parent HTML file does not exist")
            continue

        pairs = _extract_sri_tags(parent_path.read_text(encoding="utf-8"))
        if not pairs:
            failures.append(f"{parent_rel}: no SRI-protected scripts found")
            continue

        for src, embedded_hash in pairs:
            src_clean = src.split("?", 1)[0].split("#", 1)[0]
            if src_clean.startswith("/"):
                ref_path = LANDING_DIR / src_clean.lstrip("/")
            else:
                ref_path = LANDING_DIR / base_dir / src_clean
            ref_path = ref_path.resolve()

            try:
                ref_path.relative_to(LANDING_DIR.resolve())
            except ValueError:
                failures.append(f"{parent_rel}: {src} resolves outside landing/")
                continue

            if not ref_path.exists():
                failures.append(f"{parent_rel}: {src} does not exist")
                continue

            actual_hash = sha384_b64(ref_path)
            if actual_hash != embedded_hash:
                failures.append(
                    f"{parent_rel}: stale SRI for {src}\n"
                    f"  embedded: sha384-{embedded_hash}\n"
                    f"  actual:   sha384-{actual_hash}"
                )

    if failures:
        joined = "\n".join(f"  - {failure}" for failure in failures)
        raise SystemExit(
            "ERROR: SRI verification failed before signing:\n"
            f"{joined}\n"
            "Update the affected integrity= attribute before signing."
        )


def load_private_key() -> Ed25519PrivateKey:
    if not PRIV_KEY_PATH.exists():
        raise SystemExit(
            "ERROR: Ed25519 private key not found at "
            f"{PRIV_KEY_PATH}. Set BRY_SITE_SIGNER_KEY_PATH to the "
            "existing production signer key. Do not generate a replacement "
            "for an ordinary content deployment."
        )

    try:
        key = serialization.load_pem_private_key(
            PRIV_KEY_PATH.read_bytes(),
            password=None,
        )
    except Exception as exc:
        raise SystemExit(
            f"ERROR: could not load private key from {PRIV_KEY_PATH}: {exc}"
        ) from exc

    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit(
            f"ERROR: {PRIV_KEY_PATH} is not an Ed25519 private key "
            f"(got {type(key).__name__})"
        )
    return key


def public_key_hex(private_key: Ed25519PrivateKey) -> str:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


def verify_committed_public_key_matches(private_key: Ed25519PrivateKey) -> str:
    expected = public_key_hex(private_key)
    if not PUB_KEY_PATH.exists():
        raise SystemExit(
            f"ERROR: committed public key is missing: {PUB_KEY_PATH}. "
            "Restore the existing production public key before signing."
        )

    committed = PUB_KEY_PATH.read_text(encoding="utf-8").strip()
    if committed != expected:
        raise SystemExit(
            "ERROR: signing key does not match the pinned public key.\n"
            f"  committed: {committed}\n"
            f"  signer:    {expected}\n"
            "Do not rotate the site signer as part of an ordinary UI deploy."
        )
    return expected


def build_manifest(file_names: list[str], public_key: str) -> dict:
    file_hashes = {
        name: sha256_file(LANDING_DIR / name)
        for name in file_names
    }
    return {
        "schema": MANIFEST_SCHEMA,
        "site": SITE_NAME,
        "signed_at": datetime.now(timezone.utc).isoformat(),
        "file_count": len(file_hashes),
        "files": file_hashes,
        "signer": {
            "scheme": SIGNATURE_SCHEME,
            "public_key_hex": public_key,
            "public_key_url": f"https://{SITE_NAME}/site-signer.ed25519.pub",
            "domain": SIGNATURE_DOMAIN.decode("ascii"),
        },
    }


def write_signed_manifest(manifest: dict, private_key: Ed25519PrivateKey) -> None:
    signed_bytes = SIGNATURE_DOMAIN + canonical_manifest_bytes(manifest)
    signature = private_key.sign(signed_bytes)
    private_key.public_key().verify(signature, signed_bytes)

    record = {
        **manifest,
        "signature": {
            "algorithm": SIGNATURE_SCHEME,
            "domain": SIGNATURE_DOMAIN.decode("ascii"),
            "public_key_hex": manifest["signer"]["public_key_hex"],
            "signature_hex": signature.hex(),
            "canonical_json_note": (
                "The signed bytes are: "
                f"{SIGNATURE_DOMAIN.decode('ascii')} || "
                "json.dumps(manifest_without_signature, sort_keys=True, "
                "separators=(',', ':'), ensure_ascii=False).encode('utf-8'). "
                "JavaScript verifiers recursively sort object keys and call "
                "JSON.stringify with no indentation."
            ),
        },
    }

    temporary = MANIFEST_PATH.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(record, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    temporary.replace(MANIFEST_PATH)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--list-files",
        action="store_true",
        help="list the automatically discovered signed files and exit",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    verify_sri_hashes()
    file_names = discover_site_files()

    if args.list_files:
        for name in file_names:
            print(name)
        return

    private_key = load_private_key()
    public_key = verify_committed_public_key_matches(private_key)
    manifest = build_manifest(file_names, public_key)
    write_signed_manifest(manifest, private_key)

    print(f"Integrity record written: {MANIFEST_PATH}")
    print(f"Files signed: {len(file_names)}")
    print(f"Signer: {public_key}")
    print("Deploy the landing/ directory and site-integrity.json atomically.")


if __name__ == "__main__":
    main()
