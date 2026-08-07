#!/usr/bin/env python3
"""External proof that secure.imagineqira.com matches its signed integrity manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import ssl
import sys
import urllib.error
import urllib.request

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PINNED_PUB_HEX = "881de4e7616992f92013b84ba1bbd08280a007b491bde28a46d8a15612d1d326"
DOMAIN = b"BRY-NFET-SX|SITE-INTEGRITY|V2"
SCHEMA = "BRY-NFET-SX-SITE-INTEGRITY-V2"


def fetch(base: str, path: str) -> bytes:
    req = urllib.request.Request(
        base.rstrip("/") + path,
        headers={"User-Agent": "qev-live-integrity-verify/1.0"},
    )
    with urllib.request.urlopen(req, context=ssl.create_default_context(), timeout=30) as resp:
        return resp.read()


def status(base: str, path: str) -> int:
    req = urllib.request.Request(
        base.rstrip("/") + path,
        headers={"User-Agent": "qev-live-integrity-verify/1.0"},
    )
    try:
        with urllib.request.urlopen(req, context=ssl.create_default_context(), timeout=15) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--base", default="https://secure.imagineqira.com")
    p.add_argument(
        "--require-launcher",
        action="store_true",
        help="Require Qira Apps launcher markers in index.html",
    )
    args = p.parse_args()

    root = fetch(args.base, "/")
    index = fetch(args.base, "/index.html")
    if root != index:
        print("FAIL: / and /index.html are not byte-identical")
        return 1

    manifest_raw = fetch(args.base, "/site-integrity.json")
    manifest = json.loads(manifest_raw.decode("utf-8"))
    if manifest.get("schema") != SCHEMA:
        print(f"FAIL: schema {manifest.get('schema')!r}")
        return 1
    if manifest["signature"]["public_key_hex"] != PINNED_PUB_HEX:
        print("FAIL: public key is not the pinned QEV signer")
        return 1

    index_sha = hashlib.sha256(index).hexdigest()
    if manifest["files"].get("index.html") != index_sha:
        print("FAIL: live index hash does not match manifest")
        print("  live    ", index_sha)
        print("  manifest", manifest["files"].get("index.html"))
        return 1

    body = {k: v for k, v in manifest.items() if k != "signature"}
    message = DOMAIN + json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(PINNED_PUB_HEX)).verify(
            bytes.fromhex(manifest["signature"]["signature_hex"]),
            message,
        )
    except InvalidSignature:
        print("FAIL: signature invalid against pinned public key")
        return 1

    # Spot-check a few critical files if present
    for rel in (
        "site-verify.js",
        "site-signer.ed25519.pub",
        "vault/index.html",
        "assets/qira-apps/qira-product-launcher.js",
    ):
        if rel not in manifest["files"]:
            continue
        data = fetch(args.base, "/" + rel)
        if hashlib.sha256(data).hexdigest() != manifest["files"][rel]:
            print(f"FAIL: hash mismatch for {rel}")
            return 1

    for path in (
        "/.env",
        "/.git/config",
        "/site-signer.ed25519.key",
        "/data/site-signer.ed25519.key",
    ):
        st = status(args.base, path)
        if st == 200:
            print(f"FAIL: secret path is public: {path}")
            return 1

    if args.require_launcher and b"qira-product-launcher" not in index:
        print("FAIL: Qira Apps launcher missing from index.html")
        return 1

    print("PASS")
    print(f"  base={args.base}")
    print(f"  signed_at={manifest['signed_at']}")
    print(f"  file_count={manifest['file_count']}")
    print(f"  index_sha={index_sha}")
    print(f"  public_key={PINNED_PUB_HEX}")
    print("  signature=valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
