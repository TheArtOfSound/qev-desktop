#!/usr/bin/env python3
"""Resolve the public decryption challenge by publishing the master key.

See docs/CHALLENGE-RESOLUTION.md. The reveal was due 2026-04-21 and is
overdue; this script performs Path A.

WHAT IT DOES
    1. Loads the offline master key.
    2. Decrypts every message in the challenge bundle locally.
    3. Finds the `reveal_token` embedded in the plaintext.
    4. Recomputes SHA-256(reveal_token) and compares it against the
       published `reveal_commitment` in challenge-meta.json.
    5. ONLY IF THAT MATCHES, writes the reveal artifacts.

WHY IT FAILS CLOSED
    The commit-reveal scheme's whole value is that the commitment binds the
    plaintext. If the commitment does not reproduce, publishing the key
    would hand a reviewer proof that the scheme was broken - strictly worse
    than the current overdue state. So a mismatch aborts with a non-zero
    exit and writes nothing.

STATUS
    NEVER RUN AGAINST THE REAL KEY. The key was offline and unavailable when
    this was written during the 2026-07-29 audit. Run with --dry-run first
    and read the report before writing anything.

    In particular, `--token-field` encodes an assumption about where the
    reveal token sits in the decrypted plaintext. If the plaintext is shaped
    differently, --dry-run will say so and nothing is published.

EXIT CODES
    0  commitment reproduced (and artifacts written unless --dry-run)
    2  usage / input error
    3  decryption failed - wrong key, or bundle does not match the key
    4  commitment MISMATCH - do not publish; see Path B
    5  reveal token not found in the decrypted plaintext
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
from pathlib import Path

EXIT_OK, EXIT_USAGE, EXIT_DECRYPT, EXIT_MISMATCH, EXIT_NO_TOKEN = 0, 2, 3, 4, 5


def die(code: int, msg: str) -> None:
    print(f"\nERROR: {msg}", file=sys.stderr)
    raise SystemExit(code)


def load_key(path: Path) -> bytes:
    raw = path.read_bytes().strip()
    # Accept hex, base64 or raw 32 bytes.
    text = raw.decode("utf-8", "ignore").strip()
    if re.fullmatch(r"[0-9a-fA-F]{64}", text):
        return bytes.fromhex(text)
    for pad in ("", "=", "==", "==="):
        try:
            k = base64.b64decode(text + pad, validate=True)
            if len(k) == 32:
                return k
        except Exception:
            pass
    if len(raw) == 32:
        return raw
    die(EXIT_USAGE, f"could not read a 32-byte key from {path} (tried hex, base64, raw)")
    return b""  # unreachable


def decrypt_messages(artifact: dict, key: bytes) -> list[str]:
    """Decrypt each message packet. ChaCha20-Poly1305 per the packet header."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    except ImportError:
        die(EXIT_USAGE, "python 'cryptography' is required: pip install cryptography")
    aead = ChaCha20Poly1305(key)

    out: list[str] = []
    for msg in artifact.get("messages", []):
        packet = msg.get("packet") or {}
        hdr = packet.get("header") or {}
        ct_b64 = packet.get("ciphertext_b64")
        if not ct_b64:
            continue
        ct = base64.b64decode(ct_b64)
        # The nonce lives in header.packet_nonce as "env-NNNN-<hex>"; the hex
        # tail is the 12-byte ChaCha20-Poly1305 nonce. Fall back to explicit
        # base64 fields in case an older packet version is encountered.
        nonce = None
        pn = hdr.get("packet_nonce") or msg.get("packet_nonce")
        if isinstance(pn, str):
            m = re.search(r"([0-9a-fA-F]{24})$", pn)
            if m:
                nonce = bytes.fromhex(m.group(1))
        if nonce is None:
            nb64 = hdr.get("nonce_b64") or packet.get("nonce_b64")
            if nb64:
                nonce = base64.b64decode(nb64)
        if nonce is None:
            die(EXIT_DECRYPT,
                f"message {msg.get('message_index')}: could not derive a nonce from "
                f"packet_nonce={pn!r}. The packet layout differs from what this "
                "script assumes - inspect artifact.json before going further.")
        aad_b64 = hdr.get("aad_b64") or packet.get("aad_b64")
        aad = base64.b64decode(aad_b64) if aad_b64 else None
        try:
            pt = aead.decrypt(nonce, ct, aad)
        except Exception as e:
            die(EXIT_DECRYPT, f"decryption failed on message "
                              f"{msg.get('message_index')}: {e.__class__.__name__}. "
                              "Wrong key, or this bundle was not sealed with it.")
        out.append(pt.decode("utf-8", "replace"))
    if not out:
        die(EXIT_DECRYPT, "no messages decrypted - is --bundle pointing at the right directory?")
    return out


def find_token(plaintexts: list[str], field: str) -> str | None:
    """Look for the reveal token: as a JSON field first, then as a bare hex run.

    CAVEAT: the challenge packets carry `bry_mode: "token_ids_v1"` and
    `transform_family_id: "ring_shift_v1"`, so what AEAD decryption yields is
    a token-ID sequence, not necessarily readable text. If the token is not
    found, the plaintext very likely needs the project's own transform step
    applied first (see tests/test_transform_serialization.py). Decryption
    succeeding while this returns None means the key is right and only the
    decoding layer is missing - it is NOT a reason to publish.
    """
    for pt in plaintexts:
        try:
            obj = json.loads(pt)
            if isinstance(obj, dict) and field in obj:
                return str(obj[field])
        except Exception:
            pass
    for pt in plaintexts:
        m = re.search(rf'"{re.escape(field)}"\s*:\s*"([^"]+)"', pt)
        if m:
            return m.group(1)
    for pt in plaintexts:
        m = re.search(r"\b[0-9a-f]{32,64}\b", pt)
        if m:
            return m.group(0)
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description="Publish the challenge reveal (fails closed).")
    ap.add_argument("--master-key-file", required=True, type=Path)
    ap.add_argument("--bundle", required=True, type=Path, help="dir with artifact.json etc.")
    ap.add_argument("--meta", required=True, type=Path, help="challenge-meta.json")
    ap.add_argument("--out", type=Path, help="output dir (required unless --dry-run)")
    ap.add_argument("--token-field", default="reveal_token")
    ap.add_argument("--dry-run", action="store_true", help="verify only; write nothing")
    a = ap.parse_args()

    if not a.dry_run and not a.out:
        die(EXIT_USAGE, "--out is required unless --dry-run")

    meta = json.loads(a.meta.read_text())
    commitment = ((meta.get("reveal_commitment") or {}).get("value") or "").lower()
    if not commitment:
        die(EXIT_USAGE, "no reveal_commitment.value in the metadata")

    artifact = json.loads((a.bundle / "artifact.json").read_text())
    key = load_key(a.master_key_file)

    print(f"bundle      : {a.bundle}")
    print(f"envelope_id : {artifact.get('envelope_id','?')[:32]}...")
    print(f"commitment  : {commitment}")
    print(f"key         : {len(key)} bytes, sha256 {hashlib.sha256(key).hexdigest()[:16]}...")

    plaintexts = decrypt_messages(artifact, key)
    print(f"decrypted   : {len(plaintexts)} message(s) OK")

    token = find_token(plaintexts, a.token_field)
    if token is None:
        die(EXIT_NO_TOKEN,
            f"no '{a.token_field}' found in the decrypted plaintext. Decryption "
            "worked, so the key is right - but the token is somewhere this script "
            "did not look. Inspect the plaintext and pass --token-field.")

    recomputed = hashlib.sha256(token.encode()).hexdigest()
    print(f"token       : {token[:12]}... ({len(token)} chars)")
    print(f"recomputed  : {recomputed}")

    if recomputed != commitment:
        die(EXIT_MISMATCH,
            "COMMITMENT MISMATCH.\n"
            f"  published : {commitment}\n"
            f"  recomputed: {recomputed}\n"
            "  Do NOT publish. A reveal that fails its own commitment is worse\n"
            "  than the current overdue state. Use Path B (retract) and say the\n"
            "  commitment could not be reproduced.")

    print("\n  COMMITMENT REPRODUCED - the published hash binds this plaintext.")

    if a.dry_run:
        print("  --dry-run: nothing written.")
        return EXIT_OK

    out = a.out
    out.mkdir(parents=True, exist_ok=True)
    (out / "master-key.txt").write_text(key.hex() + "\n")
    (out / "reveal.json").write_text(json.dumps({
        "schema": "BRY-NFET-SX-CHALLENGE-REVEAL-V1",
        "envelope_id": artifact.get("envelope_id"),
        "reveal_token": token,
        "reveal_commitment": commitment,
        "commitment_algorithm": "SHA-256",
        "master_key_hex": key.hex(),
        "note": ("Anyone can now recompute SHA-256(reveal_token) and compare it "
                 "against reveal_commitment in challenge-meta.json, which was "
                 "published on 2026-04-14 and has not changed since. That is the "
                 "commit-reveal property: the plaintext could not have been "
                 "swapped after publication."),
    }, indent=2) + "\n")
    (out / "VERIFY.md").write_text(
        "# Verify the reveal\n\n"
        "```bash\n"
        "python3 - <<'EOF'\n"
        "import hashlib, json\n"
        "token = json.load(open('reveal.json'))['reveal_token']\n"
        "print(hashlib.sha256(token.encode()).hexdigest())\n"
        "EOF\n"
        "```\n\n"
        f"Must print `{commitment}`, which is `reveal_commitment.value` in\n"
        "`/challenge/challenge-meta.json` — published 2026-04-14, unchanged since.\n\n"
        "Then decrypt the bundle yourself with `master-key.txt` and confirm the\n"
        "token is genuinely inside the plaintext rather than merely asserted here.\n\n"
        "What this proves: the plaintext was fixed before publication and was not\n"
        "swapped afterwards. What it does not prove: anything about the strength of\n"
        "ChaCha20-Poly1305, SHA-256 or the product's other claims.\n"
    )
    print(f"  wrote {out}/master-key.txt, reveal.json, VERIFY.md")
    print("\nNext: set reveal_status=revealed in challenge-meta.json, then RE-SIGN")
    print("site-integrity.json - the challenge files are inside the signed manifest.")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
