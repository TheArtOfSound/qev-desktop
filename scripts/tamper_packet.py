from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path


def flip_first_ciphertext_byte(ciphertext_b64: str) -> str:
    raw = bytearray(base64.b64decode(ciphertext_b64))
    if not raw:
        raise ValueError("Ciphertext is empty.")
    raw[0] ^= 0x01
    return base64.b64encode(bytes(raw)).decode("ascii")


def main() -> None:
    parser = argparse.ArgumentParser(description="Tamper with a BRY-NFET-SX packet JSON file.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--set-nonce")
    parser.add_argument("--set-context")
    parser.add_argument("--flip-ciphertext-byte", action="store_true")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    packet = json.loads(input_path.read_text(encoding="utf-8"))

    if args.set_nonce is not None:
        packet["header"]["packet_nonce"] = args.set_nonce

    if args.set_context is not None:
        packet["header"]["context"] = args.set_context

    if args.flip_ciphertext_byte:
        packet["ciphertext_b64"] = flip_first_ciphertext_byte(packet["ciphertext_b64"])

    output_path.write_text(json.dumps(packet, indent=2) + "\n", encoding="utf-8")

    print(f"Wrote tampered packet to: {output_path}")
    print(json.dumps(packet["header"], indent=2))


if __name__ == "__main__":
    main()
