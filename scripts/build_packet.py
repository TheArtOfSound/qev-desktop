from __future__ import annotations

import argparse
import json
from pathlib import Path

from bry_nfet_sx.nfet import NFETConfig
from bry_nfet_sx.protocol.packet import build_packet_from_plaintext


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a BRY-NFET-SX encrypted packet.")
    parser.add_argument("--plaintext", required=True)
    parser.add_argument("--master-key", required=True)
    parser.add_argument("--packet-nonce", required=True)
    parser.add_argument("--context", default="local-dev")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    config = NFETConfig()

    result = build_packet_from_plaintext(
        plaintext=args.plaintext,
        master_key=args.master_key,
        packet_nonce=args.packet_nonce,
        context=args.context,
        config=config,
    )

    output_path = Path(args.output)
    output_path.write_text(result.packet_json + "\n", encoding="utf-8")

    print(f"Wrote packet to: {output_path}")
    print("Header:")
    print(json.dumps(result.packet["header"], indent=2))
    print("Transformed human-safe Bry:")
    print(result.transformed_human)


if __name__ == "__main__":
    main()
