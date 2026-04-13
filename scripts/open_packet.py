from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag

from bry_nfet_sx.nfet import NFETConfig
from bry_nfet_sx.protocol.packet import open_packet_to_plaintext


def main() -> None:
    parser = argparse.ArgumentParser(description="Open a BRY-NFET-SX encrypted packet.")
    parser.add_argument("--input", required=True)
    parser.add_argument("--master-key", required=True)
    args = parser.parse_args()

    input_path = Path(args.input)
    packet = json.loads(input_path.read_text(encoding="utf-8"))

    try:
        result = open_packet_to_plaintext(
            packet=packet,
            master_key=args.master_key,
            config=NFETConfig(),
        )
    except InvalidTag:
        print("AUTHENTICATION FAILED", file=sys.stderr)
        sys.exit(2)
    except Exception as exc:
        print(f"OPEN FAILED: {exc}", file=sys.stderr)
        sys.exit(3)

    print(json.dumps(
        {
            "status": "ok",
            "header": result.header.__dict__,
            "transformed_human": result.transformed_human,
            "recovered_human": result.recovered_human,
            "recovered_plaintext": result.recovered_plaintext,
            "token_count_ok": result.token_count_ok,
        },
        indent=2,
    ))


if __name__ == "__main__":
    main()
