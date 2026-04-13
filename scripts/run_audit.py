from __future__ import annotations

import argparse
import json

from bry_nfet_sx.nfet import NFETConfig
from bry_nfet_sx.protocol.audit import audit_to_dict, run_packet_audit_matrix


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the BRY-NFET-SX packet audit matrix.")
    parser.add_argument("--plaintext", required=True)
    parser.add_argument("--master-key", required=True)
    parser.add_argument("--packet-nonce", required=True)
    parser.add_argument("--context", default="local-dev")
    args = parser.parse_args()

    result = run_packet_audit_matrix(
        plaintext=args.plaintext,
        master_key=args.master_key,
        packet_nonce=args.packet_nonce,
        context=args.context,
        config=NFETConfig(),
    )
    print(json.dumps(audit_to_dict(result), indent=2))


if __name__ == "__main__":
    main()
