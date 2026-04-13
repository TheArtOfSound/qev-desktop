from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidTag

from bry_nfet_sx.nfet import NFETConfig
from bry_nfet_sx.protocol.packet import build_packet_from_plaintext, open_packet_to_plaintext


def test_packet_roundtrip() -> None:
    config = NFETConfig()

    built = build_packet_from_plaintext(
        plaintext="MY NAME IS BRYAN.",
        master_key="bry-secret-dev-key",
        packet_nonce="packet-001",
        context="local-dev",
        config=config,
    )

    opened = open_packet_to_plaintext(
        packet=built.packet,
        master_key="bry-secret-dev-key",
        config=config,
    )

    assert opened.recovered_plaintext == "MY NAME IS BRYAN."
    assert opened.token_count_ok is True


def test_packet_open_fails_with_wrong_key() -> None:
    config = NFETConfig()

    built = build_packet_from_plaintext(
        plaintext="MY NAME IS BRYAN.",
        master_key="bry-secret-dev-key",
        packet_nonce="packet-001",
        context="local-dev",
        config=config,
    )

    with pytest.raises(InvalidTag):
        open_packet_to_plaintext(
            packet=built.packet,
            master_key="wrong-key",
            config=config,
        )
