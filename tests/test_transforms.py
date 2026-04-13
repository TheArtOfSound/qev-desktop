from __future__ import annotations

from bry_nfet_sx.nfet import NFETConfig
from bry_nfet_sx.protocol.transforms import apply_transform_from_plaintext, reverse_transform_from_bry


def test_reversible_transform_roundtrip_from_plaintext() -> None:
    config = NFETConfig()

    result = apply_transform_from_plaintext(
        plaintext="MY NAME IS BRYAN.",
        master_key="key-123",
        nonce="nonce-1",
        context="ctx-a",
        config=config,
    )

    assert result.roundtrip_ok is True
    assert result.recovered_plaintext == "MY NAME IS BRYAN."


def test_reverse_transform_from_bry() -> None:
    config = NFETConfig()

    applied = apply_transform_from_plaintext(
        plaintext="WHAT'S UP?",
        master_key="key-123",
        nonce="nonce-1",
        context="ctx-a",
        config=config,
    )

    reversed_result = reverse_transform_from_bry(
        bry_text=applied.transformed_human,
        master_key="key-123",
        nonce="nonce-1",
        context="ctx-a",
        config=config,
    )

    assert reversed_result.roundtrip_ok is True
    assert reversed_result.recovered_plaintext == "WHAT'S UP?"
