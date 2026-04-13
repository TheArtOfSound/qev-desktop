from __future__ import annotations

from bry_nfet_sx.bry import parse_bry_input
from bry_nfet_sx.nfet import NFETConfig
from bry_nfet_sx.protocol.transforms import apply_transform_from_plaintext


def test_human_safe_transformed_bry_is_token_stable() -> None:
    config = NFETConfig()
    result = apply_transform_from_plaintext(
        plaintext="MY NAME IS BRYAN.",
        master_key="bry-secret-dev-key",
        nonce="nonce-456",
        context="local-dev",
        config=config,
    )

    human_tokens = parse_bry_input(result.transformed_human)
    assert "|".join(human_tokens) == result.transformed_human


def test_compact_transformed_bry_is_not_assumed_token_stable() -> None:
    config = NFETConfig()
    result = apply_transform_from_plaintext(
        plaintext="MY NAME IS BRYAN.",
        master_key="bry-secret-dev-key",
        nonce="nonce-456",
        context="local-dev",
        config=config,
    )

    compact_tokens = parse_bry_input(result.transformed_compact)
    human_tokens = parse_bry_input(result.transformed_human)

    assert isinstance(compact_tokens, list)
    assert isinstance(human_tokens, list)
