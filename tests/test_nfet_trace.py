from __future__ import annotations

from bry_nfet_sx.nfet import NFETConfig, build_trace


def test_trace_is_deterministic() -> None:
    config = NFETConfig()

    a = build_trace(
        plaintext="WHAT'S UP?",
        master_key="key-123",
        nonce="nonce-1",
        context="ctx-a",
        config=config,
    )
    b = build_trace(
        plaintext="WHAT'S UP?",
        master_key="key-123",
        nonce="nonce-1",
        context="ctx-a",
        config=config,
    )

    assert a.initial_state_hex == b.initial_state_hex
    assert [row.state_hex for row in a.rows] == [row.state_hex for row in b.rows]
    assert [row.transform_bucket for row in a.rows] == [row.transform_bucket for row in b.rows]


def test_trace_changes_when_nonce_changes() -> None:
    config = NFETConfig()

    a = build_trace(
        plaintext="WHAT'S UP?",
        master_key="key-123",
        nonce="nonce-1",
        context="ctx-a",
        config=config,
    )
    b = build_trace(
        plaintext="WHAT'S UP?",
        master_key="key-123",
        nonce="nonce-2",
        context="ctx-a",
        config=config,
    )

    assert a.initial_state_hex != b.initial_state_hex


def test_trace_row_count_matches_token_count() -> None:
    config = NFETConfig()
    result = build_trace(
        plaintext="HI!",
        master_key="key-123",
        nonce="nonce-1",
        context="ctx-a",
        config=config,
    )

    assert len(result.rows) == len(result.tokens)
    assert len(result.rows) > 0
