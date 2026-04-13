from __future__ import annotations

from bry_nfet_sx.nfet import NFETConfig, build_schedule, build_trace


def test_scheduler_depends_on_token_count_not_plaintext_content() -> None:
    config = NFETConfig()

    a = build_trace(
        plaintext="AB",
        master_key="key-123",
        nonce="nonce-1",
        context="ctx-a",
        config=config,
    )
    b = build_trace(
        plaintext="CD",
        master_key="key-123",
        nonce="nonce-1",
        context="ctx-a",
        config=config,
    )

    assert len(a.tokens) == len(b.tokens)
    assert [row.state_hex for row in a.rows] == [row.state_hex for row in b.rows]
    assert [row.transform_bucket for row in a.rows] == [row.transform_bucket for row in b.rows]


def test_scheduler_changes_when_nonce_changes() -> None:
    config = NFETConfig()

    a = build_schedule(
        token_count=10,
        master_key="key-123",
        nonce="nonce-1",
        context="ctx-a",
        config=config,
    )
    b = build_schedule(
        token_count=10,
        master_key="key-123",
        nonce="nonce-2",
        context="ctx-a",
        config=config,
    )

    assert a.initial_state_hex != b.initial_state_hex
