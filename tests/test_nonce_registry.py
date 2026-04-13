from __future__ import annotations

from pathlib import Path

from bry_nfet_sx.protocol.audit import check_and_register_nonce


def test_nonce_registry_flags_reuse(tmp_path: Path) -> None:
    registry = tmp_path / "nonce_registry.json"

    first = check_and_register_nonce(
        master_key="key-123",
        context="ctx-a",
        packet_nonce="packet-001",
        registry_path=registry,
    )
    second = check_and_register_nonce(
        master_key="key-123",
        context="ctx-a",
        packet_nonce="packet-001",
        registry_path=registry,
    )

    assert first.reused is False
    assert first.prior_uses == 0
    assert second.reused is True
    assert second.prior_uses == 1
