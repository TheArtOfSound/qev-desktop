from __future__ import annotations

from pathlib import Path

from bry_nfet_sx.nfet import NFETConfig
from bry_nfet_sx.protocol.audit import run_packet_audit_matrix


def test_audit_matrix_expected_outcomes(tmp_path: Path) -> None:
    result = run_packet_audit_matrix(
        plaintext="MY NAME IS BRYAN.",
        master_key="bry-secret-dev-key",
        packet_nonce="packet-audit-001",
        context="local-dev",
        config=NFETConfig(),
        registry_path=tmp_path / "nonce_registry.json",
    )

    cases = {case.name: case for case in result.cases}

    assert cases["baseline"].outcome == "PASS"
    assert cases["baseline"].actual_pass is True

    assert cases["wrong_master_key"].outcome == "PASS"
    assert cases["wrong_master_key"].actual_pass is False

    assert cases["tampered_header_packet_nonce"].outcome == "PASS"
    assert cases["tampered_header_packet_nonce"].actual_pass is False

    assert cases["tampered_header_context"].outcome == "PASS"
    assert cases["tampered_header_context"].actual_pass is False

    assert cases["tampered_header_token_count"].outcome == "PASS"
    assert cases["tampered_header_token_count"].actual_pass is False

    assert cases["tampered_header_alg"].outcome == "PASS"
    assert cases["tampered_header_alg"].actual_pass is False

    assert cases["tampered_header_version"].outcome == "PASS"
    assert cases["tampered_header_version"].actual_pass is False

    assert cases["tampered_header_bry_mode"].outcome == "PASS"
    assert cases["tampered_header_bry_mode"].actual_pass is False

    assert cases["tampered_ciphertext"].outcome == "PASS"
    assert cases["tampered_ciphertext"].actual_pass is False
