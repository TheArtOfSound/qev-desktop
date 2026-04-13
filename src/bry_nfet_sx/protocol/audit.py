from __future__ import annotations

from base64 import b64decode, b64encode
from copy import deepcopy
from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag

from bry_nfet_sx.nfet import NFETConfig
from bry_nfet_sx.protocol.packet import build_packet_from_plaintext, open_packet_to_plaintext


@dataclass(frozen=True)
class NonceCheckResult:
    namespace_id: str
    packet_nonce: str
    reused: bool
    prior_uses: int
    registry_path: str


@dataclass(frozen=True)
class AuditCaseResult:
    name: str
    expected_pass: bool
    actual_pass: bool
    outcome: str
    detail: str


@dataclass(frozen=True)
class PacketAuditResult:
    nonce_check: NonceCheckResult
    packet_json: str
    cases: list[AuditCaseResult]


def _default_registry_path() -> Path:
    return Path.home() / ".bry_nfet_sx_lab" / "nonce_registry.json"


def check_and_register_nonce(
    master_key: str,
    context: str,
    packet_nonce: str,
    registry_path: str | Path | None = None,
) -> NonceCheckResult:
    path = Path(registry_path) if registry_path is not None else _default_registry_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.exists():
        store = json.loads(path.read_text(encoding="utf-8"))
    else:
        store = {}

    namespace_id = sha256(f"{master_key}|{context}".encode("utf-8")).hexdigest()
    namespace = store.setdefault(namespace_id, {"context": context, "nonces": {}})
    nonces: dict[str, int] = namespace.setdefault("nonces", {})

    prior_uses = int(nonces.get(packet_nonce, 0))
    reused = prior_uses > 0
    nonces[packet_nonce] = prior_uses + 1

    path.write_text(json.dumps(store, indent=2) + "\n", encoding="utf-8")

    return NonceCheckResult(
        namespace_id=namespace_id,
        packet_nonce=packet_nonce,
        reused=reused,
        prior_uses=prior_uses,
        registry_path=str(path),
    )


def _flip_first_ciphertext_byte(packet: dict[str, Any]) -> dict[str, Any]:
    out = deepcopy(packet)
    raw = bytearray(b64decode(out["ciphertext_b64"]))
    if not raw:
        raise ValueError("Ciphertext is empty.")
    raw[0] ^= 0x01
    out["ciphertext_b64"] = b64encode(bytes(raw)).decode("ascii")
    return out


def _run_case(
    *,
    name: str,
    expected_pass: bool,
    packet: dict[str, Any],
    master_key: str,
    config: NFETConfig,
) -> AuditCaseResult:
    try:
        opened = open_packet_to_plaintext(
            packet=packet,
            master_key=master_key,
            config=config,
        )
        actual_pass = True
        detail = opened.recovered_plaintext
    except InvalidTag:
        actual_pass = False
        detail = "AUTHENTICATION FAILED"
    except Exception as exc:
        actual_pass = False
        detail = f"{type(exc).__name__}: {exc}"

    outcome = "PASS" if actual_pass == expected_pass else "FAIL"
    return AuditCaseResult(
        name=name,
        expected_pass=expected_pass,
        actual_pass=actual_pass,
        outcome=outcome,
        detail=detail,
    )


def run_packet_audit_matrix(
    plaintext: str,
    master_key: str,
    packet_nonce: str,
    context: str,
    config: NFETConfig,
    registry_path: str | Path | None = None,
) -> PacketAuditResult:
    nonce_check = check_and_register_nonce(
        master_key=master_key,
        context=context,
        packet_nonce=packet_nonce,
        registry_path=registry_path,
    )

    built = build_packet_from_plaintext(
        plaintext=plaintext,
        master_key=master_key,
        packet_nonce=packet_nonce,
        context=context,
        config=config,
    )

    good_packet = built.packet
    cases: list[AuditCaseResult] = []

    cases.append(
        _run_case(
            name="baseline",
            expected_pass=True,
            packet=good_packet,
            master_key=master_key,
            config=config,
        )
    )

    cases.append(
        _run_case(
            name="wrong_master_key",
            expected_pass=False,
            packet=good_packet,
            master_key=master_key + "::wrong",
            config=config,
        )
    )

    bad_nonce_packet = deepcopy(good_packet)
    bad_nonce_packet["header"]["packet_nonce"] = packet_nonce + "::tampered"
    cases.append(
        _run_case(
            name="tampered_header_packet_nonce",
            expected_pass=False,
            packet=bad_nonce_packet,
            master_key=master_key,
            config=config,
        )
    )

    bad_context_packet = deepcopy(good_packet)
    bad_context_packet["header"]["context"] = context + "::tampered"
    cases.append(
        _run_case(
            name="tampered_header_context",
            expected_pass=False,
            packet=bad_context_packet,
            master_key=master_key,
            config=config,
        )
    )

    bad_token_count_packet = deepcopy(good_packet)
    bad_token_count_packet["header"]["token_count"] = int(good_packet["header"]["token_count"]) + 1
    cases.append(
        _run_case(
            name="tampered_header_token_count",
            expected_pass=False,
            packet=bad_token_count_packet,
            master_key=master_key,
            config=config,
        )
    )

    bad_alg_packet = deepcopy(good_packet)
    bad_alg_packet["header"]["alg"] = "Bad-AEAD"
    cases.append(
        _run_case(
            name="tampered_header_alg",
            expected_pass=False,
            packet=bad_alg_packet,
            master_key=master_key,
            config=config,
        )
    )

    bad_version_packet = deepcopy(good_packet)
    bad_version_packet["header"]["version"] = 999
    cases.append(
        _run_case(
            name="tampered_header_version",
            expected_pass=False,
            packet=bad_version_packet,
            master_key=master_key,
            config=config,
        )
    )

    bad_mode_packet = deepcopy(good_packet)
    bad_mode_packet["header"]["bry_mode"] = "bad-mode"
    cases.append(
        _run_case(
            name="tampered_header_bry_mode",
            expected_pass=False,
            packet=bad_mode_packet,
            master_key=master_key,
            config=config,
        )
    )

    bad_cipher_packet = _flip_first_ciphertext_byte(good_packet)
    cases.append(
        _run_case(
            name="tampered_ciphertext",
            expected_pass=False,
            packet=bad_cipher_packet,
            master_key=master_key,
            config=config,
        )
    )

    return PacketAuditResult(
        nonce_check=nonce_check,
        packet_json=built.packet_json,
        cases=cases,
    )


def audit_to_dict(result: PacketAuditResult) -> dict[str, Any]:
    return {
        "nonce_check": asdict(result.nonce_check),
        "packet_json": result.packet_json,
        "cases": [asdict(case) for case in result.cases],
    }
