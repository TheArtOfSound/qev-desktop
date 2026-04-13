from __future__ import annotations

from base64 import b64decode, b64encode
from dataclasses import asdict, dataclass
import json

from bry_nfet_sx.bry import bytes_to_tokens, render_human_bry, tokens_to_bytes
from bry_nfet_sx.crypto_core.aead import decrypt_bytes, encrypt_bytes
from bry_nfet_sx.nfet import NFETConfig
from bry_nfet_sx.protocol.transforms import apply_transform_from_plaintext, reverse_transform_from_bry

SUPPORTED_PACKET_VERSION = 1
SUPPORTED_PACKET_ALG = "ChaCha20-Poly1305"
SUPPORTED_BRY_MODE = "token_ids_v1"


@dataclass(frozen=True)
class PacketHeader:
    version: int
    alg: str
    bry_mode: str
    context: str
    packet_nonce: str
    token_count: int


@dataclass(frozen=True)
class PacketBuildResult:
    header: PacketHeader
    packet: dict
    packet_json: str
    transformed_human: str
    transformed_token_count: int


@dataclass(frozen=True)
class PacketOpenResult:
    header: PacketHeader
    transformed_human: str
    recovered_plaintext: str
    recovered_human: str
    token_count_ok: bool


def validate_header(header: PacketHeader) -> None:
    if header.version != SUPPORTED_PACKET_VERSION:
        raise ValueError(
            f"Unsupported packet version: {header.version}. "
            f"Expected {SUPPORTED_PACKET_VERSION}."
        )
    if header.alg != SUPPORTED_PACKET_ALG:
        raise ValueError(
            f"Unsupported packet algorithm: {header.alg!r}. "
            f"Expected {SUPPORTED_PACKET_ALG!r}."
        )
    if header.bry_mode != SUPPORTED_BRY_MODE:
        raise ValueError(
            f"Unsupported Bry mode: {header.bry_mode!r}. "
            f"Expected {SUPPORTED_BRY_MODE!r}."
        )
    if not header.context:
        raise ValueError("Packet context must be non-empty.")
    if not header.packet_nonce:
        raise ValueError("Packet nonce must be non-empty.")
    if header.token_count < 1:
        raise ValueError("Packet token_count must be at least 1.")


def _header_bytes(header: PacketHeader) -> bytes:
    return json.dumps(
        asdict(header),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def build_packet_from_plaintext(
    plaintext: str,
    master_key: str,
    packet_nonce: str,
    context: str,
    config: NFETConfig,
) -> PacketBuildResult:
    transformed = apply_transform_from_plaintext(
        plaintext=plaintext,
        master_key=master_key,
        nonce=packet_nonce,
        context=context,
        config=config,
    )

    transformed_tokens = transformed.transformed_human.split("|")
    payload = tokens_to_bytes(transformed_tokens)

    header = PacketHeader(
        version=SUPPORTED_PACKET_VERSION,
        alg=SUPPORTED_PACKET_ALG,
        bry_mode=SUPPORTED_BRY_MODE,
        context=context,
        packet_nonce=packet_nonce,
        token_count=len(transformed_tokens),
    )
    validate_header(header)

    aad = _header_bytes(header)
    ciphertext = encrypt_bytes(
        master_key=master_key,
        packet_nonce=packet_nonce,
        context=context,
        plaintext=payload,
        aad=aad,
    )

    packet = {
        "header": asdict(header),
        "ciphertext_b64": b64encode(ciphertext).decode("ascii"),
    }

    return PacketBuildResult(
        header=header,
        packet=packet,
        packet_json=json.dumps(packet, indent=2),
        transformed_human=transformed.transformed_human,
        transformed_token_count=len(transformed_tokens),
    )


def open_packet_to_plaintext(
    packet: dict,
    master_key: str,
    config: NFETConfig,
) -> PacketOpenResult:
    raw_header = packet["header"]
    header = PacketHeader(**raw_header)
    validate_header(header)

    ciphertext = b64decode(packet["ciphertext_b64"])
    aad = _header_bytes(header)

    payload = decrypt_bytes(
        master_key=master_key,
        packet_nonce=header.packet_nonce,
        context=header.context,
        ciphertext=ciphertext,
        aad=aad,
    )

    tokens = bytes_to_tokens(payload)
    if len(tokens) != header.token_count:
        raise ValueError(
            f"Token count mismatch: header says {header.token_count}, "
            f"payload has {len(tokens)}."
        )

    transformed_human = render_human_bry(tokens)

    reversed_result = reverse_transform_from_bry(
        bry_text=transformed_human,
        master_key=master_key,
        nonce=header.packet_nonce,
        context=header.context,
        config=config,
    )

    return PacketOpenResult(
        header=header,
        transformed_human=transformed_human,
        recovered_plaintext=reversed_result.recovered_plaintext,
        recovered_human=reversed_result.original_human,
        token_count_ok=True,
    )
