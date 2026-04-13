from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import hmac


def _u32(data: bytes, offset: int) -> int:
    chunk = data[offset:offset + 4]
    if len(chunk) != 4:
        raise ValueError("Need 4 bytes to parse u32")
    return int.from_bytes(chunk, "big", signed=False)


def _clamp_unit(value: int) -> float:
    return value / 0xFFFFFFFF


@dataclass(frozen=True)
class NFETState:
    step: int
    state_bytes: bytes

    def hex(self) -> str:
        return self.state_bytes.hex()


@dataclass(frozen=True)
class NFETSchedulerView:
    transform_bucket: int
    channel_index: int
    dummy_insert: bool
    intensity: float
    ridge_signal: float
    mask_byte: int


def derive_session_key(master_key: bytes, nonce: bytes, context: bytes) -> bytes:
    return hmac.new(
        master_key,
        b"BRY-NFET-SX|SESSION|" + nonce + b"|" + context,
        sha256,
    ).digest()


def initialize_scheduler_state(
    session_key: bytes,
    nonce: bytes,
    context: bytes,
    state_bytes: int = 32,
) -> NFETState:
    digest = hmac.new(
        session_key,
        b"BRY-NFET-SX|SCHED|INIT|" + nonce + b"|" + context,
        sha256,
    ).digest()

    material = digest
    while len(material) < state_bytes:
        material += sha256(material).digest()

    return NFETState(step=0, state_bytes=material[:state_bytes])


def step_scheduler_state(
    current: NFETState,
    session_key: bytes,
    position: int,
) -> NFETState:
    payload = (
        b"BRY-NFET-SX|SCHED|STEP|"
        + current.step.to_bytes(8, "big")
        + b"|"
        + position.to_bytes(8, "big")
        + b"|"
        + current.state_bytes
    )

    digest = hmac.new(session_key, payload, sha256).digest()
    mixed = bytes(a ^ b for a, b in zip(digest[: len(current.state_bytes)], current.state_bytes))
    return NFETState(step=current.step + 1, state_bytes=mixed)


def initialize_trace_digest(
    session_key: bytes,
    nonce: bytes,
    context: bytes,
) -> bytes:
    return hmac.new(
        session_key,
        b"BRY-NFET-SX|TRACE|INIT|" + nonce + b"|" + context,
        sha256,
    ).digest()


def absorb_trace_digest(
    current_digest: bytes,
    session_key: bytes,
    token: str,
    position: int,
    left_token: str,
    right_token: str,
) -> bytes:
    payload = (
        b"BRY-NFET-SX|TRACE|STEP|"
        + position.to_bytes(8, "big")
        + b"|"
        + token.encode("utf-8")
        + b"|"
        + left_token.encode("utf-8")
        + b"|"
        + right_token.encode("utf-8")
        + b"|"
        + current_digest
    )
    return hmac.new(session_key, payload, sha256).digest()


def scheduler_view(
    state: NFETState,
    transform_bucket_count: int = 16,
    dummy_insertion_modulus: int = 7,
) -> NFETSchedulerView:
    raw = state.state_bytes

    a = _u32(raw, 0)
    b = _u32(raw, 4)
    c = _u32(raw, 8)
    d = _u32(raw, 12)

    transform_bucket = a % transform_bucket_count
    channel_index = b % 4
    dummy_insert = (c % dummy_insertion_modulus) == 0

    intensity = _clamp_unit(a)
    ridge_signal = (_clamp_unit(b) + _clamp_unit(c) + _clamp_unit(d)) / 3.0
    mask_byte = raw[16] if len(raw) > 16 else raw[0]

    return NFETSchedulerView(
        transform_bucket=transform_bucket,
        channel_index=channel_index,
        dummy_insert=dummy_insert,
        intensity=round(intensity, 6),
        ridge_signal=round(ridge_signal, 6),
        mask_byte=mask_byte,
    )
