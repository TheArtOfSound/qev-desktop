from __future__ import annotations

from dataclasses import dataclass

from bry_nfet_sx.bry.alphabet import CHAR_TO_TOKEN
from bry_nfet_sx.bry import (
    decode_from_bry,
    parse_bry_input,
    render_human_bry,
    untokenize_bry,
)
from bry_nfet_sx.nfet import NFETConfig, build_schedule, build_trace


LETTER_TOKENS: list[str] = [CHAR_TO_TOKEN[ch] for ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"]
PUNCT_TOKENS: list[str] = [CHAR_TO_TOKEN[ch] for ch in ".,?!'"]
SPACE_TOKEN = CHAR_TO_TOKEN[" "]


@dataclass(frozen=True)
class TransformRow:
    index: int
    original_token: str
    transformed_token: str
    recovered_token: str
    transform_bucket: int
    channel_index: int
    dummy_insert: bool
    intensity: float
    ridge_signal: float
    mask_byte: int


@dataclass(frozen=True)
class TransformResult:
    original_compact: str
    original_human: str
    transformed_compact: str
    transformed_human: str
    recovered_compact: str
    recovered_human: str
    recovered_plaintext: str
    roundtrip_ok: bool
    rows: list[TransformRow]


def _token_ring(token: str) -> list[str]:
    if token in LETTER_TOKENS:
        return LETTER_TOKENS
    if token in PUNCT_TOKENS:
        return PUNCT_TOKENS
    if token == SPACE_TOKEN:
        return [SPACE_TOKEN]
    raise ValueError(f"Unsupported token class for transform: {token!r}")


def _signed_direction(channel_index: int, dummy_insert: bool) -> int:
    parity = (channel_index + (1 if dummy_insert else 0)) % 2
    return 1 if parity == 0 else -1


def _shift_amount(
    token: str,
    position: int,
    transform_bucket: int,
    ridge_signal: float,
    mask_byte: int,
) -> int:
    ring = _token_ring(token)
    size = len(ring)
    if size <= 1:
        return 0

    ridge_scaled = int(ridge_signal * 1000)
    base = (
        transform_bucket * 131
        + mask_byte
        + ridge_scaled
        + position * 17
    )
    return 1 + (base % (size - 1))


def transform_token(
    token: str,
    position: int,
    transform_bucket: int,
    channel_index: int,
    dummy_insert: bool,
    ridge_signal: float,
    mask_byte: int,
) -> str:
    ring = _token_ring(token)
    if len(ring) <= 1:
        return token

    shift = _shift_amount(
        token=token,
        position=position,
        transform_bucket=transform_bucket,
        ridge_signal=ridge_signal,
        mask_byte=mask_byte,
    )
    direction = _signed_direction(channel_index=channel_index, dummy_insert=dummy_insert)
    idx = ring.index(token)
    return ring[(idx + direction * shift) % len(ring)]


def inverse_transform_token(
    token: str,
    position: int,
    transform_bucket: int,
    channel_index: int,
    dummy_insert: bool,
    ridge_signal: float,
    mask_byte: int,
) -> str:
    ring = _token_ring(token)
    if len(ring) <= 1:
        return token

    shift = _shift_amount(
        token=token,
        position=position,
        transform_bucket=transform_bucket,
        ridge_signal=ridge_signal,
        mask_byte=mask_byte,
    )
    direction = _signed_direction(channel_index=channel_index, dummy_insert=dummy_insert)
    idx = ring.index(token)
    return ring[(idx - direction * shift) % len(ring)]


def apply_transform_from_plaintext(
    plaintext: str,
    master_key: str,
    nonce: str,
    context: str,
    config: NFETConfig,
) -> TransformResult:
    trace = build_trace(
        plaintext=plaintext,
        master_key=master_key,
        nonce=nonce,
        context=context,
        config=config,
    )

    original_tokens = trace.tokens
    transformed_tokens: list[str] = []
    recovered_tokens: list[str] = []
    rows: list[TransformRow] = []

    for token, sched in zip(original_tokens, trace.rows):
        transformed = transform_token(
            token=token,
            position=sched.index,
            transform_bucket=sched.transform_bucket,
            channel_index=sched.channel_index,
            dummy_insert=sched.dummy_insert,
            ridge_signal=sched.ridge_signal,
            mask_byte=sched.mask_byte,
        )
        recovered = inverse_transform_token(
            token=transformed,
            position=sched.index,
            transform_bucket=sched.transform_bucket,
            channel_index=sched.channel_index,
            dummy_insert=sched.dummy_insert,
            ridge_signal=sched.ridge_signal,
            mask_byte=sched.mask_byte,
        )

        transformed_tokens.append(transformed)
        recovered_tokens.append(recovered)

        rows.append(
            TransformRow(
                index=sched.index,
                original_token=token,
                transformed_token=transformed,
                recovered_token=recovered,
                transform_bucket=sched.transform_bucket,
                channel_index=sched.channel_index,
                dummy_insert=sched.dummy_insert,
                intensity=sched.intensity,
                ridge_signal=sched.ridge_signal,
                mask_byte=sched.mask_byte,
            )
        )

    original_compact = untokenize_bry(original_tokens)
    transformed_compact = untokenize_bry(transformed_tokens)
    recovered_compact = untokenize_bry(recovered_tokens)

    return TransformResult(
        original_compact=original_compact,
        original_human=render_human_bry(original_tokens),
        transformed_compact=transformed_compact,
        transformed_human=render_human_bry(transformed_tokens),
        recovered_compact=recovered_compact,
        recovered_human=render_human_bry(recovered_tokens),
        recovered_plaintext=decode_from_bry(recovered_compact),
        roundtrip_ok=(original_compact == recovered_compact),
        rows=rows,
    )


def reverse_transform_from_bry(
    bry_text: str,
    master_key: str,
    nonce: str,
    context: str,
    config: NFETConfig,
) -> TransformResult:
    transformed_tokens = parse_bry_input(bry_text)

    schedule = build_schedule(
        token_count=len(transformed_tokens),
        master_key=master_key,
        nonce=nonce,
        context=context,
        config=config,
    )

    recovered_tokens: list[str] = []
    rows: list[TransformRow] = []

    for token, sched in zip(transformed_tokens, schedule.rows):
        recovered = inverse_transform_token(
            token=token,
            position=sched.index,
            transform_bucket=sched.transform_bucket,
            channel_index=sched.channel_index,
            dummy_insert=sched.dummy_insert,
            ridge_signal=sched.ridge_signal,
            mask_byte=sched.mask_byte,
        )
        reforward = transform_token(
            token=recovered,
            position=sched.index,
            transform_bucket=sched.transform_bucket,
            channel_index=sched.channel_index,
            dummy_insert=sched.dummy_insert,
            ridge_signal=sched.ridge_signal,
            mask_byte=sched.mask_byte,
        )

        recovered_tokens.append(recovered)

        rows.append(
            TransformRow(
                index=sched.index,
                original_token=recovered,
                transformed_token=token,
                recovered_token=reforward,
                transform_bucket=sched.transform_bucket,
                channel_index=sched.channel_index,
                dummy_insert=sched.dummy_insert,
                intensity=sched.intensity,
                ridge_signal=sched.ridge_signal,
                mask_byte=sched.mask_byte,
            )
        )

    recovered_compact = untokenize_bry(recovered_tokens)
    transformed_compact = untokenize_bry(transformed_tokens)

    return TransformResult(
        original_compact=recovered_compact,
        original_human=render_human_bry(recovered_tokens),
        transformed_compact=transformed_compact,
        transformed_human=render_human_bry(transformed_tokens),
        recovered_compact=transformed_compact,
        recovered_human=render_human_bry(transformed_tokens),
        recovered_plaintext=decode_from_bry(recovered_compact),
        roundtrip_ok=(transformed_compact == untokenize_bry([row.recovered_token for row in rows])),
        rows=rows,
    )
