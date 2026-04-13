from __future__ import annotations

from dataclasses import asdict, dataclass

from bry_nfet_sx.bry import encode_to_bry, normalize_plaintext, tokenize_bry
from bry_nfet_sx.nfet.config import NFETConfig
from bry_nfet_sx.nfet.state import (
    absorb_trace_digest,
    derive_session_key,
    initialize_scheduler_state,
    initialize_trace_digest,
    scheduler_view,
    step_scheduler_state,
)


@dataclass(frozen=True)
class NFETScheduleRow:
    index: int
    state_hex: str
    transform_bucket: int
    channel_index: int
    dummy_insert: bool
    intensity: float
    ridge_signal: float
    mask_byte: int


@dataclass(frozen=True)
class NFETScheduleResult:
    token_count: int
    initial_state_hex: str
    rows: list[NFETScheduleRow]


@dataclass(frozen=True)
class NFETTraceRow:
    index: int
    token: str
    left_token: str
    right_token: str
    state_hex: str
    transform_bucket: int
    channel_index: int
    dummy_insert: bool
    intensity: float
    ridge_signal: float
    mask_byte: int
    message_trace_hex: str


@dataclass(frozen=True)
class NFETTraceResult:
    normalized_plaintext: str
    canonical_bry: str
    tokens: list[str]
    initial_state_hex: str
    rows: list[NFETTraceRow]


def build_schedule(
    token_count: int,
    master_key: str,
    nonce: str,
    context: str,
    config: NFETConfig,
) -> NFETScheduleResult:
    config.validate()

    session_key = derive_session_key(
        master_key=master_key.encode("utf-8"),
        nonce=nonce.encode("utf-8"),
        context=context.encode("utf-8"),
    )

    state = initialize_scheduler_state(
        session_key=session_key,
        nonce=nonce.encode("utf-8"),
        context=context.encode("utf-8"),
        state_bytes=config.state_bytes,
    )

    initial_state_hex = state.hex()
    rows: list[NFETScheduleRow] = []

    for i in range(token_count):
        state = step_scheduler_state(
            current=state,
            session_key=session_key,
            position=i,
        )
        view = scheduler_view(
            state=state,
            transform_bucket_count=config.transform_bucket_count,
            dummy_insertion_modulus=config.dummy_insertion_modulus,
        )
        rows.append(
            NFETScheduleRow(
                index=i,
                state_hex=state.hex(),
                transform_bucket=view.transform_bucket,
                channel_index=view.channel_index,
                dummy_insert=view.dummy_insert,
                intensity=view.intensity,
                ridge_signal=view.ridge_signal,
                mask_byte=view.mask_byte,
            )
        )

    return NFETScheduleResult(
        token_count=token_count,
        initial_state_hex=initial_state_hex,
        rows=rows,
    )


def build_trace(
    plaintext: str,
    master_key: str,
    nonce: str,
    context: str,
    config: NFETConfig,
) -> NFETTraceResult:
    config.validate()

    normalized = normalize_plaintext(plaintext)
    canonical_bry = encode_to_bry(normalized)
    tokens = tokenize_bry(canonical_bry)

    schedule = build_schedule(
        token_count=len(tokens),
        master_key=master_key,
        nonce=nonce,
        context=context,
        config=config,
    )

    session_key = derive_session_key(
        master_key=master_key.encode("utf-8"),
        nonce=nonce.encode("utf-8"),
        context=context.encode("utf-8"),
    )
    trace_digest = initialize_trace_digest(
        session_key=session_key,
        nonce=nonce.encode("utf-8"),
        context=context.encode("utf-8"),
    )

    rows: list[NFETTraceRow] = []

    for i, token in enumerate(tokens):
        left_token = tokens[i - 1] if i > 0 else "<START>"
        right_token = tokens[i + 1] if i + 1 < len(tokens) else "<END>"

        trace_digest = absorb_trace_digest(
            current_digest=trace_digest,
            session_key=session_key,
            token=token,
            position=i,
            left_token=left_token,
            right_token=right_token,
        )

        sched = schedule.rows[i]
        rows.append(
            NFETTraceRow(
                index=i,
                token=token,
                left_token=left_token,
                right_token=right_token,
                state_hex=sched.state_hex,
                transform_bucket=sched.transform_bucket,
                channel_index=sched.channel_index,
                dummy_insert=sched.dummy_insert,
                intensity=sched.intensity,
                ridge_signal=sched.ridge_signal,
                mask_byte=sched.mask_byte,
                message_trace_hex=trace_digest.hex(),
            )
        )

    return NFETTraceResult(
        normalized_plaintext=normalized,
        canonical_bry=canonical_bry,
        tokens=tokens,
        initial_state_hex=schedule.initial_state_hex,
        rows=rows,
    )


def schedule_to_dict(result: NFETScheduleResult) -> dict:
    return {
        "token_count": result.token_count,
        "initial_state_hex": result.initial_state_hex,
        "rows": [asdict(row) for row in result.rows],
    }


def trace_to_dict(result: NFETTraceResult) -> dict:
    return {
        "normalized_plaintext": result.normalized_plaintext,
        "canonical_bry": result.canonical_bry,
        "tokens": result.tokens,
        "initial_state_hex": result.initial_state_hex,
        "rows": [asdict(row) for row in result.rows],
    }
