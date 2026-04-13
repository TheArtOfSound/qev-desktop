from __future__ import annotations

from dataclasses import asdict

from cryptography.exceptions import InvalidTag
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from bry_nfet_sx.bry import (
    canonicalize_bry_input,
    decode_from_bry,
    encode_to_bry,
    normalize_plaintext,
    parse_bry_input,
    render_human_bry,
)
from bry_nfet_sx.nfet import NFETConfig, build_schedule, build_trace, schedule_to_dict, trace_to_dict
from bry_nfet_sx.protocol import (
    apply_transform_from_plaintext,
    audit_to_dict,
    build_packet_from_plaintext,
    open_packet_to_plaintext,
    reverse_transform_from_bry,
    run_packet_audit_matrix,
)
from bry_nfet_sx.utils.settings import settings

app = FastAPI(
    title="BRY-NFET-SX Lab",
    version="0.6.0",
    description="Local lab for Bry canonicalization, NFET transforms, symbolic AEAD packets, and audit testing.",
)


class EncodeRequest(BaseModel):
    plaintext: str


class DecodeRequest(BaseModel):
    bry: str


class TraceRequest(BaseModel):
    plaintext: str = Field(..., min_length=1)
    master_key: str = Field(..., min_length=1)
    nonce: str = Field(..., min_length=1)
    context: str = Field(default="local-dev", min_length=1)


class ScheduleRequest(BaseModel):
    token_count: int = Field(..., ge=1)
    master_key: str = Field(..., min_length=1)
    nonce: str = Field(..., min_length=1)
    context: str = Field(default="local-dev", min_length=1)


class TransformApplyRequest(BaseModel):
    plaintext: str = Field(..., min_length=1)
    master_key: str = Field(..., min_length=1)
    nonce: str = Field(..., min_length=1)
    context: str = Field(default="local-dev", min_length=1)


class TransformReverseRequest(BaseModel):
    bry: str = Field(..., min_length=1)
    master_key: str = Field(..., min_length=1)
    nonce: str = Field(..., min_length=1)
    context: str = Field(default="local-dev", min_length=1)


class PacketBuildRequest(BaseModel):
    plaintext: str = Field(..., min_length=1)
    master_key: str = Field(..., min_length=1)
    packet_nonce: str = Field(..., min_length=1)
    context: str = Field(default="local-dev", min_length=1)


class PacketOpenRequest(BaseModel):
    packet: dict
    master_key: str = Field(..., min_length=1)


class AuditRunRequest(BaseModel):
    plaintext: str = Field(..., min_length=1)
    master_key: str = Field(..., min_length=1)
    packet_nonce: str = Field(..., min_length=1)
    context: str = Field(default="local-dev", min_length=1)


def _config() -> NFETConfig:
    return NFETConfig(
        state_bytes=settings.state_bytes,
        transform_bucket_count=settings.transform_bucket_count,
        dummy_insertion_modulus=settings.dummy_insertion_modulus,
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/bry/encode")
def bry_encode(req: EncodeRequest) -> dict[str, object]:
    normalized = normalize_plaintext(req.plaintext)
    compact = encode_to_bry(normalized)
    tokens = parse_bry_input(compact)
    human = render_human_bry(tokens)

    return {
        "normalized_plaintext": normalized,
        "canonical_bry_compact": compact,
        "canonical_bry_human": human,
        "tokens": tokens,
    }


@app.post("/bry/decode")
def bry_decode(req: DecodeRequest) -> dict[str, object]:
    tokens = parse_bry_input(req.bry)
    compact = canonicalize_bry_input(req.bry)
    decoded = decode_from_bry(compact)
    human = render_human_bry(tokens)

    return {
        "plaintext": decoded,
        "canonical_bry_compact": compact,
        "canonical_bry_human": human,
        "tokens": tokens,
    }


@app.post("/nfet/schedule")
def nfet_schedule(req: ScheduleRequest) -> dict:
    result = build_schedule(
        token_count=req.token_count,
        master_key=req.master_key,
        nonce=req.nonce,
        context=req.context,
        config=_config(),
    )
    return schedule_to_dict(result)


@app.post("/nfet/trace")
def nfet_trace(req: TraceRequest) -> dict:
    result = build_trace(
        plaintext=req.plaintext,
        master_key=req.master_key,
        nonce=req.nonce,
        context=req.context,
        config=_config(),
    )
    return trace_to_dict(result)


@app.post("/transform/apply")
def transform_apply(req: TransformApplyRequest) -> dict:
    result = apply_transform_from_plaintext(
        plaintext=req.plaintext,
        master_key=req.master_key,
        nonce=req.nonce,
        context=req.context,
        config=_config(),
    )
    return {
        "original_compact": result.original_compact,
        "original_human": result.original_human,
        "transformed_compact": result.transformed_compact,
        "transformed_human": result.transformed_human,
        "recovered_compact": result.recovered_compact,
        "recovered_human": result.recovered_human,
        "recovered_plaintext": result.recovered_plaintext,
        "roundtrip_ok": result.roundtrip_ok,
        "rows": [asdict(row) for row in result.rows],
    }


@app.post("/transform/reverse")
def transform_reverse(req: TransformReverseRequest) -> dict:
    result = reverse_transform_from_bry(
        bry_text=req.bry,
        master_key=req.master_key,
        nonce=req.nonce,
        context=req.context,
        config=_config(),
    )
    return {
        "transformed_compact": result.transformed_compact,
        "transformed_human": result.transformed_human,
        "recovered_compact": result.original_compact,
        "recovered_human": result.original_human,
        "recovered_plaintext": result.recovered_plaintext,
        "roundtrip_ok": result.roundtrip_ok,
        "rows": [asdict(row) for row in result.rows],
    }


@app.post("/packet/build")
def packet_build(req: PacketBuildRequest) -> dict:
    result = build_packet_from_plaintext(
        plaintext=req.plaintext,
        master_key=req.master_key,
        packet_nonce=req.packet_nonce,
        context=req.context,
        config=_config(),
    )
    return {
        "header": asdict(result.header),
        "packet": result.packet,
        "packet_json": result.packet_json,
        "transformed_token_count": result.transformed_token_count,
    }


@app.post("/packet/open")
def packet_open(req: PacketOpenRequest) -> dict:
    try:
        result = open_packet_to_plaintext(
            packet=req.packet,
            master_key=req.master_key,
            config=_config(),
        )
    except InvalidTag:
        raise HTTPException(status_code=400, detail="Packet authentication failed.")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return {
        "header": asdict(result.header),
        "transformed_human": result.transformed_human,
        "recovered_plaintext": result.recovered_plaintext,
        "recovered_human": result.recovered_human,
        "token_count_ok": result.token_count_ok,
    }


@app.post("/audit/run")
def audit_run(req: AuditRunRequest) -> dict:
    result = run_packet_audit_matrix(
        plaintext=req.plaintext,
        master_key=req.master_key,
        packet_nonce=req.packet_nonce,
        context=req.context,
        config=_config(),
    )
    return audit_to_dict(result)
