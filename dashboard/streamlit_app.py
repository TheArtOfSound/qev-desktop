from __future__ import annotations

import json

import pandas as pd
import streamlit as st
from cryptography.exceptions import InvalidTag

from bry_nfet_sx.bry import (
    BryDecodingError,
    BryEncodingError,
    canonicalize_bry_input,
    decode_from_bry,
    encode_to_bry,
    normalize_plaintext,
    parse_bry_input,
    render_human_bry,
)
from bry_nfet_sx.nfet import NFETConfig, build_trace
from bry_nfet_sx.protocol.audit import check_and_register_nonce, run_packet_audit_matrix
from bry_nfet_sx.protocol.packet import build_packet_from_plaintext, open_packet_to_plaintext
from bry_nfet_sx.protocol.transforms import apply_transform_from_plaintext, reverse_transform_from_bry
from bry_nfet_sx.utils.settings import settings

st.set_page_config(page_title=settings.dashboard_title, layout="wide")
st.title(settings.dashboard_title)
st.caption("Phase 5: Bry Canonical Form + NFET Scheduler + Reversible Transforms + AEAD Packets + Audit Lab")


def config() -> NFETConfig:
    return NFETConfig(
        state_bytes=settings.state_bytes,
        transform_bucket_count=settings.transform_bucket_count,
        dummy_insertion_modulus=settings.dummy_insertion_modulus,
    )


tabs = st.tabs(
    ["Encode", "Decode", "NFET Trace", "Transform Lab", "Packet Lab", "Audit Lab"]
)

with tabs[0]:
    st.subheader("Plaintext → Bry")
    plaintext = st.text_area("Plaintext", value="MY NAME IS BRYAN.", height=140, key="encode_plaintext")

    if st.button("Encode", use_container_width=True):
        try:
            normalized = normalize_plaintext(plaintext)
            compact = encode_to_bry(normalized)
            tokens = parse_bry_input(compact)
            human = render_human_bry(tokens)

            st.success("Encoding succeeded.")
            st.text_area("Normalized plaintext", value=normalized, height=100)
            st.text_area("Canonical Bry (compact)", value=compact, height=100)
            st.text_area("Canonical Bry (human-safe)", value=human, height=120)
            st.json({"token_count": len(tokens), "tokens": tokens})
        except BryEncodingError as exc:
            st.error(str(exc))

with tabs[1]:
    st.subheader("Bry → Plaintext")
    bry = st.text_area(
        "Bry text",
        value="+3|++5|-|+4|1|+3|5|-|9|+9|-|2|+8|++5|1|+4|--p",
        height=140,
        key="decode_bry",
    )

    if st.button("Decode", use_container_width=True):
        try:
            tokens = parse_bry_input(bry)
            compact = canonicalize_bry_input(bry)
            human = render_human_bry(tokens)
            decoded = decode_from_bry(compact)
            recoded = encode_to_bry(decoded)
            recoded_human = render_human_bry(parse_bry_input(recoded))

            st.success("Decoding succeeded.")
            st.text_area("Canonicalized input Bry (compact)", value=compact, height=100)
            st.text_area("Canonicalized input Bry (human-safe)", value=human, height=120)
            st.text_area("Decoded plaintext", value=decoded, height=100)
            st.text_area("Re-encoded canonical Bry (compact)", value=recoded, height=100)
            st.text_area("Re-encoded canonical Bry (human-safe)", value=recoded_human, height=120)
        except BryDecodingError as exc:
            st.error(str(exc))

with tabs[2]:
    st.subheader("NFET Trace")
    col1, col2 = st.columns(2)

    with col1:
        trace_plaintext = st.text_area("Plaintext", value="WHAT'S UP?", height=120, key="trace_plaintext")
        trace_master_key = st.text_input("Master key", value="bry-secret-dev-key", type="password", key="trace_master_key")

    with col2:
        trace_nonce = st.text_input("Nonce", value="nonce-001", key="trace_nonce")
        trace_context = st.text_input("Context", value="local-dev", key="trace_context")

    if st.button("Build NFET Trace", use_container_width=True):
        try:
            result = build_trace(
                plaintext=trace_plaintext,
                master_key=trace_master_key,
                nonce=trace_nonce,
                context=trace_context,
                config=config(),
            )

            st.success("Trace built.")
            st.text_area("Normalized plaintext", value=result.normalized_plaintext, height=80)
            st.text_area("Canonical Bry (compact)", value=result.canonical_bry, height=100)
            st.text_area("Canonical Bry (human-safe)", value=render_human_bry(result.tokens), height=120)
            st.text_area("Initial scheduler state", value=result.initial_state_hex, height=80)

            df = pd.DataFrame([row.__dict__ for row in result.rows])
            st.dataframe(df, use_container_width=True, hide_index=True)
        except (BryEncodingError, BryDecodingError, ValueError) as exc:
            st.error(str(exc))

with tabs[3]:
    st.subheader("Transform Lab")
    st.caption("Use human-safe transformed Bry for reversal. Compact transformed Bry is diagnostic only.")

    col1, col2 = st.columns(2)

    with col1:
        lab_plaintext = st.text_area("Plaintext", value="MY NAME IS BRYAN.", height=120, key="lab_plaintext")
        lab_master_key = st.text_input("Master key", value="bry-secret-dev-key", type="password", key="lab_master_key")

    with col2:
        lab_nonce = st.text_input("Nonce", value="nonce-001", key="lab_nonce")
        lab_context = st.text_input("Context", value="local-dev", key="lab_context")

    if st.button("Apply reversible transform", use_container_width=True):
        try:
            result = apply_transform_from_plaintext(
                plaintext=lab_plaintext,
                master_key=lab_master_key,
                nonce=lab_nonce,
                context=lab_context,
                config=config(),
            )

            st.success("Transform applied.")
            st.text_area("Original Bry (compact)", value=result.original_compact, height=90)
            st.text_area("Original Bry (human-safe)", value=result.original_human, height=110)
            st.text_area("Transformed Bry (compact, diagnostic only)", value=result.transformed_compact, height=90)
            st.text_area("Transformed Bry (human-safe, use this for reversal)", value=result.transformed_human, height=110)
            st.text_area("Recovered plaintext", value=result.recovered_plaintext, height=90)

            st.session_state["transform_bry_for_reverse"] = result.transformed_human

            df = pd.DataFrame([row.__dict__ for row in result.rows])
            st.dataframe(df, use_container_width=True, hide_index=True)
        except Exception as exc:
            st.error(str(exc))

    reverse_bry = st.text_area(
        "Transformed Bry input for reversal",
        value=st.session_state.get("transform_bry_for_reverse", ""),
        height=120,
        key="reverse_bry",
    )

    if st.button("Reverse transformed Bry", use_container_width=True):
        try:
            if "|" not in reverse_bry:
                st.error("Use the human-safe transformed Bry with | separators.")
            else:
                result = reverse_transform_from_bry(
                    bry_text=reverse_bry,
                    master_key=lab_master_key,
                    nonce=lab_nonce,
                    context=lab_context,
                    config=config(),
                )

                st.success("Reverse transform succeeded.")
                st.text_area("Recovered Bry (human-safe)", value=result.original_human, height=110)
                st.text_area("Recovered plaintext", value=result.recovered_plaintext, height=90)
        except Exception as exc:
            st.error(str(exc))

with tabs[4]:
    st.subheader("Packet Lab")
    st.warning("Packet nonce must be unique per master key/context in real use.")

    col1, col2 = st.columns(2)

    with col1:
        packet_plaintext = st.text_area(
            "Plaintext",
            value="MY NAME IS BRYAN.",
            height=120,
            key="packet_plaintext",
        )
        packet_master_key = st.text_input(
            "Master key",
            value="bry-secret-dev-key",
            type="password",
            key="packet_master_key",
        )

    with col2:
        packet_nonce = st.text_input(
            "Packet nonce",
            value="packet-001",
            key="packet_nonce",
        )
        packet_context = st.text_input(
            "Context",
            value="local-dev",
            key="packet_context",
        )

    if st.button("Build encrypted packet", use_container_width=True):
        try:
            nonce_check = check_and_register_nonce(
                master_key=packet_master_key,
                context=packet_context,
                packet_nonce=packet_nonce,
            )

            if nonce_check.reused:
                st.warning(
                    f"Nonce reuse warning: {packet_nonce!r} was already used "
                    f"{nonce_check.prior_uses} time(s) for this key/context namespace."
                )
            else:
                st.info("Nonce registry: first observed use for this key/context namespace.")

            result = build_packet_from_plaintext(
                plaintext=packet_plaintext,
                master_key=packet_master_key,
                packet_nonce=packet_nonce,
                context=packet_context,
                config=config(),
            )
            st.session_state["packet_json"] = result.packet_json

            st.success("Encrypted packet built.")
            st.text_area("Packet JSON", value=result.packet_json, height=260)
            st.text_area("Transformed human-safe Bry (debug only)", value=result.transformed_human, height=120)
        except Exception as exc:
            st.error(str(exc))

    packet_json = st.text_area(
        "Packet JSON to open",
        value=st.session_state.get("packet_json", ""),
        height=260,
        key="packet_json_input",
    )

    if st.button("Open encrypted packet", use_container_width=True):
        try:
            packet = json.loads(packet_json)
            result = open_packet_to_plaintext(
                packet=packet,
                master_key=packet_master_key,
                config=config(),
            )

            st.success("Packet opened and verified.")
            st.text_area("Recovered plaintext", value=result.recovered_plaintext, height=90)
            st.text_area("Recovered Bry (human-safe)", value=result.recovered_human, height=120)
            st.text_area("Transformed Bry (human-safe)", value=result.transformed_human, height=120)
            st.json(
                {
                    "header": result.header.__dict__,
                    "token_count_ok": result.token_count_ok,
                }
            )
        except InvalidTag:
            st.error("Packet authentication failed.")
        except Exception as exc:
            st.error(str(exc))

with tabs[5]:
    st.subheader("Audit Lab")
    st.caption("This runs a fixed tamper matrix against a freshly built packet.")

    col1, col2 = st.columns(2)

    with col1:
        audit_plaintext = st.text_area(
            "Plaintext",
            value="MY NAME IS BRYAN.",
            height=120,
            key="audit_plaintext",
        )
        audit_master_key = st.text_input(
            "Master key",
            value="bry-secret-dev-key",
            type="password",
            key="audit_master_key",
        )

    with col2:
        audit_packet_nonce = st.text_input(
            "Packet nonce",
            value="packet-audit-001",
            key="audit_packet_nonce",
        )
        audit_context = st.text_input(
            "Context",
            value="local-dev",
            key="audit_context",
        )

    if st.button("Run audit matrix", use_container_width=True):
        try:
            result = run_packet_audit_matrix(
                plaintext=audit_plaintext,
                master_key=audit_master_key,
                packet_nonce=audit_packet_nonce,
                context=audit_context,
                config=config(),
            )

            if result.nonce_check.reused:
                st.warning(
                    f"Nonce reuse warning: {result.nonce_check.packet_nonce!r} had "
                    f"{result.nonce_check.prior_uses} prior use(s) in this namespace."
                )
            else:
                st.info("Nonce registry: first observed use for this key/context namespace.")

            st.text_area("Fresh packet JSON used for this audit run", value=result.packet_json, height=260)

            df = pd.DataFrame([case.__dict__ for case in result.cases])
            st.dataframe(df, use_container_width=True, hide_index=True)

            failing = df[df["outcome"] != "PASS"]
            if len(failing) == 0:
                st.success("Audit matrix passed.")
            else:
                st.error("Audit matrix found unexpected results.")
        except Exception as exc:
            st.error(str(exc))

st.divider()
st.markdown(
    """
    **What exists now**
    - canonical Bry forms
    - NFET scheduler
    - reversible symbolic transforms
    - token-ID binary serialization
    - ChaCha20-Poly1305 encrypted packets
    - header validation
    - nonce reuse registry
    - automated tamper matrix

    **What comes next**
    - packet mutation corpus
    - fuzz harness
    - transform leakage statistics
    - multi-message/session safety rules
    """
)
