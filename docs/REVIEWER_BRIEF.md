# BRY-NFET-SX Reviewer Brief

## Overview

BRY-NFET-SX is a policy-aware encrypted envelope workflow platform built on standard authenticated encryption (ChaCha20-Poly1305). It packages structured messages into authenticated encrypted session artifacts, compares policy routing outcomes, persists artifacts with integrity binding, and exports signer-verifiable bundles. It is a controlled-use product preview (v0.28.1), not a hardened enterprise deployment.

## Product framing

This is a **secure workflow system**, not a new cryptographic primitive. The cryptographic foundation is standard AEAD via the Python `cryptography` library. The differentiated value is the workflow layer: policy-aware routing, multi-message session envelopes, artifact comparison, signed bundle export, and trust-aware verification.

Do not evaluate this as a novel cipher. Evaluate it as a security workflow platform.

## Strongest current capabilities

- **Authenticated encryption**: ChaCha20-Poly1305, no custom primitives
- **Multi-message envelopes**: session-level packaging with per-message routing visibility
- **Policy comparison**: same messages run under manual, default, and auto routing policies; differences are explicit and explainable
- **Signed bundles**: HMAC-SHA256 signatures over SHA-256 manifests, with key fingerprint provenance binding
- **Trust-aware verification**: `overall_trusted` requires integrity + signature + metadata consistency; unsigned and unchecked bundles are never reported as trusted
- **Storage integrity**: persisted artifacts are SHA-256 hashed at save time; tampered files are rejected on load
- **Concurrency-safe nonce registry**: file-lock serialized read-check-write in strict mode
- **Provider lockdown**: file key provider restricted to configurable root; env var provider restricted to explicit allowlist; bundle verification restricted to bundle root directory
- **189 tests** covering protocol, API, storage, signing, concurrency, trust semantics, provenance, and UI

## Current trust model

- Packets provide confidentiality and integrity via AEAD
- Envelopes provide session-level structure over packets
- Manifests provide integrity (content hashes match)
- Signatures provide authenticity (signer vouches for manifest)
- Key fingerprints provide provenance binding (derived from key material, not caller-declared)
- `overall_trusted` = `integrity_ok AND signature_verified AND metadata_consistent`
- Unsigned or unchecked bundles are never `overall_trusted`

See `docs/TRUST_SEMANTICS.md` for the full trust-field specification.

## What has been hardened

An internal adversarial review (April 2026) identified 11 issues. Phases 35A-35F resolved:

| Phase | What was fixed |
|---|---|
| 35A | File/env key provider restrictions, bundle path restriction |
| 35B | Nonce registry concurrency safety via file locking |
| 35C | Unambiguous bundle trust semantics (`overall_trusted`, etc.) |
| 35D | Storage integrity binding (content SHA-256 on save, verify on load) |
| 35E | Key fingerprint provenance binding, metadata consistency checking |
| 35F | Trust-aware UI display, honest wording for unsigned/unchecked states |

A second and third adversarial review drove additional hardening in Phases 38A-38E:

| Phase | What was fixed |
|---|---|
| 38A | Downgrade resistance: signed records missing key_fingerprint treated as metadata-inconsistent |
| 38B | Index rows HMAC-signed with auto-generated server-side secret (stored outside data/) |
| 38C | Artifact ID input validation (length, path-safe characters) |
| 38D | Unsafe temp-dir root rejection for security-critical paths |
| 38E | Encryption vs signer provenance clearly separated; NullSigner removed |
| audit-3 | Index write concurrency locked; stale signatures cleaned on re-export; envelope message limit |

## What remains limited

- Local trust model only; not hardened for hostile multi-tenant deployment
- No KMS/HSM integration; key material is local
- No key rotation or revocation mechanism
- File-based locking is POSIX only (not portable to Windows or NFS)
- No formal third-party security audit has been conducted

## Fastest local startup

```bash
uv sync
./scripts/dev_up.sh
```

- Dashboard: http://localhost:8506
- API: http://localhost:8001
- API docs: http://localhost:8001/docs

## Fastest demo path

1. **Envelopes tab**: build a 2-message envelope
2. **Envelope Policy tab**: compare 4 routing policies on 3 messages
3. **Saved Runs tab**: browse artifacts, export signed bundle, verify it
4. **Verify with wrong key**: observe trust failure

See `docs/RELEASE_WALKTHROUGH.md` for step-by-step detail.
See `docs/REVIEW_COMMANDS.md` for exact copy-paste commands.

## Example artifacts

Review artifacts are generated fresh by the preparation script — they are not committed canonical evidence files. Run:

```bash
uv run python scripts/prepare_review_artifacts.py
```

This creates artifacts under `data/review/`, `data/runs/`, and `data/bundles/`. All use non-sensitive demo secrets printed in the output.

## Key files for code review

| File | What it does |
|---|---|
| `src/bry_nfet_sx/protocol/packet.py` | Single-message AEAD packet build/open |
| `src/bry_nfet_sx/protocol/envelope.py` | Multi-message session envelope build/open |
| `src/bry_nfet_sx/protocol/bundles.py` | Bundle export, verification, trust semantics |
| `src/bry_nfet_sx/protocol/signing.py` | HMAC signer, signature records, fingerprints |
| `src/bry_nfet_sx/protocol/keys.py` | Key provider abstraction, restrictions, fingerprints |
| `src/bry_nfet_sx/protocol/storage.py` | Artifact persistence with integrity binding |
| `src/bry_nfet_sx/protocol/session.py` | Nonce registry with file locking |
| `src/bry_nfet_sx/crypto_core/aead.py` | ChaCha20-Poly1305 via `cryptography` library |
| `dashboard/streamlit_app.py` | Operator dashboard |
