# BRY-NFET-SX Product Preview

## One-line description

BRY-NFET-SX is a policy-aware encrypted envelope system for structured message and session workflows, with reproducible evaluation, persisted artifacts, bundle export, and bundle verification.

## What the buyer should understand immediately

This is not positioned as a new cryptographic primitive.

It is a secure workflow platform built on standard authenticated encryption, then extended with:

- policy-aware routing
- multi-message session envelopes
- artifact comparison
- persisted runs
- bundle export
- manifest verification
- signature verification
- provider and key-version traceability

## Fastest demo path

1. Build an envelope
2. Compare policies on the same message set
3. Compare two envelopes directly
4. Save and browse artifacts
5. Export a signed bundle
6. Verify the signed bundle

## What this proves

The product can:

- package structured messages into encrypted artifacts
- explain policy choices
- compare outcomes under different policies
- persist artifacts for later inspection
- export tamper-evident bundles
- attach signer-backed authenticity semantics
- retain provider/key-version metadata for custody traceability

## Product framing

Best framing:

- policy-aware encrypted envelope workflow platform
- secure session artifact packaging and comparison
- audit-ready persisted security artifacts
- signed bundle export and verification

Avoid framing:

- replacement for standard cryptographic primitives
- revolutionary new cipher
- superior to mature cryptographic libraries

## Current strengths

- provider-aware key handling with restricted resolution (path and env allowlists)
- saved artifacts with integrity binding (SHA-256 content hashes + index row HMAC)
- signed bundle workflow with unambiguous trust semantics
- downgrade resistance: signed records require key fingerprint
- index write concurrency safety via file locking
- encryption and signer provenance clearly separated in verification output
- deterministic evaluation
- artifact comparison
- bundle verification with `overall_trusted` / `metadata_consistent` / `key_fingerprint_consistent` fields
- concurrency-safe nonce and index registries (file-lock based)
- key fingerprint provenance binding
- trust-aware dashboard operator surface
- envelope message count limits
- 189 passing tests across three adversarial review cycles

## Remaining gaps

- managed signer / KMS-backed signer path
- key rotation and revocation mechanisms
- deployment hardening for hostile multi-tenant use
- file-based locking is POSIX-only (not portable to Windows or NFS)
