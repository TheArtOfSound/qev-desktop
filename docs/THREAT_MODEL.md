# BRY-NFET-SX Threat Model

## Purpose

This document defines the current threat model for BRY-NFET-SX as a local secure packaging and session-envelope system.

## Security objective

BRY-NFET-SX aims to protect the confidentiality and integrity of structured message artifacts while preserving explicit routing policy, deterministic evaluation, and artifact comparison capabilities.

## Protected assets

Primary assets:

- plaintext messages before encryption
- encrypted packet payloads
- encrypted multi-message envelope artifacts
- routing-policy outputs
- artifact provenance
- session structure metadata
- master keys and any derived operational keys

## Security properties targeted

BRY-NFET-SX currently targets:

- confidentiality of encrypted payloads
- integrity and authenticity of encrypted packets
- integrity of envelope structure
- reproducibility of evaluation in audit mode
- traceability of policy choice and artifact differences
- structured comparison of artifacts produced under different routing policies

## Out-of-scope claims

BRY-NFET-SX does not currently claim:

- anonymity
- deniability
- traffic analysis resistance
- endpoint compromise resistance
- secure multi-party key exchange
- forward secrecy
- post-compromise recovery
- secure cloud key custody
- formal resistance under all hostile deployment conditions

## Assumed environment

Current assumed environment:

- trusted local execution environment
- developer/operator controls master keys
- artifacts are generated and opened within a trusted local lab or controlled service boundary
- standard Python and local OS process security assumptions apply

## Adversaries considered

### Adversary A: passive artifact observer
Capabilities:

- can read stored packets/envelopes
- can inspect exported artifacts
- does not control keys

Goal:

- recover plaintext or infer message contents from encrypted artifacts

Current defense:

- authenticated encryption of packet payloads
- structured envelope packaging rather than plaintext storage

### Adversary B: active artifact tamperer
Capabilities:

- can modify packet JSON or envelope JSON
- can replay or corrupt artifact fields

Goal:

- alter messages without detection
- alter packet/envelope structure to induce incorrect open behavior

Current defense:

- authenticated packet encryption
- packet ID validation
- schema validation
- envelope content validation
- consistency checks across embedded packets and envelope fields

### Adversary C: policy observer
Capabilities:

- can inspect policy outputs and comparisons
- can observe which family was selected

Goal:

- infer system behavior or routing triggers

Current defense:

- none beyond normal artifact confidentiality boundaries
- policy visibility is intentionally part of the system design for explainability

This is a design tradeoff, not a bug.

### Adversary D: local machine compromise
Capabilities:

- can read process memory
- can read local files and keys
- can observe plaintext before encryption or after decryption

Goal:

- fully compromise confidentiality and integrity

Current defense:

- effectively none at the software-only application layer
- this adversary defeats the current trust boundary

This is currently out of scope.

## Key trust assumptions

The current trust boundary assumes:

- master keys are not exposed
- the local runtime is not malicious
- the code being executed is the intended code
- the operator is trusted to manage secrets correctly

## Attack surfaces

Primary current attack surfaces:

- key handling
- artifact storage/export
- malformed packet inputs
- malformed envelope inputs
- policy misuse or operator misunderstanding
- stale or incorrect provenance interpretation

## Known weak areas

Current weak areas from a product-security standpoint:

- no production-grade key management layer
- no formal HSM/KMS integration
- no tenant isolation model
- no formal secret rotation or revocation layer
- no signed report artifact model yet
- no formal external audit yet
- no hardened deployment guidance yet

## Misuse risks

The biggest realistic misuse risks are:

- overselling policy-routing as novel cryptography
- assuming deterministic evaluation implies operational determinism everywhere
- treating the local trust model as if it were hostile-environment safe
- failing to separate lab-mode features from production-safe deployment posture

## Security posture summary

BRY-NFET-SX is currently best understood as:

- a local secure artifact packaging lab
- with authenticated encryption
- structured envelopes
- explainable policy routing
- deterministic evaluation
- artifact comparison

It is not yet a production-hardened end-to-end security platform.

## Immediate hardening priorities

1. ~~key management architecture~~ -- done (key provider abstraction)
2. ~~signed artifact/export design~~ -- done (manifest + HMAC signing)
3. deployment trust-boundary guidance
4. secret storage and rotation model
5. ~~adversarial testing~~ -- done (April 2026 audit, 11 findings)

## Findings from adversarial audit (April 2026)

An adversarial security review confirmed 11 issues (2 critical, 4 high, 5 medium):

- **Critical:** arbitrary file read via file key provider; bundle tampering via manifest+artifact replacement
- **High:** env var exfiltration via key provider; nonce TOCTOU race; index integrity; artifact-on-disk tampering
- **Medium:** signature key_version mismatch; provenance spoofing; dashboard replay bug; arbitrary bundle_dir; ambiguous verification tri-state

These findings define the current trust boundary. The system is designed for local/controlled use; it is not hardened for hostile multi-tenant deployment.
