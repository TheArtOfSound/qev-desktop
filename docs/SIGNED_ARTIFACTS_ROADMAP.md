# BRY-NFET-SX Signed Artifacts Roadmap

## Goal

Add a credible authenticity and review layer on top of current exported protocol artifacts.

## Why this matters

Right now the system exports useful JSON and CSV artifacts. That is good for inspection, but serious buyers will want stronger guarantees around:

- artifact origin
- artifact tamper evidence
- artifact provenance binding
- report authenticity

## Current state

Current artifacts include:

- packet JSON
- envelope JSON
- comparison JSON
- CSV exports
- runtime provenance

This is good for local workflow, but not yet enough for robust external review or signed operational reports.

## Desired future state

Artifacts should be exportable in a signed form such that a reviewer can verify:

- who generated the artifact
- when it was generated
- what exact contents were signed
- whether the artifact has been altered since signing

## Recommended signed-artifact model

### Signed manifest approach

Each export bundle should eventually include:

- primary artifact payload
- provenance payload
- detached signature or signed manifest
- signer identity metadata
- signing key/version metadata

### Bundle concept

Example bundle contents:

- envelope.json
- comparison.json
- provenance.json
- manifest.json
- signature.sig

## What should be signed

Sign:

- final artifact payload
- provenance payload
- artifact type/version
- hash digests of included files

Do not rely on signing only a human-readable summary.

## Initial roadmap

### Stage 1 -- DONE
Hash-based manifest generation (`manifest.py`).

### Stage 2 -- DONE
Detached local HMAC signing for artifacts (`signing.py`).

### Stage 3 -- DONE
Signed export bundles from the UI/API (`bundles.py`, Saved Runs tab, `/bundles/export` endpoint).

### Stage 4 -- DONE
Verifier API endpoint and dashboard UX (`/bundles/verify`, Saved Runs tab).

### Stage 5
Enterprise signing integration and key management integration.

## Verification workflow

A reviewer should be able to run something like:

- verify manifest
- verify signature
- verify included payload hashes
- verify artifact schema version

## Product value

Signed artifacts make the product more credible for:

- internal review
- governance workflows
- compliance-sensitive pipelines
- security operations
- customer/vendor artifact exchange

## Near-term implementation tasks

1. ~~define manifest schema~~ -- done (BRY-NFET-SX-MANIFEST-V1)
2. ~~define export bundle schema~~ -- done (artifact.json, metadata.json, manifest.json, signature.json)
3. ~~add hash generation to exports~~ -- done (SHA-256 in manifest)
4. ~~add verifier API + UI~~ -- done (/bundles/verify + Saved Runs tab)
5. add managed/KMS key provider for signing
6. add hardened unsigned-bundle trust semantics (from adversarial audit)
