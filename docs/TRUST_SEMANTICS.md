# BRY-NFET-SX Trust Semantics

Technical specification of what the system's trust-related fields mean and how they compose.

## Layers of protection

### Packet layer

A packet seals a single message with ChaCha20-Poly1305 authenticated encryption. The AEAD tag provides both confidentiality and integrity at the message level. Packet headers are bound as additional authenticated data (AAD), so header tampering causes decryption to fail.

### Envelope layer

An envelope packages multiple packets into a session artifact. Envelope validation checks structural consistency: message count matches header, packet IDs match embedded packets, session IDs and contexts are consistent across all messages.

### Bundle layer

A bundle is an exported directory containing an artifact, metadata, a manifest, and optionally a signature. This is where the trust semantics become most relevant to reviewers.

## Bundle verification output fields

When `verify_bundle_dir()` runs, it returns these top-level trust fields:

### `integrity_ok` (bool)

The SHA-256 hashes in `manifest.json` match the actual content of `artifact.json` and `metadata.json`.

This proves: the files have not been modified since the manifest was generated.

This does **not** prove: who generated the manifest, or that the manifest itself is authentic.

### `signature_present` (bool)

A `signature.json` file exists in the bundle directory.

This proves: someone included a signature file.

This does **not** prove: the signature is valid, or that it was checked.

### `signature_checked` (bool)

The verifier had enough information (signer provider mode and credentials) to actually perform the cryptographic signature check.

`False` means: the signature file exists but no signer key was supplied, so the HMAC was never computed. The signature is unchecked.

### `signature_verified` (bool)

The HMAC-SHA256 digest computed by the verifier matches the digest in the signature record.

This proves: the manifest bytes have not changed since signing, and the verifier holds the same signing key.

This does **not** prove: the signer metadata (key_version label, etc.) is accurate.

### `metadata_consistent` (bool)

The key fingerprint in the signature record matches the key fingerprint of the verifier's key.

Key fingerprints are derived from actual key material (`SHA-256(key)[:16]`), not from caller-declared labels. This prevents an attacker from signing with a weak key and claiming a production key version.

`True` requires: `key_fingerprint_consistent` is `True`, or the signature record predates fingerprint support (legacy) and the digest verified.

### `key_fingerprint_consistent` (bool | None)

Compares the `key_fingerprint` field in the signature record against the verifier's key fingerprint.

- `True`: same key material was used for signing and verification
- `False`: different key material
- `None`: not checked (no signer supplied, or legacy record without fingerprint)

### `key_version_consistent` (bool | None)

Compares the `key_version` label in the signature record against the verifier's `key_version`.

- `True`: labels match
- `False`: labels differ (even if the actual key material is the same)
- `None`: not checked, or either side has no key_version

This is an **advisory** field. It does not gate `overall_trusted`. Key fingerprint is the binding; key version is the label.

### `overall_trusted` (bool)

The single authoritative trust verdict.

```
overall_trusted = integrity_ok AND signature_verified AND metadata_consistent
```

This is `True` only when all three conditions hold:
1. Manifest hashes match the actual files (integrity)
2. HMAC digest is cryptographically valid (authenticity)
3. Key fingerprint matches between signer and verifier (provenance)

## Trust states

| Scenario | `integrity_ok` | `sig_present` | `sig_checked` | `sig_verified` | `metadata_consistent` | `overall_trusted` |
|---|---|---|---|---|---|---|
| Unsigned bundle | True | False | False | False | False | **False** |
| Signed, no key supplied | True | True | False | False | False | **False** |
| Signed, wrong key | True | True | True | False | False | **False** |
| Signed, correct key, correct version | True | True | True | True | True | **True** |
| Signed, correct key, wrong version label | True | True | True | True | True | **True** |
| Tampered manifest | False | varies | varies | varies | varies | **False** |

Note: "correct key, wrong version label" is `overall_trusted: True` because the key fingerprint (derived from actual material) matches. The version label mismatch is exposed via `key_version_consistent: False` but does not break trust.

## Storage integrity

Persisted artifacts are SHA-256 hashed at save time. The hash is stored in the index as `content_sha256`. On load, the hash is recomputed and compared. A mismatch raises `StorageError` and the artifact is not returned.

### Index row HMAC (Phase 38B / audit-3 hardening)

Each index row is HMAC-signed over its binding fields (`artifact_id`, `category`, `path`, `content_sha256`) using a server-side secret that is **not** stored in the `data/` directory tree. This prevents index + artifact collusion: an attacker who modifies both the artifact file and updates the index hash cannot recompute the HMAC without the server secret.

The HMAC secret is resolved in this order:
1. `BRY_INDEX_HMAC_SECRET` environment variable (explicit override)
2. `~/.bry_nfet_sx_lab/index_hmac_secret` file (auto-generated on first use)

The secret is generated as 32 random bytes (hex-encoded) on first startup and persisted with 0600 permissions. It is never stored inside the `data/` tree.

### Index write concurrency

Index file writes are serialized with exclusive file locking (`fcntl.flock`) to prevent concurrent saves from overwriting each other.

### Legacy compatibility

Legacy index entries (saved before Phase 35D) that lack `content_sha256` are loaded without content verification. Legacy rows without `row_hmac` are loaded without HMAC verification. New saves always include both.

## Downgrade resistance (Phase 38A)

Signed records using a real signing algorithm (e.g. `HMAC-SHA256`) that are missing the `key_fingerprint` field are treated as metadata-inconsistent. The legacy fallback that previously allowed missing-fingerprint records to be trusted has been removed for signed algorithms. This prevents an attacker from re-signing a bundle with their own key, stripping the fingerprint, and receiving `overall_trusted: True`.

The legacy fallback now only applies to genuinely unsigned records (algorithm `none` or empty).

## Provenance separation (Phase 38E)

Bundle verification output separates encryption provenance from signer provenance:

- `encryption_provenance`: `encryption_provider_id`, `encryption_provider_label`, `encryption_key_version`, `provenance_source`
- `signer_provenance`: `signer_key_fingerprint`, `signer_key_version`, `signer_algorithm`

The `provenance_source` field indicates whether encryption provenance was self-reported from the artifact payload (`"artifact_payload"`) or derived from an independent source.

## Resource limits

Envelope build rejects requests exceeding a configurable maximum message count (default: 100, override via `BRY_MAX_ENVELOPE_MESSAGES`).

## What these semantics do NOT cover

- Key rotation or revocation (not implemented)
- Signer identity authentication beyond shared-secret HMAC (no PKI, no certificates)
- Multi-tenant access control
- Network-layer security
