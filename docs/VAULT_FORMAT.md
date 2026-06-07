# QEV vault format

Current schema:

```text
BRY-NFET-SX-VAULT-V2
```

QEV vaults are JSON envelopes containing encrypted content and the metadata
required to derive keys, authenticate fields, and decrypt the payload.

## High-level structure

```json
{
  "schema": "BRY-NFET-SX-VAULT-V2",
  "version": "0.28.1",
  "created_at": "2026-04-15T23:59:59.000Z",
  "mode": "self",
  "kdf": {
    "algorithm": "argon2id",
    "opslimit": 4,
    "memlimit": 100663296,
    "salt": "<base64url>"
  },
  "wrap": {
    "algorithm": "XChaCha20-Poly1305",
    "nonce": "<base64url>",
    "wrapped_key": "<base64url>"
  },
  "content": {
    "algorithm": "XChaCha20-Poly1305",
    "nonce": "<base64url>",
    "ciphertext": "<base64url>"
  }
}
```

## Field meanings

| Field | Meaning |
|---|---|
| `schema` | Vault schema identifier. |
| `version` | Producer implementation version. |
| `created_at` | Creation timestamp. |
| `mode` | Intended sharing mode, currently `self` or `share`. |
| `kdf` | Passphrase stretching parameters. |
| `wrap` | Encrypted random content key. |
| `content` | Encrypted plaintext payload. |

## Cryptographic model

QEV uses a two-layer envelope design:

```text
passphrase -> Argon2id -> wrap key
random content key -> encrypts plaintext
wrap key -> encrypts content key
```

This means the passphrase-derived key is not used directly as the content key.
The vault can later support additional unlock methods without re-encrypting the
payload itself.

## Associated data

The CLI derives Additional Authenticated Data from a canonical JSON view of
vault metadata. The AAD is not stored. It is reconstructed during decrypt.

Bound fields include schema, version, creation time, mode, KDF parameters,
algorithm identifiers, and nonces. If a bound field changes, decryption fails.

## Binary encoding

Binary values use base64url without padding.

## Size limits

The current CLI is designed for small artifacts. It is not a bulk file backup
format. Use it for notes, text records, small logs, and compact evidence
artifacts.

## Compatibility

A compatible implementation must:

1. Parse the schema.
2. Reconstruct AAD identically.
3. Derive the wrap key with the stored Argon2id parameters.
4. Open the wrapped content key with XChaCha20-Poly1305.
5. Open the content ciphertext with XChaCha20-Poly1305.
6. Refuse malformed or unsupported fields safely.

## Non-goals

The vault format does not provide identity, legal notarization, recovery, group
messaging, or forward secrecy. It is a local encrypted envelope.
