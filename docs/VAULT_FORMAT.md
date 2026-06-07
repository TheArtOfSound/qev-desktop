# QEV Vault Format

Current schema:

```text
BRY-NFET-SX-VAULT-V2
```

QEV vaults are JSON documents containing the metadata and ciphertext needed to decrypt a single encrypted envelope.

## Example shape

```json
{
  "schema": "BRY-NFET-SX-VAULT-V2",
  "version": "0.29.0",
  "created_at": "2026-04-15T23:59:59.000Z",
  "mode": "self",
  "kdf": {
    "algorithm": "argon2id",
    "opslimit": 4,
    "memlimit": 100663296,
    "salt": "<base64url 16 bytes>"
  },
  "wrap": {
    "algorithm": "XChaCha20-Poly1305",
    "nonce": "<base64url 24 bytes>",
    "wrapped_key": "<base64url 48 bytes>"
  },
  "content": {
    "algorithm": "XChaCha20-Poly1305",
    "nonce": "<base64url 24 bytes>",
    "ciphertext": "<base64url ciphertext + tag>"
  }
}
```

## Fields

| Field | Purpose |
|---|---|
| `schema` | Format identifier. Current value is `BRY-NFET-SX-VAULT-V2`. |
| `version` | QEV implementation version that produced the vault. |
| `created_at` | ISO timestamp produced when the vault was created. |
| `mode` | Workflow mode. Current common value: `self`. |
| `kdf` | Argon2id parameters and salt used to derive the wrapping key. |
| `wrap` | Encrypted random content key. |
| `content` | Encrypted payload. |

## Binary encoding

Binary values are encoded as base64url without padding.

## Key structure

QEV uses two encryption layers:

1. The passphrase is processed with Argon2id to derive a wrapping key.
2. The wrapping key encrypts a random 32-byte content key.
3. The content key encrypts the plaintext.

The passphrase is not used directly as the content encryption key.

## Authenticated data

Vault metadata is bound into encryption as deterministic associated data. QEV derives this associated data by canonical-JSON serializing a fixed subset of vault metadata with recursively sorted object keys and no whitespace.

Tampering with bound metadata should break authentication.

## Strength presets

| Preset | Argon2id opslimit | Argon2id memlimit | Intended use |
|---|---:|---:|---|
| `quick` | 1 | 32 MiB | testing and quick checks |
| `strong` | 4 | 96 MiB | default local use |
| `vault` | 6 | 128 MiB | slower, higher-cost vault creation |

## Compatibility

Vault files are intended to be portable across QEV CLI, desktop, and web surfaces when they implement the same schema.
