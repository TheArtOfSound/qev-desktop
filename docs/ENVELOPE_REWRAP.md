# QEV envelope rewrap

QEV V2 now supports the claim that its envelope format can rotate a phrase without re-encrypting the content payload.

## What changed

The vault format already separated:

- `wrap.wrapped_key` — the random content key encrypted by a phrase-derived wrap key
- `content.ciphertext` — the payload encrypted by the random content key

The new `rewrapVaultV2()` helper and `qev rewrap` CLI command use that separation directly.

## What `qev rewrap` does

`qev rewrap VAULT_FILE --out NEW_FILE`:

1. Opens the vault metadata.
2. Prompts for the old phrase.
3. Derives the old wrap key.
4. Decrypts only `wrap.wrapped_key` to recover the random content key.
5. Prompts for a new phrase.
6. Derives a new wrap key.
7. Re-encrypts the same content key into a new `wrap.wrapped_key`.
8. Writes a new vault JSON file.

The payload in `content.ciphertext` is not decrypted and is not re-encrypted.

## Why this matters

This makes the envelope-encryption claim concrete instead of merely architectural. QEV can now rotate the phrase protecting a vault without touching the content ciphertext.

This is useful when:

- a phrase was shared with the wrong person
- a phrase is too weak and needs to be upgraded
- a vault needs to stay byte-stable except for its wrapped key
- future multi-recipient unlock paths are added

## Limitation

QEV V2 binds metadata into AEAD additional authenticated data. To preserve compatibility, rewrap keeps the existing KDF salt, KDF limits, wrap nonce, content nonce, schema, version, created timestamp, mode, and algorithms. Changing those fields would change the AAD and make the existing `content.ciphertext` fail authentication.

So V2 rewrap rotates the phrase while preserving the existing envelope metadata. Future vault versions may support richer multiple-recipient or multi-wrap structures.

## CLI example

```sh
qev rewrap proof.vault --out proof-rotated.vault
# Old phrase: ********
# New phrase: ********
# New phrase (confirm): ********
# rewrapped phrase; wrote proof-rotated.vault
```

After rewrap:

```sh
qev unlock proof-rotated.vault
# Old phrase fails.
# New phrase unlocks.
```

## Test invariant

The test suite asserts:

- the old phrase stops working
- the new phrase works
- `content.ciphertext` does not change
- `wrap.wrapped_key` changes

That is the exact property QEV’s envelope design is meant to provide.
