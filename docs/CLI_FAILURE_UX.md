# QEV failure-mode UX

Security tools should not fail mysteriously. QEV should make failure states explicit without making claims the cryptography cannot support.

## Core rule

QEV uses authenticated encryption. When an authentication check fails, the implementation must not pretend it can always distinguish a wrong phrase from a tampered or damaged vault.

Wrong phrase, edited metadata, damaged wrapped key, and tampered ciphertext can collapse into the same safe failure: authentication failed.

## CLI categories

`qev unlock` reports failures using these categories:

| Category | Meaning | Typical causes |
|---|---|---|
| `malformed vault file` | File is not parseable JSON | partial copy, wrong file, truncated download |
| `unsupported vault format` | JSON is valid but not a supported QEV V2 vault | old/new schema, incompatible tool |
| `malformed or damaged vault` | Required field is missing, invalid, unsafe, or corrupted | manual edit, damaged file, invalid base64url, bad KDF limits |
| `authentication check failed` | AEAD tag rejected | wrong phrase, edited metadata, damaged wrapped key, tampered ciphertext |
| `decoded plaintext is not valid UTF-8` | Crypto passed but CLI cannot print decoded text | binary payload on text-only path |
| `unknown unlock error` | Anything uncategorized | implementation bug or edge case |

## Desired authentication failure copy

```text
qev: unlock failed: proof.vault
category: authentication check failed
  - Most likely causes: wrong phrase, edited vault metadata, damaged wrapped key, or tampered ciphertext.
  - For safety, QEV cannot always distinguish wrong phrase from tampering because authenticated encryption rejects both the same way.
  - Try the phrase again; if it still fails, treat the vault as damaged or modified.
technical detail: Could not decrypt: wrong phrase or tampered vault
```

## Self-test output

`qev self-test` should show separate checks instead of one vague `ok` line:

```text
qev self-test
  ✓ library round-trip, wrong-phrase, and tamper checks passed
  ✓ created BRY-NFET-SX-VAULT-V2 vault with quick preset
  ✓ decrypted with the correct phrase
  ✓ rejected wrong phrase / authentication failure
  ✓ rejected damaged/tampered ciphertext
  ✓ rejected unsupported schema
result: ok
```

## UX constraints

- Never print phrase, plaintext, derived key, or raw decrypted bytes on error.
- Never print stack traces for normal user errors.
- Do not add `--phrase`, `--password`, or other command-line secret flags.
- Explain limitations plainly: QEV can say authentication failed; it cannot always say why with certainty.
