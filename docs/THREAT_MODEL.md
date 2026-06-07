# QEV Threat Model

QEV is a local-first encrypted envelope workflow. This document states what QEV is designed to protect and what it does not protect.

## Security goal

QEV is designed to let a user turn plaintext into a portable vault artifact that can later be decrypted with the correct phrase, while detecting tampering with bound vault metadata and ciphertext.

The practical workflow is:

```text
plaintext + phrase -> QEV vault file -> later verification/decryption with phrase
```

## In scope

QEV aims to protect:

- confidentiality of vault content against someone who has the vault file but not the phrase
- integrity of ciphertext and bound metadata through authenticated encryption
- portability across CLI, browser, and desktop implementations
- local/offline creation and opening of vaults
- accidental passphrase leakage through command-line arguments
- silent tampering with schema, version, mode, KDF parameters, nonces, wrapped key, and ciphertext

## Out of scope

QEV does not protect against:

- weak, guessed, reused, disclosed, or phished passphrases
- forgotten passphrases
- malware or a compromised device
- browser extension compromise
- malicious package registry or dependency compromise
- compromised Node/npm installation
- clipboard, terminal, screen, or keyboard capture
- traffic or social metadata from the channel used to transmit the vault
- a recipient who decrypts and then discloses the plaintext
- legal compulsion or operational security failures outside QEV

## Adversary model

QEV assumes an attacker may obtain the vault file and attempt offline cracking or tampering.

QEV assumes the user device is trusted at the time the vault is created or opened. If the endpoint is compromised, QEV cannot protect plaintext or passphrases.

## Cryptographic model

QEV uses established primitives rather than custom cryptography:

- AEAD: XChaCha20-Poly1305
- KDF: Argon2id
- runtime crypto: libsodium through libsodium-wrappers-sumo
- vault schema: BRY-NFET-SX-VAULT-V2

The passphrase is stretched into a wrapping key. A random content key encrypts the plaintext. The wrapped content key and content ciphertext are authenticated with deterministic associated data derived from canonical vault metadata.

## Phrase handling

The CLI rejects passphrases supplied as command-line arguments because that leaks through shell history and process listings. Phrases are typed interactively without echo.

## Tampering behavior

A vault should fail cleanly if bound metadata, wrapped key, nonces, KDF block, content ciphertext, schema, mode, version, or creation timestamp are altered.

## Disclosure expectations

Please report security-sensitive issues privately first. See ../SECURITY.md.
