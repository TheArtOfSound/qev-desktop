# QEV Security Disclaimer

QEV is security-sensitive software. Treat it as a practical local vault workflow, not a guarantee of safety.

## What QEV is

QEV is an offline encrypted envelope format and toolchain. It uses established primitives through libsodium:

- XChaCha20-Poly1305 for authenticated encryption
- Argon2id for passphrase-based key derivation
- deterministic associated-data binding for vault metadata integrity
- local CLI / browser / desktop workflows

QEV does not introduce a new cryptographic primitive. The project value is the vault format, cross-platform packaging, and offline workflow.

## No warranty

The software is provided as-is under the MIT License. There is no warranty of merchantability, fitness for a particular purpose, non-infringement, data recovery, regulatory compliance, or suitability for high-risk environments.

## Not audited

Unless a future release states otherwise, QEV should be treated as unaudited software. Do not rely on it as the only control for material financial, medical, legal, production, military, critical infrastructure, or life-safety secrets.

## User responsibilities

QEV cannot protect against:

- weak or reused passphrases
- forgotten passphrases
- compromised endpoints
- malware, clipboard theft, keyloggers, or screen capture
- hostile browser extensions
- supply-chain compromise
- social engineering
- metadata exposure through the channel used to send the vault
- disclosure by someone who knows the phrase

Users are responsible for choosing strong passphrases, protecting their device, verifying downloads, and keeping backups of data before encryption.

## No backdoor or recovery

QEV has no account recovery, no reset flow, no escrow, and no backdoor. If the passphrase is lost, QEV cannot recover the plaintext.

## Reporting issues

Security reports should be sent privately first. See SECURITY.md.
