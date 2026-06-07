# QEV threat model

QEV is a local encrypted vault workflow. It is designed to protect small text or
file-like artifacts after they have been exported into a vault file.

QEV is not a new encryption algorithm. It is a vault format and toolchain built
on established primitives.

## Assets protected

QEV is designed to protect:

- plaintext message content
- small private notes
- AI output receipts
- research notes
- operational logs
- portable sensitive records

## Primary security goals

### Confidentiality

A vault should not reveal plaintext content to someone who only has the vault
file and does not know the passphrase.

### Integrity

A vault should fail to open if protected fields are changed after creation.
This includes ciphertext, nonces, KDF parameters, algorithm identifiers, schema,
version, mode, and creation metadata bound into associated data.

### Portability

A vault created by the CLI should be readable by compatible QEV implementations
using the same passphrase and schema version.

### Local-first operation

The CLI works without a network connection. It does not require an account or a
hosted service.

## Out of scope

QEV does not attempt to provide:

- identity verification
- forward secrecy
- group messaging
- password-manager autofill
- cloud file synchronization
- legal notarization
- recovery if the passphrase is lost
- protection from a compromised device

## Assumptions

QEV assumes:

- the user chooses a passphrase with enough strength for their risk level
- the device used to create/open the vault is trusted at that moment
- the installed package has not been altered by the local environment
- the user stores or shares the passphrase separately from the vault file

## Known limitations

### Weak passphrases

Argon2id makes guessing more expensive, but it cannot make a weak phrase strong.
A short or predictable phrase can still be guessed.

### Compromised devices

If the device is compromised while the user creates or opens a vault, plaintext
and passphrases may be exposed. QEV is not a replacement for endpoint security.

### Forgotten phrases

There is no recovery service, reset link, or backdoor. If the passphrase is
lost, the vault should be treated as unrecoverable.

### Metadata outside the vault

The transfer channel may still reveal who sent a vault, when it was sent, and to
whom. QEV protects the vault content, not surrounding communication metadata.

### Supply chain

The CLI depends on `libsodium-wrappers-sumo`. Users with strict requirements
should pin versions, audit dependencies, and install from a trusted environment.

## Safe operating guidance

- Use a long passphrase.
- Do not send the passphrase in the same message as the vault.
- Run `qev self-test` after install or upgrade.
- Keep vaults and receipts separate when using receipts for evidence tracking.
- Treat any device compromise as compromise of recently opened vault content.
