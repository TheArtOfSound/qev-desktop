# QEV — Proof Lock Labs

**MIT local-first encrypted vault envelopes for files, notes, AI receipts, logs, and proof artifacts.**

QEV is a practical vault format and toolchain for creating portable encrypted artifacts that can be verified and decrypted later without a hosted account, proprietary backend, or hidden server state.

- **Live web app:** https://theartofsound.github.io/qev-desktop/#/tool
- **CLI package:** `@bryan237l/qev-cli`
- **License:** MIT
- **Security posture:** established primitives, explicit threat model, no custom cryptography claims

```sh
npm install -g @bryan237l/qev-cli
qev self-test

echo "important proof" | qev lock --out proof.vault
qev unlock proof.vault
```

## Open-source review note

This repository is meant to be useful as public infrastructure, not just as a product landing page.

QEV gives developers, researchers, AI builders, operators, and small teams a simple local workflow:

```text
plaintext or file -> passphrase -> encrypted vault artifact -> later verification/decryption
```

The ecosystem gap it addresses is narrow but real: people often need to preserve private proof artifacts — AI output receipts, research notes, operational logs, one-shot secrets, customer records, or signed-off handoff material — without turning the workflow into a SaaS account or trusting a server to hold the secret.

QEV is intentionally conservative:

- it uses established primitives instead of inventing a new cipher;
- it keeps the core workflow local/offline by design;
- it publishes the vault format and threat model;
- it separates honest security boundaries from marketing claims;
- it provides a browser app and CLI that share the same vault schema.

This is early open-source infrastructure. It should be judged as a maintained local-first vault format/toolchain, not as a claim that the ecosystem already depends on it at package-registry scale.

## Why this exists

Normal text files, screenshots, logs, AI outputs, and research notes are easy to edit silently. QEV gives users a portable encrypted artifact that can be stored or sent through any ordinary channel and later opened only with the correct phrase.

Use it for:

- private notes;
- AI output receipts;
- research artifacts;
- operational logs;
- one-shot secrets;
- sensitive records that need a portable offline envelope.

## Public tools

| Surface | Purpose |
|---|---|
| [Web app](https://theartofsound.github.io/qev-desktop/#/tool) | Full vault workflow in the browser: lock text/files, unlock, inspect, tamper-check, record templates, guide pages. |
| [`qev-cli`](./qev-cli) | npm CLI for lock/unlock/rewrap/self-test. |
| [Desktop & Android](https://secure.imagineqira.com/downloads) | QEV apps for Mac, Windows, and Android. |
| [`docs/`](./docs) | Threat model, vault format, rewrap notes, and failure-UX notes. |
| `BRY-NFET-SX-VAULT-V2` | Current vault schema used by QEV. |

## Install the CLI

```sh
npm install -g @bryan237l/qev-cli
```

Run the built-in proof test:

```sh
qev self-test
```

Expected output:

```text
qev self-test: encrypt → decrypt → tamper → wrong-phrase ... ok
```

Run without installing:

```sh
npx @bryan237l/qev-cli self-test
```

## Basic CLI flow

```sh
# Lock text from stdin into a vault file.
echo "private note" | qev lock --out note.vault

# Unlock later with the same phrase.
qev unlock note.vault

# Inspect version/help.
qev version
qev --help
```

## What QEV protects

QEV protects the confidentiality and integrity of a vault artifact when the passphrase remains secret and the device used to create/open the vault is trusted.

It does not protect against a weak passphrase, forgotten phrase, compromised endpoint, hostile browser environment, malicious npm supply-chain event, or someone who already knows the phrase. Read the threat model before relying on it for sensitive workflows.

## What QEV is not

- It is not a password manager.
- It is not a cloud storage encryption service.
- It is not a messenger.
- It is not a blockchain, timestamping authority, or notarization service.
- It is not a new encryption algorithm.
- It is not a replacement for a professional security audit.

## Technical model

- **AEAD:** XChaCha20-Poly1305
- **KDF:** Argon2id
- **Runtime crypto:** libsodium via `libsodium-wrappers-sumo`
- **Vault schema:** `BRY-NFET-SX-VAULT-V2`
- **AAD binding:** deterministic associated-data binding for vault metadata
- **Password handling:** no `--phrase` CLI argument; phrases are typed at prompt
- **Network model:** local/offline by design
- **License:** MIT; libsodium is distributed under the ISC License

Primitives are not invented here. The value-add is the vault format, packaging, local-first workflow, cross-surface compatibility, and honest security boundary.

## Documentation

- [Open-source review note](./docs/OPEN_SOURCE_REVIEW.md)
- [Threat model](./docs/THREAT_MODEL.md)
- [Vault format](./docs/VAULT_FORMAT.md)
- [Security policy](./SECURITY.md)
- [Security disclaimer](./DISCLAIMER.md)
- [QEV CLI README](./qev-cli/README.md)
- [Contributing guide](./CONTRIBUTING.md)

## Project structure

```text
qev-desktop/
├── qev-cli/                 # npm CLI package: lock/unlock/rewrap/self-test
├── docs/                    # public site + technical docs
├── SECURITY.md              # security reporting policy
├── DISCLAIMER.md            # security disclaimer
├── CONTRIBUTING.md          # contribution and review guidelines
└── README.md
```

## GitHub Pages site

This repo includes a static site in `docs/`.

Expected public URL:

```text
https://theartofsound.github.io/qev-desktop/
```

Open the local docs entry point on macOS:

```sh
open docs/index.html
```

## License

MIT © Bryan Leonard / Qira LLC. Libsodium is distributed under the ISC License.
