# Proof Lock Labs / QEV

**Lock proof into a file. Verify it later.**

Proof Lock Labs is a Qira LLC public utility surface for **QEV — Qira Encryption Vault**, a local-first vault workflow for encrypted, tamper-evident message envelopes.

QEV is not a new encryption algorithm. It is a practical vault format and tool chain built on established cryptographic primitives: XChaCha20-Poly1305, Argon2id, deterministic associated-data binding, and a small offline CLI.

```sh
npm install -g @bryan237l/qev-cli
qev self-test

echo "important proof" | qev lock --out proof.vault
qev unlock proof.vault
```

## Why this exists

Normal text files, screenshots, logs, AI outputs, and research notes are easy to edit silently. QEV gives users a simple local workflow:

```text
your data -> passphrase -> encrypted vault -> later verification/decryption
```

Use it for:

- private notes
- AI output receipts
- research artifacts
- operational logs
- sensitive records that need a portable offline envelope

## Public tools

| Surface | Purpose |
|---|---|
| [Web app](https://theartofsound.github.io/qev-desktop/#/tool) | full vault workflow in the browser — lock text or files, unlock, inspect, tamper-check, record templates, guide pages |
| [`qev-cli`](./qev-cli) | npm CLI for lock/unlock/rewrap/self-test |
| [Desktop & Android](https://secure.imagineqira.com/downloads) | QEV apps for Mac, Windows, and Android (QR pairing + Noise XK P2P chat) |
| [BRY-NFET-SX platform](https://secure.imagineqira.com) | Qira LLC's policy-aware encrypted envelope platform |
| [`docs/`](./docs) | threat model, vault format, rewrap and failure-UX notes |
| `BRY-NFET-SX-VAULT-V2` | current vault schema used by QEV |

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

## What QEV protects

QEV protects the confidentiality and integrity of a vault artifact when the passphrase remains secret and the device used to create/open the vault is trusted.

It does not protect against a weak passphrase, a forgotten phrase, or a compromised device. Read the threat model before relying on it for anything sensitive.

## What QEV is not

- It is not a password manager.
- It is not a messenger.
- It is not a cloud storage encryption service.
- It is not a new encryption algorithm.
- It is not a replacement for a professional security audit.

## Technical model

- AEAD: XChaCha20-Poly1305
- KDF: Argon2id
- Runtime crypto: libsodium via `libsodium-wrappers-sumo`
- Vault schema: `BRY-NFET-SX-VAULT-V2`
- Password handling: no `--phrase` CLI argument; phrases are typed at prompt
- Network model: local/offline by design

## Documentation

- [Threat model](./docs/THREAT_MODEL.md)
- [Vault format](./docs/VAULT_FORMAT.md)
- [Security policy](./SECURITY.md)
- [Security disclaimer](./DISCLAIMER.md)
- [QEV CLI README](./qev-cli/README.md)

## GitHub Pages site

This repo includes a static site in `docs/`. Enable GitHub Pages from the `docs/` folder on the `main` branch to publish it.

Expected URL after enabling Pages:

```text
https://theartofsound.github.io/qev-desktop/
```

## License

MIT © Bryan Leonard / Qira LLC. Libsodium is distributed under the ISC License.
