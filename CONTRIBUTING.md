# Contributing to QEV

QEV is security-sensitive software. Contributions are welcome, but the review standard is stricter than a normal UI or app repo because small mistakes can weaken confidentiality, integrity, or user trust.

## Project stance

QEV is an MIT-licensed local-first vault format and toolchain. The project should stay conservative:

- use established cryptographic primitives;
- avoid inventing new crypto;
- keep the core lock/unlock flow local/offline;
- document security boundaries plainly;
- prefer simple, inspectable code over clever abstractions;
- treat failure UX as part of the security model.

## Good first contribution areas

Useful contributions include:

- documentation improvements;
- test coverage for malformed vaults and failure cases;
- clearer examples for CLI usage;
- compatibility tests between web and CLI vaults;
- threat-model clarifications;
- safer error messages;
- dependency and packaging hygiene;
- reproducible release notes.

## Higher-risk contribution areas

Changes in these areas require extra scrutiny:

- vault serialization/canonicalization;
- associated-data construction;
- passphrase prompt handling;
- Argon2id parameters;
- nonce generation;
- key wrapping/unwrapping;
- error handling around decrypt/tamper failures;
- changes to supported vault schemas.

Do not submit a change that introduces custom cryptography or replaces libsodium primitives unless the proposal includes a clear security rationale and independent review path.

## Local checks

From the CLI package:

```sh
cd qev-cli
npm install
npm test
npm run selftest
```

From the repository root, open the docs site locally on macOS:

```sh
open docs/index.html
```

## Pull request expectations

A useful pull request should explain:

- what changed;
- why it matters;
- what user-visible behavior changed, if any;
- what security-sensitive paths were touched;
- how it was tested.

For security-sensitive changes, include at least one negative test or failure-mode test where practical.

## Security reports

Do not open a public issue for a suspected vulnerability. Use the private reporting path in [`SECURITY.md`](./SECURITY.md).

Do not include real secrets, production vaults, private logs, personal documents, or real passphrases in an issue or pull request.
