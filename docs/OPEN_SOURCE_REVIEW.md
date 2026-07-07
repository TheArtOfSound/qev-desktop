# Open-source review note

QEV is an MIT-licensed local-first encrypted vault workflow for creating portable, tamper-evident encrypted artifacts.

This document exists so reviewers, contributors, and security-minded users can quickly understand the project's scope, impact claim, and boundaries.

## One-sentence summary

QEV lets a user lock text or small files into an encrypted vault artifact, store or send that artifact anywhere, and later verify/decrypt it locally with the correct phrase.

## Ecosystem gap

Many developers, researchers, AI builders, operators, and small teams need a lightweight way to preserve private proof artifacts without creating a hosted account or trusting a server.

Examples include:

- AI output receipts;
- research notes;
- operational logs;
- one-shot secrets;
- private handoff records;
- small proof bundles that need later verification.

Most alternatives are either too large for this job, tied to a hosted product, focused on password management, or optimized for a different workflow. QEV's niche is the portable local vault artifact: one file, one phrase, no account, no server-held secret.

## What is open here

The public repository includes:

- the CLI workflow for lock/unlock/self-test;
- the shared vault schema;
- browser-facing documentation and public pages;
- threat-model documentation;
- security reporting policy;
- security disclaimer;
- contribution guidance.

The CLI package is published as `@bryan237l/qev-cli` and is intended to be usable independently of any hosted Qira service.

## Security posture

QEV does not claim to invent cryptography.

The current implementation is built around established primitives:

- XChaCha20-Poly1305 for authenticated encryption;
- Argon2id for passphrase-based key derivation;
- libsodium via `libsodium-wrappers-sumo`;
- deterministic associated-data binding for vault metadata.

The project should remain conservative. New vault schema behavior, phrase handling, canonicalization, nonce behavior, KDF parameters, and decrypt/tamper failure paths should be reviewed as security-sensitive changes.

## What QEV does not claim

QEV does not claim to be:

- a password manager;
- a cloud storage encryption service;
- a messenger;
- a blockchain, timestamping authority, or notarization service;
- a new encryption algorithm;
- a replacement for a professional security audit.

QEV also does not protect against weak phrases, compromised endpoints, lost phrases, supply-chain compromise, or adversaries who already know the phrase.

## Current maturity

QEV is early open-source infrastructure. It should not be presented as a high-download package, critical dependency, or foundation-level project.

The accurate claim is narrower:

> QEV is a maintained, MIT-licensed, local-first vault format and toolchain for portable encrypted proof artifacts, with a CLI, browser surface, threat model, and explicit security boundaries.

## Maintenance priorities

Near-term maintenance should focus on:

- compatibility tests between CLI and browser vaults;
- malformed-vault test coverage;
- failure UX around tamper/wrong-phrase cases;
- clearer vault-format documentation;
- release notes and package reproducibility;
- contributor-ready issue templates;
- stronger examples for AI receipts, research notes, and operational logs.
