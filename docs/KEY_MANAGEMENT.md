# BRY-NFET-SX Key Management Architecture

## Goal

Define a credible path from local-lab secret handling to product-grade key management.

## Current state

Current system assumptions are local and operator-driven:

- operator supplies a master key directly
- application derives needed encryption behavior from that key
- key handling is suitable for lab and controlled local workflows
- key lifecycle is not yet product-grade

This is acceptable for a research/prototyping environment, but not enough for a serious security product.

## Required product modes

The product should eventually support three modes.

### 1. Local mode
Purpose:

- developer workflow
- testing
- offline research
- deterministic evaluation

Characteristics:

- key provided locally
- no remote key custody
- strongest for reproducibility, weakest for enterprise operational controls

### 2. Managed application mode
Purpose:

- hosted product
- internal team tooling
- controlled SaaS deployment

Characteristics:

- application does not store raw customer master keys in plain form
- wrapped or delegated key material
- access mediated through secure service controls

### 3. Enterprise KMS mode
Purpose:

- security-sensitive customers
- enterprise procurement
- regulated/internal governance environments

Characteristics:

- integrate with customer-managed KMS/HSM
- envelope encryption architecture
- audit trail for key usage
- rotation and revocation hooks

## Recommended architecture

### Root concept

Use envelope encryption in the key-management sense:

- customer/master secret is not used directly everywhere
- derive or unwrap short-lived data-encryption keys
- packet/envelope payload encryption uses scoped data keys
- policy/comparison metadata remains structurally inspectable as designed

### Logical key hierarchy

1. root key
2. context/session scoped key material
3. packet/envelope data-encryption keys

Possible example hierarchy:

- Root Key
  - Context Key
    - Session Key
      - Packet/Envelope Encryption Key

## Minimum requirements for a sellable version

### Key generation
Need:

- clear guidance on entropy source
- strong default generation path
- documented minimum key policy

### Key storage
Need:

- no plaintext hardcoded secrets
- no accidental logging
- local secure file or OS keychain mode for desktop/local
- secret manager / KMS mode for hosted deployment

### Key rotation
Need:

- explicit versioning
- artifact metadata indicating key version where appropriate
- rotation without breaking old artifact readability where policy allows

### Key revocation
Need:

- ability to disable use of a compromised or retired key
- clear rules for what happens to historical artifacts

### Access control
Need:

- scoped permissions around who can build/open envelopes
- separation between artifact access and key access
- service/operator role definitions

## Suggested first implementation path

### Step 1
Define key version metadata model.

### Step 2
Add local secure secret-loading abstraction instead of raw inline key passing everywhere.

### Step 3
Add pluggable key provider interface.

Example provider classes:

- LocalKeyProvider
- EnvVarKeyProvider
- FileKeyProvider
- KMSKeyProvider

### Step 4
Add key version and provider provenance to artifact/report outputs where appropriate.

### Step 5
Add KMS-backed prototype path.

## Product messaging guidance

Do not say:

- military grade
- impossible to break
- zero risk
- fully secure by default in every environment

Do say:

- supports authenticated encrypted envelope workflows
- designed for controlled key handling evolution
- product roadmap includes pluggable key providers and enterprise key custody integration

## Near-term repo tasks

1. ~~define key provider interface~~ -- done (keys.py: LocalKeyProvider, EnvVarKeyProvider, FileKeyProvider)
2. ~~add key version field where appropriate~~ -- done (key_version propagated through provenance)
3. ~~add local secure loading path~~ -- done (file and env providers)
4. ~~document separation of lab mode vs managed mode vs KMS mode~~ -- done (this document)
5. harden file/env provider resolution (restrict paths and env var names -- from adversarial audit)
6. add KMS-backed key provider prototype
