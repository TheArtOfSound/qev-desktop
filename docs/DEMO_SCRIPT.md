# BRY-NFET-SX Demo Script

## Goal

Provide a clean, buyer-facing demo narrative that shows real product value.

## Demo thesis

BRY-NFET-SX is not just encrypting messages. It is producing structured encrypted session artifacts with explainable policy routing, reproducible evaluation, and artifact comparison.

## Demo flow

### Part 1 — Baseline secure artifact packaging

Show:

- build a packet
- open the packet
- prove recovered plaintext matches
- show authenticated encrypted structure rather than raw plaintext storage

Message:
“This system packages structured messages into authenticated encrypted artifacts with schema validation and provenance.”

### Part 2 — Multi-message envelope build/open (Envelopes tab)

Show:

- build a two-message or three-message envelope
- inspect envelope header
- inspect embedded packet identities
- open the envelope
- show recovered replay

Message:
“This system handles structured multi-message session packaging, not just isolated ciphertext blobs.”

### Part 3 — Policy comparison (Envelope Policy tab)

Use messages like:

- MY NAME IS BRYAN.
- MY NAME IS MY NAME.
- MY NAME. YOUR NAME. MY NAME.

Show:

- compare manual ring_shift_v1
- compare manual ridge_mix_v1
- compare default
- compare auto

Highlight:

- recommended policy is auto
- auto differs from default
- only structured messages trigger specialist overrides

Message:
“The product does not just encrypt. It reasons about message structure and shows exactly what policy choice changes.”

### Part 4 — Envelope artifact comparison

Show:

- build one envelope under default
- build one envelope under auto
- compare them
- show recovered replay is the same
- show packet/family differences are explicit

Message:
“The product can compare two real secure artifacts and explain how and where policy changed the output.”

### Part 5 — Deterministic evaluation

Show:

- rerun comparison or envelope build in audit mode
- prove stable outcome under the same inputs

Message:
“This matters for testing, review, and controlled evaluation.”

## Buyer-facing summary line

“BRY-NFET-SX is a policy-aware encrypted envelope system that lets teams package structured message sessions securely, compare policy outcomes, and generate reproducible audit-ready artifacts.”

## What not to say in demo

Do not say:

- this replaces standard cryptography
- this is a new superior cipher
- this is impossible to break

## What to emphasize

Emphasize:

- authenticated encrypted artifacts
- explainable policy routing
- session envelopes
- comparison tooling
- reproducibility
- auditability
