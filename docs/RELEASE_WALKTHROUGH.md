# BRY-NFET-SX Release Preview Walkthrough

A step-by-step walkthrough of the strongest end-to-end workflow in the product.

## Prerequisites

```bash
uv sync
./scripts/dev_up.sh
```

Open the dashboard at **http://localhost:8506**.

## Step 1: Build a multi-message envelope

Go to the **Envelopes** tab.

Enter these plaintexts (one per line):
```
MY NAME IS BRYAN.
WHAT'S UP?
```

Leave defaults: master key `bry-secret-dev-key`, context `local-dev`, mode `audit`, family routing `manual`, family `ring_shift_v1`.

Click **Build envelope**.

**What to observe:**
- Envelope ID generated (64-char hex)
- Session header with version, context, and timestamp
- Per-message packet IDs, nonces, and transform family IDs
- Provenance metadata including mode and family routing

## Step 2: Compare routing policies

Go to the **Envelope Policy** tab.

Enter these plaintexts:
```
MY NAME IS BRYAN.
MY NAME IS MY NAME.
MY NAME. YOUR NAME. MY NAME.
```

Click **Compare envelope policies**.

**What to observe:**
- Four policies compared: manual ring_shift, manual ridge_mix, default, auto
- Divergence rows showing which messages trigger different routing
- Auto policy may differ from default on structured/repetitive messages
- Recommended policy with explanation

## Step 3: Browse saved artifacts

Go to the **Saved Runs** tab.

Select category **Envelopes**.

**What to observe:**
- Previously built envelopes appear in the listing
- Each row shows artifact ID, category, integrity binding status, and summary
- Selecting an artifact shows full header, messages, and raw JSON
- Use "Load selected envelope into Envelopes tab" to replay

## Step 4: Export a signed bundle

Still in the **Saved Runs** tab, scroll to **Bundle Export & Verify**.

Set signer mode to **local**, enter a signer secret (e.g. `signer-secret-123`), and set key version to `sig-v1`.

Click **Export Signed Bundle**.

**What to observe:**
- Bundle directory created under `data/bundles/`
- Bundle contains: artifact.json, metadata.json, manifest.json, signature.json
- Signature uses HMAC-SHA256 over the manifest
- Key fingerprint recorded in signature record

## Step 5: Verify the signed bundle

The bundle directory auto-fills in the verification field.

With the same signer credentials, click **Verify Bundle**.

**What to observe:**
- Trust verdict banner: "Bundle is trusted: integrity verified, signature valid, metadata consistent."
- Structured trust summary:
  - `overall_trusted: true`
  - `integrity_ok: true`
  - `signature_verified: true`
  - `metadata_consistent: true`
  - `key_fingerprint_consistent: true`
  - `key_version_consistent: true`

## Step 6: Understand trust states

Try these variations to see the trust model in action:

### Verify without signer credentials
Set signer mode to **none** and click **Verify Bundle**.

**Result:** "Signature present but not checked (no signer key supplied). Not trusted."
- `overall_trusted: false`
- `signature_checked: false`

### Verify with wrong secret
Set signer mode to **local**, enter a wrong secret, click **Verify Bundle**.

**Result:** "Signature check failed: digest mismatch. Bundle is not trusted."
- `overall_trusted: false`
- `signature_verified: false`
- `key_fingerprint_consistent: false`

### Export and verify unsigned
Click **Export Unsigned Bundle**, then verify it.

**Result:** "Integrity verified (manifest hashes match) but bundle is unsigned. Not trusted."
- `integrity_ok: true`
- `overall_trusted: false`

## What this walkthrough proves

1. Structured messages are packaged into authenticated encrypted session envelopes
2. Policy differences are explainable and inspectable per-message
3. Artifacts persist and can be browsed across sessions
4. Bundles can be exported with or without signatures
5. Verification distinguishes integrity-only from fully trusted
6. Metadata consistency (key fingerprint) is checked independently of the HMAC digest
7. The UI surfaces trust verdicts explicitly, never implying trust where none exists

## Product framing

BRY-NFET-SX is a **policy-aware encrypted envelope workflow platform** built on standard authenticated encryption (ChaCha20-Poly1305).

It is not a new cipher or a replacement for standard cryptographic primitives. The value is in the workflow: structured packaging, policy comparison, persisted artifacts, signed bundles, and honest verification.
