# BRY-NFET-SX Review Commands

Copy-paste commands for evaluating the system. All commands assume you are in the repo root.

## Prerequisites

```bash
cd ~/dev/bry_nfet_sx
uv sync
```

## Run the test suite

```bash
uv run pytest
```

Expected: 189 passed.

## Start services

```bash
# Both at once:
./scripts/dev_up.sh

# Or individually:
uv run fastapi dev src/bry_nfet_sx/api/app.py --port 8001
uv run streamlit run dashboard/streamlit_app.py --server.port 8506
```

- Dashboard: http://localhost:8506
- API: http://localhost:8001/docs

## Generate review artifacts

```bash
uv run python scripts/prepare_review_artifacts.py
```

This generates a saved envelope, a signed bundle, and a verification summary fresh from the current code. Artifacts land under `data/review/`, `data/runs/`, and `data/bundles/`. They are not pre-committed — the script produces them on demand using non-sensitive demo secrets.

## Build an envelope via API

```bash
curl -s -X POST http://localhost:8001/envelope/build \
  -H 'Content-Type: application/json' \
  -d '{
    "plaintexts": ["MY NAME IS BRYAN.", "WHAT'\''S UP?"],
    "master_key": "review-demo-key",
    "context": "review-demo",
    "mode": "audit",
    "family_mode": "manual",
    "family_id": "ring_shift_v1"
  }' | python3 -m json.tool | head -20
```

## List saved envelopes

```bash
curl -s http://localhost:8001/storage/envelopes | python3 -m json.tool
```

## Export a signed bundle

Replace `ENVELOPE_ID` with an actual ID from the listing above:

```bash
curl -s -X POST http://localhost:8001/bundles/export/envelopes/ENVELOPE_ID \
  -H 'Content-Type: application/json' \
  -d '{
    "signer_provider_mode": "local",
    "signer_secret": "review-signer-secret",
    "signer_key_version": "review-v1"
  }' | python3 -m json.tool
```

## Verify a signed bundle (correct key)

Replace `BUNDLE_DIR` with the bundle_dir from the export response:

```bash
curl -s -X POST http://localhost:8001/bundles/verify \
  -H 'Content-Type: application/json' \
  -d '{
    "bundle_dir": "BUNDLE_DIR",
    "signer_provider_mode": "local",
    "signer_secret": "review-signer-secret",
    "signer_key_version": "review-v1"
  }' | python3 -c "
import sys, json
d = json.load(sys.stdin)
print('overall_trusted:', d['overall_trusted'])
print('integrity_ok:', d['integrity_ok'])
print('signature_verified:', d['signature_verified'])
print('metadata_consistent:', d['metadata_consistent'])
print('key_fingerprint_consistent:', d['key_fingerprint_consistent'])
"
```

Expected: `overall_trusted: True`

## Verify with wrong secret (trust failure)

```bash
curl -s -X POST http://localhost:8001/bundles/verify \
  -H 'Content-Type: application/json' \
  -d '{
    "bundle_dir": "BUNDLE_DIR",
    "signer_provider_mode": "local",
    "signer_secret": "wrong-secret",
    "signer_key_version": "review-v1"
  }' | python3 -c "
import sys, json
d = json.load(sys.stdin)
print('overall_trusted:', d['overall_trusted'])
print('signature_verified:', d['signature_verified'])
print('key_fingerprint_consistent:', d['key_fingerprint_consistent'])
"
```

Expected: `overall_trusted: False`, `signature_verified: False`, `key_fingerprint_consistent: False`

## Verify without signer credentials (unchecked)

```bash
curl -s -X POST http://localhost:8001/bundles/verify \
  -H 'Content-Type: application/json' \
  -d '{
    "bundle_dir": "BUNDLE_DIR"
  }' | python3 -c "
import sys, json
d = json.load(sys.stdin)
print('overall_trusted:', d['overall_trusted'])
print('signature_present:', d['signature_present'])
print('signature_checked:', d['signature_checked'])
"
```

Expected: `overall_trusted: False`, `signature_present: True`, `signature_checked: False`

## Verify a restricted key provider (lockdown check)

```bash
# This should be rejected (arbitrary file read blocked):
curl -s -X POST http://localhost:8001/keys/resolve \
  -H 'Content-Type: application/json' \
  -d '{"provider_mode": "file", "file_path": "/etc/hosts"}'

# This should be rejected (arbitrary env var blocked):
curl -s -X POST http://localhost:8001/keys/resolve \
  -H 'Content-Type: application/json' \
  -d '{"provider_mode": "env", "env_var_name": "HOME"}'
```

Expected: both return 400 with clear error messages about restrictions.
