# BRY-NFET-SX Security Readiness Checklist

## Positioning
- [x] product one-liner finalized
- [x] “not a new crypto primitive” language enforced
- [x] target buyer profile defined

## Threat model
- [x] trust boundary documented
- [x] attacker classes documented
- [x] out-of-scope claims documented
- [x] misuse risks documented

## Key management
- [x] key provider abstraction designed
- [x] local mode documented
- [x] managed mode documented
- [x] KMS mode documented
- [x] key versioning plan documented
- [ ] rotation plan documented
- [ ] revocation plan documented

## Artifacts
- [x] packet exports defined
- [x] envelope exports defined
- [x] comparison exports defined
- [x] signed-manifest roadmap documented

## Product workflow
- [x] buyer demo script documented
- [x] local demo path repeatable
- [x] artifact comparison workflow repeatable
- [x] envelope policy workflow repeatable

## Credibility
- [x] security caveats documented honestly
- [x] no oversold crypto claims in docs/UI
- [ ] external review roadmap defined

## Hardening (from adversarial audits 1-3)
- [x] key provider path/env restrictions (Phase 35A)
- [x] nonce registry atomic file locking (Phase 35B)
- [x] persistence integrity binding (content hashes) (Phase 35D)
- [x] unsigned bundle trust-level distinction (Phase 35C)
- [x] key_version binding to key material via key fingerprint (Phase 35E)
- [x] bundle_dir path restriction (Phase 35A)
- [x] UI trust display honesty (Phase 35F)
- [x] downgrade resistance: signed records require fingerprint (Phase 38A)
- [x] index row HMAC with auto-generated server-side secret (Phase 38B / audit-3)
- [x] index write concurrency safety via file locking (audit-3)
- [x] stale signature cleanup on bundle re-export (audit-3)
- [x] artifact_id input validation (Phase 38C)
- [x] unsafe temp-dir root rejection (Phase 38D)
- [x] provenance separation: encryption vs signer (Phase 38E)
- [x] NullSigner removed (Phase 38E)
- [x] envelope message count limit (audit-3)

## Remaining hardening
- [ ] managed KMS/HSM signer path
- [ ] key rotation plan
- [ ] key revocation plan
- [ ] deployment trust-boundary guidance
