# Resolving the public decryption challenge

**Status as of 2026-07-30: the reveal is 100 days overdue.**
`published_at` 2026-04-14, `reveal_at` 2026-04-21, `reveal_status` still
`pending`, and no master key has been published at any URL.

The audit already made `/challenge` state this honestly rather than showing
a countdown that read "reveal window open" once the deadline passed. That
stops the page misleading anyone, but it does not resolve the commitment.
**Only you can, and it needs a decision.**

## Why this matters more than it looks

A commit-reveal scheme makes exactly one promise: *we published a hash of
the plaintext in advance, so we cannot swap the plaintext later — and on
date X we will publish the key so you can check.* Its entire value is the
reveal. Until then the commitment proves nothing to anyone.

To a cryptographer, an overdue reveal is not a missed deadline. It is the
scheme's one claim going unmet, on the page specifically aimed at
cryptographers. It is the first thing a technical reviewer will find, and
they will read it less charitably than a missed blog post.

Both resolutions below are respectable. Silence is the only bad option.

---

## Path A — Publish the key (preferred)

Honours the original commitment and converts the challenge from a liability
into the strongest verifiable artifact on the site.

```bash
python3 scripts/challenge_reveal.py \
  --master-key-file /path/to/offline/master.key \
  --bundle landing/challenge/bundle \
  --meta   landing/challenge/challenge-meta.json \
  --out    landing/challenge/reveal
```

The script decrypts locally, extracts the `reveal_token`, and **refuses to
emit anything unless `SHA-256(reveal_token)` equals the published
`reveal_commitment`** —
`270339e348befe4720104c4e032e379d01a322d54f59b25fb6aeeb6c0f5c3663`.

That refusal is the point. If the commitment does not reproduce, publishing
would be worse than staying silent: it would hand a reviewer proof the
scheme was broken. In that case stop and use Path B, saying plainly that the
commitment could not be reproduced.

**This script has never been run against the real key** — the key is offline
and was not available during the audit. It is written to fail closed, but
run it once with `--dry-run` first and read what it reports.

After it succeeds:

1. Set `reveal_status` to `revealed` and add `revealed_at` in
   `challenge-meta.json`.
2. Publish `landing/challenge/reveal/` (key, `reveal_token`, and the
   recomputation steps).
3. Re-sign `site-integrity.json` — the challenge files are inside the signed
   manifest, so their hashes change.
4. Update `/challenge` so the overdue banner becomes a reveal notice. The
   banner is driven by `reveal_status`, so step 1 flips it automatically —
   confirm rather than assume.

**Say why it was late.** One sentence, no excuses. "The reveal was scheduled
for 2026-04-21 and published on <date>; the delay was ours and the
commitment hash is unchanged since publication." A reviewer can verify that
last clause independently, which is what makes the sentence worth writing.

---

## Path B — Retract the challenge

Legitimate if the key is lost, if the commitment does not reproduce, or if
you would simply rather not run a public challenge right now.

Retracting is **not** an admission that the cryptography failed. It is an
admission that a commitment was not met on time, which is already true and
already visible.

1. Replace the `/challenge` hero with a dated retraction. Keep the page and
   the bundle up — deleting them looks worse than the retraction, and the
   manifest digests remain independently checkable.
2. State exactly what is and is not affected. Suggested wording:

   > **This challenge is withdrawn as of \<date\>.** It was published on
   > 2026-04-14 with a key reveal scheduled for 2026-04-21. That reveal did
   > not happen, and we are withdrawing the challenge rather than leaving it
   > open indefinitely. The bundle stays published: its per-file SHA-256
   > digests are still verifiable, and the vault format is unchanged. What
   > was never demonstrated is the commit-reveal property, because that
   > requires the key we did not publish. Nothing here indicates a weakness
   > in ChaCha20-Poly1305, Argon2id or Ed25519, and no reviewer reported
   > one — but neither did the challenge prove anything about our use of
   > them, which was its purpose.

3. Remove the challenge from the homepage's "for crypto reviewers" section,
   or relabel it as withdrawn. Do not leave it advertised as live.
4. Re-sign `site-integrity.json`.

---

## Either way, fix the terminology

Already corrected on `/challenge` by the audit, but it must not regress:
`signature.json` is an **HMAC-SHA256 authentication tag** keyed with the
inline master key. It is not a public-key signature, no third party can
verify it without the secret, and anyone holding the secret can forge it.

The Ed25519 signature at `/verify`, and the Ed25519 `package_signature` on
gateway evidence packages, *are* independently verifiable. Only those two
should ever be described as "signed" without qualification.
