# NFET Integration Decision

**Date:** 2026-04-15
**Scope:** Should BRY-NFET-AEAD-512 be integrated into the
BRY-NFET-SX product as a replacement for or supplement to
ChaCha20-Poly1305?

**Decision:** **NO.** Not yet. Not until at least one credentialed
cryptographer has independently reviewed the spec and confirmed the
self-attack findings.

## Background

The candidate primitive `NFET-SC-512` and the AEAD composition
`BRY-NFET-AEAD-512` have been implemented, self-tested, and analyzed
under four evaluation suites. Results are in `docs/NFET_SELF_ATTACK.md`.
The formal spec is in `docs/NFET_SPEC.md`. The reference implementation
lives in `spec/nfet_ref/` and does not touch any product code.

Summary of the first-pass evaluation:

- 81 self-tests pass (Bry round-trip, AEAD round-trip, Poly1305 RFC
  vector, 18 pinned test vectors)
- 8 structural tests pass (avalanche, key/nonce sensitivity, diffusion,
  counter collisions, equivalent-key collisions, chi-square, bit
  independence)
- 7 reduced-round statistical distinguishers pass at R=2 through R=16;
  R=1 fails as expected for any ARX primitive
- 32 sampled 1-bit differential probes show no detectable bias at
  R=2 through R=16 with 500 trials each (16,384 measurements per round)

## Why the decision is still NO

### Reason 1 — Passing self-tests is not a security proof

Every broken cipher passes some subset of statistical tests. ROT13
passes a distinct-byte test on non-alphabet input. The NSA's broken
random number generator Dual_EC_DRBG passed NIST's randomness tests.
The Bletchley-Park-era Lorenz SZ40 passed χ² tests for a long time
against unskilled cryptanalysts. The presence of "clean" results on
this project's self-attack tests is consistent with several
possibilities:

1. The primitive is sound and the tests correctly detect no weakness.
2. The primitive has real weaknesses that our tests are too weak to see.
3. The primitive has real weaknesses that our tests would see with
   more samples, better statistical power, or different test types
   (differential trail search with SAT, linear cryptanalysis, etc.).

**The self-attack report cannot distinguish between these three.**
Only external review by someone with independent cryptanalytic skill
and independent tooling can.

### Reason 2 — The 8× statistical safety margin is a red flag

NFETBlock becomes statistically indistinguishable from a random oracle
at **R=2**. We ship R=16. This is 8× overhead and looks like a
generous safety margin.

It is also very fast compared to ChaCha20 (indistinguishable around
R=10 with 20 rounds shipped, or ~2× margin). Fast statistical mixing
can mean:

- (a) the round function is genuinely more powerful per round, or
- (b) there is a structural symmetry that makes the state LOOK uniform
  faster than it actually mixes against an adaptive adversary.

Option (b) would not be caught by the tests run in this report. The
`ν` nonlinear response is a self-multiplying transform with known
differential-propagation subtleties. Without SAT-assisted trail search,
we cannot confirm option (a) vs option (b).

Until someone independent runs a proper differential trail search, we
do not know which of (a) or (b) is the explanation. Shipping without
knowing is not acceptable.

### Reason 3 — The existing product already has ChaCha20-Poly1305

The BRY-NFET-SX product currently uses ChaCha20-Poly1305 for all
cryptographic operations. ChaCha20-Poly1305 is Daniel J. Bernstein's
cipher, audited, widely deployed (Signal, WireGuard, TLS 1.3), and
not a source of uncertainty. The product ships real security today
based on that primitive.

Replacing ChaCha20-Poly1305 with an unreviewed candidate would be a
strict downgrade in real security, regardless of how well the candidate
performed in self-tests. The asymmetry is sharp:

- If NFET-SC-512 is sound: no user-visible benefit to replacing
  ChaCha20-Poly1305, which is also sound.
- If NFET-SC-512 has any flaw: every user of the product is exposed.

**Expected value of the swap is negative until NFET-SC-512 has been
independently validated.**

### Reason 4 — This is what every amateur cipher program gets wrong

The most common failure mode for a new cipher proposal is:

1. Build it
2. Run self-tests
3. Tests pass
4. Ship it
5. Get broken in 30 days by someone with a SAT solver
6. Reputational damage to the entire project

This report is being written specifically to not walk that path. The
self-attack is published **because** it is insufficient, not despite it.
The point is to make clear that the tests are a starting point, not a
finish line.

## What would change the decision

Integration becomes defensible when **all** of the following are true:

1. **External cryptographer review.** At least one credentialed
   cryptographer has read `docs/NFET_SPEC.md`, run their own attacks,
   and published an evaluation. "Credentialed" means published work in
   symmetric cryptanalysis, not just general security reputation.

2. **SAT-based differential trail search.** An automated trail search
   tool (Cryptominisat, Z3, Kissat, or equivalent) has been run against
   the reduced-round NFETBlock model and either:
   - reported a best-trail probability bound consistent with security
     at R=16, or
   - reported a break (in which case the decision is: discard, redesign,
     or withdraw the candidate entirely).

3. **Linear cryptanalysis.** Same as (2) for linear characteristics
   (best bit-linear correlation at R=16).

4. **Related-key and weak-key analysis** of the key schedule.
   `expand_key_schedule` has not been probed for related-key
   collisions or structural weaknesses.

5. **Independent reference implementation in a non-Python language**
   that bit-exactly agrees with the pinned test vectors. Endianness
   and rotation details can drift between implementations if the spec
   is ambiguous. A second implementation, written from the spec alone,
   is the best test of spec unambiguity.

6. **Side-channel review.** The Python reference is not constant-time.
   Any production implementation needs to be.

Until at least points (1), (2), and (3) are complete, the answer is no.

## What happens in the meantime

Until then:

- **BRY-NFET-SX product continues to use ChaCha20-Poly1305 exclusively.**
  No product code under `src/bry_nfet_sx/` is modified. The challenge,
  the chat feature, the dashboard, and every bundle generated by the
  product continue to use ChaCha20-Poly1305.
- **The NFET reference implementation stays isolated** in
  `spec/nfet_ref/`. It is research material, not product code. It can
  be read, run, and attacked by anyone. It produces test vectors
  anyone can reproduce.
- **The spec and self-attack report** are published in `docs/` and
  can be shared with reviewers. If feedback comes back, the design
  can be iterated, the spec updated, and the cycle repeated.
- **No public claim of security** is made about NFET-SC-512. Any
  public description of the work must carry a "candidate, unreviewed"
  label.

## If review returns broken

If a reviewer finds a real flaw:

1. Acknowledge it publicly and in this document.
2. Document the flaw honestly — what attack, what round count, what
   probability, what recovered state.
3. Decide: discard, redesign, or withdraw.
4. Do not retroactively claim the flaw was "expected" or "minor."
5. Thank the reviewer publicly with attribution they approve.

This is how serious cryptographic research works. Broken candidates
are the norm, not the exception. The goal is to find out before
anyone relies on the result.

## If review returns clean

If a credentialed reviewer, or preferably two, return a clean
evaluation with the SAT-based trail search showing no meaningful
differential characteristic at full rounds:

1. Update this document to reflect the review.
2. Consider a controlled rollout: keep ChaCha20-Poly1305 as the
   default, offer NFET as an alternative behind an explicit flag,
   with both disabled by default in production.
3. Run additional independent reviews (one review is not two).
4. Build the C/Rust reference and verify byte-exact agreement.
5. Only then consider equal-status deployment.

Even a clean review does **not** mean "replace ChaCha20-Poly1305."
It means "eligible for production evaluation alongside ChaCha20-Poly1305."

## Signed

This decision is the author's own, written before any external feedback
has been received. It will be revisited the moment that feedback
arrives, in whichever direction.
