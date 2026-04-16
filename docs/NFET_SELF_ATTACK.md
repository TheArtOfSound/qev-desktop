# NFET-SC-512 / BRY-NFET-AEAD-512 — Self-Attack Report

**Date:** 2026-04-15
**Version under evaluation:** candidate v0.0.1
**Reference implementation:** `spec/nfet_ref/` (Python, ~3400 lines including tests)
**Evaluator:** the primitive's author, running the adversarial analysis from
inside the same session. This is a first-pass self-attack, not an external review.

## Purpose of this document

This document is the honest record of what happens when the author of a
candidate cryptographic primitive runs a battery of attacks against it
before anyone else. It covers:

1. What was implemented
2. What attacks were run
3. What the numbers are
4. What the numbers mean and don't mean
5. What hasn't been tested
6. What would kill the primitive and what wouldn't

**This report does not claim the primitive is secure.** It claims a specific
set of tests were run and a specific set of results were observed. The difference
between that and a claim of security is the entire point of this report.

---

## 1. What was implemented

### 1.1 Layer A — Bry v2 public transform

File: `spec/nfet_ref/bry.py`

Deterministic, public, reversible, unkeyed byte-level transform with two
representations:

- **Bry-Core**: binary `(y_i, m_i)` token stream. Each input byte produces one
  token pair via a causal stateful recurrence with two integer state variables
  `q_i ∈ Z_256` and `r_i ∈ Z_256` plus previous-class memory `p_i ∈ {0..5}`.
  The variant nibble `m_i` is a public 4-bit MAC over the class and state,
  stored in a full byte.
- **Bry-Surface**: human-readable token alphabet (`+3` = M, `^+3` = m, `-` =
  space, `#3` = '3', `--p` = '.', `~HH` = raw byte escape). Longest-match
  lexical parsing. Full round-trip for arbitrary UTF-8.

**Bry claims no cryptographic properties.** It is a canonicalization layer.

### 1.2 Layer B — NFET-SC-512 keyed core

Files: `spec/nfet_ref/constants.py`, `spec/nfet_ref/nfet_block.py`

8-lane 64-bit-word state. Each `NFETBlock(K, N, ctr, d)` call produces 64 bytes
of output from:

- 256-bit key `K`
- 128-bit nonce `N`
- 64-bit counter `ctr`
- 64-bit domain separator `d`

Public constants:
- `C_0..C_7` = digits of π (Blowfish's P-array)
- Round constant generator = SplitMix64 seeded with 2^64·(√2−1)
- Key schedule multiplier = 0x9E3779B185EBCA87 (golden ratio prime)
- Round function rotation vectors α, β, ρ, σ and lane permutation π are fixed
- Nonlinear response constant = 0xD1342543DE82EF95
- Rounds = 16 (with reduced-round support for evaluation)

Round function is parallel (all φ_i, then all ν_i, then all z_i, then permute
by π). Key schedule runs one step per round, producing `K^(r) = W^(r+1)`.
Feedforward is additive (`o_i = x_i^(16) ⊞ x_i^(0) mod 2^64`).

### 1.3 Authentication — standalone Poly1305

File: `spec/nfet_ref/poly1305.py`

Textbook RFC 8439 Poly1305. Standard r-clamping. One-time Poly1305 key derived
from `NFETBlock(K, N, 0, d_tag)` with `d_tag` ≠ `d_enc`.

### 1.4 Composition — BRY-NFET-AEAD-512

File: `spec/nfet_ref/aead.py`

Full pipeline:

```
plaintext
  -> UTF-8 bytes
  -> Bry-Core encode (byte -> (y,m) pairs, doubles length)
  -> Bry-Core serialize (2 bytes per token)
  -> 64-byte bucket padding (0x80 marker + zeros)
  -> NFET keystream under d_enc domain
  -> ciphertext
  -> Poly1305 tag over (AD || pad || CT || pad || len64(AD) || len64(CT))
     with one-time key from NFETBlock(K, N, 0, d_tag)
```

### 1.5 Test coverage

- `test_bry.py`: 31 tests (Bry-Core + Bry-Surface round-trip, edge cases, tamper)
- `selftest.py`: 32 tests (constants, key schedule, NFETBlock, Poly1305, AEAD)
- `verify_test_vectors.py`: 18 pinned test vectors (verifies against `test_vectors.json`)

**All 81 self-tests pass.**

Most importantly: **the RFC 8439 Section 2.5.2 Poly1305 known-answer test
passes byte-for-byte.** The author's Poly1305 implementation agrees with the
standard. This rules out an entire class of implementation bugs in the
authentication layer.

---

## 2. Attacks run

Four distinct evaluation suites were run against the reference implementation:

1. **Structural evaluation (`eval_harness.py`)** — avalanche, key/nonce
   sensitivity, diffusion speed, counter-collision, equivalent-key search,
   byte-distribution chi-square, bit-independence probe.

2. **Deep bit-independence (`bit_independence_deep.py`)** — specifically
   verifies that the bit-pair correlation decays as 1/√N to rule out real
   dependencies masquerading as sample noise.

3. **Reduced-round distinguishers (`reduced_round_distinguisher.py`)** — at
   each round count R=1..16, run byte chi-square, bit balance, serial
   correlation, runs test, Shannon entropy, and Hamming weight distribution
   on 64 KiB of keystream. Identifies the smallest round count where the
   primitive becomes statistically indistinguishable from uniform random.

4. **Differential probe (`differential_probe.py`)** — at each round count,
   sample 32 random 1-bit input differentials, run 500 base trials each,
   measure per-output-bit XOR bias. Noise floor under null: ~0.0985 at
   N=500 with 16384 measurements.

---

## 3. Results, with numbers

### 3.1 Structural evaluation (full mode)

| Test | Result | Target |
|---|---|---|
| Avalanche at R=16 | mean 255.33, std 11.25, 0/1280 out-of-tol | mean ~256, std ~11.3 |
| Key sensitivity | mean 255.97, std 10.79 | mean ~256 |
| Nonce sensitivity | mean 255.60, std 11.78 | mean ~256 |
| Full diffusion reached | R = 2 | ≤ R=8 |
| Counter collisions (32768 ctrs, 8-byte prefix) | 0 | 0 |
| Equivalent-key collisions (10000 trials, 8-byte prefix) | 0 | 0 |
| Keystream χ² (1 MiB) | 232.42 | 255 ± 22.6 |
| Bit-independence max \|corr\| (500 pairs, 200 samples) | 0.2107 | ≤ 0.25 |

**All 8 structural tests: pass.**

### 3.2 Deep bit-independence

Max |correlation| across 300 sampled pairs as sample size grows:

| N samples | max \|corr\| | mean \|corr\| | noise floor 1/√N | ratio to floor |
|---|---|---|---|---|
| 80 | 0.3293 | 0.0868 | 0.1118 | 2.95 |
| 200 | 0.2084 | 0.0559 | 0.0707 | 2.95 |
| 500 | 0.1169 | 0.0348 | 0.0447 | 2.61 |
| 1000 | 0.0997 | 0.0234 | 0.0316 | 3.15 |
| 2000 | 0.0861 | 0.0172 | 0.0224 | 3.85 |
| 5000 | 0.0429 | 0.0109 | 0.0141 | 3.03 |

**Observed shrinkage 80→5000: 7.68x. Expected under independence null: 7.91x.**
Near-perfect 1/√N scaling. **Interpretation: bits are independent; initial
high max was finite-sample noise.**

At N=5000, **0 pairs have |correlation| > 0.05** out of 300. At N=80, 209 did.

### 3.3 Reduced-round distinguisher (full mode, 64 KiB/round)

At each round count, 7 tests evaluated: byte χ², distinct-bytes, bit-fraction,
serial correlation, runs, Shannon entropy, Hamming weight.

**R=1** fails everything:
- χ² = 48373.75 (vs 255 ± 22.6 target)
- serial corr z = 21.08 (vs |z| < 5 target)
- runs z = -21.15
- entropy = 7.704 (deficit 0.296, vs 0.008 threshold)

**R=2 through R=16**: **all 7 tests pass cleanly at every round count.**
Selected values:

| R | χ² | balance z | serial z | runs z | entropy | HW mean | HW std |
|---|---|---|---|---|---|---|---|
| 2 | 265.41 | -0.28 | 2.24 | -2.24 | 7.997 | 255.9 | 11.59 |
| 8 | 239.77 | -0.25 | -0.24 | 0.24 | 7.997 | 255.9 | 11.04 |
| 16 | 229.94 | 1.02 | -1.11 | 1.11 | 7.997 | 256.4 | 11.41 |

**Smallest round count passing all tests: R=2. Default R=16 safety margin: 8x.**

### 3.4 Differential probe (full mode, 32 input bits × 500 trials)

Under the null, expected max |bias| across 16384 measurements = 0.0985.
Expected count of bits at |bias|>0.10 ≈ 0.1 (essentially zero).

| R | worst \|bias\| | mean max \|bias\| | bits>0.05 | bits>0.10 | verdict |
|---|---|---|---|---|---|
| 1 | 0.5000 | 0.4994 | 3947 | 2841 | **BIASED (5.1x)** |
| 2 | 0.0900 | 0.0717 | 446 | 0 | CLEAN (0.91x) |
| 3 | 0.0860 | 0.0733 | 424 | 0 | CLEAN |
| 4 | 0.0940 | 0.0747 | 420 | 0 | CLEAN |
| 6 | 0.0880 | 0.0735 | 429 | 0 | CLEAN |
| 8 | 0.0880 | 0.0719 | 436 | 0 | CLEAN |
| 10 | 0.1040 | 0.0740 | 374 | 1 | CLEAN (1.06x) |
| 12 | 0.0860 | 0.0707 | 386 | 0 | CLEAN |
| 14 | 0.0940 | 0.0726 | 415 | 0 | CLEAN |
| 16 | 0.0920 | 0.0709 | 393 | 0 | CLEAN |

**Expected count under null at |bias|>0.05: 415.** Observed at R=2..16: range
374-446, mean ~412. **Matches null expectation almost exactly.**

**Interpretation:**

- At R=1, 2841 output bits have |bias| > 0.10. This is saturation — a 1-bit
  input flip deterministically propagates to specific output bits at a single
  round. Expected and not a problem.
- At R=2 and above, the worst-case max |bias| across 32 input differentials
  is within ±6% of the expected null max. **There is no detectable differential
  signal at R=2 or above in this probe.**
- Smallest round count with differential behavior indistinguishable from a
  random oracle: **R=2**. Safety margin to default R=16: **14 rounds**.

---

## 4. What these numbers mean, and don't mean

### 4.1 What they do mean

1. The reference implementation is functionally correct. Every round-trip
   works. Every tamper test fails closed. RFC 8439 Poly1305 vector agrees.

2. The round function is not a linear map. A linear or affine round function
   would show strong differential signal at every round count; we see none
   beyond R=1.

3. The round function mixes fast. Full diffusion at R=2 and statistical
   uniformity at R=2 are both much faster than ChaCha20's comparable metrics,
   and suspiciously so. See 4.3.

4. There is no trivial structural leak at 1-bit differentials. The most
   common amateur-cipher failure mode — "flip one bit of the key and watch
   one bit of the output flip" — does not happen at R=2+.

5. No counter collisions or equivalent-key collisions in small sampled
   populations. Consistent with a well-behaved cipher.

### 4.2 What they do NOT mean

1. **This is not a proof of security.** Not even close. The tests run here
   are first-pass statistical checks and a sampled 1-bit differential probe
   at 500 trials. A real cryptanalytic evaluation would include:
   - Exhaustive 1-bit and 2-bit differential trail search with SAT/SMT
   - Linear cryptanalysis (bias toward bit-linear combinations)
   - Truncated differential analysis
   - Integral (square) attacks
   - Slide attacks
   - Invariant subspace attacks
   - Rotational cryptanalysis
   - Related-key attacks (this is especially important for the key schedule)
   - Algebraic attacks at reduced rounds
   - Side-channel resistance review

2. **Passing statistical tests does not imply passing cryptanalytic tests.**
   Many broken ciphers pass NIST-style randomness tests. Differential
   characteristics with low (but non-zero) probability can exist and still
   escape statistical detection at the sample sizes used here.

3. **32 sampled 1-bit input differentials is not comprehensive.** There are
   512 single-bit input positions. We sampled 32. There are also 2-bit,
   3-bit, and higher-weight differentials we did not test at all. A targeted
   search for the best trail would require SAT-solver assistance and is out
   of scope for this report.

4. **The 8x statistical safety margin is suspicious, not reassuring.**
   ChaCha20 with 20 rounds is considered to have "adequate" safety margin;
   its statistical uniformity appears around R=10. Our primitive appearing
   uniform at R=2 either means:
   - (a) the round function is legitimately much more powerful per-round,
     OR
   - (b) there is a structural symmetry that makes the state appear random
     faster than it actually mixes adversarially.
   
   Option (b) is rare but not unknown. We cannot distinguish (a) from (b)
   with the tests run here. Only differential trail search can.

5. **The key schedule has not been independently attacked.** Related-key
   attacks, weak-key classes, and slide attacks on the schedule were not
   evaluated in this report.

### 4.3 Specific concern: the 8x margin

If NFET-SC-512 really becomes indistinguishable at R=2 and we run 16 rounds,
we are doing 8x more work than a naive reading of these tests suggests is
necessary. That's usually interpreted as "great, strong safety margin." It
could also be interpreted as "our statistical probes are too weak to see
what the cipher is actually doing."

The honest read: **I cannot distinguish these two interpretations from this
report alone.** A cryptographer with SAT-solver experience could settle it
in a day. I can't.

---

## 5. What hasn't been tested (explicit non-coverage)

The following are all things a real evaluation would cover and this report
does not:

### 5.1 Primitive-level gaps
- Best 1-bit differential trail probability at each round count (SAT search)
- Best 2-bit differential trail
- Best linear characteristic (bit-wise bias toward affine combinations)
- Boomerang / rectangle probes
- Integral / square attacks
- Algebraic degree measurement
- Interpolation attacks
- Invariant subspace search under the permutation π
- Rotation-invariant features of the ARX core
- Related-key differential analysis
- Key schedule weakness (weak key classes, slide attacks, related-key)
- Sponge-like indifferentiability if framed as a permutation

### 5.2 Multi-user and state-compromise gaps
- Multi-user security (how many users can share a single key before
  collision risk becomes noticeable)
- Forward secrecy (none claimed, none analyzed)
- State compromise impact

### 5.3 Implementation gaps
- Constant-time audit (the Python reference is not constant-time; side
  channels on real hardware would need a C implementation and formal
  constant-time checking)
- Fault-injection resistance (none claimed)
- Serialization ambiguity attacks on the vault format
- Cross-platform bit-exact reproducibility (only Python tested)

### 5.4 AEAD composition gaps
- Misuse resistance under nonce reuse (spec explicitly says nonce must be
  unique; the consequences of reuse are not quantified)
- Tag length analysis (we use 16 bytes; no shorter tag analysis)
- Padding oracle resistance

### 5.5 Mandatory external step
- **External cryptographer review.** This cannot be done by the author.
  Any claim of security, even provisional, must wait until at least one
  credentialed cryptographer has read the spec, run their own attacks,
  and published an evaluation.

---

## 6. What would kill the primitive, and what wouldn't

### 6.1 Kill signals

Any of the following would mean the design is broken and should not be used:

- A differential trail with probability > 2^−128 across 16 rounds
- A linear characteristic with bias > 2^−64 at full rounds
- A key-schedule collision producing equivalent keys with positive probability
  at reasonable effort
- A slide attack at any round count (round function being too self-similar
  under key translation)
- Any fixed point or invariant subspace under the round function
- Any structural weakness in π, ν, or the additive feedforward that allows
  state recovery faster than brute force

None of these were found by the first-pass tests in this report.
**Absence of findings at this level is not absence of such flaws.**

### 6.2 Non-kill signals

The following are NOT disqualifying, even if present:

- Slow Python implementation speed (a real cipher is benchmarked in C)
- Non-constant-time reference code (reference implementations are for
  correctness, not side-channel safety)
- Rounds count being "too many" (more rounds = more margin, not a flaw)
- Bry layer being public (Bry is not the secrecy layer)
- Bit-independence max |correlation| at small sample sizes (we verified this
  is noise)

---

## 7. Recommended next steps, in priority order

1. **Do not integrate this primitive into any product.** ChaCha20-Poly1305
   remains the actual secrecy layer of BRY-NFET-SX. NFET-SC-512 is a research
   artifact until external review is complete.

2. **Get at least one credentialed cryptographer to read the spec and run
   their own attacks.** This is the gating step before any security claim.
   Reasonable review targets: academic groups at university crypto labs,
   Signal or WireGuard project members, or individual experts in ARX design.

3. **Run SAT-based differential trail search.** This is the single most
   valuable adversarial test that could be run on this primitive and was
   NOT run in this report. A multi-day run on a modern SMT solver (Z3,
   Cryptominisat, or similar) against a reduced-round NFETBlock model
   would produce either (a) a best-trail bound that gives real evidence
   for or against security, or (b) a break.

4. **Run linear cryptanalysis.** Same as (3) but for linear characteristics.

5. **Write a formal threat model.** The current report has a "what hasn't
   been tested" section, which is a start. A formal threat model with
   explicit attacker capabilities and security goals is the next artifact.

6. **Cross-platform test vector validation.** Re-implement the reference in
   C or Rust and verify byte-level agreement with the Python reference on
   every test vector. Endianness, integer overflow behavior, and rotation
   details can all drift between implementations if the spec is ambiguous.

7. **Document the spec formally.** Phase 3 in the project plan — a
   standalone specification document with pseudocode, constants tables,
   invertibility sketch, and test vector appendix.

---

## 8. Conclusion

The NFET-SC-512 candidate primitive and its BRY-NFET-AEAD-512 composition
implement cleanly, round-trip cleanly, and pass first-pass statistical and
differential probes with a wide (8x-to-14x) safety margin above the smallest
distinguishable round count. These are positive indicators but not proofs.

**The primitive cannot be integrated into any product with a security claim
until external cryptographer review is complete.** Until then, this is a
research artifact, published for feedback, and BRY-NFET-SX continues to rely
on ChaCha20-Poly1305 for actual secrecy.

The single most important thing this report is not: a green light.

---

## Appendix A — Reproducing these results

Every number in this report can be reproduced by running:

```bash
cd bry_nfet_sx
python3 spec/nfet_ref/test_bry.py             # 31 Bry tests
python3 spec/nfet_ref/selftest.py             # 32 full-pipeline tests
python3 spec/nfet_ref/verify_test_vectors.py  # 18 pinned vectors
python3 spec/nfet_ref/eval_harness.py         # Phase 4 structural
python3 spec/nfet_ref/bit_independence_deep.py # Bit-independence deep dive
python3 spec/nfet_ref/reduced_round_distinguisher.py  # Phase 5
python3 spec/nfet_ref/differential_probe.py   # Phase 6
```

Every script is deterministic given its seed. The seeds in this report:

- `eval_harness.py`: mixed seeds, deterministic per Python RNG
- `bit_independence_deep.py`: seed 0xB11DEE9
- `reduced_round_distinguisher.py`: seed 0xDEEB9009
- `differential_probe.py`: seed 0xDEA1B175, key/nonce sampled from 0xD1FFC0DE

Changing these seeds changes the specific numbers but should not change
the qualitative conclusions.
