# BRY-NFET-AEAD-512 — Candidate Specification

**Version:** 0.0.1 (candidate)
**Status:** unreviewed research artifact
**Reference implementation:** `spec/nfet_ref/` (Python)
**Test vectors:** `spec/nfet_ref/test_vectors.json`
**Self-attack report:** `docs/NFET_SELF_ATTACK.md`

## 0. Preamble

This document specifies a candidate cryptographic primitive and AEAD
composition. It is published for evaluation, not for use.

**The cryptographic claims in this document are candidate claims, not
proven claims.** The primitive has been through a first-pass self-attack
(see `docs/NFET_SELF_ATTACK.md`) and has not been externally reviewed.
Any deployment that requires security guarantees should use
ChaCha20-Poly1305 until a credentialed cryptographer has read this
document and the reference implementation and published an evaluation.

The BRY-NFET-SX product (live at secure.imagineqira.com) continues to
use ChaCha20-Poly1305 for actual secrecy. This spec describes a
separate candidate primitive that is **not** integrated into the product.

## 1. Scope

This specification defines:

- **Bry v2** — a public, deterministic, reversible, unkeyed byte
  transform layer with two representations (Core and Surface)
- **NFET-SC-512** — a candidate 512-bit keyed block function
- **BRY-NFET-AEAD-512** — the full AEAD composition using Bry, NFET,
  and a standalone RFC 8439 Poly1305 for authentication

Out of scope:

- Security proofs
- Formal threat model (see §12 for a partial threat model)
- Cross-platform reference implementations (only Python is provided)
- Production deployment

## 2. Notation and conventions

- `||` concatenation of byte strings
- `⊕` bitwise XOR on equal-length byte strings or on 64-bit words
- `⊞` addition modulo 2^64 on 64-bit words
- `x <<< r` left-rotate 64-bit word `x` by `r` bits (r mod 64)
- `a . b` multiplication mod 2^64 on 64-bit words
- `bytes` are unsigned 8-bit values
- **All 64-bit words are serialized in little-endian byte order**
- `||A||` denotes the byte length of string A

## 3. Bry v2 — public transform layer

Bry v2 operates on UTF-8 byte streams and has two equivalent
representations:

- **Bry-Core**: binary `(y, m)` token pairs consumed by the cipher layer
- **Bry-Surface**: human-readable token alphabet

Both preserve full reversibility. Bry makes no cryptographic claim.

### 3.1 Public class function

Define `c : {0..255} → {0..5}`:

- `c(b) = 1` if `b ∈ {A,E,I,O,U,a,e,i,o,u}` (vowel letters)
- `c(b) = 2` if `b` is any other ASCII letter
- `c(b) = 3` if `b ∈ {0..9}` (digit characters)
- `c(b) = 4` if `b ∈ {0x09, 0x0A, 0x0D, 0x20}` (whitespace)
- `c(b) = 5` if `b ∈ {. , ! ? ; : ' " - _ / \ ( ) [ ] { } < > @ # $ % ^ & * + = | ~ `}`
- `c(b) = 0` otherwise

### 3.2 Bry-Core state

Three state variables, all public:

- `q_i ∈ Z_256`, initialized `q_0 = 0`
- `r_i ∈ Z_256`, initialized `r_0 = 0`
- `p_i ∈ {0..5}`, initialized `p_0 = 0`

### 3.3 Bry-Core encode

For each input byte `b_i` at position `i = 0, 1, 2, ...`:

1. **Offset:**
   ```
   u_i = (3·q_i + 5·r_i + 11·p_i + i) mod 256
   ```
2. **Encoded byte:**
   ```
   y_i = (b_i + u_i) mod 256
   ```
3. **Variant nibble:**
   ```
   m_i = (c(b_i) + q_i + 2·r_i + i) mod 16
   ```
4. **Emit token `(y_i, m_i)`.**
5. **State update:**
   ```
   q_{i+1} = (q_i + b_i + 13·c(b_i) + 17·m_i + i) mod 256
   r_{i+1} = (5·r_i + b_i + 3·q_{i+1} + 9·c(b_i) + 1) mod 256
   p_{i+1} = c(b_i)
   ```

### 3.4 Bry-Core decode

Given tokens `(y_i, m_i)` and the same initial state:

1. Recompute `u_i` from current state
2. Recover `b_i = (y_i − u_i) mod 256`
3. Recompute `ĉ_i = c(b_i)`
4. **Verify:** `m_i ?= (ĉ_i + q_i + 2·r_i + i) mod 16`. If not, **fail closed**.
5. Update state using the same rules as encode.

Decode is **fail-closed**: any nibble mismatch raises an error and
decoding halts.

### 3.5 Invertibility proof sketch

At step `i`, the decoder knows `q_i, r_i, p_i, i` (all derived from
public rules and prior decoded bytes). So it computes `u_i` identically
to the encoder, recovers `b_i` uniquely, recomputes the same `ĉ_i`
and `m_i`, and the state updates produce `q_{i+1}, r_{i+1}, p_{i+1}`
identical to the encoder.

Formally: let `φ(q, r, p, i, b)` denote the forward-step function and
`φ⁻¹(q, r, p, i, y, m)` the backward-step function. For any input byte
`b` and any state `(q, r, p, i)`:

```
φ⁻¹(q, r, p, i, φ(q, r, p, i, b).y, φ(q, r, p, i, b).m) = b
```

This holds because `y = b + u mod 256` has a unique `b` for fixed `u`,
and `u` is derived from the state, which is identical on both sides.

Bry is therefore a bijection on the space of valid UTF-8 byte streams.

### 3.6 Bry-Core serialization

Each token `(y_i, m_i)` is serialized as 2 bytes: `y_i || m_i`.
The variant nibble occupies a full byte for simplicity. The total
serialized length is `2n` where `n` is the input byte count.

### 3.7 Bry-Core padding

Let `L` be the serialized length. Choose bucket size 64. Define:

```
P = 64 · ⌈(L + 1) / 64⌉
```

Append `0x80` followed by `(P − L − 1)` zero bytes. Minimum pad size
is 1 byte; maximum is 64 bytes.

Unpadding: strip trailing `0x00` bytes until a non-zero byte is found;
that byte must be `0x80`, otherwise fail closed.

### 3.8 Bry-Surface

Human-readable token alphabet parallel to Bry-Core. Each input byte
maps to a token from a fixed public table (A=`1`, B=`2`, …, Z=`++6`,
lowercase prefix `^`, digits `#0`..`#9`, punctuation `--p` etc., raw
byte escape `~HH`). Parsed with longest-match lexical rules.

Bry-Surface is **not** part of the cryptographic pipeline. It is an
optional rendering of the byte stream for human consumption. The full
alphabet table is in `spec/nfet_ref/bry.py`.

## 4. NFET-SC-512 — keyed block function

### 4.1 Inputs

- `K ∈ {0,1}^256` — key (32 bytes)
- `N ∈ {0,1}^128` — nonce (16 bytes); **MUST be unique per key**
- `ctr ∈ Z_{2^64}` — counter (8 bytes)
- `d ∈ Z_{2^64}` — domain separator (8 bytes)

Key and nonce bytes are parsed as little-endian 64-bit words.

### 4.2 Public constants

Fixed public values, all derived from "nothing-up-my-sleeve" sources:

**`C_0 .. C_7`** (first 64-bit words of the fractional part of π, same
as Blowfish's P-array):

```
C_0 = 0x243F6A8885A308D3
C_1 = 0x13198A2E03707344
C_2 = 0xA4093822299F31D0
C_3 = 0x082EFA98EC4E6C89
C_4 = 0x452821E638D01377
C_5 = 0xBE5466CF34E90C6C
C_6 = 0xC0AC29B7C97C50DD
C_7 = 0x3F84D5B5B5470917
```

**Round constants `RC_0 .. RC_15`** — generated by SplitMix64 from
the seed `z_0 = 0x6A09E667F3BCC909` (which equals `⌊2^64 · (√2 − 1)⌋`).
Each step produces one `RC_r`. Exact SplitMix64 recurrence:

```
z_{r+1} = (z_r + 0x9E3779B97F4A7C15) mod 2^64
u = z_{r+1}
u = ((u ⊕ (u >> 30)) · 0xBF58476D1CE4E5B9) mod 2^64
u = ((u ⊕ (u >> 27)) · 0x94D049BB133111EB) mod 2^64
RC_r = u ⊕ (u >> 31)
```

**Key-schedule multiplier:**

```
KSCHED_MULTIPLIER = 0x9E3779B185EBCA87
```

(Knuth's 64-bit multiplicative hash constant, approximately
`⌊2^64 · ((√5 − 1) / 2)⌋`.)

**Rotation vectors:**

```
α = [7,  11, 13, 17, 19, 23, 29, 31]   # key schedule inner rotate
β = [5,  9,  14, 18, 22, 27, 33, 39]   # key schedule outer rotate
ρ = [9,  13, 17, 25, 29, 37, 43, 53]   # round function inner rotate
σ = [7,  19, 23, 31, 37, 41, 47, 59]   # round function outer rotate
```

**Lane permutation:**

```
π = [2, 5, 0, 7, 4, 1, 6, 3]
```

(Verify: π is a permutation of {0..7}.)

**Nonlinear response constant:**

```
NU_CONST = 0xD1342543DE82EF95
```

**Domain separation tags (little-endian ASCII):**

```
d_tag = "TAG-NFET" (as LE word) = 0x54454E2D47415415   (incorrect — see below)
d_enc = "ENC-NFET" (as LE word)
```

Actual little-endian packing of `"TAG-NFET"` yields `0x54454E2D47415415` — wait, compute:
"T", "A", "G", "-", "N", "F", "E", "T" = 0x54, 0x41, 0x47, 0x2D, 0x4E, 0x46, 0x45, 0x54.
LE-packed: `0x54454E2D47415454`. The reference implementation computes these at runtime via `int.from_bytes("TAG-NFET".encode("ascii"), "little")` so the exact integer value is unambiguous.
**Normative:** `d_tag = int.from_bytes(b"TAG-NFET", "little")`; `d_enc = int.from_bytes(b"ENC-NFET", "little")`. These must be distinct.

### 4.3 Initial state x^(0)

Given parsed 64-bit words `k_0..k_3` from `K`, `n_0, n_1` from `N`,
and scalars `ctr, d`:

```
x_0^(0) = k_0 ⊕ C_0
x_1^(0) = k_1 ⊕ C_1
x_2^(0) = k_2 ⊕ C_2
x_3^(0) = k_3 ⊕ C_3
x_4^(0) = n_0 ⊕ C_4
x_5^(0) = n_1 ⊕ C_5
x_6^(0) = ctr ⊕ C_6
x_7^(0) = d   ⊕ C_7
```

### 4.4 Key schedule

Initial schedule state `W^(0) = (k_0, k_1, k_2, k_3, n_0, n_1, ctr, d)`.

For each `r = 0, 1, 2, ..., 15`:

```
for i = 0..7:
    t_i = ((w_i^(r) ⊞ RC_r ⊞ i) <<< α_i)
          ⊕ w_{(i+3) mod 8}^(r)
          ⊕ (w_{(i+5) mod 8}^(r) <<< β_i)
for i = 0..7:
    w_i^(r+1) = t_i · KSCHED_MULTIPLIER (mod 2^64)
K^(r) = w^(r+1)
```

That is, `K^(r) = W^(r+1)`: the round `r` subkeys are derived by
running one schedule step forward from `W^(r)`. The raw initial state
`W^(0)` is **never** used directly as round keys; it is only the seed
for the schedule.

Total: 16 schedule steps, producing 16 subkey vectors `K^(0)..K^(15)`,
each with 8 words.

### 4.5 Round function

Parallel round: compute all `φ_i^(r)`, then all `ν_i^(r)`, then all
`z_i`, then permute by π.

**Local field (φ):**

```
for i = 0..7:
    φ_i^(r) = ((x_{(i-1) mod 8}^(r) <<< α_i)
               ⊞ x_i^(r)
               ⊞ (x_{(i+1) mod 8}^(r) <<< β_i)
               ⊞ K_i^(r)
               ⊞ RC_r)
              mod 2^64
```

**Nonlinear response (ν):**

```
for i = 0..7:
    left   = (φ_i^(r) ⊕ (φ_i^(r) <<< 17)) mod 2^64
    right  = (((φ_i^(r) >> 1) | 1) ⊕ NU_CONST) mod 2^64
    ν_i^(r) = (left · right) mod 2^64
```

Note: `((φ >> 1) | 1)` forces the low bit of the multiplier to 1, so
the multiplier is always odd (a unit in Z_{2^64}).

**Lane update (z) with second key injection:**

```
for i = 0..7:
    inner  = (x_i^(r) ⊕ ν_i^(r) ⊕ K_{(i+r) mod 8}^(r))
    left   = (inner <<< ρ_i)
    right  = (ν_{(i+3) mod 8}^(r) <<< σ_i)
    z_i    = (left ⊞ right) mod 2^64
```

**Lane permutation:**

```
for i = 0..7:
    x_i^(r+1) = z_{π[i]}
```

### 4.6 Feedforward and output

After 16 rounds:

```
o_i = (x_i^(16) ⊞ x_i^(0)) mod 2^64   for i = 0..7
```

Serialize `o_0 || o_1 || ... || o_7` as little-endian 64-bit words
to produce the 64-byte output block.

### 4.7 Keystream

For the keystream under a given `(K, N, d)`, iterate `ctr = 0, 1, 2, ...`:

```
KS = NFETBlock(K, N, 0, d) || NFETBlock(K, N, 1, d) || ...
```

Truncate to the desired length. Counter overflow is a fatal error
(spec supports up to 2^64 blocks per `(K, N, d)` tuple, which is 2^70
bytes — more than any realistic usage).

## 5. BRY-NFET-AEAD-512 — full AEAD construction

### 5.1 Inputs

- `K` — 32-byte key
- `N` — 16-byte nonce, **unique per key**
- `M` — plaintext (arbitrary bytes or UTF-8 string)
- `A` — associated data (arbitrary bytes, may be empty)

### 5.2 Encrypt

1. Encode `M` as UTF-8 bytes.
2. Compute Bry-Core tokens from the byte stream.
3. Serialize tokens to the 2-byte-per-token stream `Σ_B`.
4. Pad `Σ_B` to a 64-byte bucket: `P = Σ_B || 0x80 || zeros`.
5. Generate `|P|` bytes of NFET keystream `KS` under domain `d_enc`.
6. Compute ciphertext `C = P ⊕ KS`.
7. Derive Poly1305 one-time key:
   - Compute `B_tag = NFETBlock(K, N, 0, d_tag)`
   - Take `T = B_tag[0:32]` (first 32 bytes)
   - `r` = `T[0:16]` with standard RFC 8439 clamping
   - `s` = `T[16:32]`
8. Compute Poly1305 input:
   ```
   auth_input = A || pad16(A) || C || pad16(C) || len64(A) || len64(C)
   ```
   where `pad16(x)` zero-pads to the next 16-byte boundary and
   `len64(x)` is the byte length as a little-endian 64-bit integer.
9. Compute tag: `Tag = Poly1305(r, s, auth_input)`.
10. Output `(C, Tag)`.

### 5.3 Decrypt

1. Parse `(C, Tag)` with companion `(K, N, A)`.
2. Derive `(r, s)` as in encrypt.
3. Compute expected `Tag' = Poly1305(r, s, auth_input)` where
   `auth_input` is assembled from the received `(A, C)`.
4. **Constant-time compare** `Tag' ?= Tag`. If unequal, **fail closed**.
5. Generate keystream `KS` under `d_enc` matching `|C|`.
6. Compute padded bytes `P = C ⊕ KS`.
7. Remove padding (strip trailing zeros, verify last non-zero is `0x80`).
8. Deserialize back to token pairs.
9. Bry-Core decode to UTF-8 bytes.
10. Decode UTF-8 (if the caller expects a string).

At every step, failure is **fail-closed**: padding error, deserialization
error, Bry nibble mismatch, UTF-8 error, or tag failure → raise.

## 6. Security properties claimed (candidate only)

This section describes **candidate** claims, not proven ones. See
`docs/NFET_SELF_ATTACK.md` for what has and has not been tested.

### 6.1 Confidentiality

Nonce-based indistinguishability of ciphertext from random under
adaptive chosen-plaintext attack, under the assumption that NFETBlock
is a secure pseudorandom function with respect to its counter input.

**This assumption is not proven.** First-pass self-attack tests are
consistent with it but do not prove it.

### 6.2 Authenticity

Standard Poly1305 EUF-CMA (RFC 8439), under the assumption that the
one-time Poly1305 key derived from `NFETBlock(K, N, 0, d_tag)` is
pseudorandom. Same caveat.

### 6.3 Domain separation

`d_tag` and `d_enc` are distinct 64-bit values. Tag-derivation blocks
and keystream blocks cannot be confused.

### 6.4 Integrity (Bry layer)

Bry-Core cascades: a single byte flip in a token stream causes a
nibble check failure within 0-1 positions after the flip. This is
**not** cryptographic integrity (Bry is unkeyed; any attacker can
recompute Bry for any input). Poly1305 provides the cryptographic
integrity.

## 7. Explicit non-claims

This spec does **not** claim:

- Security under nonce reuse
- Forward secrecy
- Post-quantum security
- Side-channel resistance (the reference implementation is not
  constant-time)
- Multi-user security bounds
- Related-key resistance
- Fault-attack resistance
- Related-constant attacks on `d_tag`, `d_enc`, or `RC_r`

## 8. Test vectors

Pinned in `spec/nfet_ref/test_vectors.json`:

- 5 NFETBlock outputs at fixed `(K, N, ctr, d)` tuples
- 2 full key-schedule expansions
- 4 Bry-Core encoding cases
- 6 BRY-NFET-AEAD-512 encrypt tuples
- 1 RFC 8439 Poly1305 known-answer test

Verify with `python spec/nfet_ref/verify_test_vectors.py`.

## 9. Reference implementation

Python 3 reference lives in `spec/nfet_ref/`. Files:

| File | Purpose | LoC |
|---|---|---|
| `bry.py` | Bry-Core and Bry-Surface | ~330 |
| `constants.py` | Public constants + arithmetic helpers | ~180 |
| `nfet_block.py` | NFETBlock, key schedule, round function | ~310 |
| `poly1305.py` | Standalone RFC 8439 Poly1305 | ~110 |
| `aead.py` | BRY-NFET-AEAD-512 composition | ~210 |
| `test_bry.py` | 31 Bry self-tests | ~420 |
| `selftest.py` | 32 full-pipeline tests | ~500 |
| `gen_test_vectors.py` | Pinned vector generator | ~280 |
| `verify_test_vectors.py` | Vector verifier | ~165 |
| `eval_harness.py` | Phase 4 structural evaluation | ~450 |
| `bit_independence_deep.py` | Phase 4 follow-up | ~140 |
| `reduced_round_distinguisher.py` | Phase 5 statistical | ~310 |
| `differential_probe.py` | Phase 6 differential | ~260 |

## 10. Threats and attacker model (partial)

The candidate primitive is evaluated against the following attacker
capabilities:

- **CPA/CCA**: adversary can query encryption (and decryption for
  error oracle tests) at will, under unique nonces per key.
- **Key/nonce control**: adversary chooses none of `K`, may choose
  `N` but not reuse.
- **Related-key**: NOT evaluated.
- **State compromise**: NOT evaluated; no forward secrecy claim.
- **Side channels**: NOT evaluated; reference is not constant-time.
- **Nonce reuse**: out of scope; spec explicitly forbids.

## 11. Known gaps

See `docs/NFET_SELF_ATTACK.md` section 5 for the full list of things
not tested. The gating gap is **external cryptographer review**.

## 12. Version history

| Version | Date | Summary |
|---|---|---|
| 0.0.1 | 2026-04-15 | Initial candidate spec + reference + self-attack |

## Appendix A. Constants summary

| Name | Value | Origin |
|---|---|---|
| `C_0..C_7` | π P-array | Blowfish constants |
| `z_0` | `0x6A09E667F3BCC909` | ⌊2^64 · (√2−1)⌋ |
| `RC_r` | SplitMix64(z_0) iteration r | Sebastiano Vigna's SplitMix64 |
| `KSCHED_MULTIPLIER` | `0x9E3779B185EBCA87` | Knuth's 64-bit multiplicative hash |
| `NU_CONST` | `0xD1342543DE82EF95` | (see §4.5) |
| `ROUNDS` | 16 | — |
| `α` | [7,11,13,17,19,23,29,31] | primes < 32 |
| `β` | [5,9,14,18,22,27,33,39] | — |
| `ρ` | [9,13,17,25,29,37,43,53] | — |
| `σ` | [7,19,23,31,37,41,47,59] | — |
| `π` | [2,5,0,7,4,1,6,3] | — |
| `d_tag` | LE-bytes of "TAG-NFET" | domain tag |
| `d_enc` | LE-bytes of "ENC-NFET" | domain tag |

## Appendix B. Self-test pass record

At the time of publication:

- `python3 spec/nfet_ref/test_bry.py` → 31/31 pass
- `python3 spec/nfet_ref/selftest.py` → 32/32 pass
- `python3 spec/nfet_ref/verify_test_vectors.py` → 18/18 pass
- `python3 spec/nfet_ref/eval_harness.py` → 0 failures, 0 warnings
- `python3 spec/nfet_ref/reduced_round_distinguisher.py` → smallest
  indistinguishable round = 2, safety margin 8×
- `python3 spec/nfet_ref/differential_probe.py` → R=2+ clean at
  16,384 measurements, safety margin 14 rounds

See `docs/NFET_SELF_ATTACK.md` for the full numbers.
