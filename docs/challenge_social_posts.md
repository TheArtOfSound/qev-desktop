# BRY-NFET-SX Bundle Tampering Challenge — Social Post Drafts

These are ready-to-paste post drafts for the public challenge at
https://secure.imagineqira.com/challenge.

## Framing rule (read this first)

**One challenge. One target. No crypto theater.**

The challenge is: tamper with the bundle, or with the workflow around it,
in such a way that our verifier reports `overall_trusted: true` on the
result. We are NOT asking the public to break ChaCha20-Poly1305 or
HMAC-SHA256. Doing so would be a category error — those are well-vetted
public primitives, not part of what we built. Asking the public to
attack them invites snarky tweets from cryptographers and frames the
project as crypto theater.

An earlier version of these drafts enumerated three challenges
(decrypt the plaintext, forge the signature, find a workflow flaw).
The first two have been removed. If you find an old draft of yours
mentioning "three concrete targets" or "decrypt the plaintext if you
can" — those are stale. Use the drafts below.

---

## LinkedIn — primary post

I posted a real signed bundle from BRY-NFET-SX online and asked the
public to break it.

The challenge is not to break ChaCha20-Poly1305 or HMAC-SHA256. Those
are well-vetted public primitives I deliberately did not invent, and
asking the public to attack them would be a category error. The
challenge is to break my use of them.

Specifically: tamper with the bundle, or find any path through the
storage and verification layer, such that my own verifier reports the
result as `overall_trusted: true` while the bundle is materially
different from the one I published. That is the realistic and
interesting attack surface for a solo-built signed-bundle system, and
it is where actual bugs live.

The bundle is downloadable. The source is published. The verifier is
the target. I will hold the master key offline for seven days; on day
seven I publish it and the plaintext along with a SHA-256 commitment
that prevents me from swapping anything.

Credible findings will be acknowledged publicly.

https://secure.imagineqira.com/challenge

Qira LLC | v0.28.1 | controlled-use product preview

---

## LinkedIn — short follow-up (day 2 or 3)

Day N of the BRY-NFET-SX bundle tampering challenge. Bundle is live
and publicly downloadable. The target is `overall_trusted: true` on
tampered content. The crypto primitives are not in scope.

If you are in security: the most likely find is in the canonicalization
layer, the metadata-consistency rules, or the trust-aggregation logic —
not in the cipher.

https://secure.imagineqira.com/challenge

---

## Reddit — r/netsec

**Title:** I posted a real signed bundle and the only challenge is "tamper with it in a way our verifier accepts as trusted"

**Context.** BRY-NFET-SX is a workflow platform I built. It packages
messages into signed bundles using standard AEAD (ChaCha20-Poly1305) and
HMAC-SHA256 over a SHA-256 manifest, and exposes a `verify_bundle_dir`
function with explicit trust semantics: `integrity_ok`,
`signature_verified`, `metadata_consistent`,
`key_fingerprint_consistent`, `overall_trusted`. Overall_trusted is
only true when all of those pass.

**The single challenge.** Take the published bundle. Modify it any
way you like. Or find any other path through the BRY-NFET-SX bundle
and storage layer. Produce content that the verifier reports as
`overall_trusted: true` while differing from the published bundle.

**What this is not.** I am not asking the public to break
ChaCha20-Poly1305 or HMAC-SHA256. I deliberately did not invent
either, and asking the public to attack well-analyzed primitives is a
category error that signals naivety. The interesting bugs in any
solo-built signed-bundle system live in the parser, the canonicalizer,
the path resolution, the metadata aggregation, and the trust rules —
not in the cipher. That is the honest target.

**Receipts.** A SHA-256 commitment to a random reveal token embedded
in the plaintext is published from day zero, so I cannot swap
plaintexts after the fact. The master key is published on day seven.
Source is linked from the page.

**Scope.** The bundle, the published source, anything you compute
locally on your own machine. Out of scope: attacks on the server,
the live demo, brute force, social engineering.

https://secure.imagineqira.com/challenge

If a credible workflow finding shows up, it gets acknowledged
publicly with attribution you approve.

---

## Reddit — r/crypto

**Title:** Solo-built signed bundle workflow, source and bundle
published, asking for workflow attacks (not cryptanalysis)

Quick framing note for r/crypto: the challenge here is explicitly NOT
"attack ChaCha20-Poly1305" or "attack HMAC-SHA256." I know that asking
the public to break well-vetted primitives is a category error. The
ask is workflow-level: tamper with the bundle in a way that my own
`verify_bundle_dir` reports as `overall_trusted: true`. That is where
solo-built systems actually have bugs — the canonicalization, the
metadata rules, the trust aggregation.

If anyone wants to spend ten minutes reading the source and pointing
out a flaw in how I bind the manifest to the signature, or how I
resolve the bundle path, or how I compute `metadata_consistent` —
that is exactly the feedback I want.

Bundle, source, and verifier are all published.

https://secure.imagineqira.com/challenge

---

## Hacker News — Show HN

**Title:** Show HN: I published a signed bundle and asked for workflow
attacks (not cryptanalysis)

A real signed bundle from a workflow platform I built (BRY-NFET-SX).
Standard primitives — ChaCha20-Poly1305, SHA-256, HMAC-SHA256 — and
the explicit framing is "we are not asking you to attack the
primitives, we are asking you to attack our use of them."

The challenge is to produce content that my `verify_bundle_dir`
function reports as `overall_trusted: true` while differing from the
published bundle. Bugs in solo-built signed-bundle systems live in
the canonicalizer, the parser, the metadata-consistency rules, and
the trust aggregation — not in the cipher. That is the honest attack
surface.

Source is published. Bundle is downloadable. Master key released in
seven days. SHA-256 commitment to the plaintext is published from day
zero so I cannot swap.

https://secure.imagineqira.com/challenge

Happy to take feedback in the thread.

---

## Twitter / X

Public BRY-NFET-SX bundle tampering challenge.

Real signed bundle. Standard primitives (ChaCha20-Poly1305 + HMAC-SHA256
+ SHA-256). The challenge is NOT to break the primitives — that's a
category error. The challenge is to tamper with the bundle in a way
that my verifier reports as `overall_trusted: true`.

Source published. Bundle downloadable. Verifier is the target.

https://secure.imagineqira.com/challenge

---

## Email (direct outreach)

**Subject:** BRY-NFET-SX bundle tampering challenge — workflow attacks
welcome, cryptanalysis explicitly not asked for

Short note from Qira LLC.

I published a real signed bundle from BRY-NFET-SX at
secure.imagineqira.com/challenge. The framing of the challenge is
deliberately narrow: I am not asking the public to break
ChaCha20-Poly1305 or HMAC-SHA256, because I did not invent either of
them and asking the public to attack well-analyzed primitives is a
category error. I am asking you to find a way to tamper with the
bundle, or with the storage and verification workflow around it,
such that my own `verify_bundle_dir` reports the result as
`overall_trusted: true`.

The published source is part of the in-scope material. The bundle is
downloadable. The verifier is the target. Master key released in
seven days, with a SHA-256 commitment from day zero so the plaintext
cannot be swapped.

If you or someone on your team wants to look, the rules of engagement
are on the page and credible findings will be acknowledged publicly
with attribution you approve.

https://secure.imagineqira.com/challenge

Bryan Leonard
Qira LLC
bryanleonard@imagineqira.com

---

## Reveal-day post (save for day 7)

**LinkedIn:**

The BRY-NFET-SX bundle tampering challenge has reached its reveal
window.

The master key, signer secret, and plaintext are now published at
https://secure.imagineqira.com/challenge. The reveal token embedded in
the plaintext hashes to the SHA-256 commitment published seven days
ago. Anyone can confirm the reveal is genuine.

[Outcome summary goes here based on submissions received. Examples:
"No credible workflow findings were submitted." / "One workflow
observation was received and is documented in the security posture." /
"Finding X was reported by Y and has been acknowledged."]

The challenge is closed. Thank you to everyone who looked at the
bundle and the source.

https://secure.imagineqira.com/challenge
