# Changelog

## 0.31.0 — 2026-07-29

Remediates findings from an independent client audit.

### Changed — passphrase generator (security relevant)

`qev gen-phrase` drew from a 180-word list in which **every word began
with a, b, c, d or e** — the list was alphabetically truncated at
"elm". Four words plus two digits gave about **36.6 bits**.

It now draws from the standard EFF long wordlist: **7776 words, full
a–z**, giving about **58.3 bits** for the same 4-word + 2-digit format.
That is roughly **3.5 million times** more work for an offline attacker
holding a stolen vault file. (The list's four hyphenated entries were
replaced with unhyphenated equivalents, since the phrase format joins
words with `-`.)

The identical list ships in the browser vault and the desktop app, so
generated phrases remain consistent across all three.

**No action needed for existing vaults.** The phrase is user-supplied
input; the generator is not used in any encrypt, decrypt or key
derivation path. Vaults created with earlier versions open normally —
verified byte-exact against a vault produced by the pre-change browser
build. If you generated a phrase with an earlier version and it
protects something valuable, consider `qev rewrap` to move that vault
to a stronger phrase.

### Fixed — version reporting

`qev --version` reported `0.29.0` in the published 0.30.0 package. The
version is now sourced from `package.json`, so the npm release, the
`--version` output and the `version` field stamped into each vault
cannot drift apart.

### Unchanged

Vault format (`BRY-NFET-SX-VAULT-V2`), cipher (XChaCha20-Poly1305), KDF
(Argon2id, ops 4, mem 96 MiB) and the 8–256 MiB KDF parameter clamp
that rejects work-factor downgrade attacks.

## 0.30.0

Published with `qev --version` incorrectly reporting `0.29.0`, and with
the truncated passphrase wordlist described above. Use 0.31.0.

## 0.28.1

Earlier release.
