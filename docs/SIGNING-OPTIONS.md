# Code signing — what it actually costs, researched 2026-07-30

The audit's most user-hostile finding was the download page teaching people
to run `xattr -cr` and `sudo codesign --force --deep --sign -` to defeat
their OS. The page no longer claims an ad-hoc signature proves anything, but
the underlying cause stands: **the binaries are unsigned.**

I looked for every legitimate way to fix that cheaply. Summary: one platform
has a much cheaper option than a traditional certificate; the other has no
free path at all.

## macOS — no way around $99/year

Notarization has been mandatory for software distributed outside the Mac App
Store since macOS 10.15, and notarization requires a Developer ID
certificate, which requires the paid Apple Developer Program. There is no
free tier, no individual exemption, and no third-party substitute.

Everything else on offer is a **user-side bypass**, not a fix:

| "alternative" | what it really is |
|---|---|
| `xattr -rd com.apple.quarantine` | teaching users to strip Gatekeeper — what the audit flagged |
| Homebrew cask | performs the same quarantine strip during install |
| ad-hoc `codesign --sign -` | identifies nobody; carries no authenticity whatsoever |

So: **$99/year, or the warnings stay** — and they stay *correct*, because
macOS genuinely cannot verify who built the app. The honest framing now on
the download page is the right interim position.

## Windows — much cheaper than the EV certificate assumed

**Azure Artifact Signing** (renamed from Trusted Signing; same service) is
now Generally Available at roughly **$10/month**, versus roughly $300–500/yr
for a traditional EV certificate.

It also recently opened up in a way that matters here: **self-employed
individuals can apply**, and the previous three-years-of-business-history
requirement has been dropped. Currently limited to the USA and Canada for
individuals, so check eligibility before budgeting for it.

**One caveat, and it is important — do not repeat the audit's mistake by
overstating this.** Artifact Signing does **not** grant instant SmartScreen
trust. It follows the same reputation-building model as an OV certificate:
new binaries still show a SmartScreen warning until they accumulate download
history. It gives you a real, verifiable publisher identity — which is worth
having — but it does not make the first-run warning disappear on day one.

Only an EV certificate confers immediate SmartScreen reputation. If removing
the warning on day one is the goal, EV is the only thing that does it, at
roughly 3–4× the cost.

## Realistic budget

| | cost |
|---|---|
| Apple Developer Program | $99/yr |
| Azure Artifact Signing | ~$120/yr |
| **both platforms signed** | **~$219/yr** |
| EV certificate instead, for instant SmartScreen | +$300–500/yr |

For a product whose entire pitch is verifiable trust, ~$219/yr to stop
telling users to disable their OS protections is the highest-leverage money
in the whole remediation. It is cheaper than one hour of the security review
that will eventually be needed anyway.

## What is already in place, at zero cost

Worth stating, because it is genuinely more than most unsigned software
offers — and it is what makes the current position defensible while the
certificates are pending:

- Every binary's SHA-256 is published **and covered by the Ed25519-signed
  manifest**, so a download can be verified against a signature the operator
  cannot forge after the fact.
- The download page now shows the exact `shasum` / `Get-FileHash` command.
- `scripts/verify_site_integrity.py` lets anyone confirm the whole chain
  without our cooperation.

Hashes prove you received the intended bytes. They do **not** substitute for
code signing, which proves who produced them — the page says so plainly, and
should keep saying so until the certificates are real.

## Sources

- [Azure Artifact Signing pricing](https://azure.microsoft.com/en-in/pricing/details/trusted-signing/)
- [Trusted Signing open to individual developers](https://techcommunity.microsoft.com/blog/microsoft-security-blog/trusted-signing-is-now-open-for-individual-developers-to-sign-up-in-public-previ/4273554)
- [Windows code signing options](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options)
- [Apple: safely open apps on your Mac](https://support.apple.com/en-us/102445)
- [Apple notarization overview](https://www.revenera.com/blog/software-installation/apples-application-notarization-for-macos/)
