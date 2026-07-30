# Design deliverables — 2026-07-29 audit remediation

Two prototypes. Neither is wired into the live site; both are references
for the rebuild, and both run standalone in a browser.

## `trust-marks-system.html` — the token + component system
Renders the palette, the four verdict states and the target-size fix.
Ships for real as `../landing/trust-marks.css`.

The rule it enforces: **a trust mark cannot render without a scope.**
`.tm-scope` is a required child; omit it and the component draws itself
as broken. This is the product's own stated position ("badges link to
scoped certificates, never 'this whole company is secure'") turned into
something the markup enforces rather than something the copy promises.

Contrast is measured, not estimated. Every token passes WCAG 2.2 AA for
body text in both themes. `--text-dim` (#8590a2) failed at 3.23:1 and is
retired in favour of #6b7280 at 4.83:1.

## `vault-flow-redesign.html` — the vault flow
Interactive. Click through it; nothing cryptographic runs.

The audited page asks the user to confront `secret number`, `scramble
code`, `lock recipe` and `box style` as form fields — four cryptographic
internals presented as decisions, three auto-generated and the fourth
unchangeable, each behind a 15px "what is this?" button. Meanwhile the
two things that actually determine whether the tool works — send the
phrase on a different channel, and there is no recovery — were plain
paragraphs below the fold.

The redesign inverts that:

- **Eleven fields to three decisions.** Generated values move out of the
  form into a receipt shown *after* sealing, where they are evidence
  instead of input.
- **The phrase is pre-generated.** The old page opened empty with the
  submit button disabled, so a new user's first experience was a
  refusal.
- **The handoff gets the layout.** A two-column diagram at the moment it
  becomes actionable, not a sentence under the fold.
- **Clear is a control.** The audit found decrypted plaintext stayed on
  screen after a later failed unlock with no way to remove it.
- **Every target ≥ 44px.** 17 controls measured under the 24px WCAG 2.2
  minimum; the explanations are now inline at the step that needs them,
  so nothing tiny is left to tap.

### Not carried over deliberately
The old page's honest threat-model section is *better* than most of what
ships in this category. It should survive the rebuild intact — the
redesign removes cognitive load from the form, not candour from the page.
