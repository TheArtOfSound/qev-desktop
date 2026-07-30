# Deploy order — audit remediation (2026-07-29)

**Read this before deploying anything from the `audit-remediation-2026-07-29` branch.**

The remediation rewrote user-facing security copy so that it accurately
describes controls that **do not exist on the live server yet**. If you deploy
the HTML without the nginx config, you recreate the exact finding the audit
opened with — a page asserting a Content-Security-Policy that isn't there.

## The ordering constraint

`landing/vault/index.html` and `landing/privacy.html` now state, as fact, that
`/vault` is served with a `Content-Security-Policy` response header containing
`connect-src 'none'`, and they invite the reader to confirm it in DevTools.

That is true **only after** `deploy/nginx-secure.conf` is live.

- Deploy nginx first, or nginx and the pages together.
- Never deploy the pages alone.

## Sequence

1. **Apply the nginx config.**
   `deploy/nginx-secure.conf` mirrors production. Copy it to the server,
   then:
   ```
   nginx -t && systemctl reload nginx
   ```
   `nginx -t` was not run during remediation — nginx isn't installed in the
   authoring environment. Braces balance and directives desk-check, but
   **you must run `nginx -t` before reloading.**

2. **Verify the headers actually arrive.** `add_header` does not inherit into
   a location that sets any `add_header` of its own, so the block is repeated
   in every location. Confirm empirically, don't assume:
   ```
   curl -sI https://secure.imagineqira.com/vault/ | grep -i content-security-policy
   curl -sI https://secure.imagineqira.com/       | grep -i strict-transport
   curl -sI https://secure.imagineqira.com/downloads | grep -i x-frame-options
   ```
   `/vault/` must show `connect-src 'none'`; everything else `connect-src 'self'`.

3. **Confirm the vault still works.** The CSP is strict. Open `/vault/`,
   encrypt and decrypt a throwaway string, and check the console for CSP
   violations. If `sodium.js` or `chat.js` is blocked, the page is dead —
   roll back step 1 immediately.

4. **Re-sign the integrity manifest.** Every changed file under `landing/`
   has a new SHA-256, so `site-integrity.json` is now stale. Re-sign with the
   offline Ed25519 key (`scripts/sign_site_content.py`, or
   `qev-platform/scripts/resign-site-integrity.py`). **This was not done
   during remediation — the private key is yours and is not on this machine.**

5. **Verify the signature end-to-end** with the verifier that now exists:
   ```
   python3 qev-platform/scripts/verify_site_integrity.py \
       --url https://secure.imagineqira.com \
       --expect-key 881de4e7616992f92013b84ba1bbd08280a007b491bde28a46d8a15612d1d326
   ```
   Must exit 0 and report every file matching. It verified 75/75 against the
   pre-remediation site, so a failure here means the re-sign went wrong.

6. **Load `/verify` in a browser** and confirm the green
   `✓ site-integrity verified` badge appears. If it shows the red tamper
   banner, step 4 did not take.

## SRI — already handled, but don't undo it

`landing/vault/chat.js` and `landing/site-verify.js` changed, which invalidated
the `integrity="sha384-…"` attributes referencing them across **12 pages**.
Those were recomputed. Had they not been, the browser would have refused to
execute both scripts and the vault page would simply not work.

If you edit either file again, recompute before deploying. Any mismatch is
fatal, not cosmetic.

## Still outstanding — these need you, not code

| Item | Why it can't be done here |
|---|---|
| **Apple Developer + EV Authenticode certificates** | Requires purchase (~$99/yr Apple) and identity validation. Until then the downloads stay unsigned and the OS warnings stay correct. |
| **Publish or retract the challenge master key** | `reveal_at` was 2026-04-21; it is 98 days overdue and `reveal_status` is still `pending`. The key is held offline. Either publish it or formally retract the challenge with a dated note — leaving it pending is the worst of the three. |
| **`npm publish` the CLI** | The published 0.30.0 reports `qev 0.29.0`; the repo fix (`createRequire` from package.json) is correct but unpublished. Republishing also ships the 7776-word passphrase list. |
| **Push branches / open PRs** | Outward-facing; not done without your say-so. Both repos are on `audit-remediation-2026-07-29`, committed locally, `main` untouched. |
| **GitHub Pages duplicate** | `theartofsound.github.io/qev-desktop/` serves a second, unsigned vault with no SRI, outside the manifest, and `robots.txt` 404s there. Decide: redirect to the signed site, or keep it with a prominent "unsigned mirror" banner. |
| **Gateway health auth** | `/platform/v1/health` is still unauthenticated and returns full preflight detail, connector inventory and signing key id. The agent assigned this did not finish. |
| **IndexNow key** | `/indexnow.txt` 404s while `indexnow-submit.mjs` exists, so submissions cannot be working. The key is tied to your Bing account. |

## Analytics — a decision you should know about

Ten landing pages carried a GA4 tag (`G-XV71TRRR8Z`) in the repo, while the
deployed site served none and `/privacy` promised "No analytics — no Google
Analytics". Deploying the repo as-is would have switched analytics on and
broken that promise on the same page that makes it.

The tags were **removed**, so repo, production and the Privacy Policy now
agree, and the CSP permits no third-party host at all. If you want analytics
back, `/privacy` and `deploy/nginx-secure.conf` must change in the same commit
as the tag — that coupling is noted in both files.
