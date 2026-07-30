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
   **This config has now been validated locally** (2026-07-30, nginx 1.31.3;
   production runs 1.28.3). `nginx -t` reports *syntax is ok / test is
   successful* with all 74 `add_header` directives intact. The certbot-managed
   `ssl_certificate`, `ssl_dhparam` and `include` lines were stubbed for the
   local run because those paths only exist on the server — nothing else was
   changed. **Still run `nginx -t` on the server before reloading**, since
   those TLS lines were not exercised here.

   It was also run for real and probed with curl. Every one of the five
   headers arrived on all ten paths tested (`/`, `/vault/`, `/vault`,
   `/verify`, `/downloads`, `/privacy`, `/challenge`, `/styles.css`,
   `/vault/chat.js`, `/site-verify.js`) — including the static-asset location
   that sets its own `Cache-Control`, which is exactly where `add_header`
   non-inheritance silently drops everything. `/vault*` returned
   `connect-src 'none'`; everything else `connect-src 'self'`.

2. **Verify the headers actually arrive.** `add_header` does not inherit into
   a location that sets any `add_header` of its own, so the block is repeated
   in every location. Confirm empirically, don't assume:
   ```
   curl -sI https://secure.imagineqira.com/vault/ | grep -i content-security-policy
   curl -sI https://secure.imagineqira.com/       | grep -i strict-transport
   curl -sI https://secure.imagineqira.com/downloads | grep -i x-frame-options
   ```
   `/vault/` must show `connect-src 'none'`; everything else `connect-src 'self'`.

3. **Confirm the vault still works.** Done locally against the real config:
   `/vault/` rendered, `typeof sodium === "object"` (so the SRI-pinned
   `sodium.js` and `chat.js` both executed under `script-src 'self'`), and
   the Lock/Open controls were present. Outbound calls were genuinely
   blocked — `fetch` threw `TypeError` and synchronous `XMLHttpRequest`
   threw, where at audit time both returned 200. The page's
   `connect-src 'none'` claim is now true rather than aspirational.

   Repeat the check on the server anyway after deploying, since TLS and the
   real certificate chain were not part of the local run.

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

## Reference copies of what production served

`docs/deployed-rescue/` holds byte-exact copies of the five pages that had
no source anywhere. They live under `docs/` deliberately: inside `landing/`
they would be rsynced to the web root and signed into the manifest, serving
the pre-remediation pages — false CSP claim included — at live URLs. Diff
against them before deploying; do not deploy them.

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
| **Publish or retract the challenge** | Still yours — the key is offline. Both paths are now prepared: see `docs/CHALLENGE-RESOLUTION.md` and `scripts/challenge_reveal.py` (fails closed if the commitment does not reproduce). |
| ~~`npm publish` the CLI~~ | **DONE 2026-07-30.** `@bryan237l/qev-cli@0.31.0` published and verified from a clean install: reports 0.31.0, 7776-word list, old vaults still open byte-exactly. |
| ~~Push branches~~ | **DONE.** All branches pushed; `main` untouched in both repos. Opening PRs / merging remains your call. |
| ~~GitHub Pages duplicate~~ | **DONE.** The Pages workflow now injects `noindex` + a canonical to the signed site and ships a robots.txt. Takes effect on the next Pages build. |
| ~~Gateway health auth~~ | **DONE.** Split into public liveness vs Bearer-gated detail, timing-safe, fails closed on the shipped default token. 11/11 gateway tests pass. Needs deploying with the gateway. |
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
