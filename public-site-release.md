# Public fallback website release

`public-site/` is the complete, signature-verified public release recovered from the active `secure-qev-dr` Pages deployment. It includes the browser vault, downloads, verification code, and public keys. `landing/` is older and must not overwrite this deployment without reconciliation.

This update adds Qira orientation to marketing pages and simplifies first use. It does not change the vault, installers, hosted API, or pinned signing key.

1. Edit only intended public files. Never add private keys or environment files.
2. Set `BRY_SITE_SIGNER_KEY_PATH` to the existing production key in the operator environment. Run `node scripts/sign-public-site.cjs`. It refuses a mismatched key and validates local SRI.
3. Run `node scripts/sign-public-site.cjs --verify` to verify every hash and the pinned signature.
4. Commit and push. Archive `public-site` from that exact commit, retaining bytes through `.gitattributes`. Verify the staged release.
5. Deploy only that directory to Pages project `secure-qev-dr`, branch `main`, with the source commit in deployment metadata. Retain the previous deployment for rollback.
6. Verify the live manifest, browser verification badge, first-use links, mobile navigation, and vault availability at `secure.imagineqira.com`.

The disaster-recovery proxy currently serves public reads. Hosted API calls remain unavailable; do not describe this fallback as a working hosted team service.
