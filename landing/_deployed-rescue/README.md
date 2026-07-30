# Rescued deployed pages — 2026-07-30

**These are byte-for-byte copies of what secure.imagineqira.com was actually
serving on 2026-07-30, fetched over HTTPS.**

They are here because they had **no source anywhere on this machine**. Every
`qev-desktop` checkout was searched (`~/QEV`, `~/Documents/CLI`,
`~/Downloads/05 Projects & Code/07 QEV`, `~/dev/bry_nfet_sx`) plus
`~/Projects/qev-platform`, hashing every `.html`/`.css`/`.js`/`.txt` file after
whitespace normalisation. Nothing matched. These five pages were edited on the
server, or from a directory that no longer exists.

That set is not random — it is the security-critical surface:

| page | why losing it matters |
|---|---|
| `/verify` | the entire independent-verification story |
| `/privacy` | a legal document |
| `/security` | the public security posture |
| `/downloads` | how people obtain the binaries |
| `/challenge` | the public cryptographic challenge |

## Read this before deploying

`landing/*.html` in this repo is **not** what is deployed. The audit
remediation edited the repo copies. Deploying them replaces the live pages with
content that has never been diffed against what users actually see.

Do this first:

```bash
diff <(python3 -c "import re,sys;print(re.sub(r'\s+',' ',open(sys.argv[1]).read()))" landing/_deployed-rescue/verify.html) \
     <(python3 -c "import re,sys;print(re.sub(r'\s+',' ',open(sys.argv[1]).read()))" landing/verify.html)
```

Repeat per page. Reconcile deliberately — decide which differences are the
remediation (intended) and which are live edits that were never committed
(must be preserved). Only then deploy.

## After reconciling

Delete this directory. It exists to stop an unversioned production page being
silently overwritten, not to become a second source of truth.
