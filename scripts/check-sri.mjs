// check-sri.mjs — verify/repair the SHA-384 Subresource Integrity
// attributes in landing/**/*.html.
//
// Why this exists: editing vault/chat.js or site-verify.js invalidates the
// integrity="sha384-…" attributes that reference them from every page that
// loads them. The browser then REFUSES to execute the script — the vault
// page simply stops working. During the 2026-07-29 remediation a single
// edit to those two files left 12 of 13 attributes stale at once.
//
//   node scripts/check-sri.mjs           report drift, exit 1 if any
//   node scripts/check-sri.mjs --write   rewrite the attributes in place
//
// Re-signing site-integrity.json is still required afterwards: the HTML
// bytes change, so the signed manifest goes stale too.

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const LANDING = process.env.QEV_LANDING || new URL('../landing', import.meta.url).pathname;
const WRITE = process.argv.includes('--write');

// _deployed-rescue holds byte-exact copies of what production was actually
// serving. They deliberately reference the OLD site-verify.js hash. Rewriting
// them would destroy the only surviving record of those deployed pages.
const SKIP_DIRS = new Set(['_deployed-rescue']);

const sri = (buf) => 'sha384-' + crypto.createHash('sha384').update(buf).digest('base64');
const resolve = (src) => path.join(LANDING, src.split('?')[0].replace(/^\//, ''));

const htmlFiles = [];
(function walk(dir) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (!SKIP_DIRS.has(e.name)) walk(p);
    } else if (e.name.endsWith('.html')) {
      htmlFiles.push(p);
    }
  }
})(LANDING);

let checked = 0;
let changed = 0;
const missing = [];

for (const hf of htmlFiles) {
  const orig = fs.readFileSync(hf, 'utf8');
  // src and integrity may sit on separate lines, so match across newlines.
  const next = orig.replace(
    /<script\s+src="([^"]+)"([\s\S]{0,400}?)integrity="([^"]+)"/g,
    (m, src, mid, integ) => {
      const fp = resolve(src);
      if (!fs.existsSync(fp)) {
        missing.push(`${path.relative(LANDING, hf)} -> ${src}`);
        return m;
      }
      checked++;
      const want = sri(fs.readFileSync(fp));
      if (want === integ) return m;
      changed++;
      console.log(`MISMATCH ${path.relative(LANDING, hf)}  ${src}`);
      console.log(`   in html: ${integ}`);
      console.log(`   actual : ${want}`);
      return m.replace(`integrity="${integ}"`, `integrity="${want}"`);
    },
  );
  if (next !== orig && WRITE) {
    fs.writeFileSync(hf, next);
    console.log(`  -> rewrote ${path.relative(LANDING, hf)}`);
  }
}

console.log(
  `\nchecked ${checked} SRI attrs across ${htmlFiles.length} html files; ` +
    `${changed} mismatched${WRITE ? ' (written)' : ' (dry run)'}`,
);
if (missing.length) console.log('unresolved srcs:', missing);
if (!WRITE && changed > 0) process.exitCode = 1;
