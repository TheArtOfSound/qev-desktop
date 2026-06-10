// site-verify.js — in-page tamper-evidence for secure.imagineqira.com.
//
// Fires on every HTML page that includes this script. Fetches the
// signed `site-integrity.json`, verifies the ed25519 signature
// against the baked-in public key (so a swapped manifest doesn't
// get trusted), then checks that THIS page's bytes hash to the
// value recorded in the manifest. Mismatch → render a prominent
// red "tampered" banner, block the <main> content, and halt.
//
// Why this matters
//
//   An attacker with write access to /var/www/ could swap any HTML
//   file. HTTPS prevents MITM but not origin tampering. Subresource
//   Integrity (SRI) protects <script> and <link> imports but NOT the
//   HTML shell itself. This verifier closes that gap: if the shell is
//   tampered, the user sees red; if the script itself is tampered,
//   browsers already reject it via its own SRI hash (embedded in the
//   <script> tag that loads THIS file).
//
// Fail-closed semantics
//
//   - Any fetch error, JSON parse error, signature mismatch, or hash
//     mismatch → show banner, stop page.
//   - Network failure on the manifest fetch also fails closed — better
//     a false positive than a silent skip.
//
// Public key is hard-coded below so a tampered <script src> that
// points at a malicious verifier can't "verify" itself with the
// attacker's key. The hex string is 32 bytes; matches
// site-signer.ed25519.pub.

(function () {
  "use strict";

  // Pinned ed25519 public key hex. Regenerate this constant in
  // lock-step with landing/site-signer.ed25519.pub whenever the
  // signing key rotates. Hard-coding here means a swap of
  // /site-signer.ed25519.pub alone can't forge verifications.
  const PINNED_SIGNER_PUBKEY_HEX =
    "881de4e7616992f92013b84ba1bbd08280a007b491bde28a46d8a15612d1d326";

  // Domain separator. MUST match the Python SIGNATURE_DOMAIN constant
  // in scripts/sign_site_content.py EXACTLY — pipes, no colon,
  // NOT the schema tag (which uses hyphens instead of pipes). The
  // manifest also exposes the correct value at
  // `signature.domain` so a future verifier can cross-check.
  const SIGNATURE_DOMAIN = "BRY-NFET-SX|SITE-INTEGRITY|V2";

  // Mapping from pathname → manifest key. Manifest uses relative
  // repo paths ("index.html", "vault/index.html", etc.); the browser
  // gives us the URL pathname. This normalization keeps the
  // verification exact.
  function manifestKeyForLocation() {
    const p = location.pathname;
    if (p === "/" || p === "") return "index.html";
    const stripped = p.startsWith("/") ? p.slice(1) : p;
    // trailing slashes and bare route names both resolve to index.html
    if (stripped.endsWith("/")) return stripped + "index.html";
    if (!stripped.includes(".")) {
      // /downloads → downloads.html etc. (landing pages without extension)
      return stripped + ".html";
    }
    return stripped;
  }

  async function sha256Hex(buf) {
    const h = await crypto.subtle.digest("SHA-256", buf);
    return Array.from(new Uint8Array(h))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  function hexToBytes(hex) {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) {
      out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
  }

  function concatBytes(a, b) {
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0);
    out.set(b, a.length);
    return out;
  }

  // Produce the same bytes Python does with:
  //   json.dumps(obj, sort_keys=True, separators=(',', ':'),
  //              ensure_ascii=False).encode('utf-8')
  //
  // Strategy: recursively sort object keys into a new object, then
  // hand it to native JSON.stringify. JSON.stringify with no indent
  // outputs compact JSON (no whitespace) and uses UTF-16 code units
  // natively — matches Python's ensure_ascii=False output byte-for-
  // byte as long as we deep-sort keys first.
  function deepSortKeys(obj) {
    if (obj === null || typeof obj !== "object") return obj;
    if (Array.isArray(obj)) return obj.map(deepSortKeys);
    const sorted = {};
    Object.keys(obj)
      .sort()
      .forEach((k) => {
        sorted[k] = deepSortKeys(obj[k]);
      });
    return sorted;
  }
  function canonicalJsonBytes(obj) {
    return new TextEncoder().encode(JSON.stringify(deepSortKeys(obj)));
  }

  function showTamperBanner(reason, details) {
    console.error("[site-verify] TAMPER DETECTED:", reason, details || "");
    const b = document.createElement("div");
    b.setAttribute("role", "alert");
    b.style.cssText =
      "position:fixed;inset:0;z-index:2147483647;background:#1a0606;color:#ffd7d7;" +
      "padding:40px;font:14px/1.5 ui-monospace,Menlo,Consolas,monospace;" +
      "overflow:auto;";
    b.innerHTML =
      '<h1 style="color:#ff6b6b;font-size:1.6rem;margin:0 0 12px;font-family:system-ui,sans-serif;">' +
      "⚠️ Tampered page detected" +
      "</h1>" +
      '<p style="max-width:720px;font-family:system-ui,sans-serif;font-size:15px;color:#ffcccc;">' +
      "This page's bytes do not match the bytes that were signed by " +
      "<code>site-signer.ed25519.pub</code>. Either the server has been " +
      "compromised, a proxy is rewriting responses, or the signed manifest " +
      "is itself corrupt." +
      "</p>" +
      '<p style="max-width:720px;font-family:system-ui,sans-serif;font-size:14px;color:#ffb0b0;margin-top:18px;">' +
      "<strong>Do not enter any passwords or personal data on this page.</strong> " +
      'Verify out-of-band with <code>/verify</code> or fetch the manifest from a ' +
      "clean network." +
      "</p>" +
      '<details style="margin-top:24px;font-size:12px;"><summary style="cursor:pointer;color:#ff8a8a;">Technical detail</summary>' +
      '<pre style="white-space:pre-wrap;word-break:break-all;margin-top:10px;color:#ffcccc;">' +
      ((reason || "") + "\n\n" + (details || "")).replace(/</g, "&lt;") +
      "</pre></details>";
    // Blank out the rendered page so users can't interact with
    // tampered content.
    (document.body || document.documentElement).prepend(b);
    // Also drop any <main>/<form>/<script src> that hadn't already
    // rendered — best-effort.
    document.querySelectorAll("main,form,nav,section,header,footer").forEach((el) => {
      el.style.visibility = "hidden";
    });
  }

  // Green "verified" badge. Only on /verify to avoid UI clutter.
  function showVerifiedBadge() {
    if (location.pathname.replace(/\/$/, "") !== "/verify") return;
    const b = document.createElement("div");
    b.style.cssText =
      "position:fixed;bottom:16px;right:16px;z-index:2147483646;" +
      "background:#0a2818;color:#8affb5;border:1px solid #2fb170;" +
      "padding:8px 14px;border-radius:8px;" +
      "font:12px/1.4 ui-monospace,Menlo,Consolas,monospace;" +
      "box-shadow:0 4px 14px rgba(0,0,0,0.25);";
    b.textContent = "✓ site-integrity verified";
    document.body.appendChild(b);
  }

  // Pages whose CSP forbids all outbound requests (`connect-src 'none'`)
  // cannot fetch the manifest from this script. That's a deliberate
  // property of those pages — e.g. /vault is supposed to prove in
  // DevTools that nothing leaves the tab — so we'd break that promise
  // if we forced a fetch. Integrity on these pages is still enforced
  // by (a) Subresource-Integrity hashes on every <script>/<link> tag,
  // enforced by the browser, and (b) the /verify page, which fetches
  // the manifest from a less-restrictive origin and lets the user
  // cross-check any page's hash themselves.
  //
  // Matching by path prefix is intentional: future /vault/* sub-pages
  // inherit the strict CSP and the same skip rationale.
  const STRICT_CSP_PREFIXES = ["/vault"];
  function hasStrictCsp() {
    const p = location.pathname.replace(/\/$/, "");
    return STRICT_CSP_PREFIXES.some(
      (pfx) => p === pfx || p.startsWith(pfx + "/")
    );
  }

  // A very subtle bottom-corner notice — so a curious user knows
  // why the usual /verify badge isn't green on this page, but not
  // so loud as to scare off normal visitors.
  function showStrictCspNotice() {
    if (document.getElementById("site-verify-strict-csp-notice")) return;
    const b = document.createElement("div");
    b.id = "site-verify-strict-csp-notice";
    b.style.cssText =
      "position:fixed;bottom:10px;right:10px;z-index:2147483645;" +
      "background:#1a1735;color:#c3bff3;border:1px solid #2a2740;" +
      "padding:6px 10px;border-radius:6px;" +
      "font:11px/1.4 ui-monospace,Menlo,Consolas,monospace;" +
      "opacity:0.75;max-width:260px;";
    b.innerHTML =
      '\u2139\ufe0f Integrity check skipped here (strict CSP). ' +
      'Cross-check at <a href="/verify" style="color:#9983ff;text-decoration:underline;">/verify</a>.';
    document.body && document.body.appendChild(b);
  }

  async function verify() {
    // Strict-CSP pages: skip the in-page verification rather than
    // showing a false tamper banner. See STRICT_CSP_PREFIXES above.
    if (hasStrictCsp()) {
      // Wait for body to exist before injecting the notice (this
      // script runs from <head>).
      if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", showStrictCspNotice);
      } else {
        showStrictCspNotice();
      }
      return;
    }

    const key = manifestKeyForLocation();

    // 1. Fetch manifest. Cache-bust so an aged-out CDN copy doesn't
    //    false-alarm after a legitimate deploy.
    let manifest;
    try {
      const res = await fetch("/site-integrity.json?_=" + Date.now(), {
        cache: "no-store",
      });
      if (!res.ok) throw new Error("HTTP " + res.status);
      manifest = await res.json();
    } catch (e) {
      showTamperBanner(
        "Could not fetch /site-integrity.json",
        (e && e.message) || String(e),
      );
      return;
    }

    if (manifest.schema !== "BRY-NFET-SX-SITE-INTEGRITY-V2") {
      showTamperBanner("Manifest schema unknown: " + manifest.schema);
      return;
    }
    if (
      !manifest.signature ||
      manifest.signature.algorithm !== "ed25519" ||
      !manifest.signature.signature_hex ||
      !manifest.signer ||
      manifest.signer.public_key_hex !== PINNED_SIGNER_PUBKEY_HEX
    ) {
      showTamperBanner(
        "Manifest signer key doesn't match the pinned key.",
        "got=" + (manifest.signer && manifest.signer.public_key_hex) +
          "\npinned=" + PINNED_SIGNER_PUBKEY_HEX,
      );
      return;
    }

    // 2. Rebuild the signed bytes = domain || canonical_json(manifest - signature)
    const manifestForSig = Object.assign({}, manifest);
    delete manifestForSig.signature;
    const domainBytes = new TextEncoder().encode(SIGNATURE_DOMAIN);
    const manifestBytes = canonicalJsonBytes(manifestForSig);
    const signedBytes = concatBytes(domainBytes, manifestBytes);
    const sigBytes = hexToBytes(manifest.signature.signature_hex);
    const pubBytes = hexToBytes(PINNED_SIGNER_PUBKEY_HEX);

    // 3. Verify ed25519. Requires SubtleCrypto + Ed25519 support
    //    (Chrome 113+, Firefox 130+, Safari 17+). Older browsers get
    //    a "couldn't verify" banner — fail closed.
    let sigOk = false;
    try {
      const cryptoKey = await crypto.subtle.importKey(
        "raw",
        pubBytes,
        { name: "Ed25519" },
        false,
        ["verify"],
      );
      sigOk = await crypto.subtle.verify("Ed25519", cryptoKey, sigBytes, signedBytes);
    } catch (e) {
      showTamperBanner(
        "Browser doesn't support Ed25519 signature verification.",
        "Upgrade to a current Chrome / Firefox / Safari. " +
          ((e && e.message) || ""),
      );
      return;
    }
    if (!sigOk) {
      showTamperBanner(
        "Manifest signature verification FAILED.",
        "The manifest bytes don't match the claimed ed25519 signature. " +
          "Either the manifest was modified after signing, or the signing " +
          "key was compromised.",
      );
      return;
    }

    // 4. Look up the expected hash for this page + compare.
    const expectedHash = manifest.files && manifest.files[key];
    if (!expectedHash) {
      console.warn(
        "[site-verify] page not covered by manifest: " + key +
          " — skipping hash check (signature still verified)",
      );
      showVerifiedBadge();
      return;
    }

    let actualHash;
    try {
      const pageRes = await fetch(location.pathname, { cache: "no-store" });
      if (!pageRes.ok) throw new Error("HTTP " + pageRes.status);
      const pageBytes = await pageRes.arrayBuffer();
      actualHash = await sha256Hex(pageBytes);
    } catch (e) {
      showTamperBanner(
        "Could not fetch this page for self-hash check.",
        (e && e.message) || String(e),
      );
      return;
    }

    if (actualHash !== expectedHash) {
      showTamperBanner(
        "Page hash mismatch.",
        "path:     " + location.pathname + "\n" +
          "expected: " + expectedHash + "\n" +
          "actual:   " + actualHash,
      );
      return;
    }

    // All good.
    console.log(
      "[site-verify] ok: " + key + " matches signed manifest " +
        manifest.signed_at,
    );
    showVerifiedBadge();
  }

  // Defer until DOMContentLoaded so showTamperBanner can prepend
  // safely. If the document's already parsed, run immediately.
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", verify);
  } else {
    verify();
  }
})();
