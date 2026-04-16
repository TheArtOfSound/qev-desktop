// QEV Web Vault — private-preview access gate
//
// Runs first on landing/vault/index.html, before sodium.js and chat.js,
// so the vault UI is hidden until the visitor supplies a valid access
// code. Private preview gate, not hard security: if you view source
// you can see EXPECTED_HASH (SHA-256 hex). You cannot reverse it to
// recover the plaintext code without brute-forcing a 43-character
// random string, which is infeasible.
//
// The plaintext access code is NEVER in this file. It ships only as
// its SHA-256 hex digest. To rotate the code:
//   1. Compute a new hash: echo -n 'NEW_CODE' | shasum -a 256
//   2. Replace EXPECTED_HASH below with the new hex digest
//   3. Re-sign site content + rsync to server
//   4. Every previously-unlocked visitor's localStorage entry
//      automatically invalidates (the stored code no longer hashes
//      to the new expected value) and they get re-prompted
//   5. Email the new code to whoever should still have access
//
// This file is loaded from index.html via <script src="./gate.js">
// — an external same-origin script, which the CSP allows. The CSP
// still forbids inline <script> blocks, so any gate logic that lives
// inside index.html directly would silently fail to execute.

(function () {
  "use strict";

  // SHA-256 hex of the current access code. Only the hash ships
  // publicly; the plaintext code is kept in the operator's email.
  var EXPECTED_HASH =
    "318c075099c7d2eb92a173d6a67dbbd14463ecbf6088c1fb43e30973c8995842";

  // localStorage key for auto-unlock. We store the RAW code (not
  // the hash) so rotation of EXPECTED_HASH invalidates cached unlocks
  // automatically — the stored code re-hashes to the old digest
  // which no longer matches the new expected one.
  var STORAGE_KEY = "qev-vault-access-code";

  async function sha256Hex(str) {
    var buf = new TextEncoder().encode(str);
    var digest = await crypto.subtle.digest("SHA-256", buf);
    var bytes = new Uint8Array(digest);
    var hex = "";
    for (var i = 0; i < bytes.length; i++) {
      hex += bytes[i].toString(16).padStart(2, "0");
    }
    return hex;
  }

  function showApp() {
    document.body.classList.remove("gate-locked");
    var overlay = document.getElementById("gate-overlay");
    if (overlay) overlay.style.display = "none";
  }

  function showError(msg) {
    var err = document.getElementById("gate-error");
    if (err) {
      err.textContent = msg || "That code didn't match. Check for stray spaces.";
      err.classList.add("visible");
    }
  }

  function clearError() {
    var err = document.getElementById("gate-error");
    if (err) err.classList.remove("visible");
  }

  async function tryUnlock(code) {
    if (!code || code.length < 4) {
      showError("Enter the access code you received by email.");
      return false;
    }
    // Trim leading/trailing whitespace — email copy-paste very often
    // drags along a stray space or newline, which is the single most
    // common "the code doesn't work" false alarm.
    code = code.replace(/^\s+|\s+$/g, "");
    var hash;
    try {
      hash = await sha256Hex(code);
    } catch (e) {
      showError("Crypto failure: " + e.message);
      return false;
    }
    if (hash === EXPECTED_HASH) {
      try {
        localStorage.setItem(STORAGE_KEY, code);
      } catch (e) {
        // localStorage can be disabled in private browsing; still
        // unlock for this session, just won't persist.
      }
      showApp();
      return true;
    }
    showError();
    return false;
  }

  function wireGate() {
    var input = document.getElementById("gate-code");
    var submit = document.getElementById("gate-submit");
    var reveal = document.getElementById("gate-reveal");
    if (!input || !submit) return;

    submit.addEventListener("click", function () {
      tryUnlock(input.value);
    });
    input.addEventListener("keydown", function (e) {
      if (e.key === "Enter") {
        e.preventDefault();
        tryUnlock(input.value);
      }
    });
    input.addEventListener("input", clearError);
    if (reveal) {
      reveal.addEventListener("click", function () {
        if (input.type === "password") {
          input.type = "text";
          reveal.textContent = "Hide";
        } else {
          input.type = "password";
          reveal.textContent = "Show";
        }
      });
    }
    // Autofocus for fast paste.
    setTimeout(function () {
      try {
        input.focus();
      } catch (e) {}
    }, 100);
  }

  // Auto-unlock from stored code if it still matches EXPECTED_HASH.
  async function autoUnlock() {
    var stored = null;
    try {
      stored = localStorage.getItem(STORAGE_KEY);
    } catch (e) {}
    if (!stored) return false;
    try {
      var hash = await sha256Hex(stored);
      if (hash === EXPECTED_HASH) {
        showApp();
        return true;
      }
      // Stale — code has been rotated. Clear it.
      try {
        localStorage.removeItem(STORAGE_KEY);
      } catch (e) {}
    } catch (e) {}
    return false;
  }

  function init() {
    wireGate();
    autoUnlock();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
