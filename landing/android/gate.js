// QEV Android gate — same pattern as /vault/gate.js.
//
// SHA-256 hash of the access code is stored here; the plaintext
// never appears in source. Users who don't have the code can
// email bryanleonard@imagineqira.com to request it.

(function () {
  "use strict";

  var EXPECTED_HASH =
    "b461a6b698db9076f2ee4733c571ad404de044b3d766d00121b1c5a9e8df50f2";
  var STORAGE_KEY = "qev-android-access-code";
  var APK_URL = "/assets/QEV_0.28.1_android.apk";

  function sha256Hex(str) {
    return crypto.subtle
      .digest("SHA-256", new TextEncoder().encode(str))
      .then(function (buf) {
        return Array.from(new Uint8Array(buf))
          .map(function (b) {
            return b.toString(16).padStart(2, "0");
          })
          .join("");
      });
  }

  function tryUnlock(code) {
    return sha256Hex(code.trim()).then(function (hash) {
      if (hash === EXPECTED_HASH) {
        localStorage.setItem(STORAGE_KEY, code.trim());
        unlock();
        return true;
      }
      return false;
    });
  }

  function unlock() {
    document.body.classList.remove("gate-locked");
    var overlay = document.getElementById("gate-overlay");
    if (overlay) overlay.style.display = "none";
    var content = document.querySelector(".gate-app-content");
    if (content) content.style.display = "block";
    // Set the download link href
    var dlBtn = document.getElementById("android-download-btn");
    if (dlBtn) dlBtn.href = APK_URL;
  }

  // Auto-unlock from localStorage on return visits.
  var stored = localStorage.getItem(STORAGE_KEY);
  if (stored) {
    sha256Hex(stored).then(function (hash) {
      if (hash === EXPECTED_HASH) {
        unlock();
      } else {
        // Stale code — hash changed. Clear and re-gate.
        localStorage.removeItem(STORAGE_KEY);
      }
    });
  }

  // Wire the gate form.
  var form = document.getElementById("gate-form");
  var input = document.getElementById("gate-input");
  var error = document.getElementById("gate-error");
  if (form) {
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      if (!input || !input.value) return;
      tryUnlock(input.value).then(function (ok) {
        if (!ok && error) {
          error.textContent = "That code didn't match. Check for stray spaces.";
          error.style.display = "block";
        }
      });
    });
  }
})();
