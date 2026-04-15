// QEV — native-app glue layer
// =============================================================
//
// This file runs inside the BRY-Vault.app WKWebView host. It does
// ONLY the things that have to be different between the browser
// page and the native app:
//
//   1. Tab switching between the Lock and Open panels (the inline
//      version of this was blocked by CSP script-src 'self', which
//      forbids inline <script>).
//
//   2. Download interception: <a download> clicks that would otherwise
//      make WKWebView navigate to a blob: URL (and render the JSON
//      inline in the main frame, trapping the user) are caught,
//      the blob bytes are read, and shipped to Swift via a
//      WKScriptMessageHandler so the native side can show an
//      NSSavePanel and write the file to disk.
//
//   3. Clipboard writes: navigator.clipboard.writeText is replaced
//      by a message-handler round trip to Swift/NSPasteboard, since
//      WKWebView clipboard permissions under file:// are flaky.
//
//   4. Disable the right-click Inspect menu that WebKit exposes by
//      default — a commercial vault tool shouldn't advertise a
//      "View Source" affordance to grandma.
//
// This file deliberately does NOT touch chat.js or sodium.js. Those
// are byte-for-byte copies of the live site's /chat page and must
// stay identical so the vault format matches.
//
// Load order matters and is enforced by index.html:
//
//     <script src="./app.js"></script>    (this file — installs hooks)
//     <script src="./sodium.js"></script>  (libsodium)
//     <script src="./chat.js"></script>   (vault logic; uses the hooks)

(function () {
  "use strict";

  // ---------------------------------------------------------------
  // Blob URL interception.
  //
  // chat.js creates downloads via:
  //     const url = URL.createObjectURL(blob);
  //     const a = document.createElement("a");
  //     a.href = url; a.download = "...";
  //     a.click();
  //
  // WKWebView sees the synthetic click and tries to navigate to the
  // blob URL. Because the blob is JSON or text/plain, WKWebView
  // renders it inline — replacing our app UI with "the raw vault
  // JSON as a web page" with no back button.
  //
  // Fix: remember every blob we create, intercept the click, read
  // the blob bytes, ship them to Swift. Then Swift shows an
  // NSSavePanel and writes the bytes to whatever path the user picks.
  //
  // The Map uses blob-URL-string as key → Blob object as value.
  // Cleared on revokeObjectURL so we don't leak.
  // ---------------------------------------------------------------

  var __vaultBlobs = new Map();
  var __origCreate = URL.createObjectURL.bind(URL);
  var __origRevoke = URL.revokeObjectURL.bind(URL);

  URL.createObjectURL = function (obj) {
    var url = __origCreate(obj);
    if (obj instanceof Blob) {
      __vaultBlobs.set(url, obj);
    }
    return url;
  };
  URL.revokeObjectURL = function (url) {
    __vaultBlobs.delete(url);
    return __origRevoke(url);
  };

  // ---------------------------------------------------------------
  // Native bridge detection — runs in THREE hosts:
  //
  //   1. Swift WKWebView (dist/QEV.app on Mac): uses
  //      window.webkit.messageHandlers.* and postMessage.
  //
  //   2. Tauri WebView (tauri-app, cross-platform Mac+Windows): uses
  //      window.__TAURI__.core.invoke(command, args) → Promise.
  //
  //   3. Plain browser (dev / local HTTP server): no bridge, falls
  //      back to default <a download> navigation.
  //
  // We detect which host we're in once at load time and wrap the
  // capability calls (saveText, copyText, pickFile) behind a single
  // abstraction so the rest of app.js doesn't care.
  // ---------------------------------------------------------------

  function hasWebkitBridge(name) {
    return !!(
      window.webkit &&
      window.webkit.messageHandlers &&
      window.webkit.messageHandlers[name]
    );
  }

  function hasTauriBridge() {
    return !!(window.__TAURI__ && window.__TAURI__.core && window.__TAURI__.core.invoke);
  }

  // Resolve to one of "tauri" | "webkit" | "browser".
  function detectHost() {
    if (hasTauriBridge()) return "tauri";
    if (hasWebkitBridge("vaultDownload")) return "webkit";
    return "browser";
  }

  var HOST = detectHost();

  // Abstraction layer — the rest of app.js calls bridge.saveText(),
  // bridge.copyText(), bridge.pickFile(), and the right host-specific
  // implementation runs underneath. When a new host is added (iOS
  // WKWebView, Android, Electron, whatever) only this object needs to
  // grow a branch.
  var bridge = {
    /**
     * Save a text payload to a user-picked path.
     * Returns a Promise that resolves to true if saved, false if cancelled.
     */
    saveText: function (opts) {
      // opts: { filename, mime, text }
      if (HOST === "tauri") {
        return window.__TAURI__.core
          .invoke("save_vault_file", {
            payload: { filename: opts.filename, text: opts.text },
          })
          .then(function (result) {
            return !!(result && result.saved);
          });
      }
      if (HOST === "webkit") {
        window.webkit.messageHandlers.vaultDownload.postMessage({
          filename: opts.filename,
          mime: opts.mime || "text/plain",
          text: opts.text,
        });
        // WebKit postMessage is fire-and-forget; we can't know if the
        // user cancelled the save panel. Resolve true optimistically.
        return Promise.resolve(true);
      }
      // Browser fallback: trigger a default <a download> passthrough.
      return Promise.resolve(false);
    },

    /**
     * Copy a string to the system clipboard.
     * Returns a Promise that resolves on success.
     */
    copyText: function (text) {
      if (HOST === "tauri") {
        return window.__TAURI__.core.invoke("copy_to_clipboard", { text: String(text) });
      }
      if (HOST === "webkit" && hasWebkitBridge("vaultClipboard")) {
        window.webkit.messageHandlers.vaultClipboard.postMessage({
          text: String(text),
        });
        return Promise.resolve();
      }
      // Browser fallback: try navigator.clipboard natively
      if (navigator.clipboard && navigator.clipboard.writeText) {
        return navigator.clipboard.writeText(String(text));
      }
      return Promise.reject(new Error("Clipboard not available"));
    },

    /**
     * Open a native file picker and return { text, filename } or null.
     * Used to populate the decrypt textarea.
     */
    pickFile: function () {
      if (HOST === "tauri") {
        return window.__TAURI__.core.invoke("pick_vault_file").then(function (result) {
          if (result && result.loaded) {
            return { text: result.text, filename: result.filename };
          }
          return null;
        });
      }
      // WebKit uses the native file input via WKUIDelegate, handled
      // by chat.js's wireDecryptForm — nothing for us to do here.
      return Promise.resolve(null);
    },
  };

  // Legacy helper kept for backward compat with the WebKit-only path.
  function hasBridge(name) {
    return hasWebkitBridge(name);
  }

  // ---------------------------------------------------------------
  // Download bridge.
  //
  // Every vault artifact we ship is text: a JSON vault, a recovery
  // sheet .txt, or a vault text line. So we read the blob as a plain
  // UTF-8 string via FileReader.readAsText and post the STRING itself
  // to Swift — no base64 round trip. Swift writes the string to disk
  // as UTF-8 bytes. This eliminates a whole class of encoding bugs
  // where the base64 round trip corrupts a byte and the resulting
  // vault fails AEAD verification at decrypt time.
  //
  // The message payload shape:
  //     { filename: String, mime: String, text: String }
  //
  // If we ever need to ship binary files (zip, image, etc.), we can
  // add a separate "bytesBase64" field. For now, text is the only
  // path and it is exact.
  // ---------------------------------------------------------------

  function readBlobAsText(blob) {
    return new Promise(function (resolve, reject) {
      var fr = new FileReader();
      fr.onload = function () {
        resolve(String(fr.result || ""));
      };
      fr.onerror = function () { reject(fr.error || new Error("FileReader error")); };
      fr.readAsText(blob, "utf-8");
    });
  }

  function handleDownloadClick(anchor) {
    var href = anchor.href;
    var filename = anchor.download || "vault.bin";
    var blob = __vaultBlobs.get(href);
    if (!blob) {
      console.error("QEV: blob URL not in cache:", href);
      return;
    }
    readBlobAsText(blob).then(
      function (text) {
        if (HOST === "browser") {
          // Plain browser — passthrough to the default <a download> path.
          console.warn("QEV: no native bridge; using default download");
          var fallback = document.createElement("a");
          fallback.href = href;
          fallback.download = filename;
          fallback.style.display = "none";
          document.body.appendChild(fallback);
          fallback.setAttribute("data-vault-passthrough", "1");
          fallback.click();
          document.body.removeChild(fallback);
          return;
        }
        bridge
          .saveText({
            filename: filename,
            mime: blob.type || "text/plain",
            text: text,
          })
          .catch(function (err) {
            console.error("QEV: saveText failed:", err);
          });
      },
      function (err) {
        console.error("QEV: blob read failed:", err);
      }
    );
  }

  // Capture-phase click listener. Runs BEFORE the default link
  // navigation handler, so preventDefault actually cancels the
  // WKWebView navigation. Handles bubbling through nested tags
  // (like a span inside the anchor).
  document.addEventListener(
    "click",
    function (ev) {
      var node = ev.target;
      while (node && node !== document) {
        if (
          node.tagName === "A" &&
          node.hasAttribute("download") &&
          !node.hasAttribute("data-vault-passthrough")
        ) {
          ev.preventDefault();
          ev.stopPropagation();
          handleDownloadClick(node);
          return;
        }
        node = node.parentNode;
      }
    },
    true
  );

  // ---------------------------------------------------------------
  // Clipboard bridge.
  //
  // chat.js calls navigator.clipboard.writeText when the user hits
  // "Copy as text." Under both WKWebView (file://) and Tauri
  // (custom protocol), this can be flaky, so we override it to route
  // through the native bridge.
  // ---------------------------------------------------------------

  if (HOST !== "browser" && navigator.clipboard) {
    navigator.clipboard.writeText = function (text) {
      return bridge.copyText(text);
    };
  }

  // ---------------------------------------------------------------
  // Suppress the default WebKit right-click menu. On macOS WKWebView
  // it contains "Inspect Element" and other developer affordances
  // that are wrong for a consumer app. The Edit menu bar item still
  // provides Cut/Copy/Paste/Select All via keyboard shortcuts and
  // menu entries, so nothing the user needs is removed.
  //
  // If we want a custom context menu later (e.g. "Copy decrypted
  // text"), add it here instead of suppressing blanket.
  // ---------------------------------------------------------------

  document.addEventListener("contextmenu", function (ev) {
    ev.preventDefault();
  });

  // ---------------------------------------------------------------
  // Tauri-native file picker.
  //
  // In WKWebView, chat.js's <input type="file"> fires through my
  // WKUIDelegate.runOpenPanelWith which shows an NSOpenPanel sheet.
  // In Tauri, the <input type="file"> is routed by the webview but
  // the native dialog isn't guaranteed to appear the same way —
  // instead we intercept clicks on the file-choose label and call
  // bridge.pickFile() to get a native dialog via the Rust command.
  // The returned {text, filename} is injected directly into the
  // decrypt textarea, bypassing FileReader entirely.
  // ---------------------------------------------------------------

  function wireTauriFilePicker() {
    if (HOST !== "tauri") return;
    // The label's for="vault-decrypt-file" attribute triggers the
    // hidden file input on click. Intercept the label click BEFORE
    // the browser processes the for="" relation, and call our Rust
    // command instead.
    var label = document.querySelector('label[for="vault-decrypt-file"]');
    var textarea = document.getElementById("vault-decrypt-input");
    var status = document.getElementById("vault-decrypt-status");
    if (!label || !textarea) return;

    label.addEventListener(
      "click",
      function (ev) {
        ev.preventDefault();
        ev.stopPropagation();
        bridge.pickFile().then(
          function (result) {
            if (!result) return; // user cancelled
            textarea.value = result.text;
            textarea.dispatchEvent(new Event("input", { bubbles: true }));
            if (status) {
              status.textContent =
                "Loaded " + (result.filename || "file") + ". Now type the password.";
              status.className = "app-status app-status-info";
            }
          },
          function (err) {
            console.error("QEV: pickFile failed:", err);
          }
        );
      },
      true
    );
  }

  // ---------------------------------------------------------------
  // Tab switcher.
  //
  // Runs after DOMContentLoaded so the tab elements exist. Also
  // wires a URL-hash-free state so the tab selection survives a
  // click on the app window title bar (no navigation happens).
  // ---------------------------------------------------------------

  function wireTabs() {
    var tabs = document.querySelectorAll(".app-tab");
    var panels = {
      lock: document.getElementById("app-panel-lock"),
      open: document.getElementById("app-panel-open"),
    };
    if (tabs.length === 0 || !panels.lock || !panels.open) {
      console.error("QEV: tab switcher DOM not found");
      return;
    }

    function activate(target) {
      tabs.forEach(function (t) {
        t.classList.toggle(
          "app-tab-active",
          t.getAttribute("data-app-tab") === target
        );
      });
      Object.keys(panels).forEach(function (k) {
        panels[k].classList.toggle("app-panel-hidden", k !== target);
      });
      // Scroll the newly-shown panel to the top for a clean transition.
      var wrap = document.querySelector(".app-panel-wrap");
      if (wrap) wrap.scrollTop = 0;
    }

    tabs.forEach(function (tab) {
      tab.addEventListener("click", function () {
        activate(tab.getAttribute("data-app-tab"));
      });
    });
  }

  // ---------------------------------------------------------------
  // Focus management — move keyboard focus to the message textarea
  // as soon as the form is enabled, so the user can start typing
  // immediately without clicking.
  // ---------------------------------------------------------------

  function wireFocus() {
    // Watch for the encrypt-submit to become enabled; the init path
    // in chat.js enables it only after the self-test passes. Once
    // it's enabled, set focus to the message textarea.
    var submit = document.getElementById("vault-encrypt-submit");
    var msg = document.getElementById("vault-encrypt-message");
    if (!submit || !msg) return;

    var focused = false;
    function tryFocus() {
      if (!focused && !submit.disabled) {
        msg.focus();
        focused = true;
      }
    }
    // Poll briefly — cheaper than a MutationObserver and guaranteed
    // to resolve in at most ~2 seconds on any machine.
    var tries = 0;
    var iv = setInterval(function () {
      tries++;
      tryFocus();
      if (focused || tries > 40) clearInterval(iv);
    }, 100);
  }

  // ---------------------------------------------------------------
  // Init
  // ---------------------------------------------------------------

  function init() {
    wireTabs();
    wireFocus();
    wireTauriFilePicker();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
