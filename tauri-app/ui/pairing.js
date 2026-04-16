// pairing.js — QEV Phase 2 pairing UI glue.
//
// Drives the four Tauri commands exposed in src-tauri/src/lib.rs:
//
//   pairing_show_qr(name, device)   → { qr_text, qr_svg, own_public_hex, listen_port }
//   pairing_preview_invite(qr_text) → { name, device, public_hex, addrs, expires_at }
//   pairing_accept_invite(qr_text)  → PairedPeer { id, peer_name, peer_device, safety_number, peer_addrs }
//   pairing_send_vault(...)         → void
//
// Plus a listener on the Tauri event 'pairing://complete' that
// the show_qr command emits when the responder side accepts its
// first connection.
//
// NO LOGGING of vault bytes, safety numbers, or public keys beyond
// what the UI itself displays. Any console.log of user data is a
// bug.
//
// The whole file is scoped inside an IIFE to avoid leaking names
// into the global object the main chat.js uses.

(function () {
  "use strict";

  // Shorthand wrappers around Tauri's IPC.
  //
  // We don't rely on the @tauri-apps/api NPM package because the
  // tauri-app UI bundle is kept dependency-free — the only scripts
  // it loads are sodium.js, chat.js, app.js, jsQR (vendored), and
  // this file. window.__TAURI__ is injected by the Tauri shell at
  // page load and is stable across versions of Tauri v2.
  const tauri = window.__TAURI__;
  if (!tauri) {
    // Pairing is native-only for now. If the page is loaded in a
    // plain browser (file:// or https for testing), the pairing
    // tab shows a disabled notice instead of the functional UI.
    return;
  }
  const invoke = tauri.core && tauri.core.invoke ? tauri.core.invoke : tauri.invoke;
  const listen = tauri.event && tauri.event.listen ? tauri.event.listen : null;

  // --- DOM ----------------------------------------------------

  const $ = (id) => document.getElementById(id);
  const pair = {
    tab: $("app-tab-pair"),
    panel: $("app-panel-pair"),

    // "Show QR" sub-flow
    showBtn: $("pair-show-btn"),
    showNameInput: $("pair-show-name"),
    showDeviceInput: $("pair-show-device"),
    qrBox: $("pair-qr-box"),
    qrSvg: $("pair-qr-svg"),
    qrText: $("pair-qr-text"),
    qrStatus: $("pair-qr-status"),

    // "Scan to pair" sub-flow
    scanBtn: $("pair-scan-btn"),
    scanVideo: $("pair-scan-video"),
    scanPasteInput: $("pair-scan-paste"),
    scanPasteBtn: $("pair-scan-paste-btn"),
    scanPreviewBox: $("pair-scan-preview"),
    scanAcceptBtn: $("pair-scan-accept-btn"),
    scanResultBox: $("pair-scan-result"),
    scanStatus: $("pair-scan-status"),
  };

  // Early exit if none of the pairing DOM is present. This lets
  // the file coexist with the older Tauri UI that didn't have a
  // Pair tab — pages that don't include the Pair markup simply
  // get a no-op.
  if (!pair.tab) return;

  let scanStream = null;
  let scanAnimFrame = null;
  let pendingPreview = null;

  // --- Tab wiring ---------------------------------------------

  pair.tab.addEventListener("click", () => {
    setStatus(pair.qrStatus, "", "");
    setStatus(pair.scanStatus, "", "");
  });

  // --- SHOW QR (responder) ------------------------------------

  pair.showBtn.addEventListener("click", async () => {
    const name = (pair.showNameInput.value || "").trim();
    const device = (pair.showDeviceInput.value || "").trim();
    if (!name || !device) {
      setStatus(pair.qrStatus, "Enter a name and a device label first.", "err");
      return;
    }
    pair.showBtn.disabled = true;
    setStatus(pair.qrStatus, "Starting listener and generating QR...", "info");
    try {
      const result = await invoke("pairing_show_qr", { name, device });
      pair.qrSvg.innerHTML = result.qr_svg;
      pair.qrText.textContent = result.qr_text;
      pair.qrBox.classList.remove("app-hidden");
      setStatus(
        pair.qrStatus,
        `Ready. Listening on port ${result.listen_port}. Show this QR to the other device.`,
        "ok",
      );
    } catch (err) {
      setStatus(pair.qrStatus, String(err), "err");
    } finally {
      pair.showBtn.disabled = false;
    }
  });

  // Listen for the 'pairing://complete' event emitted by the
  // background responder task when the handshake succeeds (or
  // fails). The event's payload is { status: "ok", peer: {...} }
  // or { status: "error", error: "..." }.
  if (listen) {
    listen("pairing://complete", (event) => {
      const payload = event.payload;
      if (!payload) return;
      if (payload.status === "ok" && payload.peer) {
        setStatus(
          pair.qrStatus,
          `Pairing completed. Safety number: ${payload.peer.safety_number}`,
          "ok",
        );
      } else {
        setStatus(
          pair.qrStatus,
          "Pairing failed: " + (payload.error || "unknown error"),
          "err",
        );
      }
    });
  }

  // --- SCAN TO PAIR (initiator) -------------------------------
  //
  // Two paths to feed the QR content in:
  //
  //   1. Live camera — getUserMedia + canvas + jsQR decode loop.
  //      Preferred on phones where a rear camera is available.
  //
  //   2. Paste box — user can paste the base64url invite text
  //      directly. Used when the camera path is unavailable
  //      (permissions denied, no camera, desktop build without
  //      a webcam, or the user prefers to transfer the invite
  //      over a different channel like AirDrop or a shared doc).

  pair.scanBtn.addEventListener("click", async () => {
    if (scanStream) {
      stopScanner();
      return;
    }
    try {
      setStatus(pair.scanStatus, "Requesting camera access...", "info");
      scanStream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: "environment" },
        audio: false,
      });
      pair.scanVideo.srcObject = scanStream;
      pair.scanVideo.setAttribute("playsinline", "true");
      await pair.scanVideo.play();
      setStatus(pair.scanStatus, "Camera on. Point at a QEV pairing QR.", "info");
      pair.scanBtn.textContent = "Stop camera";
      runScanLoop();
    } catch (err) {
      setStatus(pair.scanStatus, "Camera denied or unavailable: " + err, "err");
      stopScanner();
    }
  });

  pair.scanPasteBtn.addEventListener("click", async () => {
    const txt = (pair.scanPasteInput.value || "").trim();
    if (!txt) {
      setStatus(pair.scanStatus, "Paste the invite text first.", "err");
      return;
    }
    await previewInvite(txt);
  });

  function runScanLoop() {
    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d");
    const tick = () => {
      if (!scanStream) return; // stopped
      if (pair.scanVideo.readyState !== pair.scanVideo.HAVE_ENOUGH_DATA) {
        scanAnimFrame = requestAnimationFrame(tick);
        return;
      }
      canvas.width = pair.scanVideo.videoWidth;
      canvas.height = pair.scanVideo.videoHeight;
      ctx.drawImage(pair.scanVideo, 0, 0, canvas.width, canvas.height);
      const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      // jsQR is loaded from ./vendor/jsQR.js in a <script> tag
      // before this file.
      // eslint-disable-next-line no-undef
      const code = window.jsQR
        ? window.jsQR(imgData.data, imgData.width, imgData.height)
        : null;
      if (code && code.data) {
        stopScanner();
        previewInvite(code.data);
        return;
      }
      scanAnimFrame = requestAnimationFrame(tick);
    };
    tick();
  }

  function stopScanner() {
    if (scanAnimFrame) cancelAnimationFrame(scanAnimFrame);
    scanAnimFrame = null;
    if (scanStream) {
      scanStream.getTracks().forEach((t) => t.stop());
      scanStream = null;
    }
    pair.scanVideo.srcObject = null;
    pair.scanBtn.textContent = "Scan QR with camera";
  }

  async function previewInvite(qrText) {
    try {
      setStatus(pair.scanStatus, "Verifying invite...", "info");
      const preview = await invoke("pairing_preview_invite", { qrText });
      pendingPreview = { qr_text: qrText, preview };
      renderPreview(preview);
    } catch (err) {
      setStatus(pair.scanStatus, "Invite rejected: " + err, "err");
    }
  }

  function renderPreview(preview) {
    pair.scanPreviewBox.classList.remove("app-hidden");
    pair.scanPreviewBox.innerHTML = `
      <div class="pair-preview-row"><b>Peer name:</b> ${escapeHtml(preview.name)}</div>
      <div class="pair-preview-row"><b>Peer device:</b> ${escapeHtml(preview.device)}</div>
      <div class="pair-preview-row"><b>Peer public key:</b> <code>${escapeHtml(preview.public_hex)}</code></div>
      <div class="pair-preview-row"><b>Addresses:</b> ${preview.addrs.map(escapeHtml).join(", ")}</div>
      <div class="pair-preview-row"><b>Expires:</b> ${escapeHtml(preview.expires_at)}</div>
    `;
    pair.scanAcceptBtn.classList.remove("app-hidden");
    pair.scanAcceptBtn.disabled = false;
  }

  pair.scanAcceptBtn.addEventListener("click", async () => {
    if (!pendingPreview) return;
    pair.scanAcceptBtn.disabled = true;
    setStatus(pair.scanStatus, "Connecting and running handshake...", "info");
    try {
      const peer = await invoke("pairing_accept_invite", {
        qrText: pendingPreview.qr_text,
      });
      renderResult(peer);
      setStatus(pair.scanStatus, "Paired.", "ok");
    } catch (err) {
      setStatus(pair.scanStatus, "Pairing failed: " + err, "err");
    } finally {
      pair.scanAcceptBtn.disabled = false;
    }
  });

  function renderResult(peer) {
    pair.scanResultBox.classList.remove("app-hidden");
    pair.scanResultBox.innerHTML = `
      <h4>Paired with ${escapeHtml(peer.peer_name)} / ${escapeHtml(peer.peer_device)}</h4>
      <div class="pair-preview-row"><b>Peer ID:</b> <code>${escapeHtml(peer.id)}</code></div>
      <div class="pair-preview-row"><b>Safety number:</b></div>
      <div class="pair-safety-number">${escapeHtml(peer.safety_number)}</div>
      <p class="pair-safety-hint">
        Compare this number out loud with ${escapeHtml(peer.peer_name)}.
        If it matches on both devices, the pairing is verified.
        If it does NOT match, something is wrong — abort and try again.
      </p>
    `;
  }

  // --- SEND TO PEER (from Lock tab) ----------------------------
  //
  // After a vault is locked, the user can click 'Send to paired
  // peer...' on the result card. We open a modal with the list
  // of peers returned by pairing_peers_list(), the user picks
  // one, and we call pairing_send_vault() with the just-locked
  // vault bytes + filename.
  //
  // The button is hidden by default; we un-hide it at init time
  // iff we're running in Tauri AND pairing_peers_list returns
  // at least one peer. That way the button doesn't appear in
  // the browser-only build or on a brand-new install with no
  // paired peers.

  const sendBtn = $("vault-send-peer-btn");
  const sendModal = $("vault-send-peer-modal");
  const sendList = $("vault-send-peer-list");
  const sendCancel = $("vault-send-peer-cancel");

  async function refreshSendButtonVisibility() {
    if (!sendBtn) return;
    try {
      const peers = await invoke("pairing_peers_list");
      if (Array.isArray(peers) && peers.length > 0) {
        sendBtn.classList.remove("app-hidden");
      } else {
        sendBtn.classList.add("app-hidden");
      }
    } catch (_e) {
      sendBtn.classList.add("app-hidden");
    }
  }

  // Watch the vault-encrypt-result visibility. When it appears
  // (user just locked a vault), refresh the send button.
  const encryptResult = document.getElementById("vault-encrypt-result");
  if (encryptResult) {
    const obs = new MutationObserver(() => {
      if (!encryptResult.classList.contains("vault-hidden")) {
        refreshSendButtonVisibility();
      }
    });
    obs.observe(encryptResult, { attributes: true, attributeFilter: ["class"] });
  }

  if (sendBtn) {
    sendBtn.addEventListener("click", async () => {
      try {
        const peers = await invoke("pairing_peers_list");
        openSendModal(peers || []);
      } catch (err) {
        alert("Could not load peers: " + err);
      }
    });
  }
  if (sendCancel) {
    sendCancel.addEventListener("click", () => {
      if (sendModal) sendModal.classList.add("app-hidden");
    });
  }

  function openSendModal(peers) {
    if (!sendList || !sendModal) return;
    sendList.innerHTML = "";
    peers.forEach((peer) => {
      const row = document.createElement("div");
      row.className = "pair-send-peer-row";
      const trustClass =
        peer.trust === "verified"
          ? "pair-send-peer-trust-verified"
          : "pair-send-peer-trust-unverified";
      row.innerHTML = `
        <div class="pair-send-peer-info">
          <div class="name">${escapeHtml(peer.peer_name)}</div>
          <div class="device">${escapeHtml(peer.peer_device)}</div>
        </div>
        <span class="pair-send-peer-trust ${trustClass}">${escapeHtml(peer.trust)}</span>
      `;
      row.addEventListener("click", () => sendToPeer(peer));
      sendList.appendChild(row);
    });
    sendModal.classList.remove("app-hidden");
  }

  async function sendToPeer(peer) {
    // Pull the just-locked vault bytes from the result JSON box.
    // chat.js renders the vault as pretty-printed JSON there; we
    // re-serialize it for the send.
    const resultJson = document.getElementById("vault-encrypt-result-json");
    if (!resultJson || !resultJson.textContent.trim()) {
      alert("No locked vault found. Lock a message first.");
      return;
    }
    let vaultObj;
    try {
      vaultObj = JSON.parse(resultJson.textContent);
    } catch (e) {
      alert("Could not parse locked vault JSON: " + e);
      return;
    }
    const vaultBytes = new TextEncoder().encode(JSON.stringify(vaultObj));
    const filename = `vault-${new Date().toISOString().slice(0, 10)}.vault.json`;

    if (sendModal) sendModal.classList.add("app-hidden");
    try {
      // Tauri's invoke automatically coerces Uint8Array -> Vec<u8>
      // for the Rust side via serde_bytes.
      await invoke("pairing_send_vault", {
        peerId: peer.id,
        vaultBytes: Array.from(vaultBytes),
        filename,
        note: null,
      });
      alert(`Sent to ${peer.peer_name}.`);
    } catch (err) {
      alert("Send failed: " + err);
    }
  }

  // --- utils --------------------------------------------------

  function setStatus(el, text, kind) {
    if (!el) return;
    el.textContent = text;
    el.className = "app-status" + (kind ? " app-status-" + kind : "");
  }

  function escapeHtml(s) {
    return String(s || "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }
})();
