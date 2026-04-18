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

  const tauri = window.__TAURI__;
  if (!tauri) {
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

  pair.tab.onclick = function () {
    setStatus(pair.qrStatus, "", "");
    setStatus(pair.scanStatus, "", "");
  };

  // --- SHOW QR (responder) ------------------------------------

  pair.showBtn.onclick = function () {
    var self = this;
    self.textContent = "Working...";
    var name = (pair.showNameInput.value || "").trim();
    var device = (pair.showDeviceInput.value || "").trim();
    if (!name || !device) {
      setStatus(pair.qrStatus, "Enter a name and a device label first.", "err");
      self.textContent = "Show QR";
      return;
    }
    self.disabled = true;
    setStatus(pair.qrStatus, "Starting listener and generating QR...", "info");

    // Snapshot current peers BEFORE showing QR so we can detect new ones
    var peersBefore = [];
    invoke("pairing_peers_list").then(function (list) {
      peersBefore = (list || []).map(function (p) { return p.id; });
    }).catch(function () {});

    invoke("pairing_show_qr", { name: name, device: device }).then(function (result) {
      pair.qrSvg.innerHTML = result.qr_svg;
      pair.qrText.textContent = result.qr_text;
      pair.qrBox.classList.remove("app-hidden");
      setStatus(
        pair.qrStatus,
        "Waiting for the other device to scan this QR...",
        "ok",
      );

      // Poll for new peers every 2 seconds. When a new peer appears,
      // the handshake completed — show safety number.
      var pollCount = 0;
      var pairingPoll = setInterval(function () {
        pollCount++;
        if (pollCount > 150) { // 5 minutes max
          clearInterval(pairingPoll);
          setStatus(pair.qrStatus, "Timed out waiting. Try again.", "err");
          return;
        }
        invoke("pairing_peers_list").then(function (list) {
          var current = (list || []).map(function (p) { return p.id; });
          // Find new peer IDs
          for (var i = 0; i < current.length; i++) {
            if (peersBefore.indexOf(current[i]) === -1) {
              // NEW PEER! Pairing completed.
              clearInterval(pairingPoll);
              var newPeer = list.filter(function (p) { return p.id === current[i]; })[0];
              // Get the safety number for in-person verification, then prompt for shared phrase
              invoke("pairing_safety_number", { peerId: current[i] }).then(function (sn) {
                pair.qrBox.classList.add("app-hidden");
                setStatus(
                  pair.qrStatus,
                  "Paired with " + escapeHtml(newPeer.peer_name) + "!\n\nSafety number:\n" + sn +
                  "\n\nCompare this number with " + escapeHtml(newPeer.peer_name) + " in person.\nIf it matches, set your shared chat phrase next.",
                  "ok",
                );
                // Prompt for shared phrase right now — both sides are together
                setTimeout(function () {
                  if (window.qevShowPhraseDialog) {
                    window.qevShowPhraseDialog(newPeer.peer_name, function (phrase) {
                      if (phrase && window.qevSetPhraseForPeer) {
                        window.qevSetPhraseForPeer(current[i], phrase);
                        setStatus(
                          pair.qrStatus,
                          "Paired with " + escapeHtml(newPeer.peer_name) + ". Shared phrase saved. Go to Chat to start messaging.",
                          "ok",
                        );
                      }
                    });
                  }
                }, 400);
              }).catch(function () {
                pair.qrBox.classList.add("app-hidden");
                setStatus(
                  pair.qrStatus,
                  "Paired with " + escapeHtml(newPeer.peer_name) + "! Go to Chat to start messaging.",
                  "ok",
                );
              });
              self.disabled = false;
              self.textContent = "Show QR";
              return;
            }
          }
        }).catch(function () {});
      }, 2000);

    }).catch(function (err) {
      setStatus(pair.qrStatus, String(err), "err");
      self.disabled = false;
      self.textContent = "Show QR";
    });
  };

  // NOTE: pairing://complete events are replaced by polling above.
  // Polling is more reliable across Tauri v2 capability configs.

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

  pair.scanBtn.onclick = async function () {
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
  };

  pair.scanPasteBtn.onclick = async function () {
    const txt = (pair.scanPasteInput.value || "").trim();
    if (!txt) {
      setStatus(pair.scanStatus, "Paste the invite text first.", "err");
      return;
    }
    await previewInvite(txt);
  };

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

  pair.scanAcceptBtn.onclick = async function () {
    if (!pendingPreview) return;
    // The accept command needs our own name/device for the identity.
    // Reuse the "Show QR" fields — they're on the same panel.
    var ownName = (pair.showNameInput.value || "").trim() || "user";
    var ownDevice = (pair.showDeviceInput.value || "").trim() || "device";
    pair.scanAcceptBtn.disabled = true;
    setStatus(pair.scanStatus, "Connecting and running handshake...", "info");
    try {
      const peer = await invoke("pairing_accept_invite", {
        qrText: pendingPreview.qr_text,
        ownName: ownName,
        ownDevice: ownDevice,
      });
      renderResult(peer);
      setStatus(pair.scanStatus, "Paired. Compare the safety number in person, then set your shared chat phrase.", "ok");
      // Prompt for shared phrase right now — both sides are together
      setTimeout(function () {
        if (window.qevShowPhraseDialog) {
          window.qevShowPhraseDialog(peer.peer_name, function (phrase) {
            if (phrase && window.qevSetPhraseForPeer) {
              window.qevSetPhraseForPeer(peer.id, phrase);
              setStatus(pair.scanStatus, "Shared phrase saved. Go to Chat to start messaging.", "ok");
            }
          });
        }
      }, 400);
    } catch (err) {
      setStatus(pair.scanStatus, "Pairing failed: " + err, "err");
    } finally {
      pair.scanAcceptBtn.disabled = false;
    }
  };

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
    // Group peers by name for a cleaner display.
    // "alice (laptop)" and "alice (phone)" group under "alice".
    // Each device still gets its own send/unpair action.
    peers.forEach((peer) => {
      const row = document.createElement("div");
      row.className = "pair-send-peer-row";
      const trustClass =
        peer.trust === "verified"
          ? "pair-send-peer-trust-verified"
          : "pair-send-peer-trust-unverified";
      row.innerHTML = `
        <div class="pair-send-peer-info" data-action="send">
          <div class="name">${escapeHtml(peer.peer_name)}</div>
          <div class="device">${escapeHtml(peer.peer_device)}</div>
        </div>
        <span class="pair-send-peer-trust ${trustClass}">${escapeHtml(peer.trust)}</span>
        <button class="pair-unpair-btn" title="Unpair this device">&times;</button>
      `;
      // Click the info area to send
      row.querySelector("[data-action=send]").addEventListener("click", () => sendToPeer(peer));
      // Click the × to unpair
      row.querySelector(".pair-unpair-btn").addEventListener("click", async (ev) => {
        ev.stopPropagation();
        if (!confirm(`Unpair ${peer.peer_name} / ${peer.peer_device}? This cannot be undone.`)) return;
        try {
          await invoke("pairing_unpair", { peerId: peer.id });
          row.remove();
          // If no peers left, close modal
          if (sendList.children.length === 0) {
            sendModal.classList.add("app-hidden");
            sendBtn.classList.add("app-hidden");
          }
        } catch (err) {
          alert("Unpair failed: " + err);
        }
      });
      sendList.appendChild(row);
    });
    sendModal.classList.remove("app-hidden");
  }

  async function sendToPeer(peer) {
    // Pull the just-locked vault bytes from the result JSON box.
    const resultJson = document.getElementById("vault-encrypt-result-json");
    if (!resultJson || !resultJson.textContent.trim()) {
      alert("No locked vault found. Lock a message first.");
      return;
    }
    let vaultJson;
    try {
      vaultJson = resultJson.textContent.trim();
      JSON.parse(vaultJson); // validate
    } catch (e) {
      alert("Could not parse locked vault JSON: " + e);
      return;
    }

    // Check if user wants to add an extra seal phrase.
    const sealCheckbox = document.getElementById("pair-send-seal-check");
    let finalPayload = vaultJson;

    if (sealCheckbox && sealCheckbox.checked) {
      const sealPhrase = prompt(
        "Enter a seal phrase for extra protection.\n\n" +
        "The recipient will need BOTH this seal phrase AND the " +
        "original vault phrase to read the message.\n\n" +
        "Use a different phrase from the vault phrase."
      );
      if (!sealPhrase) {
        alert("Seal cancelled — message not sent.");
        return;
      }
      try {
        finalPayload = await invoke("seal_vault_cmd", {
          innerVaultJson: vaultJson,
          sealPhrase,
        });
      } catch (err) {
        alert("Seal failed: " + err);
        return;
      }
    }

    const vaultBytes = new TextEncoder().encode(finalPayload);
    const filename = `vault-${new Date().toISOString().slice(0, 10)}.vault.json`;

    if (sendModal) sendModal.classList.add("app-hidden");
    try {
      await invoke("pairing_send_vault", {
        peerId: peer.id,
        vaultBytes: Array.from(vaultBytes),
        filename,
        note: null,
      });
      alert(`Sent to ${peer.peer_name}${sealCheckbox?.checked ? " (sealed)" : ""}.`);
    } catch (err) {
      // If direct P2P fails, offer relay fallback.
      if (confirm(`Direct send failed: ${err}\n\nTry sending via relay instead?`)) {
        try {
          await invoke("relay_send_to_peer", {
            peerId: peer.id,
            vaultBytes: Array.from(vaultBytes),
            filename,
            note: null,
          });
          alert(`Sent via relay to ${peer.peer_name}${sealCheckbox?.checked ? " (sealed)" : ""}.`);
        } catch (relayErr) {
          alert("Relay send also failed: " + relayErr);
        }
      }
    }
  }

  // --- RELAY INBOX --------------------------------------------
  //
  // A 'Check relay inbox' button on the Pair tab. Calls
  // relay_fetch_inbox() and displays any waiting envelopes.

  const inboxBtn = document.getElementById("pair-relay-inbox-btn");
  const inboxList = document.getElementById("pair-relay-inbox-list");

  if (inboxBtn) {
    inboxBtn.addEventListener("click", async () => {
      inboxBtn.disabled = true;
      inboxBtn.textContent = "Checking...";
      try {
        const envelopes = await invoke("relay_fetch_inbox");
        renderInbox(envelopes || []);
      } catch (err) {
        if (inboxList) {
          inboxList.innerHTML = `<div class="pair-hint" style="color:var(--text-dim)">Relay unreachable: ${escapeHtml(String(err))}</div>`;
        }
      } finally {
        inboxBtn.disabled = false;
        inboxBtn.textContent = "Check relay inbox";
      }
    });
  }

  function renderInbox(envelopes) {
    if (!inboxList) return;
    if (envelopes.length === 0) {
      inboxList.innerHTML = '<div class="pair-hint">No pending envelopes.</div>';
      return;
    }
    inboxList.innerHTML = "";
    envelopes.forEach((env, i) => {
      const row = document.createElement("div");
      row.className = "pair-inbox-row";
      row.innerHTML = `
        <div class="pair-inbox-from">From: <code>${escapeHtml(env.from_hex.slice(0, 16))}...</code></div>
        <div class="pair-inbox-time">${new Date(env.created_at).toLocaleString()}</div>
        <button class="app-btn-small" data-env-idx="${i}">Open</button>
      `;
      row.querySelector("button").addEventListener("click", async () => {
        let payload = env.payload;
        // Check if this is a sealed vault — if so, prompt for
        // the seal phrase first to unwrap the outer layer.
        try {
          const sealed = await invoke("is_sealed_cmd", { jsonStr: payload });
          if (sealed) {
            const sealPhrase = prompt(
              "This message has an extra seal.\n\n" +
              "Enter the seal phrase the sender shared with you " +
              "(this is separate from the vault phrase):"
            );
            if (!sealPhrase) return;
            payload = await invoke("unseal_vault_cmd", {
              sealedJson: payload,
              sealPhrase,
            });
          }
        } catch (err) {
          alert("Unseal failed: " + err);
          return;
        }
        // Put the (possibly-unsealed) vault JSON into the
        // decrypt tab's textarea and switch to that tab.
        const ta = document.getElementById("vault-decrypt-input");
        if (ta) ta.value = payload;
        const openTab = document.querySelector('[data-app-tab="open"]');
        if (openTab) openTab.click();
      });
      inboxList.appendChild(row);
    });
    // Auto-ack.
    const ackIds = envelopes.map((e) => e.id);
    invoke("relay_ack_envelopes", { idsHex: ackIds }).catch(() => {});
  }

  // --- RELAY SEND OPTION IN PEER PICKER -----------------------
  //
  // When the peer picker modal lists peers, add a "Via relay"
  // secondary option next to each peer row. Clicking it calls
  // relay_send_to_peer instead of pairing_send_vault.

  // Monkey-patch the openSendModal function to add relay buttons.
  const _origOpenSendModal = window._qev_openSendModal;
  // (We can't easily monkey-patch because it's closure-scoped.
  // Instead, we'll modify the sendToPeer function to detect a
  // data attribute indicating "use relay" and dispatch accordingly.
  // This is done inside the sendToPeer function above: it always
  // tries direct first, then falls back to relay.)

  // For now, the 'Send to paired peer' button tries direct P2P.
  // If the user can't reach the peer on the LAN, the UI shows
  // an error with a "Try via relay?" hint. Phase 3.x.4 adds a
  // proper fallback.

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

  // ========== Identity backup & restore ==========
  //
  // Wraps the three Tauri commands added in src/lib.rs:
  //   identity_backup_status() → { has_identity, has_never_backed_up,
  //                                last_backup_at, peer_count }
  //   export_identity_backup(passphrase) → String (envelope JSON)
  //   import_identity_backup(envelope_json, passphrase) →
  //       { own_public_hex, name, device, peers_restored,
  //         backup_created_at }
  //
  // Plus the UI layer:
  //   - top-of-app at-risk banner when the user has paired but
  //     never backed up
  //   - an export panel (passphrase + confirm → save-file dialog)
  //   - an import panel (pick-file → passphrase → restore)

  const backupEls = {
    banner: document.getElementById("identity-risk-banner"),
    bannerDetail: document.getElementById("identity-risk-banner-detail"),
    bannerPeerCount: document.getElementById("identity-risk-peer-count"),
    bannerCTA: document.getElementById("identity-risk-banner-cta"),
    bannerDismiss: document.getElementById("identity-risk-banner-dismiss"),
    statusText: document.getElementById("identity-backup-status-text"),
    exportBtn: document.getElementById("backup-export-btn"),
    importBtn: document.getElementById("backup-import-btn"),
    exportPanel: document.getElementById("backup-export-panel"),
    importPanel: document.getElementById("backup-import-panel"),
    exportPass: document.getElementById("backup-export-passphrase"),
    exportPassConfirm: document.getElementById("backup-export-passphrase-confirm"),
    exportGoBtn: document.getElementById("backup-export-go-btn"),
    exportCancelBtn: document.getElementById("backup-export-cancel-btn"),
    exportStatus: document.getElementById("backup-export-status"),
    importPickBtn: document.getElementById("backup-import-pick-btn"),
    importFilename: document.getElementById("backup-import-filename"),
    importPass: document.getElementById("backup-import-passphrase"),
    importGoBtn: document.getElementById("backup-import-go-btn"),
    importCancelBtn: document.getElementById("backup-import-cancel-btn"),
    importStatus: document.getElementById("backup-import-status"),
  };

  // Loaded backup text kept in closure until the user clicks
  // Restore. Never persisted.
  let loadedBackupJson = null;
  const RISK_DISMISS_KEY = "qev_identity_risk_banner_dismissed_this_session";

  async function refreshBackupStatus() {
    try {
      const st = await invoke("identity_backup_status");
      // Banner: show only if user has an identity AND paired peers
      // AND has never backed up AND hasn't dismissed this session.
      const dismissed =
        sessionStorage.getItem(RISK_DISMISS_KEY) === "1";
      const shouldShow =
        st.has_identity &&
        st.peer_count > 0 &&
        st.has_never_backed_up &&
        !dismissed;
      if (backupEls.banner) {
        backupEls.banner.hidden = !shouldShow;
        if (shouldShow && backupEls.bannerPeerCount) {
          backupEls.bannerPeerCount.textContent = String(st.peer_count);
        }
      }
      // Status line in the backup section.
      if (backupEls.statusText) {
        if (!st.has_identity) {
          backupEls.statusText.textContent =
            "No identity yet — pair a device first, then back up.";
        } else if (st.has_never_backed_up) {
          backupEls.statusText.innerHTML =
            "<strong>You've never backed up your identity.</strong> " +
            "If you lose this Mac without a backup, you'll need to re-pair every device.";
        } else {
          const when = st.last_backup_at.replace("T", " ").slice(0, 19);
          backupEls.statusText.textContent =
            "Last backup: " + when + " (UTC). Refresh your backup after major changes.";
        }
      }
    } catch (e) {
      console.warn("identity_backup_status failed:", e);
    }
  }

  function hideBackupPanels() {
    if (backupEls.exportPanel) backupEls.exportPanel.classList.add("app-hidden");
    if (backupEls.importPanel) backupEls.importPanel.classList.add("app-hidden");
    if (backupEls.exportPass) backupEls.exportPass.value = "";
    if (backupEls.exportPassConfirm) backupEls.exportPassConfirm.value = "";
    if (backupEls.importPass) backupEls.importPass.value = "";
    if (backupEls.importFilename) {
      backupEls.importFilename.classList.add("app-hidden");
      backupEls.importFilename.textContent = "";
    }
    if (backupEls.importGoBtn) backupEls.importGoBtn.disabled = true;
    loadedBackupJson = null;
    setStatus(backupEls.exportStatus, "");
    setStatus(backupEls.importStatus, "");
  }

  function openExportPanel() {
    hideBackupPanels();
    if (backupEls.exportPanel) backupEls.exportPanel.classList.remove("app-hidden");
    if (backupEls.exportPass) backupEls.exportPass.focus();
  }

  function openImportPanel() {
    hideBackupPanels();
    if (backupEls.importPanel) backupEls.importPanel.classList.remove("app-hidden");
  }

  function switchToPairTab() {
    // The pairing tab's click handler is bound via a data-app-tab
    // attribute in chat.js; just click it programmatically.
    const pairTab = document.getElementById("app-tab-pair");
    if (pairTab) pairTab.click();
  }

  async function onExportGo() {
    const pass = backupEls.exportPass?.value || "";
    const confirm = backupEls.exportPassConfirm?.value || "";
    if (pass.length < 12) {
      setStatus(backupEls.exportStatus, "Passphrase must be at least 12 characters.", "err");
      return;
    }
    if (pass !== confirm) {
      setStatus(backupEls.exportStatus, "Passphrases don't match.", "err");
      return;
    }
    setStatus(backupEls.exportStatus, "Encrypting backup…");
    backupEls.exportGoBtn.disabled = true;

    // Watchdog: if no status transition happens in 6 seconds, surface
    // a hint that a macOS Keychain prompt or save dialog might be
    // hidden behind the app window. Without this hint, a stuck prompt
    // looks indistinguishable from a crashed app.
    let watchdogFired = false;
    const watchdog = setTimeout(() => {
      watchdogFired = true;
      setStatus(
        backupEls.exportStatus,
        "Still waiting… if your macOS password prompt or save dialog is hidden behind the window, " +
          "click outside this app (Cmd+Tab) or check your menu bar. If it's truly stuck, press Cancel " +
          "and try again.",
        "warn"
      );
    }, 6000);

    try {
      const envelope = await invoke("export_identity_backup", { passphrase: pass });
      // Keychain unwrap + crypto done. Tell the user what's next so
      // the save dialog (next phase) has narrative context instead of
      // popping out of nowhere or getting buried.
      if (!watchdogFired) {
        setStatus(backupEls.exportStatus, "Encrypted. Pick where to save the backup file…");
      }
      const date = new Date().toISOString().slice(0, 10);
      const filename = `qev-identity-backup-${date}.json`;
      const saveResult = await invoke("save_vault_file", {
        payload: { filename, text: envelope },
      });
      clearTimeout(watchdog);
      if (saveResult && saveResult.saved) {
        setStatus(
          backupEls.exportStatus,
          "Backup saved to " + (saveResult.path || filename) +
            ". Keep it somewhere safe — 1Password, encrypted USB, or similar. The passphrase is the only thing protecting it.",
          "ok"
        );
        await refreshBackupStatus();
      } else {
        setStatus(backupEls.exportStatus, "Save cancelled.");
      }
    } catch (e) {
      clearTimeout(watchdog);
      setStatus(backupEls.exportStatus, "Export failed: " + (e?.toString() || "unknown"), "err");
    } finally {
      clearTimeout(watchdog);
      backupEls.exportGoBtn.disabled = false;
    }
  }

  async function onImportPick() {
    try {
      const result = await invoke("pick_vault_file");
      if (!result || !result.loaded) {
        setStatus(backupEls.importStatus, "No file picked.");
        return;
      }
      loadedBackupJson = result.text;
      if (backupEls.importFilename) {
        backupEls.importFilename.textContent = "Loaded: " + (result.filename || "backup file");
        backupEls.importFilename.classList.remove("app-hidden");
      }
      if (backupEls.importGoBtn) backupEls.importGoBtn.disabled = false;
      setStatus(backupEls.importStatus, "Enter the passphrase that locks this backup.");
    } catch (e) {
      setStatus(backupEls.importStatus, "Pick failed: " + (e?.toString() || "unknown"), "err");
    }
  }

  async function onImportGo() {
    if (!loadedBackupJson) {
      setStatus(backupEls.importStatus, "Pick a backup file first.", "err");
      return;
    }
    const pass = backupEls.importPass?.value || "";
    if (!pass) {
      setStatus(backupEls.importStatus, "Enter the passphrase.", "err");
      return;
    }
    setStatus(backupEls.importStatus, "Decrypting & restoring…");
    backupEls.importGoBtn.disabled = true;
    try {
      const r = await invoke("import_identity_backup", {
        envelopeJson: loadedBackupJson,
        passphrase: pass,
      });
      setStatus(
        backupEls.importStatus,
        "Restored. You are now " +
          escapeHtml(r.name) + " (" + escapeHtml(r.device) + ") · fingerprint " +
          (r.own_public_hex || "").slice(0, 16) + " · " +
          r.peers_restored + " peer(s) merged from backup. " +
          "Reload the app to see your peers.",
        "ok"
      );
      loadedBackupJson = null;
      await refreshBackupStatus();
    } catch (e) {
      setStatus(backupEls.importStatus, "Restore failed: " + (e?.toString() || "unknown"), "err");
    } finally {
      backupEls.importGoBtn.disabled = false;
    }
  }

  // ---- Wire up listeners (defensive — elements may not exist on
  //      older index.html versions) ----
  if (backupEls.exportBtn) backupEls.exportBtn.addEventListener("click", openExportPanel);
  if (backupEls.importBtn) backupEls.importBtn.addEventListener("click", openImportPanel);
  if (backupEls.exportGoBtn) backupEls.exportGoBtn.addEventListener("click", onExportGo);
  if (backupEls.exportCancelBtn)
    backupEls.exportCancelBtn.addEventListener("click", hideBackupPanels);
  if (backupEls.importPickBtn) backupEls.importPickBtn.addEventListener("click", onImportPick);
  if (backupEls.importGoBtn) backupEls.importGoBtn.addEventListener("click", onImportGo);
  if (backupEls.importCancelBtn)
    backupEls.importCancelBtn.addEventListener("click", hideBackupPanels);
  if (backupEls.bannerCTA) {
    backupEls.bannerCTA.addEventListener("click", () => {
      switchToPairTab();
      // Give the tab a beat to render before we scroll & open.
      setTimeout(() => {
        const section = document.getElementById("identity-backup-section");
        if (section) section.scrollIntoView({ behavior: "smooth", block: "start" });
        openExportPanel();
      }, 50);
    });
  }
  if (backupEls.bannerDismiss) {
    backupEls.bannerDismiss.addEventListener("click", () => {
      if (backupEls.banner) backupEls.banner.hidden = true;
      try {
        sessionStorage.setItem(RISK_DISMISS_KEY, "1");
      } catch (_) {
        /* sessionStorage blocked — banner reappears on reload, that's fine */
      }
    });
  }

  // Kick off an initial status check. We defer slightly (500ms)
  // because Tauri's IPC bridge isn't reliably ready the instant the
  // DOM parses — a too-early invoke can hang indefinitely. On the
  // user's first interactive click everything works, but the page-
  // load initial refresh needs this gap.
  //
  // We ALSO kick off again when the Pair tab is clicked, so the
  // status line updates whenever the user navigates there, without
  // depending on whether the first refresh succeeded.
  const kickoff = () => setTimeout(refreshBackupStatus, 500);
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", kickoff);
  } else {
    kickoff();
  }
  const pairTab = document.getElementById("app-tab-pair");
  if (pairTab) {
    pairTab.addEventListener("click", () => {
      // A short delay lets the existing tab-switch logic finish
      // rendering before we potentially overwrite the status line.
      setTimeout(refreshBackupStatus, 120);
    });
  }
})();
