// chat-ui.js — Encrypted chat messaging between paired devices.
//
// Messages are encrypted with a shared phrase that both users agree on
// in person during the pairing moment. Encryption uses XChaCha20-Poly1305
// via the already-loaded libsodium.js. The relay only ever sees ciphertext.
//
// Key derivation is SYMMETRIC: both sides sort their two public key hexes
// lexicographically and BLAKE2b(phrase || sorted_ids || context). This
// guarantees both devices produce the same key from the same phrase.
//
// Exposes three globals so pairing.js can drive the phrase flow:
//   window.qevShowPhraseDialog(peerName, callback) — opens the dialog
//   window.qevSetPhraseForPeer(peerId, phrase)     — store + derive
//   window.qevHasPhraseForPeer(peerId)             — true if set
//
// NO LOGGING of plaintext, phrases, or keys.

(function () {
  "use strict";

  var tauri = window.__TAURI__;
  if (!tauri) return;
  var invoke = tauri.core && tauri.core.invoke ? tauri.core.invoke : tauri.invoke;

  var $ = function (id) { return document.getElementById(id); };

  var peerList = $("chat-peer-list");
  var threadEmpty = $("chat-thread-empty");
  var threadHeader = $("chat-thread-header");
  var threadTitle = $("chat-thread-title");
  var threadBack = $("chat-thread-back");
  var lockBtn = $("chat-lock-btn");
  var lockedNotice = $("chat-locked-notice");
  var unlockBtn = $("chat-unlock-btn");
  var messagesDiv = $("chat-messages");
  var inputBar = $("chat-input-bar");
  var chatInput = $("chat-input");
  var sendBtn = $("chat-send-btn");
  var chatBadge = $("chat-badge");
  var chatContainer = document.querySelector(".chat-container");

  if (!peerList || !messagesDiv) return;

  var activePeerId = null;
  var peers = [];
  var pollTimer = null;
  var ownPkHex = null;  // This device's own public key hex (loaded on init)

  function copyToClipboard(text, feedbackBtn) {
    var done = function () {
      if (feedbackBtn) {
        var prev = feedbackBtn.textContent;
        feedbackBtn.textContent = "Copied";
        setTimeout(function () { feedbackBtn.textContent = prev; }, 1200);
      }
    };
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, function () {
          // Fallback: hidden textarea + execCommand.
          var ta = document.createElement("textarea");
          ta.value = text;
          ta.style.position = "fixed";
          ta.style.left = "-9999px";
          document.body.appendChild(ta);
          ta.select();
          try { document.execCommand("copy"); } catch (e) {}
          document.body.removeChild(ta);
          done();
        });
      } else {
        var ta2 = document.createElement("textarea");
        ta2.value = text;
        ta2.style.position = "fixed";
        ta2.style.left = "-9999px";
        document.body.appendChild(ta2);
        ta2.select();
        try { document.execCommand("copy"); } catch (e) {}
        document.body.removeChild(ta2);
        done();
      }
    } catch (e) {}
  }

  // Load own public key hex — needed for symmetric key derivation.
  invoke("pairing_own_public_hex").then(function (hex) {
    ownPkHex = hex;
  }).catch(function (e) {
    console.warn("[chat-ui] Could not load own pk hex:", e);
  });

  // ---- Shared-phrase encryption (symmetric key derivation) ----
  //
  // Security design: the shared phrase is NEVER persisted. Not in
  // localStorage, not in IndexedDB, not in the OS keystore. The
  // derived AEAD key lives only in JS memory for this session, and
  // the user can explicitly wipe it at any time with the Lock
  // button. On app restart every conversation starts locked.
  // Plaintext is also never written to disk — the chat store
  // always holds ciphertext envelopes; plaintext only exists in
  // memory while the user is actively viewing a conversation.

  var phraseKeys = {}; // peerId → Uint8Array(32) in-memory derived key ONLY

  function getPhraseKey(peerId) {
    return phraseKeys[peerId] || null;
  }

  function setPhraseKey(peerId, phrase) {
    try {
      phraseKeys[peerId] = deriveKey(phrase, peerId);
      return true;
    } catch (e) {
      return false;
    }
  }

  function wipePhraseKey(peerId) {
    // Zero the key bytes before dropping the reference. sodium.memzero
    // overwrites the underlying buffer so a memory dump after lock
    // can't recover the key.
    if (phraseKeys[peerId]) {
      try { sodium.memzero(phraseKeys[peerId]); } catch (e) {}
      delete phraseKeys[peerId];
    }
  }

  function deriveKey(phrase, peerId) {
    // SYMMETRIC derivation: sort both hexes so both sides produce
    // the same key. Without this, Device A encrypts with key derived
    // from hex(B) and Device B tries to decrypt with key derived from
    // hex(A), and the AEAD tag always fails.
    if (!ownPkHex) {
      throw new Error("Own public key not loaded yet. Try again in a moment.");
    }
    var ids = [ownPkHex.toLowerCase(), peerId.toLowerCase()].sort();
    var phraseBytes = new TextEncoder().encode(phrase);
    var contextBytes = new TextEncoder().encode("QEV-CHAT-V1:" + ids[0] + ":" + ids[1]);
    var combined = new Uint8Array(phraseBytes.length + contextBytes.length);
    combined.set(phraseBytes);
    combined.set(contextBytes, phraseBytes.length);
    var key = sodium.crypto_generichash(32, combined);
    sodium.memzero(combined);
    sodium.memzero(phraseBytes);
    return key;
  }

  function encryptMessage(text, key) {
    var nonce = sodium.randombytes_buf(24);
    var msgBytes = new TextEncoder().encode(text);
    var ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(msgBytes, null, null, nonce, key);
    sodium.memzero(msgBytes);
    return {
      nonce: sodium.to_base64(nonce, sodium.base64_variants.URLSAFE_NO_PADDING),
      ct: sodium.to_base64(ct, sodium.base64_variants.URLSAFE_NO_PADDING)
    };
  }

  function decryptMessage(nonceB64, ctB64, key) {
    try {
      var nonce = sodium.from_base64(nonceB64, sodium.base64_variants.URLSAFE_NO_PADDING);
      var ct = sodium.from_base64(ctB64, sodium.base64_variants.URLSAFE_NO_PADDING);
      var pt = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ct, null, nonce, key);
      return new TextDecoder().decode(pt);
    } catch (e) {
      return "[can't decrypt — wrong phrase or different device]";
    }
  }

  // ---- Phrase dialog ----

  var phraseDialog = $("chat-phrase-dialog");
  var phraseInput = $("chat-phrase-input");
  var phraseOk = $("chat-phrase-ok");
  var phraseCancel = $("chat-phrase-cancel");
  var phraseTitle = $("chat-phrase-title");
  var phraseHint = $("chat-phrase-hint");
  var pendingPhraseResolve = null;

  function showPhraseDialog(peerName, hintText) {
    return new Promise(function (resolve) {
      pendingPhraseResolve = resolve;
      if (phraseTitle) phraseTitle.textContent = "Shared phrase with " + peerName;
      if (phraseHint && hintText) phraseHint.textContent = hintText;
      if (phraseInput) phraseInput.value = "";
      if (phraseDialog) phraseDialog.classList.add("chat-phrase-visible");
      setTimeout(function () { if (phraseInput) phraseInput.focus(); }, 100);
    });
  }

  function hidePhraseDialog() {
    if (phraseDialog) phraseDialog.classList.remove("chat-phrase-visible");
  }

  if (phraseOk) {
    phraseOk.onclick = function () {
      var val = phraseInput ? phraseInput.value.trim() : "";
      hidePhraseDialog();
      if (pendingPhraseResolve) pendingPhraseResolve(val || null);
      pendingPhraseResolve = null;
    };
  }
  if (phraseCancel) {
    phraseCancel.onclick = function () {
      hidePhraseDialog();
      if (pendingPhraseResolve) pendingPhraseResolve(null);
      pendingPhraseResolve = null;
    };
  }
  if (phraseInput) {
    phraseInput.onkeydown = function (e) {
      if (e.key === "Enter") { e.preventDefault(); if (phraseOk) phraseOk.click(); }
    };
  }

  // ---- Public API for pairing.js ----

  window.qevShowPhraseDialog = function (peerName, callback) {
    showPhraseDialog(peerName,
      "Pick a secret phrase and both type it in. It encrypts every message between you two. The phrase never leaves your devices — agree on it in person right now.")
      .then(callback);
  };

  window.qevSetPhraseForPeer = function (peerId, phrase) {
    // Memory-only — phrase is never persisted.
    return setPhraseKey(peerId, phrase);
  };

  window.qevHasPhraseForPeer = function (peerId) {
    // "Has phrase" means the user has unlocked this peer in this
    // session. Lock wipes it; app restart wipes all.
    return !!phraseKeys[peerId];
  };

  // ---- Chat tab handling ----

  var chatTab = $("app-tab-chat");
  if (chatTab) {
    chatTab.onclick = function () {
      loadPeers();
      startPolling();
    };
  }

  // Auto-refresh peer list (picks up new pairings)
  setInterval(function () { loadPeers(); }, 5000);

  // ---- Peer list ----

  function loadPeers() {
    invoke("pairing_peers_list").then(function (list) {
      peers = list || [];
      renderPeerList();
      updateBadges();
    }).catch(function () {
      peers = [];
      renderPeerList();
    });
  }

  function renderPeerList() {
    var header = peerList.querySelector(".chat-peers-header");
    peerList.innerHTML = "";
    if (header) peerList.appendChild(header);

    if (peers.length === 0) {
      var emptyDiv = document.createElement("div");
      emptyDiv.className = "chat-peers-empty";
      emptyDiv.innerHTML = 'No paired peers yet. Go to the <strong>Pair</strong> tab to add someone.';
      peerList.appendChild(emptyDiv);
      return;
    }

    peers.forEach(function (peer) {
      var item = document.createElement("div");
      item.className = "chat-peer-item" + (peer.id === activePeerId ? " active" : "");
      item.dataset.peerId = peer.id;
      var unlocked = window.qevHasPhraseForPeer(peer.id);
      item.innerHTML =
        '<div class="chat-peer-name">' + esc(peer.peer_name) +
        (unlocked ? '' : ' <span style="font-size:0.7rem;color:var(--text-dim);">🔒 locked</span>') +
        ' <span class="chat-peer-badge" id="badge-' + peer.id + '" style="display:none;"></span></div>' +
        '<div class="chat-peer-preview" id="preview-' + peer.id + '"></div>';
      item.onclick = function () {
        selectPeer(peer.id, peer.peer_name);
      };
      peerList.appendChild(item);
    });

    updatePreviews();
  }

  // Active peer's human name — tracked for the header/dialog UX.
  var activePeerName = null;

  function selectPeer(peerId, peerName) {
    // Opening a conversation never auto-prompts anymore. The chat
    // always opens in whatever lock state the user left it (locked
    // by default on a fresh session). The locked banner exposes
    // the Unlock button.
    openChat(peerId, peerName);
  }

  function openChat(peerId, peerName) {
    activePeerId = peerId;
    activePeerName = peerName;
    var items = peerList.querySelectorAll(".chat-peer-item");
    items.forEach(function (el) {
      el.classList.toggle("active", el.dataset.peerId === peerId);
    });
    threadEmpty.style.display = "none";
    if (threadHeader) {
      threadHeader.style.display = "flex";
      if (threadTitle) threadTitle.textContent = peerName;
    }
    // Mobile: slide in the thread view (CSS hides the peer list).
    if (chatContainer) chatContainer.classList.add("chat-mobile-threaded");
    applyLockState(peerId);
    loadMessages(peerId);
    invoke("chat_mark_read", { peerId: peerId }).catch(function () {});
    updateBadges();
    renderPeerList();
  }

  // Mobile: back button returns to peer list.
  if (threadBack) {
    threadBack.onclick = function () {
      if (chatContainer) chatContainer.classList.remove("chat-mobile-threaded");
      if (threadHeader) threadHeader.style.display = "none";
      if (threadEmpty) threadEmpty.style.display = "flex";
      activePeerId = null;
      activePeerName = null;
      var items = peerList.querySelectorAll(".chat-peer-item");
      items.forEach(function (el) { el.classList.remove("active"); });
    };
  }

  function applyLockState(peerId) {
    var unlocked = !!phraseKeys[peerId];
    if (lockBtn) {
      lockBtn.textContent = unlocked ? "Lock" : "Unlock";
      lockBtn.dataset.locked = unlocked ? "false" : "true";
    }
    // Messages stay visible regardless — when locked they just render
    // as ciphertext bubbles (selectable + copyable). Scrollback works.
    if (messagesDiv) messagesDiv.style.display = "flex";
    // Locked notice appears ABOVE the message list with an inline Unlock.
    if (lockedNotice) lockedNotice.style.display = unlocked ? "none" : "flex";
    // Input bar only appears unlocked — you can't send without a key.
    if (inputBar) {
      if (unlocked) inputBar.classList.add("chat-input-bar-visible");
      else inputBar.classList.remove("chat-input-bar-visible");
    }
  }

  // Unlock flow — prompt for phrase, derive key in memory, render.
  function promptUnlock() {
    if (!activePeerId || !activePeerName) return;
    showPhraseDialog(activePeerName,
      "Enter the shared phrase for chatting with " + activePeerName + ". The phrase is never saved — you re-enter it each time you unlock.")
      .then(function (phrase) {
        if (!phrase) return;
        var ok = setPhraseKey(activePeerId, phrase);
        if (!ok) return;
        applyLockState(activePeerId);
        loadMessages(activePeerId);
      });
  }

  // Lock flow — wipe the in-memory key and re-render the thread as
  // raw ciphertext. Plaintext DOM nodes are discarded (innerHTML
  // rewrite). The AEAD key's bytes are zeroed via sodium.memzero
  // before the reference is dropped.
  function doLock() {
    if (!activePeerId) return;
    wipePhraseKey(activePeerId);
    applyLockState(activePeerId);
    // Re-render with no key — bubbles will show ciphertext.
    loadMessages(activePeerId);
    renderPeerList();
  }

  if (lockBtn) {
    lockBtn.onclick = function () {
      if (!activePeerId) return;
      if (phraseKeys[activePeerId]) doLock();
      else promptUnlock();
    };
  }
  if (unlockBtn) {
    unlockBtn.onclick = promptUnlock;
  }

  // ---- Messages ----

  function loadMessages(peerId) {
    invoke("chat_get_history", { peerId: peerId }).then(function (msgs) {
      renderMessages(msgs || [], peerId);
    }).catch(function () {
      renderMessages([], peerId);
    });
  }

  function renderMessages(msgs, peerId) {
    messagesDiv.innerHTML = "";
    if (msgs.length === 0) {
      messagesDiv.innerHTML = '<div style="text-align:center;color:var(--text-dim);padding:40px;font-size:0.85rem;">No messages yet. Say hello!</div>';
      scrollToBottom();
      return;
    }
    // Re-read the key every render. If the peer was locked while
    // the thread was open, key becomes null and we display ciphertext.
    var key = getPhraseKey(peerId);

    msgs.forEach(function (msg) {
      var bubble = document.createElement("div");
      var isOut = msg.direction === "outgoing";
      bubble.className = "chat-msg " + (isOut ? "chat-msg-out" : "chat-msg-in");
      var time = new Date(msg.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      var statusIcon = "";
      if (isOut) {
        if (msg.status === "sending") statusIcon = "...";
        else if (msg.status === "sent") statusIcon = "✓";
        else if (msg.status === "failed") statusIcon = "Failed";
      }

      // Extract ciphertext if the stored text is the envelope JSON.
      // The chat store ALWAYS holds ciphertext — plaintext never
      // persists. We re-decrypt per render; if the peer is locked
      // (no key), we display the ciphertext verbatim.
      var envCipher = null;
      var rawText = msg.text || "";
      if (rawText.charAt(0) === '{') {
        try {
          var env = JSON.parse(rawText);
          if (env.v === 1 && env.nonce && env.ct) envCipher = env.ct;
        } catch (e) { /* not a known envelope — show raw */ }
      }

      var displayText;
      var isCipher = false;
      var fullEnvelope = null;
      if (envCipher) {
        if (key) {
          var env2 = JSON.parse(rawText);
          displayText = decryptMessage(env2.nonce, env2.ct, key);
        } else {
          displayText = envCipher;
          isCipher = true;
          // Build the portable chat envelope that Open-a-vault and
          // /vault can decrypt. Includes the sorted peer ID pair so
          // any recipient who knows the phrase can reconstruct the
          // same AEAD key. The raw on-disk form stays minimal; this
          // expanded form is only what the user copies.
          try {
            var inner = JSON.parse(rawText);
            if (ownPkHex && peerId) {
              var sortedIds = [ownPkHex.toLowerCase(), peerId.toLowerCase()].sort();
              fullEnvelope = JSON.stringify({
                schema: "QEV-CHAT-ENVELOPE-V1",
                ids: sortedIds,
                nonce: inner.nonce,
                ct: inner.ct,
                v: 1
              });
            } else {
              fullEnvelope = rawText;
            }
          } catch (e) {
            fullEnvelope = rawText;
          }
        }
      } else {
        displayText = rawText;
      }

      var copyBtnHtml = isCipher
        ? '<button type="button" class="chat-msg-copy" data-copy="envelope">Copy envelope</button>'
        : '';

      bubble.innerHTML =
        '<div' + (isCipher ? ' class="chat-msg-cipher"' : '') + '>' + esc(displayText) + '</div>' +
        '<div class="chat-msg-time">' + time +
        (statusIcon ? '<span class="chat-msg-status">' + statusIcon + '</span>' : '') +
        copyBtnHtml +
        '</div>';

      if (isCipher && fullEnvelope) {
        var copyBtn = bubble.querySelector(".chat-msg-copy");
        if (copyBtn) {
          copyBtn.onclick = function (ev) {
            ev.stopPropagation();
            copyToClipboard(fullEnvelope, copyBtn);
          };
        }
      }
      messagesDiv.appendChild(bubble);
    });
    scrollToBottom();
  }

  function scrollToBottom() {
    messagesDiv.scrollTop = messagesDiv.scrollHeight;
  }

  // ---- Send ----

  if (sendBtn) {
    sendBtn.onclick = doSend;
  }
  if (chatInput) {
    chatInput.onkeydown = function (e) {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        doSend();
      }
    };
  }

  function doSend() {
    if (!activePeerId || !chatInput) return;
    var plaintext = chatInput.value.trim();
    if (!plaintext) return;

    // Double-check: the input bar is hidden when locked, so this
    // path normally can't run. But guard anyway so no plaintext is
    // ever handed to chat_send without a key.
    var key = getPhraseKey(activePeerId);
    if (!key) {
      alert("This conversation is locked. Unlock it first with the shared phrase.");
      return;
    }

    // Encrypt to ciphertext envelope. The plaintext local var goes
    // out of scope as soon as encryptMessage returns; its bytes are
    // zeroed by encryptMessage before release.
    var encrypted = encryptMessage(plaintext, key);
    var envelope = JSON.stringify({ v: 1, nonce: encrypted.nonce, ct: encrypted.ct });

    chatInput.value = "";
    plaintext = null; // drop our reference; the only remaining plaintext is envelope... which is ciphertext.
    sendBtn.disabled = true;

    invoke("chat_send", { peerId: activePeerId, text: envelope })
      .then(function () {
        loadMessages(activePeerId);
        updatePreviews();
      })
      .catch(function () {
        loadMessages(activePeerId);
        updatePreviews();
      })
      .finally(function () {
        sendBtn.disabled = false;
        chatInput.focus();
      });
  }

  // ---- Badges & previews ----

  function updateBadges() {
    invoke("chat_unread_counts").then(function (counts) {
      var total = 0;
      peers.forEach(function (peer) {
        var n = counts[peer.id] || 0;
        total += n;
        var badge = $("badge-" + peer.id);
        if (badge) {
          badge.textContent = n > 0 ? String(n) : "";
          badge.style.display = n > 0 ? "inline-block" : "none";
        }
      });
      if (chatBadge) {
        chatBadge.textContent = total > 0 ? String(total) : "";
        chatBadge.style.display = total > 0 ? "inline-block" : "none";
      }
    }).catch(function () {});
  }

  function updatePreviews() {
    peers.forEach(function (peer) {
      invoke("chat_get_history", { peerId: peer.id }).then(function (msgs) {
        if (!msgs || msgs.length === 0) return;
        var last = msgs[msgs.length - 1];
        var preview = $("preview-" + peer.id);
        if (preview) {
          // Previews always show ciphertext. Even if we have the key we
          // don't decrypt here — only the active chat thread decrypts.
          // This keeps sensitive content off the overview at a glance.
          var text = last.text;
          var snippet;
          if (text && text.charAt(0) === '{') {
            try {
              var env = JSON.parse(text);
              if (env.v === 1 && env.nonce && env.ct) {
                snippet = env.ct.slice(0, 36);
              } else {
                snippet = text.slice(0, 36);
              }
            } catch (e) {
              snippet = text.slice(0, 36);
            }
          } else {
            snippet = (text || "").slice(0, 36);
          }
          preview.textContent = (last.direction === "outgoing" ? "You: " : "") +
            snippet + (snippet.length >= 36 ? "..." : "");
        }
      }).catch(function () {});
    });
  }

  // ---- Relay polling ----

  function startPolling() {
    if (pollTimer) return;
    fetchNewMessages();
    pollTimer = setInterval(fetchNewMessages, 8000);
  }

  // Start polling immediately
  startPolling();

  function fetchNewMessages() {
    invoke("chat_fetch_relay_messages").then(function (count) {
      if (count > 0) {
        updateBadges();
        updatePreviews();
        if (activePeerId) loadMessages(activePeerId);
      }
    }).catch(function (err) {
      console.warn("[chat] fetch failed:", err);
      window._lastRelayErr = String(err);
    });
  }

  // ---- Helpers ----

  function esc(s) {
    return String(s || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }
})();
