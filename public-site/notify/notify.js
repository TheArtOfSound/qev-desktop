// Qira Notify — client-side encrypt/decrypt + tiny polling API client.
//
// All crypto runs IN THIS TAB via libsodium (/vault/sodium.js). The
// server sees nothing but opaque ciphertext; the phrase never leaves
// the browser. Message format is the existing QEV vault-V2 shape
// (Argon2id + XChaCha20-Poly1305) so a notification is literally a
// one-shot vault file posted to an addressed endpoint.
//
// Security invariants (do not break):
//   - The server URL (window.location.origin + /notify/<topic>) is
//     the only network endpoint. No third-party analytics or beacons.
//   - The phrase MUST NOT leave this tab. We never POST it anywhere,
//     never log it, never include it in a URL. localStorage storage
//     is strictly opt-in and origin-scoped.
//   - JSON.stringify(vault) is what goes on the wire. No plaintext.
//
// Non-invariants (things we're OK with for MVP):
//   - Timing metadata: the relay sees when each message arrives.
//     Acceptable for the "encrypted pings" use case.
//   - Topic-URL leak: knowing the URL lets someone spam the topic.
//     Server rate-limits at 60 POSTs/min per topic.

(function () {
  "use strict";

  // ---------- DOM refs ----------
  const $ = (id) => document.getElementById(id);
  const el = {
    pubTopic: $("pub-topic"),
    pubMsg: $("pub-msg"),
    pubPhrase: $("pub-phrase"),
    pubSend: $("pub-send"),
    pubRandom: $("pub-random"),
    pubStatus: $("pub-status"),

    subTopic: $("sub-topic"),
    subPhrase: $("sub-phrase"),
    subStart: $("sub-start"),
    subStop: $("sub-stop"),
    subStatus: $("sub-status"),
    subRemember: $("sub-remember"),
    subShare: $("sub-share"),
    subShareUrl: $("sub-share-url"),
    subCopyUrl: $("sub-copy-url"),

    pushRow: $("push-row"),
    pushEnable: $("push-enable"),
    pushDisable: $("push-disable"),
    pushStatus: $("push-status"),
    pushInstallHint: $("push-install-hint"),

    demoStart: $("demo-start"),
    demoStatus: $("demo-status"),

    inviteWelcome: $("invite-welcome"),
    inviteTopic: $("invite-topic"),
    shareCard: $("share-card"),
    shareText: $("share-text"),
    shareCopyText: $("share-copy-text"),
    shareCopyUrlOnly: $("share-copy-url-only"),

    inbox: $("inbox"),
    inboxEmpty: $("inbox-empty"),
  };

  // Public demo feed constants — kept in sync with
  // scripts/qira_notify_demo_publisher.py on the droplet.
  const DEMO_TOPIC = "qira-demo-feed";
  const DEMO_PHRASE = "qira demo feed public heartbeat 2026";

  // ---------- sodium readiness ----------
  let sodium = null;
  const sodiumReady = (async () => {
    // The /vault/sodium.js bundle exposes `sodium` on window after
    // its own `sodium.ready` settles. We just wait on that.
    while (!(window.sodium && window.sodium.ready)) {
      await new Promise((r) => setTimeout(r, 20));
    }
    await window.sodium.ready;
    sodium = window.sodium;
    return sodium;
  })();

  // ---------- URL shape ----------
  function topicApiUrl(topic) {
    return window.location.origin + "/notify/" + encodeURIComponent(topic);
  }
  function shareUrl(topic) {
    // ?t= lets the subscriber open a shareable link; they still need the phrase.
    return (
      window.location.origin +
      "/notify/?t=" +
      encodeURIComponent(topic)
    );
  }

  // ---------- Topic validation (mirror server-side) ----------
  function validTopic(t) {
    return (
      typeof t === "string" &&
      t.length >= 3 &&
      t.length <= 64 &&
      /^[A-Za-z0-9_-]+$/.test(t)
    );
  }

  // ---------- Vault V2 encrypt ----------
  // Format matches landing/vault/chat.js's V2 output. Client-side
  // decryption with libsodium via crypto_pwhash + crypto_aead_xchacha20poly1305.
  async function encryptMessage(plaintext, phrase) {
    await sodiumReady;
    if (!phrase) throw new Error("phrase required");

    // Fresh per-message salt + nonces + vault_key.
    const salt = sodium.randombytes_buf(
      sodium.crypto_pwhash_SALTBYTES
    );
    const wrapNonce = sodium.randombytes_buf(
      sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
    );
    const contentNonce = sodium.randombytes_buf(
      sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
    );
    const vaultKey = sodium.randombytes_buf(
      sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES
    );

    // Argon2id: medium preset (≈ 1-2s in the browser). Matches
    // vault/chat.js's "quick" preset. Strong enough that a brute-force
    // attacker pays real compute per candidate.
    const opslimit = sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE;
    const memlimit = sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE;
    const wrapKey = sodium.crypto_pwhash(
      sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
      phrase,
      salt,
      opslimit,
      memlimit,
      sodium.crypto_pwhash_ALG_ARGON2ID13
    );

    // AAD = the domain string so a content ciphertext can't be
    // lifted into a wrap ciphertext and vice versa.
    const wrapAad = sodium.from_string("QIRA-NOTIFY-V1-WRAP");
    const contentAad = sodium.from_string("QIRA-NOTIFY-V1-CONTENT");

    const wrapped = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      vaultKey,
      wrapAad,
      null,
      wrapNonce,
      wrapKey
    );
    const plainBytes = sodium.from_string(plaintext);
    const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      plainBytes,
      contentAad,
      null,
      contentNonce,
      vaultKey
    );

    // Zero the key material we're done with.
    sodium.memzero(vaultKey);
    sodium.memzero(wrapKey);

    return {
      schema: "QIRA-NOTIFY-V1",
      created_at: new Date().toISOString(),
      kdf: {
        algorithm: "argon2id",
        opslimit,
        memlimit,
        salt: sodium.to_base64(salt, sodium.base64_variants.URLSAFE_NO_PADDING),
      },
      wrap: {
        algorithm: "xchacha20poly1305-ietf",
        aad: "QIRA-NOTIFY-V1-WRAP",
        nonce: sodium.to_base64(wrapNonce, sodium.base64_variants.URLSAFE_NO_PADDING),
        wrapped_key: sodium.to_base64(wrapped, sodium.base64_variants.URLSAFE_NO_PADDING),
      },
      content: {
        algorithm: "xchacha20poly1305-ietf",
        aad: "QIRA-NOTIFY-V1-CONTENT",
        nonce: sodium.to_base64(contentNonce, sodium.base64_variants.URLSAFE_NO_PADDING),
        ciphertext: sodium.to_base64(ct, sodium.base64_variants.URLSAFE_NO_PADDING),
      },
    };
  }

  async function decryptMessage(envelope, phrase) {
    await sodiumReady;
    if (!envelope || envelope.schema !== "QIRA-NOTIFY-V1") {
      throw new Error("unrecognized envelope schema");
    }
    const B64 = sodium.base64_variants.URLSAFE_NO_PADDING;
    const salt = sodium.from_base64(envelope.kdf.salt, B64);
    const wrapNonce = sodium.from_base64(envelope.wrap.nonce, B64);
    const wrappedKey = sodium.from_base64(envelope.wrap.wrapped_key, B64);
    const contentNonce = sodium.from_base64(envelope.content.nonce, B64);
    const ciphertext = sodium.from_base64(envelope.content.ciphertext, B64);
    const wrapKey = sodium.crypto_pwhash(
      sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
      phrase,
      salt,
      envelope.kdf.opslimit,
      envelope.kdf.memlimit,
      sodium.crypto_pwhash_ALG_ARGON2ID13
    );
    const wrapAad = sodium.from_string(envelope.wrap.aad);
    const contentAad = sodium.from_string(envelope.content.aad);
    let vaultKey;
    try {
      vaultKey = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null,
        wrappedKey,
        wrapAad,
        wrapNonce,
        wrapKey
      );
    } finally {
      sodium.memzero(wrapKey);
    }
    try {
      const plain = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null,
        ciphertext,
        contentAad,
        contentNonce,
        vaultKey
      );
      return sodium.to_string(plain);
    } finally {
      sodium.memzero(vaultKey);
    }
  }

  // ---------- API client ----------
  async function publishMessage(topic, envelope) {
    const body = JSON.stringify(envelope);
    const r = await fetch(topicApiUrl(topic), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
    });
    if (!r.ok) {
      const txt = await r.text().catch(() => "");
      throw new Error(`publish failed: ${r.status} ${txt.slice(0, 200)}`);
    }
    return r.json();
  }
  async function fetchInbox(topic, afterTs) {
    const url = topicApiUrl(topic) + (afterTs ? `?after_ts=${afterTs}` : "");
    const r = await fetch(url, { method: "GET" });
    if (!r.ok) {
      const txt = await r.text().catch(() => "");
      throw new Error(`fetch failed: ${r.status} ${txt.slice(0, 200)}`);
    }
    return r.json();
  }

  // ---------- Rendering ----------
  function setStatus(node, text, kind) {
    if (!node) return;
    node.textContent = text;
    node.className = "notify-status" + (kind ? " " + kind : "");
  }
  function randomTopic() {
    const alphabet = "abcdefghjkmnpqrstuvwxyz23456789";
    let out = "";
    const bytes = new Uint8Array(14);
    crypto.getRandomValues(bytes);
    for (const b of bytes) out += alphabet[b % alphabet.length];
    return out;
  }

  // ---------- Publish wiring ----------
  async function onPublish() {
    const topic = el.pubTopic.value.trim();
    const msg = el.pubMsg.value;
    const phrase = el.pubPhrase.value;
    if (!validTopic(topic)) {
      return setStatus(el.pubStatus, "topic: 3-64 chars, [A-Za-z0-9_-] only", "err");
    }
    if (!msg) {
      return setStatus(el.pubStatus, "message cannot be empty", "err");
    }
    if (!phrase || phrase.length < 4) {
      return setStatus(el.pubStatus, "phrase must be at least 4 characters", "err");
    }
    setStatus(el.pubStatus, "Encrypting…");
    el.pubSend.disabled = true;
    try {
      const env = await encryptMessage(msg, phrase);
      const r = await publishMessage(topic, env);
      setStatus(
        el.pubStatus,
        `Published encrypted message ${r.id}. Subscribers with the phrase will see it.`,
        "ok"
      );
      el.pubMsg.value = "";
    } catch (e) {
      setStatus(el.pubStatus, String(e.message || e), "err");
    } finally {
      el.pubSend.disabled = false;
    }
  }

  // ---------- Subscribe / inbox polling ----------
  let pollTimer = null;
  let currentTopic = null;
  let currentPhrase = null;
  let lastSeenTs = 0;
  const seenIds = new Set();

  // localStorage key shape: qn:<topic>:phrase (origin-scoped already).
  function persistedPhraseKey(topic) {
    return `qn:${topic}:phrase`;
  }
  function savePhrase(topic, phrase) {
    try {
      localStorage.setItem(persistedPhraseKey(topic), phrase);
    } catch (_) {
      /* storage blocked — silent */
    }
  }
  function loadPhrase(topic) {
    try {
      return localStorage.getItem(persistedPhraseKey(topic));
    } catch (_) {
      return null;
    }
  }
  function forgetPhrase(topic) {
    try {
      localStorage.removeItem(persistedPhraseKey(topic));
    } catch (_) {}
  }

  async function pollOnce() {
    if (!currentTopic) return;
    try {
      const messages = await fetchInbox(currentTopic, lastSeenTs);
      for (const m of messages) {
        if (seenIds.has(m.id)) continue;
        seenIds.add(m.id);
        lastSeenTs = Math.max(lastSeenTs, m.ts);
        await renderMessage(m);
      }
    } catch (e) {
      setStatus(el.subStatus, `poll error: ${e.message || e}`, "warn");
    }
  }

  async function renderMessage(m) {
    const li = document.createElement("li");
    li.className = "msg";
    const meta = document.createElement("div");
    meta.className = "meta";
    const when = new Date(m.ts).toLocaleString();
    meta.innerHTML = `<span>${when}</span><span>·</span><span>${m.id}</span>`;
    const pill = document.createElement("span");
    meta.appendChild(pill);
    const body = document.createElement("div");
    body.className = "body";
    li.append(meta, body);

    // ---- Raw-ciphertext toggle ----
    // This is the "look what the server actually stored" reveal. Every
    // visitor should be able to compare the plaintext above with the
    // JSON envelope below and confirm that the server is holding
    // opaque bytes, nothing readable. Collapsed by default to keep the
    // inbox skimmable.
    const rawToggle = document.createElement("button");
    rawToggle.type = "button";
    rawToggle.className = "raw-toggle";
    rawToggle.textContent = "Show raw ciphertext ▸";
    const rawWrap = document.createElement("div");
    rawWrap.className = "raw-wrap";
    rawWrap.hidden = true;
    const rawHead = document.createElement("div");
    rawHead.className = "raw-wrap-head";
    const rawHeadLabel = document.createElement("span");
    rawHeadLabel.innerHTML =
      "stored as <code>QIRA-NOTIFY-V1</code> envelope (server sees only this):";
    const rawCopy = document.createElement("button");
    rawCopy.type = "button";
    rawCopy.className = "raw-copy";
    rawCopy.textContent = "Copy JSON";
    rawHead.append(rawHeadLabel, rawCopy);

    // Phrase-used line — captured at render time so late-changes to
    // currentPhrase don't retroactively reassign what unlocked which
    // message. Empty when we had no phrase (message rendered locked).
    const phraseAtRender = currentPhrase || null;
    const rawPhrase = document.createElement("div");
    rawPhrase.className = "raw-phrase";
    rawWrap.append(rawHead, rawPhrase);

    const rawPre = document.createElement("pre");
    rawPre.className = "raw-json";
    rawPre.innerHTML = highlightJson(m.body);
    rawWrap.append(rawPre);
    rawToggle.addEventListener("click", () => {
      rawWrap.hidden = !rawWrap.hidden;
      rawToggle.textContent = rawWrap.hidden
        ? "Show raw ciphertext ▸"
        : "Hide raw ciphertext ▾";
    });
    rawCopy.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(
          JSON.stringify(m.body, null, 2)
        );
        rawCopy.textContent = "Copied ✓";
        setTimeout(() => (rawCopy.textContent = "Copy JSON"), 1500);
      } catch (_) {
        rawCopy.textContent = "Copy failed";
      }
    });
    li.append(rawToggle, rawWrap);

    // Hide the "no messages" hint once we have one.
    if (el.inboxEmpty) el.inboxEmpty.hidden = true;

    // Try to decrypt with the current phrase if we have one.
    let decryptedOk = false;
    if (currentPhrase) {
      try {
        const plain = await decryptMessage(m.body, currentPhrase);
        li.classList.add("unlocked");
        pill.className = "unlocked-pill";
        pill.textContent = "Unlocked";
        body.textContent = plain;
        decryptedOk = true;
      } catch (_) {
        li.classList.add("locked");
        pill.className = "locked-pill";
        pill.textContent = "🔒 Wrong phrase";
        body.textContent = "(decryption failed — phrase doesn't match)";
      }
    } else {
      li.classList.add("locked");
      pill.className = "locked-pill";
      pill.textContent = "🔒 Locked";
      body.textContent = "(enter the phrase above to decrypt)";
    }

    // Fill in the "phrase used" line in the raw-wrap header. Shown
    // only when decryption succeeded — otherwise it would be
    // misleading ("this phrase unlocked it" when it didn't).
    if (decryptedOk && phraseAtRender) {
      rawPhrase.innerHTML =
        '<span class="rp-label">Phrase used to unlock this message:</span> ' +
        `<code class="rp-phrase">${escapeHtml(phraseAtRender)}</code>`;
    } else {
      rawPhrase.remove();
    }

    el.inbox.prepend(li);
  }

  // Tiny HTML escaper (no innerHTML injection via phrase content).
  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  // Tiny JSON pretty-printer + color-classer. Not a real syntax
  // highlighter — just enough to make the structure legible without
  // pulling in highlight.js (which would blow up the CSP surface).
  function highlightJson(obj) {
    const esc = (s) =>
      s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    const pretty = JSON.stringify(obj, null, 2);
    // Order matters: strings before numbers/bools because strings
    // themselves can contain digits.
    return esc(pretty)
      .replace(
        /"([^"\\]*(?:\\.[^"\\]*)*)"(\s*:)/g,
        '<span class="k">"$1"</span>$2'
      )
      .replace(
        /:(\s*)"([^"\\]*(?:\\.[^"\\]*)*)"/g,
        ':$1<span class="s">"$2"</span>'
      )
      .replace(/:(\s*)(-?\d+(?:\.\d+)?)/g, ':$1<span class="n">$2</span>')
      .replace(/:(\s*)(true|false|null)/g, ':$1<span class="b">$2</span>');
  }

  function startWatching() {
    const topic = el.subTopic.value.trim();
    const phrase = el.subPhrase.value;
    if (!validTopic(topic)) {
      return setStatus(el.subStatus, "topic: 3-64 chars, [A-Za-z0-9_-] only", "err");
    }
    stopWatching(false);
    currentTopic = topic;
    currentPhrase = phrase || null;
    lastSeenTs = 0;
    seenIds.clear();
    if (el.inbox) el.inbox.innerHTML = "";
    if (el.inboxEmpty) el.inboxEmpty.hidden = false;

    if (el.subRemember.checked && phrase) savePhrase(topic, phrase);
    else if (!el.subRemember.checked) forgetPhrase(topic);

    const url = shareUrl(topic);
    el.subShare.hidden = false;
    el.subShareUrl.value = url;

    setStatus(el.subStatus, "Watching…", "ok");
    el.subStart.disabled = true;
    el.subStop.disabled = false;

    pollOnce();
    pollTimer = setInterval(pollOnce, 3500);

    // Expose the subscribe-push UI now that we have a topic to attach to.
    refreshPushUiForTopic().catch(() => {});

    // Populate the group-invite card so the user can share this topic.
    // We hide it for the public demo since "share the demo" isn't a
    // real use case — it's already documented as public on the page.
    populateShareCard(topic);
  }

  // ---------- Group invite card ----------
  //
  // Given the topic the user is currently watching, build a ready-to-
  // paste invite block plus a URL-only copy. Hidden for the public
  // demo topic because the demo is already documented inline.
  function populateShareCard(topic) {
    if (!el.shareCard) return;
    if (topic === DEMO_TOPIC) {
      el.shareCard.hidden = true;
      return;
    }
    const url = shareUrl(topic);
    // Phrase deliberately NOT in the text we generate — the page warns
    // elsewhere that the phrase must be shared separately. But we do
    // prompt the user to fill in an appropriate placeholder.
    const inviteText =
      "🔒 You're invited to an encrypted notification feed.\n" +
      "\n" +
      "Open this link on your phone or computer:\n" +
      url +
      "\n" +
      "\n" +
      "When it asks for a phrase, use the one I told you (not in this message).\n" +
      "Every message is encrypted in your browser — the server can't read any of it.\n" +
      "\n" +
      "Android users: after opening, tap \"Enable Android/phone notifications\"\n" +
      "and then install the page as an app (Chrome menu → Install app). You'll\n" +
      "get a system notification every time a new message is posted.";
    el.shareText.textContent = inviteText;
    el.shareCard.hidden = false;
  }

  if (el.shareCopyText) {
    el.shareCopyText.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(el.shareText.textContent);
        el.shareCopyText.textContent = "Copied ✓";
        setTimeout(() => (el.shareCopyText.textContent = "Copy invite text"), 1500);
      } catch (_) {
        const range = document.createRange();
        range.selectNodeContents(el.shareText);
        const sel = window.getSelection();
        sel.removeAllRanges(); sel.addRange(range);
      }
    });
  }
  if (el.shareCopyUrlOnly) {
    el.shareCopyUrlOnly.addEventListener("click", async () => {
      // URL only, no instructions. Useful when the user will paste into
      // an existing conversation and type their own message.
      const url = currentTopic ? shareUrl(currentTopic) : "";
      try {
        await navigator.clipboard.writeText(url);
        el.shareCopyUrlOnly.textContent = "Copied ✓";
        setTimeout(() => (el.shareCopyUrlOnly.textContent = "Copy URL only"), 1500);
      } catch (_) {}
    });
  }
  function stopWatching(updateUi) {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = null;
    currentTopic = null;
    currentPhrase = null;
    if (updateUi !== false) {
      setStatus(el.subStatus, "Stopped.");
      el.subStart.disabled = false;
      el.subStop.disabled = true;
    }
    // Hide the push-row when no topic is active — prevents confusing
    // "enable push for ...?" UI with a blank topic.
    if (el.pushRow) el.pushRow.hidden = true;
    // Also hide the share card — it only makes sense while watching.
    if (el.shareCard) el.shareCard.hidden = true;
  }

  // ---------- Share URL autoload ----------
  (function () {
    const p = new URLSearchParams(window.location.search);
    const t = p.get("t") || p.get("topic"); // `?topic=` used by SW click handler
    if (t && validTopic(t)) {
      el.subTopic.value = t;
      const saved = loadPhrase(t);
      if (saved) {
        el.subPhrase.value = saved;
        el.subRemember.checked = true;
        // Auto-start if both topic + persisted phrase are present.
        setTimeout(() => startWatching(), 100);
      } else if (t !== DEMO_TOPIC) {
        // Shared-link landing: nobody's given us the phrase yet. Show
        // a welcome card so the recipient knows to enter the phrase
        // their inviter told them out-of-band. The demo topic has its
        // own inline UI — skip the welcome banner there.
        if (el.inviteWelcome && el.inviteTopic) {
          el.inviteTopic.textContent = t;
          el.inviteWelcome.hidden = false;
          // Scroll the Subscribe card into view since that's where
          // the user needs to type the phrase next.
          setTimeout(() => {
            const sub = document.getElementById("sub-phrase");
            if (sub) { sub.focus(); sub.scrollIntoView({ behavior: "smooth", block: "center" }); }
          }, 400);
        }
      }
    }
  })();

  // ===================================================================
  //  Android / PWA Web Push
  // ===================================================================
  //
  // A subscriber installs the site as a PWA (Android Chrome: "Install
  // app" or "Add to Home screen"), grants notification permission, and
  // we store a push subscription on the relay. The relay then pushes
  // a tiny `{t, id, ts}` JSON every time a new message for that topic
  // arrives — the service worker fires a system notification. The body
  // stays encrypted server-side; tapping the notification opens the
  // PWA which decrypts with the remembered phrase.
  //
  // Why opt-in / per-topic:
  //   - Android push requires `userVisibleOnly: true` — every push MUST
  //     result in a visible notification. That's exactly the contract
  //     we want.
  //   - Phrases are NEVER sent to the server. The SW shows a generic
  //     notification; decryption happens in the page when it opens.

  let pushSubscriptionCache = null; // last-known PushSubscription object
  let vapidPubCache = null;         // cached Uint8Array of VAPID pubkey
  let pushRegistrationTopic = null; // topic we're currently subscribed for

  const PUSH_STATE_KEY = "qn:push:topic"; // localStorage key tracking
                                          // which topic this device is
                                          // currently subscribed to.

  function pushSupported() {
    return (
      "serviceWorker" in navigator &&
      "PushManager" in window &&
      "Notification" in window
    );
  }

  // RFC 4648 base64url → Uint8Array (used for applicationServerKey).
  function b64urlToUint8(b64) {
    const pad = "=".repeat((4 - (b64.length % 4)) % 4);
    const std = (b64 + pad).replace(/-/g, "+").replace(/_/g, "/");
    const raw = atob(std);
    const out = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
  }

  async function getVapidPub() {
    if (vapidPubCache) return vapidPubCache;
    const r = await fetch("/notify/vapid-public", { method: "GET" });
    if (!r.ok) throw new Error(`vapid fetch ${r.status}`);
    const j = await r.json();
    if (!j.public_b64url) throw new Error("vapid: bad response");
    vapidPubCache = b64urlToUint8(j.public_b64url);
    return vapidPubCache;
  }

  async function registerServiceWorker() {
    if (!("serviceWorker" in navigator)) return null;
    try {
      const reg = await navigator.serviceWorker.register(
        "/notify/sw.js?v=0.30.0",
        { scope: "/notify/" }
      );
      // Wait for it to be active so subscription calls don't race.
      if (reg.installing) {
        await new Promise((res) => {
          reg.installing.addEventListener("statechange", () => {
            if (reg.installing === null) res();
          });
        });
      }
      return reg;
    } catch (e) {
      // Common failures: private browsing, insecure origin, storage
      // quota. All make push impossible — surface in the UI.
      console.warn("sw register failed:", e);
      return null;
    }
  }

  async function getExistingPushSubscription() {
    if (!pushSupported()) return null;
    const reg = await navigator.serviceWorker.ready;
    return reg.pushManager.getSubscription();
  }

  async function enablePush() {
    if (!currentTopic) {
      return setStatus(
        el.pushStatus,
        "Start watching a topic first.",
        "warn"
      );
    }
    if (!pushSupported()) {
      return setStatus(
        el.pushStatus,
        "This browser doesn't support Web Push. Try Chrome/Edge on Android, or Firefox.",
        "err"
      );
    }

    setStatus(el.pushStatus, "Asking permission…");
    el.pushEnable.disabled = true;
    try {
      // Request the user's permission. On Android Chrome this is a
      // single system prompt. If the user has previously denied it,
      // `Notification.requestPermission()` resolves to "denied" without
      // prompting — they have to clear the site setting first.
      const perm = await Notification.requestPermission();
      if (perm !== "granted") {
        throw new Error(
          "Permission " +
            perm +
            ". Check your browser notification settings and try again."
        );
      }

      const reg = await navigator.serviceWorker.ready;
      const applicationServerKey = await getVapidPub();
      // userVisibleOnly is required by the spec in Chrome/Android —
      // every push must result in a visible system notification.
      let sub = await reg.pushManager.getSubscription();
      if (!sub) {
        sub = await reg.pushManager.subscribe({
          userVisibleOnly: true,
          applicationServerKey,
        });
      }

      // Serialize to the flat shape the relay expects.
      const json = sub.toJSON();
      const p256dh = json && json.keys ? json.keys.p256dh : null;
      const auth = json && json.keys ? json.keys.auth : null;
      if (!json || !json.endpoint || !p256dh || !auth) {
        throw new Error("subscription missing fields; browser bug?");
      }
      const body = JSON.stringify({
        endpoint: json.endpoint,
        p256dh,
        auth,
      });

      const r = await fetch(
        topicApiUrl(currentTopic) + "/subscribe",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body,
        }
      );
      if (!r.ok) {
        const txt = await r.text().catch(() => "");
        throw new Error(`relay ${r.status}: ${txt.slice(0, 200)}`);
      }

      pushSubscriptionCache = sub;
      pushRegistrationTopic = currentTopic;
      try {
        localStorage.setItem(PUSH_STATE_KEY, currentTopic);
      } catch (_) {}

      setStatus(
        el.pushStatus,
        `\u2705 Push enabled. Firing a test notification to verify end-to-end…`,
        "ok"
      );
      el.pushEnable.hidden = true;
      el.pushDisable.hidden = false;

      // Nudge users to actually install the PWA on Android — that's
      // what makes the notifications wake the device with the browser
      // fully closed. Browsers without standalone-display won't show
      // the hint.
      if (
        /Android/i.test(navigator.userAgent) &&
        !window.matchMedia("(display-mode: standalone)").matches
      ) {
        el.pushInstallHint.hidden = false;
      }

      // ---- Immediate test push ----
      // After the user finishes granting permission, fire exactly ONE
      // "hello, push is working" message to the same topic using the
      // phrase from the Subscribe form. The user feels the notification
      // within seconds instead of waiting up to 2 minutes for the next
      // demo tick or for a real publisher to hit this topic.
      try {
        const phrase = el.subPhrase.value || DEMO_PHRASE;
        const testMsg =
          "\u2705 Test notification — your Qira Notify push is working. " +
          "(" + new Date().toLocaleTimeString() + ")";
        const env = await encryptMessage(testMsg, phrase);
        await publishMessage(currentTopic, env);
        setStatus(
          el.pushStatus,
          `\u2705 Push enabled. Test message queued — it should buzz in 1\u20135s. ` +
          `Future messages to "${currentTopic}" will also fire notifications.`,
          "ok"
        );
      } catch (testErr) {
        // Don't bubble this to an error state — push IS enabled, just
        // the convenience self-test failed.
        console.warn("self-test publish failed:", testErr);
        setStatus(
          el.pushStatus,
          `\u2705 Push enabled for "${currentTopic}". (Self-test publish failed: ` +
          `${testErr.message || testErr} \u2014 but real messages will still fire notifications.)`,
          "warn"
        );
      }
    } catch (e) {
      setStatus(el.pushStatus, String(e.message || e), "err");
    } finally {
      el.pushEnable.disabled = false;
    }
  }

  async function disablePush() {
    if (!pushSupported()) return;
    setStatus(el.pushStatus, "Unsubscribing…");
    el.pushDisable.disabled = true;
    try {
      const reg = await navigator.serviceWorker.ready;
      const sub = await reg.pushManager.getSubscription();
      if (sub && pushRegistrationTopic) {
        // Tell the relay to forget this endpoint for this topic first
        // (so it stops pushing immediately). If this fails we still
        // call pushManager.unsubscribe() — the relay will prune the
        // dead endpoint on first 410.
        try {
          await fetch(
            topicApiUrl(pushRegistrationTopic) + "/unsubscribe",
            {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ endpoint: sub.endpoint }),
            }
          );
        } catch (_) {}
      }
      if (sub) await sub.unsubscribe();
      pushSubscriptionCache = null;
      pushRegistrationTopic = null;
      try {
        localStorage.removeItem(PUSH_STATE_KEY);
      } catch (_) {}
      setStatus(el.pushStatus, "Push disabled on this device.", "ok");
      el.pushEnable.hidden = false;
      el.pushDisable.hidden = true;
      el.pushInstallHint.hidden = true;
    } catch (e) {
      setStatus(el.pushStatus, String(e.message || e), "err");
    } finally {
      el.pushDisable.disabled = false;
    }
  }

  async function refreshPushUiForTopic() {
    // Called whenever currentTopic changes. Show the push-row once
    // we have a topic to attach to, and set button visibility to
    // reflect whether THIS topic is already subscribed on this device.
    if (!currentTopic) {
      el.pushRow.hidden = true;
      return;
    }
    if (!pushSupported()) {
      el.pushRow.hidden = false;
      setStatus(
        el.pushStatus,
        "Your browser doesn't support Android-style push notifications.",
        "warn"
      );
      el.pushEnable.hidden = true;
      el.pushDisable.hidden = true;
      return;
    }
    el.pushRow.hidden = false;
    setStatus(el.pushStatus, "");
    let lastTopic = null;
    try {
      lastTopic = localStorage.getItem(PUSH_STATE_KEY);
    } catch (_) {}

    const existing = await getExistingPushSubscription();
    if (existing && lastTopic === currentTopic) {
      pushSubscriptionCache = existing;
      pushRegistrationTopic = currentTopic;
      el.pushEnable.hidden = true;
      el.pushDisable.hidden = false;
      setStatus(el.pushStatus, `\u2705 Push enabled for "${currentTopic}".`, "ok");
    } else if (existing && lastTopic && lastTopic !== currentTopic) {
      // Device is subscribed to a *different* topic. Offer to switch.
      el.pushEnable.hidden = false;
      el.pushDisable.hidden = true;
      setStatus(
        el.pushStatus,
        `Push is currently enabled for "${lastTopic}". Enable here to switch to "${currentTopic}" on this device.`,
        "warn"
      );
    } else {
      el.pushEnable.hidden = false;
      el.pushDisable.hidden = true;
    }
  }

  // Listen for SW click → focus this tab → jump to a topic.
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.addEventListener("message", (ev) => {
      const d = ev.data || {};
      if (d.type === "qira-notify:open-topic" && d.topic && validTopic(d.topic)) {
        el.subTopic.value = d.topic;
        const saved = loadPhrase(d.topic);
        if (saved) {
          el.subPhrase.value = saved;
          el.subRemember.checked = true;
        }
        setTimeout(() => startWatching(), 50);
      }
    });
  }

  // Fire-and-forget: register the SW as soon as the page loads so the
  // PWA install prompt has what it needs.
  registerServiceWorker().catch(() => {});

  // ---------- Wire up ----------
  el.pubSend.addEventListener("click", onPublish);
  el.pubRandom.addEventListener("click", () => {
    el.pubTopic.value = randomTopic();
  });
  el.subStart.addEventListener("click", startWatching);
  el.subStop.addEventListener("click", () => stopWatching(true));
  el.subCopyUrl.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(el.subShareUrl.value);
      setStatus(el.subStatus, "Share URL copied.", "ok");
    } catch (_) {
      el.subShareUrl.select();
    }
  });
  if (el.pushEnable) el.pushEnable.addEventListener("click", enablePush);
  if (el.pushDisable) el.pushDisable.addEventListener("click", disablePush);
  if (el.demoStart) {
    el.demoStart.addEventListener("click", async () => {
      // Auto-fill the Subscribe form with the public demo credentials,
      // start watching, then immediately prompt to enable push.
      // One click → permission prompt → test notification in a few
      // seconds. No hunting around for buttons.
      el.subTopic.value = DEMO_TOPIC;
      el.subPhrase.value = DEMO_PHRASE;
      el.subRemember.checked = true;
      setStatus(
        el.demoStatus,
        "Starting \u2014 about to ask for notification permission next. Say yes and a test push fires instantly.",
        "ok"
      );
      startWatching();

      // Scroll the push row into view so the user visually tracks the
      // permission prompt and the subsequent status message.
      setTimeout(() => {
        const pushRow = document.getElementById("push-row");
        if (pushRow) pushRow.scrollIntoView({ behavior: "smooth", block: "center" });
      }, 120);

      // Tiny delay so the watching-state UI updates first, then kick
      // off the subscribe+permission flow.
      await new Promise((r) => setTimeout(r, 400));
      try {
        if (pushSupported() && Notification.permission !== "denied") {
          enablePush();
        } else {
          setStatus(
            el.demoStatus,
            pushSupported()
              ? "Notification permission is 'denied' \u2014 clear the site's notification setting in your browser and try again."
              : "Your browser doesn't expose the Push API \u2014 try Chrome/Edge on Android or Firefox.",
            "warn"
          );
        }
      } catch (_) {}
    });
  }
})();
