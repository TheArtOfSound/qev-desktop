// BRY-NFET-SX Vault — client-side encryption logic
//
// NO LOGGING — any console.log of a password, plaintext, or derived key is a
// bug. Do not add diagnostic logs of user data even temporarily.
//
// All cryptography runs in this tab via libsodium.js (see sodium.js).
// Plaintext never leaves the browser. There are zero network requests after
// the page loads (enforced by Content-Security-Policy connect-src 'none').
//
// VAULT FORMAT V2 (default for new encryptions):
//   {
//     "schema":     "BRY-NFET-SX-VAULT-V2",
//     "version":    "0.28.1",
//     "created_at": "<iso>",
//     "mode":       "self" | "share",
//     "kdf": {
//       "algorithm": "argon2id",
//       "opslimit":  4,
//       "memlimit":  100663296,
//       "salt":      "<b64url, 16 bytes>"
//     },
//     "wrap": {
//       "algorithm":   "XChaCha20-Poly1305",
//       "nonce":       "<b64url, 24 bytes>",
//       "wrapped_key": "<b64url, 48 bytes (32-byte vault_key + 16-byte tag)>"
//     },
//     "content": {
//       "algorithm":  "XChaCha20-Poly1305",
//       "nonce":      "<b64url, 24 bytes>",
//       "ciphertext": "<b64url>"
//     }
//   }
//
// V2 separates the DATA encryption key from the PASSWORD-derived key:
//   1. A fresh random 32-byte `vault_key` is generated for every vault.
//   2. The password is stretched by Argon2id into a `wrap_key`.
//   3. `wrap_key` wraps `vault_key` via XChaCha20-Poly1305 (wrap_nonce + AAD).
//   4. `vault_key` encrypts the plaintext via XChaCha20-Poly1305
//      (content_nonce + SAME AAD).
//   5. On decrypt: derive wrap_key → unwrap vault_key → decrypt content.
//
// Why this matters: the password's role is demoted from "the entire vault
// secrecy key" to "one unlock path for the data key." Today there is still
// only one unlock path (the password). The format change is the primitive
// you need before you could ever add a second unlock path (recovery code,
// device-bound key, etc.) without re-encrypting the data.
//
// Legacy V1 vaults are still readable. V1 encryption is NOT performed for
// new vaults; it exists only to keep old boxes openable and to run a V1
// round-trip self-test at page load.
//
// AAD is NOT stored. It is derived deterministically on both encrypt and
// decrypt by canonical-JSON-serializing the full metadata block. The SAME
// AAD is used for both wrap and content AEAD operations, so tampering with
// any bound field breaks at least one of them.

(function () {
  "use strict";

  // -------- Constants --------
  const SCHEMA_V1 = "BRY-NFET-SX-VAULT-V1";
  const SCHEMA_V2 = "BRY-NFET-SX-VAULT-V2";
  // Qira Notify envelope — structurally similar to V2 but with
  // literal `wrap.aad` / `content.aad` domain strings as AAD (not
  // a canonical-JSON-derived binding). Accepted here for read-only
  // decryption so a Notify JSON + phrase opens in the Vault tab.
  const SCHEMA_QIRA_NOTIFY_V1 = "QIRA-NOTIFY-V1";
  const SCHEMA = SCHEMA_V2; // default schema for new encryptions
  const VERSION = "0.28.1";
  const KDF_ALG = "argon2id";
  const AEAD_ALG = "XChaCha20-Poly1305";
  const DEFAULT_OPSLIMIT = 4;
  const DEFAULT_MEMLIMIT = 96 * 1024 * 1024;
  const MIN_OPSLIMIT = 1;
  const MAX_OPSLIMIT = 10;
  const MIN_MEMLIMIT = 8 * 1024 * 1024;
  const MAX_MEMLIMIT = 256 * 1024 * 1024;
  const SALT_BYTES = 16;
  const NONCE_BYTES = 24;
  const KEY_BYTES = 32;
  const MAX_PLAINTEXT_BYTES = 256 * 1024;
  const MAX_CIPHERTEXT_BYTES = 1024 * 1024;
  const VAULT_TEXT_PREFIX_V1 = "BRY-VAULT-V1.";
  const VAULT_TEXT_PREFIX_V2 = "BRY-VAULT-V2.";
  // Password-strength gate: submit is blocked until the live strength score
  // meets this threshold. 3 on a 0-7 scale corresponds roughly to "okay"
  // (~12+ chars or a 4-word phrase). Weak single-word inputs fall below it.
  const MIN_STRENGTH_SCORE = 3;

  // Lock strength presets. Stronger = longer to lock/unlock, but linearly
  // more expensive for an offline brute-force attacker per password guess.
  //
  // Strong-lock was bumped in v0.28.1-phrase1 from opslimit=3/64 MiB (~2s)
  // to opslimit=4/96 MiB (~4s). Double the cost, double the attacker's
  // offline brute-force time, negligible UX impact for legitimate users
  // who unlock at most a few times per session.
  const LOCK_PRESETS = {
    quick:  { opslimit: 1, memlimit: 32  * 1024 * 1024, label: "Quick lock",  hint: "about 1 second"  },
    strong: { opslimit: 4, memlimit: 96  * 1024 * 1024, label: "Strong lock", hint: "about 4 seconds" },
    vault:  { opslimit: 6, memlimit: 128 * 1024 * 1024, label: "Vault lock",  hint: "about 7 seconds" },
  };
  const DEFAULT_PRESET_KEY = "strong";

  // Tiny wordlist for the passphrase generator. 192 simple memorable
  // words. log2(192^4) ~= 30 bits — not great, so we add 2 random
  // digits for ~37 bits. Suggest only; users should still pick longer
  // passwords.
  const PASSPHRASE_WORDS = (
    "able acid acre add age aim air ant ape arm army art ask atom auto " +
    "baby back bad bag bake ball band bank bar barn base bat bath bay " +
    "beam bean bear beat bed bee beef bell belt bend best bid big bike " +
    "bill bird bit blue boat body bold bolt bone book boot born boss " +
    "both bow bowl box boy bran brave bread bring brown brush bug build " +
    "burn bus bush busy buy cab cage cake calf calm camp can cap car " +
    "card care cart case cash cast cat catch cave cell chair chalk " +
    "charm cheap chest chief chin chip city claim clay clean clear " +
    "click cliff cloak clock cloth cloud club coal coast coat coin " +
    "cold come cook cool corn cost couch count court cow crab crew " +
    "crop cross crown cry cup curl daisy damp dance dark dawn day deal " +
    "deep deer desk dial dig dim dish dive dock dog doll door dot " +
    "dove down draft drag draw dream dress drift drive drop drum dry " +
    "duck dust eagle ear earth east easy edge egg eight elbow elf elm"
  ).split(/\s+/).filter(Boolean);

  // -------- Helpers --------

  function utf8(s) {
    return new TextEncoder().encode(s);
  }

  function fromUtf8(bytes) {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  }

  function b64urlEncode(bytes) {
    return sodium.to_base64(bytes, sodium.base64_variants.URLSAFE_NO_PADDING);
  }

  function b64urlDecode(str) {
    return sodium.from_base64(str, sodium.base64_variants.URLSAFE_NO_PADDING);
  }

  // Recursive sorted-keys JSON serializer with no whitespace.
  // NOT JSON.stringify(obj, Object.keys(obj).sort()) — that only sorts top
  // level. This walks the whole tree.
  function canonicalJSON(value) {
    if (value === null || typeof value !== "object") {
      return JSON.stringify(value);
    }
    if (Array.isArray(value)) {
      return "[" + value.map(canonicalJSON).join(",") + "]";
    }
    const keys = Object.keys(value).sort();
    const parts = keys.map(function (k) {
      return JSON.stringify(k) + ":" + canonicalJSON(value[k]);
    });
    return "{" + parts.join(",") + "}";
  }

  // -------- v2 helpers --------

  // Compute a friendly "envelope ID" for the vault: SHA-256 hex of the
  // canonical JSON of the full vault. This gives the user a unique name
  // for their box that they can reference in conversation. It is not
  // cryptographically meaningful (the vault already has its own AEAD
  // tag); it is purely a human identifier.
  function computeEnvelopeId(vault) {
    const bytes = utf8(canonicalJSON(vault));
    const digest = sodium.crypto_hash_sha256(bytes);
    return sodium.to_hex(digest);
  }

  // Generate a 4-word passphrase plus 2 random digits.
  // Example output: "river-purple-dragon-cloud-47"
  function generatePassphrase() {
    const words = [];
    for (let i = 0; i < 4; i++) {
      const idx = sodium.randombytes_uniform(PASSPHRASE_WORDS.length);
      words.push(PASSPHRASE_WORDS[idx]);
    }
    const d1 = sodium.randombytes_uniform(10);
    const d2 = sodium.randombytes_uniform(10);
    return words.join("-") + "-" + d1 + d2;
  }

  // Hand-rolled password strength estimator. Not zxcvbn but adequate
  // for a "too weak / okay / strong / very strong" indicator. Scores by
  // length, character class diversity, word count, and absence of obvious
  // patterns. Scores below MIN_STRENGTH_SCORE block the submit button.
  function passwordStrength(pw) {
    if (!pw || pw.length === 0) {
      return { score: 0, label: "(empty)", hint: "Type a phrase" };
    }
    let score = 0;
    // Length buckets
    if (pw.length >= 8) score += 1;
    if (pw.length >= 12) score += 1;
    if (pw.length >= 16) score += 1;
    if (pw.length >= 24) score += 1;
    // Character class diversity (maxes at 2 for word-based phrases)
    let classes = 0;
    if (/[a-z]/.test(pw)) classes += 1;
    if (/[A-Z]/.test(pw)) classes += 1;
    if (/[0-9]/.test(pw)) classes += 1;
    if (/[^a-zA-Z0-9]/.test(pw)) classes += 1;
    score += Math.min(classes, 2);
    // Bonus for multi-word phrases (separator between letters)
    const wordSeparators = (pw.match(/[\s\-_.]+/g) || []).length;
    if (wordSeparators >= 3) score += 1; // 4+ tokens
    if (wordSeparators >= 4) score += 1; // 5+ tokens
    // Penalties
    if (/(.)\1\1/.test(pw)) score -= 2; // triple-repeat
    if (/^(password|qwerty|123|letmein|admin|secret|welcome)/i.test(pw)) score -= 4;
    if (pw.length < 8) score = Math.min(score, 1); // hard cap short inputs
    // Reject single-token short inputs (one word, no separators, <12 chars)
    if (pw.length < 12 && wordSeparators === 0) score = Math.min(score, 2);
    if (score < 0) score = 0;
    if (score > 7) score = 7;

    // Map raw score to display bucket
    let label, hint;
    if (score <= 1) {
      label = "too weak";
      hint = "A single word is crackable in hours. Use 4+ random words or the generator below.";
    } else if (score <= 2) {
      label = "weak";
      hint = "Still guessable offline. Try 4+ random words.";
    } else if (score <= 4) {
      label = "okay";
      hint = "Usable. Longer or more words would be safer.";
    } else if (score <= 6) {
      label = "strong";
      hint = "Good. Hard to guess.";
    } else {
      label = "very strong";
      hint = "Excellent. This is very hard to crack.";
    }
    return { score: score, label: label, hint: hint };
  }

  // Build the printable recovery sheet text. This is a plain text file
  // the user can save or print. It contains:
  //   - The two things they need to decrypt (file + phrase)
  //   - All the auto-generated values for reference (already in the box)
  //   - Step-by-step instructions for how to decrypt later
  //   - How to verify the page integrity
  // No information is exposed beyond what is in the .vault.json file.
  function buildRecoverySheet(vault, downloadFilename, envelopeId) {
    const lines = [];
    function L(s) { lines.push(s); }
    function HR() { lines.push("=".repeat(54)); }
    function HR2() { lines.push("-".repeat(54)); }
    const isV2 = vault.schema === SCHEMA_V2;
    HR();
    L("BRY-NFET-SX VAULT  RECOVERY SHEET");
    HR();
    L("");
    L("Locked at: " + vault.created_at);
    L("Made on:   secure.imagineqira.com/chat");
    L("");
    HR2();
    L("TO OPEN THIS LATER, YOU NEED TWO THINGS:");
    HR2();
    L("");
    L("  1. THE LOCKED BOX FILE");
    L("     File name:  " + downloadFilename);
    L("     Save this file. Email it to yourself. Put it on a USB drive.");
    L("     The file is in your downloads folder.");
    L("");
    L("  2. YOUR SECRET PHRASE");
    L("     This is the phrase you typed.");
    L("     We do not know it. We do not store it.");
    L("     If you forget it, the box CANNOT be opened. There is no recovery.");
    L("");
    HR2();
    L("EVERYTHING BELOW IS ALREADY INSIDE THE BOX.");
    L("You do NOT need to save it separately.");
    L("It is here only for your records.");
    HR2();
    L("");
    L("  Box name (envelope ID):");
    L("      " + envelopeId);
    L("");
    L("  Box style:         " + vault.schema);
    L("  Made by version:   " + vault.version);
    L("  Mode:              " + (vault.mode === "share" ? "share with someone" : "just for yourself"));
    L("");
    L("  Lock recipe:");
    if (isV2) {
      L("      Wrap (vault key): " + vault.wrap.algorithm + " (24-byte nonce, 16-byte tag)");
      L("      Content:          " + vault.content.algorithm + " (24-byte nonce, 16-byte tag)");
    } else {
      L("      Encryption:    " + vault.aead.algorithm + " (24-byte nonce, 16-byte tag)");
    }
    L("      Phrase mix:    " + vault.kdf.algorithm + " (work units " + vault.kdf.opslimit + ", memory " + Math.round(vault.kdf.memlimit / 1024 / 1024) + " MiB)");
    L("");
    L("  Your scramble code (salt, base64url):");
    L("      " + vault.kdf.salt);
    L("");
    if (isV2) {
      L("  Wrap nonce (base64url):");
      L("      " + vault.wrap.nonce);
      L("");
      L("  Wrapped vault key (base64url):");
      const wk = vault.wrap.wrapped_key;
      for (let i = 0; i < wk.length; i += 64) {
        L("      " + wk.slice(i, i + 64));
      }
      L("");
      L("  Content nonce (base64url):");
      L("      " + vault.content.nonce);
      L("");
      L("  Encrypted message (ciphertext, base64url):");
      const ct = vault.content.ciphertext;
      for (let i = 0; i < ct.length; i += 64) {
        L("      " + ct.slice(i, i + 64));
      }
    } else {
      L("  Your secret number (nonce, base64url):");
      L("      " + vault.aead.nonce);
      L("");
      L("  Encrypted message (ciphertext, base64url):");
      const ct = vault.aead.ciphertext;
      for (let i = 0; i < ct.length; i += 64) {
        L("      " + ct.slice(i, i + 64));
      }
    }
    L("");
    HR2();
    L("HOW TO OPEN THIS BOX AGAIN:");
    HR2();
    L("");
    L("  1. Go to:    https://secure.imagineqira.com/chat");
    L('  2. Drop EITHER the .vault.json file OR this recovery sheet onto');
    L("     the page. (This sheet contains the full box at the bottom.)");
    L("  3. Type your secret phrase.");
    L('  4. Click "Open it!"');
    L("");
    HR2();
    L("THE LOCKED BOX (machine-readable copy)");
    HR2();
    L("");
    L("If you lost the .vault.json file, you can paste this entire recovery");
    L("sheet into the Open box on the page. The page will find the box");
    L("content between the markers below automatically.");
    L("");
    L("----- BEGIN BRY-NFET-SX VAULT -----");
    const vaultLines = JSON.stringify(vault, null, 2).split("\n");
    vaultLines.forEach(function (vl) { L(vl); });
    L("----- END BRY-NFET-SX VAULT -----");
    L("");
    HR2();
    L("HOW TO VERIFY THIS PAGE IS HONEST:");
    HR2();
    L("");
    L("  1. Go to:    https://secure.imagineqira.com/verify");
    L("  2. Compare the SHA-256 of /chat/chat.js and /chat/sodium.js");
    L("     against the signed integrity record.");
    L("  3. If they match, the JavaScript is the published, signed version.");
    L("");
    HR();
    return lines.join("\n") + "\n";
  }

  function downloadRecoverySheet(vault, downloadFilename, envelopeId) {
    const text = buildRecoverySheet(vault, downloadFilename, envelopeId);
    const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    const stamp = new Date().toISOString().replace(/[:.]/g, "-").replace("T", "_").replace("Z", "");
    a.href = url;
    a.download = "vault-recovery-" + stamp + ".txt";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  // Build the canonical V1 AAD bytes. Binds schema, version, created_at,
  // mode, kdf{*}, aead{algorithm,nonce}. Used for legacy V1 decryption.
  function buildAADV1(vault) {
    const aadObj = {
      aead: {
        algorithm: vault.aead.algorithm,
        nonce: vault.aead.nonce,
      },
      created_at: vault.created_at,
      kdf: {
        algorithm: vault.kdf.algorithm,
        memlimit: vault.kdf.memlimit,
        opslimit: vault.kdf.opslimit,
        salt: vault.kdf.salt,
      },
      mode: vault.mode,
      schema: vault.schema,
      version: vault.version,
    };
    return utf8(canonicalJSON(aadObj));
  }

  // Build the canonical V2 AAD bytes. Binds every piece of metadata
  // EXCEPT the wrapped_key and ciphertext themselves: schema, version,
  // created_at, mode, kdf{*}, wrap{algorithm,nonce}, content{algorithm,
  // nonce}. This same AAD is used for BOTH the wrap AEAD operation and
  // the content AEAD operation, so tampering with any bound field (salt,
  // kdf params, either nonce, either algorithm string, mode, created_at,
  // schema, version) breaks at least one of the two AEAD tags on decrypt.
  function buildAADV2(vault) {
    const aadObj = {
      content: {
        algorithm: vault.content.algorithm,
        nonce: vault.content.nonce,
      },
      created_at: vault.created_at,
      kdf: {
        algorithm: vault.kdf.algorithm,
        memlimit: vault.kdf.memlimit,
        opslimit: vault.kdf.opslimit,
        salt: vault.kdf.salt,
      },
      mode: vault.mode,
      schema: vault.schema,
      version: vault.version,
      wrap: {
        algorithm: vault.wrap.algorithm,
        nonce: vault.wrap.nonce,
      },
    };
    return utf8(canonicalJSON(aadObj));
  }

  // -------- Validation --------

  function enforceKdfCaps(kdf) {
    if (!kdf || typeof kdf !== "object") {
      throw new Error("Vault malformed: missing kdf section");
    }
    if (kdf.algorithm !== KDF_ALG) {
      throw new Error("Unsupported KDF algorithm: " + kdf.algorithm);
    }
    if (
      typeof kdf.opslimit !== "number" ||
      kdf.opslimit < MIN_OPSLIMIT ||
      kdf.opslimit > MAX_OPSLIMIT
    ) {
      throw new Error(
        "KDF opslimit out of range (" + MIN_OPSLIMIT + "-" + MAX_OPSLIMIT + ")"
      );
    }
    if (
      typeof kdf.memlimit !== "number" ||
      kdf.memlimit < MIN_MEMLIMIT ||
      kdf.memlimit > MAX_MEMLIMIT
    ) {
      throw new Error(
        "KDF memlimit out of range (" +
          (MIN_MEMLIMIT / 1024 / 1024) +
          "-" +
          (MAX_MEMLIMIT / 1024 / 1024) +
          " MiB)"
      );
    }
    if (typeof kdf.salt !== "string") {
      throw new Error("Vault malformed: kdf.salt must be a string");
    }
  }

  function validateCommonVaultFields(vault) {
    if (!vault || typeof vault !== "object") {
      throw new Error("Vault malformed: not an object");
    }
    if (typeof vault.version !== "string") {
      throw new Error("Vault malformed: missing version");
    }
    if (typeof vault.created_at !== "string") {
      throw new Error("Vault malformed: missing created_at");
    }
    if (vault.mode !== "self" && vault.mode !== "share") {
      throw new Error('Vault malformed: mode must be "self" or "share"');
    }
    enforceKdfCaps(vault.kdf);
  }

  function validateVaultSchemaV1(vault) {
    validateCommonVaultFields(vault);
    if (vault.schema !== SCHEMA_V1) {
      throw new Error(
        'Unsupported vault schema: "' + vault.schema + '" (expected ' + SCHEMA_V1 + ")"
      );
    }
    if (!vault.aead || vault.aead.algorithm !== AEAD_ALG) {
      throw new Error(
        "Unsupported AEAD algorithm: " + (vault.aead && vault.aead.algorithm)
      );
    }
    if (typeof vault.aead.nonce !== "string") {
      throw new Error("Vault malformed: missing aead.nonce");
    }
    if (typeof vault.aead.ciphertext !== "string") {
      throw new Error("Vault malformed: missing aead.ciphertext");
    }
  }

  function validateVaultSchemaV2(vault) {
    validateCommonVaultFields(vault);
    if (vault.schema !== SCHEMA_V2) {
      throw new Error(
        'Unsupported vault schema: "' + vault.schema + '" (expected ' + SCHEMA_V2 + ")"
      );
    }
    if (!vault.wrap || vault.wrap.algorithm !== AEAD_ALG) {
      throw new Error(
        "Unsupported wrap algorithm: " + (vault.wrap && vault.wrap.algorithm)
      );
    }
    if (typeof vault.wrap.nonce !== "string") {
      throw new Error("Vault malformed: missing wrap.nonce");
    }
    if (typeof vault.wrap.wrapped_key !== "string") {
      throw new Error("Vault malformed: missing wrap.wrapped_key");
    }
    if (!vault.content || vault.content.algorithm !== AEAD_ALG) {
      throw new Error(
        "Unsupported content algorithm: " + (vault.content && vault.content.algorithm)
      );
    }
    if (typeof vault.content.nonce !== "string") {
      throw new Error("Vault malformed: missing content.nonce");
    }
    if (typeof vault.content.ciphertext !== "string") {
      throw new Error("Vault malformed: missing content.ciphertext");
    }
  }

  // Qira Notify uses libsodium's canonical alg name; Vault uses
  // our brand-specific title-case. Both refer to the same AEAD.
  const NOTIFY_AEAD_ALG = "xchacha20poly1305-ietf";

  // Qira Notify V1 validator. Structurally V2-shaped but no `mode`
  // or `version` fields, and it carries its own AAD as literal
  // strings in `wrap.aad` / `content.aad`. Algorithm strings use
  // the libsodium canonical naming (lowercase, `-ietf`) rather
  // than the vault's title-case.
  function validateVaultSchemaQiraNotifyV1(vault) {
    if (!vault || typeof vault !== "object") {
      throw new Error("Vault malformed: not an object");
    }
    if (vault.schema !== SCHEMA_QIRA_NOTIFY_V1) {
      throw new Error(
        'Unsupported vault schema: "' + vault.schema +
        '" (expected ' + SCHEMA_QIRA_NOTIFY_V1 + ")"
      );
    }
    if (typeof vault.created_at !== "string") {
      throw new Error("Notify envelope malformed: missing created_at");
    }
    enforceKdfCaps(vault.kdf);
    if (!vault.wrap || vault.wrap.algorithm !== NOTIFY_AEAD_ALG) {
      throw new Error(
        "Unsupported wrap algorithm: " + (vault.wrap && vault.wrap.algorithm)
      );
    }
    if (typeof vault.wrap.aad !== "string") {
      throw new Error("Notify envelope malformed: missing wrap.aad");
    }
    if (typeof vault.wrap.nonce !== "string") {
      throw new Error("Notify envelope malformed: missing wrap.nonce");
    }
    if (typeof vault.wrap.wrapped_key !== "string") {
      throw new Error("Notify envelope malformed: missing wrap.wrapped_key");
    }
    if (!vault.content || vault.content.algorithm !== NOTIFY_AEAD_ALG) {
      throw new Error(
        "Unsupported content algorithm: " + (vault.content && vault.content.algorithm)
      );
    }
    if (typeof vault.content.aad !== "string") {
      throw new Error("Notify envelope malformed: missing content.aad");
    }
    if (typeof vault.content.nonce !== "string") {
      throw new Error("Notify envelope malformed: missing content.nonce");
    }
    if (typeof vault.content.ciphertext !== "string") {
      throw new Error("Notify envelope malformed: missing content.ciphertext");
    }
  }

  // Dispatch validator — chooses V1, V2, or Notify-V1 based on schema.
  function validateVaultSchema(vault) {
    if (!vault || typeof vault !== "object") {
      throw new Error("Vault malformed: not an object");
    }
    if (vault.schema === SCHEMA_V2) return validateVaultSchemaV2(vault);
    if (vault.schema === SCHEMA_V1) return validateVaultSchemaV1(vault);
    if (vault.schema === SCHEMA_QIRA_NOTIFY_V1) {
      return validateVaultSchemaQiraNotifyV1(vault);
    }
    throw new Error(
      'Unsupported vault schema: "' + vault.schema +
      '" (expected ' + SCHEMA_V2 + ", " + SCHEMA_V1 + ", or " +
      SCHEMA_QIRA_NOTIFY_V1 + ")"
    );
  }

  // -------- Encrypt / Decrypt --------
  //
  // Two schemas are supported:
  //   V1 (legacy) — direct encryption of plaintext with a password-derived
  //                 key. Still readable for backward compat; not produced
  //                 for new vaults.
  //   V2 (current) — random vault_key wraps the data, wrap_key (derived
  //                  from password) wraps the vault_key. Same AEAD
  //                  primitive for both layers. Same AAD for both layers.
  //
  // Top-level encryptVault() always produces V2. Top-level decryptVault()
  // dispatches on vault.schema so old V1 boxes still open cleanly.

  // ---- V1 (legacy) ----

  function encryptVaultV1(opts) {
    const plaintext = opts.plaintext;
    const password = opts.password;
    const mode = opts.mode;
    const salt = opts.salt || sodium.randombytes_buf(SALT_BYTES);
    const nonce = opts.nonce || sodium.randombytes_buf(NONCE_BYTES);
    const opslimit = opts.opslimit || DEFAULT_OPSLIMIT;
    const memlimit = opts.memlimit || DEFAULT_MEMLIMIT;

    if (typeof plaintext !== "string" || plaintext.length === 0) {
      throw new Error("Type a message before encrypting");
    }
    if (typeof password !== "string" || password.length === 0) {
      throw new Error("Type a phrase before encrypting");
    }
    if (mode !== "self" && mode !== "share") {
      throw new Error("Pick a mode first");
    }
    if (!(salt instanceof Uint8Array) || salt.length !== SALT_BYTES) {
      throw new Error("Invalid salt (must be " + SALT_BYTES + " bytes)");
    }
    if (!(nonce instanceof Uint8Array) || nonce.length !== NONCE_BYTES) {
      throw new Error("Invalid nonce (must be " + NONCE_BYTES + " bytes)");
    }
    if (opslimit < MIN_OPSLIMIT || opslimit > MAX_OPSLIMIT) {
      throw new Error("opslimit out of range");
    }
    if (memlimit < MIN_MEMLIMIT || memlimit > MAX_MEMLIMIT) {
      throw new Error("memlimit out of range");
    }

    const ptBytes = utf8(plaintext);
    if (ptBytes.length > MAX_PLAINTEXT_BYTES) {
      throw new Error(
        "Message too large (max " + (MAX_PLAINTEXT_BYTES / 1024) + " KiB)"
      );
    }

    const pwBytes = utf8(password);
    const key = sodium.crypto_pwhash(
      KEY_BYTES,
      pwBytes,
      salt,
      opslimit,
      memlimit,
      sodium.crypto_pwhash_ALG_ARGON2ID13
    );
    sodium.memzero(pwBytes);

    const vault = {
      schema: SCHEMA_V1,
      version: VERSION,
      created_at: new Date().toISOString(),
      mode: mode,
      kdf: {
        algorithm: KDF_ALG,
        opslimit: opslimit,
        memlimit: memlimit,
        salt: b64urlEncode(salt),
      },
      aead: {
        algorithm: AEAD_ALG,
        nonce: b64urlEncode(nonce),
        ciphertext: "", // filled below
      },
    };

    const aad = buildAADV1(vault);

    let ct;
    try {
      ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        ptBytes, aad, null, nonce, key
      );
    } finally {
      sodium.memzero(key);
    }
    vault.aead.ciphertext = b64urlEncode(ct);
    return vault;
  }

  function decryptVaultV1(opts) {
    const vault = opts.vault;
    const password = opts.password;

    validateVaultSchemaV1(vault);

    if (typeof password !== "string" || password.length === 0) {
      throw new Error("Type the phrase");
    }

    const salt = b64urlDecode(vault.kdf.salt);
    const nonce = b64urlDecode(vault.aead.nonce);
    const ct = b64urlDecode(vault.aead.ciphertext);

    if (salt.length !== SALT_BYTES) throw new Error("Vault malformed: salt length");
    if (nonce.length !== NONCE_BYTES) throw new Error("Vault malformed: nonce length");
    if (ct.length === 0) throw new Error("Vault malformed: empty ciphertext");
    if (ct.length > MAX_CIPHERTEXT_BYTES) {
      throw new Error("Vault too large (max " + (MAX_CIPHERTEXT_BYTES / 1024) + " KiB)");
    }

    const pwBytes = utf8(password);
    const key = sodium.crypto_pwhash(
      KEY_BYTES, pwBytes, salt,
      vault.kdf.opslimit, vault.kdf.memlimit,
      sodium.crypto_pwhash_ALG_ARGON2ID13
    );
    sodium.memzero(pwBytes);

    const aad = buildAADV1(vault);

    let plaintextBytes;
    try {
      plaintextBytes = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null, ct, aad, nonce, key
      );
    } catch (err) {
      sodium.memzero(key);
      throw new Error("Could not decrypt: wrong phrase or tampered vault");
    }
    sodium.memzero(key);

    try {
      return fromUtf8(plaintextBytes);
    } catch (err) {
      throw new Error("Decrypted bytes are not valid UTF-8 (vault may be corrupted)");
    }
  }

  // ---- V2 (current) ----

  function encryptVaultV2(opts) {
    const plaintext = opts.plaintext;
    const password = opts.password;
    const mode = opts.mode;
    // Caller-supplied randomness so the live UI displays what was used.
    // Fallback to fresh random values if not supplied (used by self-test).
    const salt = opts.salt || sodium.randombytes_buf(SALT_BYTES);
    const wrapNonce = opts.wrapNonce || sodium.randombytes_buf(NONCE_BYTES);
    const contentNonce = opts.contentNonce || sodium.randombytes_buf(NONCE_BYTES);
    const vaultKey = opts.vaultKey || sodium.randombytes_buf(KEY_BYTES);
    const opslimit = opts.opslimit || DEFAULT_OPSLIMIT;
    const memlimit = opts.memlimit || DEFAULT_MEMLIMIT;

    if (typeof plaintext !== "string" || plaintext.length === 0) {
      throw new Error("Type a message before encrypting");
    }
    if (typeof password !== "string" || password.length === 0) {
      throw new Error("Type a phrase before encrypting");
    }
    if (mode !== "self" && mode !== "share") {
      throw new Error("Pick a mode first");
    }
    if (!(salt instanceof Uint8Array) || salt.length !== SALT_BYTES) {
      throw new Error("Invalid salt (must be " + SALT_BYTES + " bytes)");
    }
    if (!(wrapNonce instanceof Uint8Array) || wrapNonce.length !== NONCE_BYTES) {
      throw new Error("Invalid wrap nonce (must be " + NONCE_BYTES + " bytes)");
    }
    if (!(contentNonce instanceof Uint8Array) || contentNonce.length !== NONCE_BYTES) {
      throw new Error("Invalid content nonce (must be " + NONCE_BYTES + " bytes)");
    }
    if (!(vaultKey instanceof Uint8Array) || vaultKey.length !== KEY_BYTES) {
      throw new Error("Invalid vault_key (must be " + KEY_BYTES + " bytes)");
    }
    if (opslimit < MIN_OPSLIMIT || opslimit > MAX_OPSLIMIT) {
      throw new Error("opslimit out of range");
    }
    if (memlimit < MIN_MEMLIMIT || memlimit > MAX_MEMLIMIT) {
      throw new Error("memlimit out of range");
    }

    const ptBytes = utf8(plaintext);
    if (ptBytes.length > MAX_PLAINTEXT_BYTES) {
      throw new Error(
        "Message too large (max " + (MAX_PLAINTEXT_BYTES / 1024) + " KiB)"
      );
    }

    // Derive wrap_key from the password. This is the ONLY role the password
    // plays in V2 — it unlocks the vault_key, which in turn unlocks the data.
    const pwBytes = utf8(password);
    const wrapKey = sodium.crypto_pwhash(
      KEY_BYTES, pwBytes, salt,
      opslimit, memlimit,
      sodium.crypto_pwhash_ALG_ARGON2ID13
    );
    sodium.memzero(pwBytes);

    // Build the vault skeleton so we can compute the shared AAD once.
    const vault = {
      schema: SCHEMA_V2,
      version: VERSION,
      created_at: new Date().toISOString(),
      mode: mode,
      kdf: {
        algorithm: KDF_ALG,
        opslimit: opslimit,
        memlimit: memlimit,
        salt: b64urlEncode(salt),
      },
      wrap: {
        algorithm: AEAD_ALG,
        nonce: b64urlEncode(wrapNonce),
        wrapped_key: "", // filled below
      },
      content: {
        algorithm: AEAD_ALG,
        nonce: b64urlEncode(contentNonce),
        ciphertext: "", // filled below
      },
    };

    const aad = buildAADV2(vault);

    // Step 1: wrap vault_key with wrap_key (AEAD over the vault_key bytes).
    let wrappedKey;
    try {
      wrappedKey = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        vaultKey, aad, null, wrapNonce, wrapKey
      );
    } finally {
      sodium.memzero(wrapKey);
    }
    vault.wrap.wrapped_key = b64urlEncode(wrappedKey);

    // Step 2: encrypt plaintext with vault_key (AEAD over the plaintext).
    let contentCt;
    try {
      contentCt = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        ptBytes, aad, null, contentNonce, vaultKey
      );
    } finally {
      sodium.memzero(vaultKey);
    }
    vault.content.ciphertext = b64urlEncode(contentCt);

    return vault;
  }

  function decryptVaultV2(opts) {
    const vault = opts.vault;
    const password = opts.password;

    validateVaultSchemaV2(vault);

    if (typeof password !== "string" || password.length === 0) {
      throw new Error("Type the phrase");
    }

    const salt = b64urlDecode(vault.kdf.salt);
    const wrapNonce = b64urlDecode(vault.wrap.nonce);
    const wrappedKey = b64urlDecode(vault.wrap.wrapped_key);
    const contentNonce = b64urlDecode(vault.content.nonce);
    const contentCt = b64urlDecode(vault.content.ciphertext);

    if (salt.length !== SALT_BYTES) throw new Error("Vault malformed: salt length");
    if (wrapNonce.length !== NONCE_BYTES) throw new Error("Vault malformed: wrap nonce length");
    if (contentNonce.length !== NONCE_BYTES) throw new Error("Vault malformed: content nonce length");
    // wrapped_key = 32-byte vault_key + 16-byte Poly1305 tag = 48 bytes exactly
    if (wrappedKey.length !== KEY_BYTES + 16) {
      throw new Error("Vault malformed: wrapped_key length (got " + wrappedKey.length + ")");
    }
    if (contentCt.length === 0) throw new Error("Vault malformed: empty ciphertext");
    if (contentCt.length > MAX_CIPHERTEXT_BYTES) {
      throw new Error("Vault too large (max " + (MAX_CIPHERTEXT_BYTES / 1024) + " KiB)");
    }

    // Derive wrap_key from the password.
    const pwBytes = utf8(password);
    const wrapKey = sodium.crypto_pwhash(
      KEY_BYTES, pwBytes, salt,
      vault.kdf.opslimit, vault.kdf.memlimit,
      sodium.crypto_pwhash_ALG_ARGON2ID13
    );
    sodium.memzero(pwBytes);

    const aad = buildAADV2(vault);

    // Step 1: unwrap vault_key. If this fails, the phrase is wrong OR the
    // wrap metadata has been tampered with. Either way, the user-visible
    // error is the same.
    let vaultKey;
    try {
      vaultKey = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null, wrappedKey, aad, wrapNonce, wrapKey
      );
    } catch (err) {
      sodium.memzero(wrapKey);
      throw new Error("Could not decrypt: wrong phrase or tampered vault");
    }
    sodium.memzero(wrapKey);

    if (vaultKey.length !== KEY_BYTES) {
      sodium.memzero(vaultKey);
      throw new Error("Vault malformed: unwrapped vault_key is not " + KEY_BYTES + " bytes");
    }

    // Step 2: decrypt content with vault_key. If the unwrap succeeded, the
    // phrase was correct — so a failure here means the ciphertext block was
    // modified independently from the wrap. Report it distinctly.
    let plaintextBytes;
    try {
      plaintextBytes = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null, contentCt, aad, contentNonce, vaultKey
      );
    } catch (err) {
      sodium.memzero(vaultKey);
      throw new Error("Could not decrypt: vault content was tampered with");
    }
    sodium.memzero(vaultKey);

    try {
      return fromUtf8(plaintextBytes);
    } catch (err) {
      throw new Error("Decrypted bytes are not valid UTF-8 (vault may be corrupted)");
    }
  }

  // -------- Qira Notify V1 decrypt --------
  //
  // A Notify envelope is structurally V2-shaped but its AAD is the
  // envelope's literal `wrap.aad` / `content.aad` strings, not a
  // canonical-JSON binding of the metadata. Same AEAD + KDF as V2;
  // only the AAD differs.
  //
  // Read-only: QEV never produces Notify envelopes — this path
  // exists so a user who pastes a Notify inbox JSON can open it
  // with their phrase in the Vault tab, no extra tooling required.
  function decryptVaultQiraNotifyV1(opts) {
    const vault = opts.vault;
    const password = opts.password;

    validateVaultSchemaQiraNotifyV1(vault);

    if (typeof password !== "string" || password.length === 0) {
      throw new Error("Type the phrase");
    }

    const salt = b64urlDecode(vault.kdf.salt);
    const wrapNonce = b64urlDecode(vault.wrap.nonce);
    const wrappedKey = b64urlDecode(vault.wrap.wrapped_key);
    const contentNonce = b64urlDecode(vault.content.nonce);
    const contentCt = b64urlDecode(vault.content.ciphertext);

    if (salt.length !== SALT_BYTES) throw new Error("Notify envelope malformed: salt length");
    if (wrapNonce.length !== NONCE_BYTES) throw new Error("Notify envelope malformed: wrap nonce length");
    if (contentNonce.length !== NONCE_BYTES) throw new Error("Notify envelope malformed: content nonce length");
    if (wrappedKey.length !== KEY_BYTES + 16) {
      throw new Error("Notify envelope malformed: wrapped_key length (got " + wrappedKey.length + ")");
    }
    if (contentCt.length === 0) throw new Error("Notify envelope malformed: empty ciphertext");
    if (contentCt.length > MAX_CIPHERTEXT_BYTES) {
      throw new Error("Notify envelope too large (max " + (MAX_CIPHERTEXT_BYTES / 1024) + " KiB)");
    }

    const pwBytes = utf8(password);
    const wrapKey = sodium.crypto_pwhash(
      KEY_BYTES, pwBytes, salt,
      vault.kdf.opslimit, vault.kdf.memlimit,
      sodium.crypto_pwhash_ALG_ARGON2ID13
    );
    sodium.memzero(pwBytes);

    const wrapAad = utf8(vault.wrap.aad);
    const contentAad = utf8(vault.content.aad);

    let vaultKey;
    try {
      vaultKey = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null, wrappedKey, wrapAad, wrapNonce, wrapKey
      );
    } catch (err) {
      sodium.memzero(wrapKey);
      throw new Error("Could not decrypt: wrong phrase or tampered envelope");
    }
    sodium.memzero(wrapKey);

    if (vaultKey.length !== KEY_BYTES) {
      sodium.memzero(vaultKey);
      throw new Error("Notify envelope malformed: unwrapped vault_key is not " + KEY_BYTES + " bytes");
    }

    let plaintextBytes;
    try {
      plaintextBytes = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null, contentCt, contentAad, contentNonce, vaultKey
      );
    } catch (err) {
      sodium.memzero(vaultKey);
      throw new Error("Could not decrypt: Notify envelope content was tampered with");
    }
    sodium.memzero(vaultKey);

    try {
      return fromUtf8(plaintextBytes);
    } catch (err) {
      throw new Error("Decrypted bytes are not valid UTF-8");
    }
  }

  // ---- Top-level dispatch ----

  // Encrypt always produces V2. There is no reason to produce new V1 vaults.
  function encryptVault(opts) {
    return encryptVaultV2(opts);
  }

  // Decrypt dispatches on the schema string so legacy V1 boxes still
  // open AND Qira Notify envelopes open too.
  function decryptVault(opts) {
    const vault = opts && opts.vault;
    if (!vault || typeof vault !== "object") {
      throw new Error("Vault malformed: not an object");
    }
    if (vault.schema === SCHEMA_V2) return decryptVaultV2(opts);
    if (vault.schema === SCHEMA_V1) return decryptVaultV1(opts);
    if (vault.schema === SCHEMA_QIRA_NOTIFY_V1) {
      return decryptVaultQiraNotifyV1(opts);
    }
    throw new Error(
      'Unsupported vault schema: "' + vault.schema +
      '" (expected ' + SCHEMA_V2 + ", " + SCHEMA_V1 + ", or " +
      SCHEMA_QIRA_NOTIFY_V1 + ")"
    );
  }

  // -------- Self-test --------
  // Exercises the full encrypt/decrypt paths for BOTH V1 and V2 before
  // the UI is enabled. Catches "WASM did not load", "library is broken",
  // any regression in either vault format, and any break in the dispatch
  // logic. Uses the Quick lock (opslimit=1, 32 MiB) so load time stays
  // under ~1s on modest hardware; production encrypts still use whatever
  // preset the user selects.
  function runSelfTest() {
    const testPlain = "self-test: hello world";
    const testPassword = "self-test-phrase-only";
    const quick = LOCK_PRESETS.quick;

    // ---- V2 round-trip (primary path) ----
    const v2 = encryptVaultV2({
      plaintext: testPlain,
      password: testPassword,
      mode: "self",
      opslimit: quick.opslimit,
      memlimit: quick.memlimit,
    });
    if (v2.schema !== SCHEMA_V2) {
      throw new Error("Self-test: V2 encrypt produced wrong schema");
    }
    const v2Round = decryptVault({ vault: v2, password: testPassword });
    if (v2Round !== testPlain) {
      throw new Error("Self-test: V2 round-trip mismatch");
    }
    // Wrong-phrase negative test — unwrap must fail cleanly.
    let v2WrongPwOk = false;
    try {
      decryptVault({ vault: v2, password: "wrong-phrase" });
    } catch (e) {
      v2WrongPwOk = true;
    }
    if (!v2WrongPwOk) {
      throw new Error("Self-test: V2 wrong-phrase check failed");
    }
    // Tamper test — flip a byte in the content ciphertext and confirm
    // the content AEAD tag rejects it. This catches any regression that
    // lets a partially-tampered vault silently decrypt.
    const tampered = JSON.parse(JSON.stringify(v2));
    const ctBytes = b64urlDecode(tampered.content.ciphertext);
    ctBytes[0] = ctBytes[0] ^ 0x01;
    tampered.content.ciphertext = b64urlEncode(ctBytes);
    let v2TamperOk = false;
    try {
      decryptVault({ vault: tampered, password: testPassword });
    } catch (e) {
      v2TamperOk = true;
    }
    if (!v2TamperOk) {
      throw new Error("Self-test: V2 tamper check failed");
    }

    // ---- V1 round-trip (legacy path — backward compat) ----
    const v1 = encryptVaultV1({
      plaintext: testPlain,
      password: testPassword,
      mode: "self",
      opslimit: quick.opslimit,
      memlimit: quick.memlimit,
    });
    if (v1.schema !== SCHEMA_V1) {
      throw new Error("Self-test: V1 encrypt produced wrong schema");
    }
    const v1Round = decryptVault({ vault: v1, password: testPassword });
    if (v1Round !== testPlain) {
      throw new Error("Self-test: V1 legacy round-trip mismatch");
    }
  }

  // -------- DOM wiring --------

  let currentMode = "self";
  // Live values displayed on the encrypt form. For V2 vaults we need
  // two separate nonces: one for wrapping the vault_key, one for the
  // content. The user-visible "secret number" knob shows the wrap nonce
  // (the public-facing one) and the content nonce is auto-generated
  // fresh at submit time.
  let currentNonce = null; // used as the V2 wrap nonce
  let currentSalt = null;
  let currentPresetKey = DEFAULT_PRESET_KEY;

  function $(id) {
    return document.getElementById(id);
  }

  function getCurrentLockStrength() {
    return LOCK_PRESETS[currentPresetKey] || LOCK_PRESETS[DEFAULT_PRESET_KEY];
  }

  function refreshNonceDisplay() {
    const el = $("vault-knob-nonce-value");
    if (el && currentNonce) {
      el.textContent = b64urlEncode(currentNonce);
    }
  }
  function refreshSaltDisplay() {
    const el = $("vault-knob-salt-value");
    if (el && currentSalt) {
      el.textContent = b64urlEncode(currentSalt);
    }
  }
  function regenerateNonce() {
    currentNonce = sodium.randombytes_buf(NONCE_BYTES);
    refreshNonceDisplay();
  }
  function regenerateSalt() {
    currentSalt = sodium.randombytes_buf(SALT_BYTES);
    refreshSaltDisplay();
  }
  function refreshLockStrengthButtons() {
    Object.keys(LOCK_PRESETS).forEach(function (key) {
      const btn = $("vault-lock-preset-" + key);
      if (btn) {
        btn.classList.toggle("vault-preset-active", key === currentPresetKey);
      }
    });
  }
  function setLockStrength(key) {
    if (LOCK_PRESETS[key]) {
      currentPresetKey = key;
      refreshLockStrengthButtons();
    }
  }
  // Track whether the self-test has enabled the form at least once. We
  // only gate submit on strength AFTER init completes, so a failed self-
  // test still wins (submit stays disabled for the right reason).
  let formsEnabledAfterSelfTest = false;

  function refreshPasswordStrength() {
    const input = $("vault-encrypt-password");
    const meter = $("vault-pw-strength");
    const submit = $("vault-encrypt-submit");
    const hintEl = $("vault-pw-hint");
    if (!input || !meter) return;
    const result = passwordStrength(input.value);
    const fill = meter.querySelector(".vault-pw-strength-fill");
    const label = meter.querySelector(".vault-pw-strength-label");
    if (fill) {
      const pct = Math.round((result.score / 7) * 100);
      fill.style.width = pct + "%";
      let color = "#dc2626";
      if (result.score >= MIN_STRENGTH_SCORE) color = "#d97706";
      if (result.score >= 5) color = "#0d7a4f";
      fill.style.background = color;
    }
    if (label) {
      label.textContent = result.label;
    }
    // Gate the submit button on strength. Only takes effect after the
    // self-test has run and enabled the forms once; before that, submit
    // stays disabled by init().
    if (submit && formsEnabledAfterSelfTest) {
      const weak = result.score < MIN_STRENGTH_SCORE;
      submit.disabled = weak;
      submit.title = weak
        ? "Phrase is too weak. Use 4+ random words or the generator button."
        : "";
    }
    // Live per-field hint text (shows weak-phrase guidance inline).
    if (hintEl) {
      if (input.value.length === 0) {
        hintEl.textContent = "";
      } else {
        hintEl.textContent = result.hint;
      }
      hintEl.className = "vault-pw-hint " +
        (result.score < MIN_STRENGTH_SCORE ? "vault-pw-hint-weak" : "vault-pw-hint-ok");
    }
  }

  function wireKnobControls() {
    // Regenerate buttons
    const regenNonce = $("vault-regen-nonce");
    if (regenNonce) regenNonce.addEventListener("click", regenerateNonce);
    const regenSalt = $("vault-regen-salt");
    if (regenSalt) regenSalt.addEventListener("click", regenerateSalt);

    // Lock strength preset buttons
    Object.keys(LOCK_PRESETS).forEach(function (key) {
      const btn = $("vault-lock-preset-" + key);
      if (btn) {
        btn.addEventListener("click", function () { setLockStrength(key); });
      }
    });

    // Passphrase generator
    const genBtn = $("vault-pw-generate");
    if (genBtn) {
      genBtn.addEventListener("click", function () {
        const input = $("vault-encrypt-password");
        if (!input) return;
        input.type = "text"; // briefly show the generated passphrase
        input.value = generatePassphrase();
        refreshPasswordStrength();
        // Hide it again after a few seconds so it doesn't sit on screen
        setTimeout(function () {
          if (input.type === "text") {
            // Keep visible until user toggles or clears
          }
        }, 0);
      });
    }

    // Password strength meter live update
    const pwInput = $("vault-encrypt-password");
    if (pwInput) {
      pwInput.addEventListener("input", refreshPasswordStrength);
    }

    // Tooltip click-to-reveal (CSS handles styling, JS toggles a class)
    document.querySelectorAll("[data-vault-tooltip-toggle]").forEach(function (el) {
      el.addEventListener("click", function (ev) {
        ev.preventDefault();
        const targetId = el.getAttribute("data-vault-tooltip-toggle");
        const target = $(targetId);
        if (target) {
          target.classList.toggle("vault-tooltip-open");
        }
      });
    });

    // Initialize displays
    refreshLockStrengthButtons();
    refreshPasswordStrength();
  }

  function setStatus(elId, msg, kind) {
    const el = $(elId);
    if (!el) return;
    el.textContent = msg;
    el.className =
      "vault-status" + (kind ? " vault-status-" + kind : "");
  }

  function setMode(mode) {
    currentMode = mode;
    const selfBtn = $("vault-mode-self");
    const shareBtn = $("vault-mode-share");
    if (selfBtn) selfBtn.classList.toggle("vault-mode-active", mode === "self");
    if (shareBtn) shareBtn.classList.toggle("vault-mode-active", mode === "share");
    const headline = $("vault-mode-headline");
    const helper = $("vault-mode-helper");
    if (mode === "self") {
      if (headline) headline.textContent = "Encrypt a note for yourself";
      if (helper) {
        helper.textContent =
          "Type a message and a password. Save the vault file. Remember the password. You can decrypt it later on any device.";
      }
    } else {
      if (headline) headline.textContent = "Send a secret to someone";
      if (helper) {
        helper.textContent =
          "Share a password with the recipient on a separate channel (call them, text them). Encrypt with that password. Send them the vault file by any means. They paste the file and the password to read it.";
      }
    }
  }

  function downloadVault(vault) {
    const json = JSON.stringify(vault, null, 2);
    const blob = new Blob([json], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    const stamp = new Date()
      .toISOString()
      .replace(/[:.]/g, "-")
      .replace("T", "_")
      .replace("Z", "");
    a.href = url;
    a.download = "vault-" + stamp + ".vault.json";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () {
      URL.revokeObjectURL(url);
    }, 1000);
  }

  function copyVaultText(vault) {
    const json = canonicalJSON(vault);
    const enc = b64urlEncode(utf8(json));
    // Use the V2 prefix for new (V2) vaults and the V1 prefix for legacy.
    // Decrypt-side accepts both prefixes regardless.
    const prefix = vault.schema === SCHEMA_V1 ? VAULT_TEXT_PREFIX_V1 : VAULT_TEXT_PREFIX_V2;
    const text = prefix + enc;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text);
    }
    return Promise.reject(new Error("Clipboard API not available"));
  }

  // Chat envelope decrypt path. Returns { plaintext, meta } on
  // success, null if the input isn't a chat envelope, or throws a
  // user-friendly Error if the input IS a chat envelope but decryption
  // fails (wrong phrase, malformed payload, etc). The caller catches
  // the throw and surfaces the error to the user.
  function tryDecryptChatEnvelope(raw, phrase) {
    const trimmed = (raw || "").trim();
    if (trimmed.length === 0 || trimmed.charAt(0) !== "{") return null;
    let parsed;
    try {
      parsed = JSON.parse(trimmed);
    } catch (e) {
      return null;
    }
    if (!parsed || parsed.schema !== "QEV-CHAT-ENVELOPE-V1") return null;
    if (!Array.isArray(parsed.ids) || parsed.ids.length !== 2) {
      throw new Error("Chat envelope missing 'ids' pair");
    }
    if (typeof parsed.nonce !== "string" || typeof parsed.ct !== "string") {
      throw new Error("Chat envelope missing 'nonce' or 'ct'");
    }
    if (typeof phrase !== "string" || phrase.length === 0) {
      throw new Error("Type the shared phrase to decrypt the chat message");
    }
    const ids = parsed.ids
      .map(function (s) { return String(s).toLowerCase(); })
      .sort();
    const contextStr = "QEV-CHAT-V1:" + ids[0] + ":" + ids[1];
    const phraseBytes = new TextEncoder().encode(phrase);
    const contextBytes = new TextEncoder().encode(contextStr);
    const combined = new Uint8Array(phraseBytes.length + contextBytes.length);
    combined.set(phraseBytes);
    combined.set(contextBytes, phraseBytes.length);
    const key = sodium.crypto_generichash(32, combined);
    sodium.memzero(combined);
    sodium.memzero(phraseBytes);
    let nonceBytes;
    let ctBytes;
    try {
      nonceBytes = sodium.from_base64(parsed.nonce, sodium.base64_variants.URLSAFE_NO_PADDING);
      ctBytes = sodium.from_base64(parsed.ct, sodium.base64_variants.URLSAFE_NO_PADDING);
    } catch (e) {
      throw new Error("Chat envelope base64 malformed");
    }
    let ptBytes;
    try {
      ptBytes = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ctBytes, null, nonceBytes, key);
    } catch (e) {
      sodium.memzero(key);
      throw new Error("Wrong phrase (AEAD auth tag mismatch)");
    }
    sodium.memzero(key);
    const plaintext = new TextDecoder().decode(ptBytes);
    sodium.memzero(ptBytes);
    const meta = "Schema: QEV-CHAT-ENVELOPE-V1  |  Participants: " + ids[0].slice(0, 8) + "… ↔ " + ids[1].slice(0, 8) + "…";
    return { plaintext: plaintext, meta: meta };
  }

  function parseVaultInput(raw) {
    const trimmed = (raw || "").trim();
    if (trimmed.length === 0) {
      throw new Error("Paste a vault first");
    }
    // Form 1: recovery sheet — look for the BEGIN/END markers and
    // extract the JSON between them. This lets users drop or paste
    // the recovery .txt file and have it work the same as the
    // .vault.json file.
    const beginMarker = "----- BEGIN BRY-NFET-SX VAULT -----";
    const endMarker = "----- END BRY-NFET-SX VAULT -----";
    const beginIdx = trimmed.indexOf(beginMarker);
    const endIdx = trimmed.indexOf(endMarker);
    if (beginIdx !== -1 && endIdx !== -1 && endIdx > beginIdx) {
      const inner = trimmed
        .slice(beginIdx + beginMarker.length, endIdx)
        .trim();
      try {
        return JSON.parse(inner);
      } catch (e) {
        throw new Error(
          "Recovery sheet found but the embedded vault JSON is malformed"
        );
      }
    }
    // Form 2: single-line text form. Accept either V1 or V2 prefix.
    const textPrefix =
      trimmed.indexOf(VAULT_TEXT_PREFIX_V2) === 0 ? VAULT_TEXT_PREFIX_V2 :
      trimmed.indexOf(VAULT_TEXT_PREFIX_V1) === 0 ? VAULT_TEXT_PREFIX_V1 :
      null;
    if (textPrefix) {
      const b64 = trimmed.slice(textPrefix.length);
      let bytes;
      try {
        bytes = b64urlDecode(b64);
      } catch (e) {
        throw new Error("Vault text format is invalid");
      }
      const jsonStr = fromUtf8(bytes);
      return JSON.parse(jsonStr);
    }
    // Form 3: raw JSON (the .vault.json file)
    try {
      return JSON.parse(trimmed);
    } catch (e) {
      throw new Error(
        "Could not parse vault. Drop the .vault.json file or the recovery sheet .txt file."
      );
    }
  }

  function wireEncryptForm() {
    const form = $("vault-encrypt-form");
    if (!form) return;
    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      setStatus("vault-encrypt-status", "Encrypting...", "info");
      const submitBtn = $("vault-encrypt-submit");
      if (submitBtn) submitBtn.disabled = true;
      // Defer the blocking Argon2id call to the next macrotask so the
      // browser can paint the "Encrypting..." message first. Do NOT use
      // requestAnimationFrame — modern browsers throttle rAF to never
      // fire in background/hidden tabs, which would silently freeze the
      // form. setTimeout(fn, 0) runs regardless of tab visibility.
      setTimeout(function () {
        (function () {
          try {
            const message = $("vault-encrypt-message").value;
            const password = $("vault-encrypt-password").value;
            const preset = getCurrentLockStrength();
            // Re-check strength at submit time (belt-and-suspenders —
            // the button gating already catches weak inputs, but this
            // defends against anyone bypassing the disabled attribute).
            const pwCheck = passwordStrength(password);
            if (pwCheck.score < MIN_STRENGTH_SCORE) {
              throw new Error(
                "Phrase is too weak to lock. Use 4+ random words or click the generator button."
              );
            }
            // currentNonce is the V2 wrap nonce (the user-visible one).
            // The content nonce is generated fresh at encrypt time so no
            // two vaults share it even if the user doesn't regenerate.
            const vault = encryptVault({
              plaintext: message,
              password: password,
              mode: currentMode,
              salt: currentSalt,
              wrapNonce: currentNonce,
              opslimit: preset.opslimit,
              memlimit: preset.memlimit,
            });
            // Clear sensitive form fields
            $("vault-encrypt-message").value = "";
            $("vault-encrypt-password").value = "";
            // Compute envelope ID for the result panel + recovery sheet
            const envelopeId = computeEnvelopeId(vault);
            const downloadStamp = new Date().toISOString().slice(0, 10);
            const downloadFilename = "vault-" + downloadStamp + ".vault.json";
            // Regenerate the displayed nonce + salt so the next encrypt
            // doesn't reuse the same values (visible feedback that each
            // box gets its own).
            regenerateNonce();
            regenerateSalt();
            refreshPasswordStrength();
            // Render result
            const resultJson = JSON.stringify(vault, null, 2);
            $("vault-encrypt-result-json").textContent = resultJson;
            const idEl = $("vault-encrypt-result-envelope-id");
            if (idEl) idEl.textContent = envelopeId;
            $("vault-encrypt-result").classList.remove("vault-hidden");
            // Wire result buttons
            $("vault-download-btn").onclick = function () {
              downloadVault(vault);
            };
            $("vault-copy-btn").onclick = function () {
              copyVaultText(vault).then(
                function () {
                  setStatus(
                    "vault-encrypt-status",
                    "Copied vault text to clipboard",
                    "ok"
                  );
                },
                function (err) {
                  setStatus(
                    "vault-encrypt-status",
                    "Could not copy: " + err.message,
                    "err"
                  );
                }
              );
            };
            const recBtn = $("vault-recovery-btn");
            if (recBtn) {
              recBtn.onclick = function () {
                downloadRecoverySheet(vault, downloadFilename, envelopeId);
              };
            }
            setStatus(
              "vault-encrypt-status",
              "Locked! Save the box file and remember your secret phrase.",
              "ok"
            );
          } catch (err) {
            setStatus("vault-encrypt-status", err.message, "err");
          } finally {
            if (submitBtn) submitBtn.disabled = false;
          }
        })();
      }, 0);
    });
  }

  function wireDecryptForm() {
    const form = $("vault-decrypt-form");
    if (!form) return;

    // Drag-and-drop file input
    const dropzone = $("vault-decrypt-dropzone");
    const fileInput = $("vault-decrypt-file");
    if (dropzone) {
      ["dragenter", "dragover"].forEach(function (ev) {
        dropzone.addEventListener(ev, function (e) {
          e.preventDefault();
          dropzone.classList.add("vault-dropzone-hover");
        });
      });
      ["dragleave", "drop"].forEach(function (ev) {
        dropzone.addEventListener(ev, function (e) {
          e.preventDefault();
          dropzone.classList.remove("vault-dropzone-hover");
        });
      });
      dropzone.addEventListener("drop", function (e) {
        const files = e.dataTransfer && e.dataTransfer.files;
        if (files && files.length > 0) {
          loadFileIntoTextarea(files[0]);
        }
      });
    }
    if (fileInput) {
      fileInput.addEventListener("change", function () {
        if (fileInput.files && fileInput.files.length > 0) {
          loadFileIntoTextarea(fileInput.files[0]);
        }
      });
    }

    function loadFileIntoTextarea(file) {
      const reader = new FileReader();
      reader.onload = function () {
        $("vault-decrypt-input").value = reader.result;
        setStatus(
          "vault-decrypt-status",
          "Loaded " + file.name + ". Now type the password.",
          "info"
        );
      };
      reader.onerror = function () {
        setStatus("vault-decrypt-status", "Could not read file", "err");
      };
      reader.readAsText(file);
    }

    form.addEventListener("submit", function (ev) {
      ev.preventDefault();
      setStatus("vault-decrypt-status", "Decrypting...", "info");
      const submitBtn = $("vault-decrypt-submit");
      if (submitBtn) submitBtn.disabled = true;
      // setTimeout (not rAF) — rAF is throttled in background tabs.
      setTimeout(function () {
        (function () {
          try {
            const raw = $("vault-decrypt-input").value;
            const password = $("vault-decrypt-password").value;

            // Chat-envelope fast path. Before attempting vault decode,
            // peek at the trimmed JSON and see if it's a chat envelope
            // copied from a locked conversation. If so, decrypt with
            // the per-chat BLAKE2b(phrase || context) key and bypass
            // the vault Argon2id path entirely. Vault code is never
            // touched — this is a pre-check that only fires for the
            // chat schema string.
            const chatResult = tryDecryptChatEnvelope(raw, password);
            if (chatResult !== null) {
              $("vault-decrypt-password").value = "";
              $("vault-decrypt-result-text").textContent = chatResult.plaintext;
              $("vault-decrypt-result").classList.remove("vault-hidden");
              $("vault-decrypt-result-meta").textContent = chatResult.meta;
              setStatus("vault-decrypt-status", "Chat message decrypted", "ok");
              return;
            }

            const vault = parseVaultInput(raw);
            const plaintext = decryptVault({ vault: vault, password: password });
            // Clear sensitive form fields
            $("vault-decrypt-password").value = "";
            // Render result
            $("vault-decrypt-result-text").textContent = plaintext;
            $("vault-decrypt-result").classList.remove("vault-hidden");
            // Meta line adapts to the schema — Notify envelopes don't
            // have `mode`/`version`, so we show a tailored label for
            // those and skip the missing fields rather than showing
            // "your own note" (wrong) or "vundefined" (ugly).
            const isNotify = vault.schema === SCHEMA_QIRA_NOTIFY_V1;
            const metaParts = [];
            if (isNotify) {
              metaParts.push("Source: Qira Notify encrypted notification");
            } else {
              metaParts.push(
                "Mode: " +
                  (vault.mode === "share" ? "shared with you" : "your own note")
              );
            }
            metaParts.push("Created: " + vault.created_at);
            metaParts.push(
              "Schema: " + vault.schema + (vault.version ? " v" + vault.version : "")
            );
            const meta = metaParts.join("  |  ");
            $("vault-decrypt-result-meta").textContent = meta;
            setStatus("vault-decrypt-status", "Decrypted successfully", "ok");
          } catch (err) {
            setStatus("vault-decrypt-status", err.message, "err");
          } finally {
            if (submitBtn) submitBtn.disabled = false;
          }
        })();
      }, 0);
    });
  }

  function wirePasswordRevealToggles() {
    const toggles = document.querySelectorAll("[data-vault-reveal-target]");
    toggles.forEach(function (toggle) {
      toggle.addEventListener("click", function () {
        const targetId = toggle.getAttribute("data-vault-reveal-target");
        const target = $(targetId);
        if (!target) return;
        if (target.type === "password") {
          target.type = "text";
          toggle.textContent = "Hide";
        } else {
          target.type = "password";
          toggle.textContent = "Show";
        }
      });
    });
  }

  function wireModeChooser() {
    const selfBtn = $("vault-mode-self");
    const shareBtn = $("vault-mode-share");
    if (selfBtn) {
      selfBtn.addEventListener("click", function () {
        setMode("self");
      });
    }
    if (shareBtn) {
      shareBtn.addEventListener("click", function () {
        setMode("share");
      });
    }
    setMode("self");
  }

  function init() {
    if (typeof sodium === "undefined") {
      setStatus(
        "vault-load-status",
        "Crypto library failed to load. Refresh and try again.",
        "err"
      );
      return;
    }
    setStatus("vault-load-status", "Loading crypto module...", "info");
    sodium.ready
      .then(function () {
        try {
          runSelfTest();
        } catch (err) {
          setStatus(
            "vault-load-status",
            "Self-test failed: " + err.message + ". Encryption disabled.",
            "err"
          );
          return;
        }
        // Self-test passed — enable forms.
        // The decrypt submit is enabled unconditionally (users may be
        // opening a vault with any phrase). The encrypt submit is
        // enabled here but then immediately gated by the strength check
        // on the empty password field, so it will re-disable until the
        // user enters a phrase that meets MIN_STRENGTH_SCORE.
        const decryptSubmit = $("vault-decrypt-submit");
        if (decryptSubmit) decryptSubmit.disabled = false;
        const encryptSubmit = $("vault-encrypt-submit");
        if (encryptSubmit) encryptSubmit.disabled = false;
        formsEnabledAfterSelfTest = true;
        setStatus("vault-load-status", "Ready", "ok");
        // Compute initial nonce + salt so the knob displays have values
        // from the first paint.
        regenerateNonce();
        regenerateSalt();
        wireModeChooser();
        wireKnobControls();
        wireEncryptForm();
        wireDecryptForm();
        wirePasswordRevealToggles();
        // Apply the initial strength gate so the button is properly
        // disabled until the user types a strong phrase.
        refreshPasswordStrength();
      })
      .catch(function (err) {
        setStatus(
          "vault-load-status",
          "Crypto module init error: " + (err && err.message ? err.message : err),
          "err"
        );
      });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
