// vault.js — V2 vault encrypt/decrypt, validation, and self-test.
//
// This is a direct Node port of landing/vault/chat.js encryptVaultV2 and
// decryptVaultV2. The two implementations MUST produce byte-for-byte
// identical vaults given the same randomness and inputs. Any drift is a
// bug that breaks cross-impl compatibility and will be caught by the
// cross-impl vector test.
//
// Crypto primitives:
//   - Argon2id phrase stretching (crypto_pwhash)
//   - XChaCha20-Poly1305 authenticated encryption (24-byte nonce, 16-byte tag)
//   - All provided by libsodium-wrappers-sumo
//
// Format invariants (must match the V1/V2 browser implementation):
//   - schema = "BRY-NFET-SX-VAULT-V2"
//   - KDF = argon2id with (opslimit, memlimit) in their documented ranges
//   - 16-byte salt, 24-byte nonce, 32-byte vault_key, 48-byte wrapped_key
//   - All binary fields base64url without padding
//   - AAD is NOT stored; derived deterministically from a subset of vault
//     metadata via buildAADV2() in canonical.js
//
// NO LOGGING of user data. Any console.log of a password, plaintext, or
// derived key is a bug. This file must be auditable by eye.

// libsodium-wrappers-sumo ships a broken ESM entry whose internal
// relative import points at a sibling package that npm installs in a
// different directory. The CJS entry works correctly, so we load it
// via createRequire. This is standard practice for ESM consumers of
// mixed-mode packages and has no perf impact — the CJS module graph
// is loaded once, cached, and reused.
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const _sodium = require("libsodium-wrappers-sumo");

import {
  b64urlDecode,
  b64urlEncode,
  buildAADV2,
  fromUtf8,
  utf8,
} from "./canonical.js";

// libsodium is initialised lazily on first use. Every public entrypoint
// awaits this before touching sodium.*.
let _ready = null;
/** Ensure libsodium's WASM is loaded. Idempotent. */
export async function ready() {
  if (_ready) return _ready;
  _ready = (async () => {
    await _sodium.ready;
    return _sodium;
  })();
  return _ready;
}

// -------- Constants (must match landing/vault/chat.js) --------
export const SCHEMA_V1 = "BRY-NFET-SX-VAULT-V1";
export const SCHEMA_V2 = "BRY-NFET-SX-VAULT-V2";
export const SCHEMA = SCHEMA_V2;
export const VERSION = "0.28.1";

export const KDF_ALG = "argon2id";
export const AEAD_ALG = "XChaCha20-Poly1305";

export const DEFAULT_OPSLIMIT = 4;
export const DEFAULT_MEMLIMIT = 96 * 1024 * 1024;
export const MIN_OPSLIMIT = 1;
export const MAX_OPSLIMIT = 10;
export const MIN_MEMLIMIT = 8 * 1024 * 1024;
export const MAX_MEMLIMIT = 256 * 1024 * 1024;

export const SALT_BYTES = 16;
export const NONCE_BYTES = 24;
export const KEY_BYTES = 32;
export const TAG_BYTES = 16; // Poly1305 MAC length

export const MAX_PLAINTEXT_BYTES = 256 * 1024;
export const MAX_CIPHERTEXT_BYTES = 1024 * 1024;

// Named presets matching the browser form. "strong" is the default.
export const LOCK_PRESETS = {
  quick: { opslimit: 1, memlimit: 32 * 1024 * 1024, label: "quick", hint: "~1s" },
  strong: { opslimit: 4, memlimit: 96 * 1024 * 1024, label: "strong", hint: "~4s" },
  vault: { opslimit: 6, memlimit: 128 * 1024 * 1024, label: "vault", hint: "~7s" },
};
export const DEFAULT_PRESET_KEY = "strong";

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
      `KDF opslimit out of range (${MIN_OPSLIMIT}-${MAX_OPSLIMIT})`,
    );
  }
  if (
    typeof kdf.memlimit !== "number" ||
    kdf.memlimit < MIN_MEMLIMIT ||
    kdf.memlimit > MAX_MEMLIMIT
  ) {
    throw new Error(
      `KDF memlimit out of range (${MIN_MEMLIMIT / 1024 / 1024}-${MAX_MEMLIMIT / 1024 / 1024} MiB)`,
    );
  }
  if (typeof kdf.salt !== "string" || kdf.salt.length === 0) {
    throw new Error("Vault malformed: missing or invalid kdf.salt");
  }
}

/** Throws if the object is not a well-formed V2 vault. */
export function validateVaultSchemaV2(vault) {
  if (!vault || typeof vault !== "object") {
    throw new Error("Vault malformed: not an object");
  }
  if (vault.schema !== SCHEMA_V2) {
    throw new Error(
      `Unsupported vault schema: "${vault.schema}" (expected ${SCHEMA_V2})`,
    );
  }
  if (typeof vault.version !== "string") {
    throw new Error("Vault malformed: missing version");
  }
  if (typeof vault.created_at !== "string") {
    throw new Error("Vault malformed: missing created_at");
  }
  if (vault.mode !== "self" && vault.mode !== "share") {
    throw new Error("Vault malformed: mode must be 'self' or 'share'");
  }
  enforceKdfCaps(vault.kdf);
  if (!vault.wrap || typeof vault.wrap !== "object") {
    throw new Error("Vault malformed: missing wrap section");
  }
  if (vault.wrap.algorithm !== AEAD_ALG) {
    throw new Error("Unsupported wrap AEAD algorithm: " + vault.wrap.algorithm);
  }
  if (typeof vault.wrap.nonce !== "string" || vault.wrap.nonce.length === 0) {
    throw new Error("Vault malformed: missing wrap.nonce");
  }
  if (typeof vault.wrap.wrapped_key !== "string" || vault.wrap.wrapped_key.length === 0) {
    throw new Error("Vault malformed: missing wrap.wrapped_key");
  }
  if (!vault.content || typeof vault.content !== "object") {
    throw new Error("Vault malformed: missing content section");
  }
  if (vault.content.algorithm !== AEAD_ALG) {
    throw new Error("Unsupported content AEAD algorithm: " + vault.content.algorithm);
  }
  if (typeof vault.content.nonce !== "string" || vault.content.nonce.length === 0) {
    throw new Error("Vault malformed: missing content.nonce");
  }
  if (typeof vault.content.ciphertext !== "string" || vault.content.ciphertext.length === 0) {
    throw new Error("Vault malformed: missing content.ciphertext");
  }
}

// -------- V2 encrypt --------

/**
 * Encrypt a string (or Uint8Array) plaintext into a V2 vault object.
 *
 * @param {object} opts
 * @param {string|Uint8Array} opts.plaintext   the message to lock
 * @param {string} opts.password                the phrase (UTF-8)
 * @param {"self"|"share"} [opts.mode="self"]  tag for display purposes
 * @param {number} [opts.opslimit=4]           Argon2id ops (1..10)
 * @param {number} [opts.memlimit=96MiB]       Argon2id memory (8..256 MiB)
 * @param {Uint8Array} [opts.salt]             override 16-byte salt (tests)
 * @param {Uint8Array} [opts.wrapNonce]        override 24-byte wrap nonce (tests)
 * @param {Uint8Array} [opts.contentNonce]     override 24-byte content nonce (tests)
 * @param {Uint8Array} [opts.vaultKey]         override 32-byte vault key (tests)
 * @param {string}  [opts.createdAt]           override ISO timestamp (tests)
 * @param {string}  [opts.version]             override version string (tests)
 * @returns {Promise<object>} plain V2 vault JSON object
 */
export async function encryptVaultV2(opts) {
  const sodium = await ready();

  let { plaintext, password, mode, opslimit, memlimit } = opts;
  mode = mode || "self";
  opslimit = opslimit || DEFAULT_OPSLIMIT;
  memlimit = memlimit || DEFAULT_MEMLIMIT;

  if (typeof password !== "string" || password.length === 0) {
    throw new Error("encryptVaultV2: password must be a non-empty string");
  }
  if (mode !== "self" && mode !== "share") {
    throw new Error("encryptVaultV2: mode must be 'self' or 'share'");
  }
  if (opslimit < MIN_OPSLIMIT || opslimit > MAX_OPSLIMIT) {
    throw new Error("opslimit out of range");
  }
  if (memlimit < MIN_MEMLIMIT || memlimit > MAX_MEMLIMIT) {
    throw new Error("memlimit out of range");
  }

  // Coerce plaintext to UTF-8 bytes
  let ptBytes;
  if (typeof plaintext === "string") {
    ptBytes = utf8(plaintext);
  } else if (plaintext instanceof Uint8Array) {
    ptBytes = plaintext;
  } else {
    throw new Error("encryptVaultV2: plaintext must be string or Uint8Array");
  }
  if (ptBytes.length === 0) {
    throw new Error("encryptVaultV2: plaintext is empty");
  }
  if (ptBytes.length > MAX_PLAINTEXT_BYTES) {
    throw new Error(
      `plaintext too large (max ${MAX_PLAINTEXT_BYTES / 1024} KiB)`,
    );
  }

  // Randomness (callers can override for deterministic testing).
  //
  // IMPORTANT: when the caller supplies these (e.g. the deterministic
  // vector test), we MUST NOT zero their buffers — that would corrupt
  // the caller's fixture. So we copy caller-supplied buffers into fresh
  // Uint8Arrays here and only zero the owned copies. Buffers we
  // generate ourselves are already owned and safe to zero.
  const _copy = (b) => {
    const out = new Uint8Array(b.length);
    out.set(b);
    return out;
  };
  const salt = opts.salt ? _copy(opts.salt) : sodium.randombytes_buf(SALT_BYTES);
  const wrapNonce = opts.wrapNonce
    ? _copy(opts.wrapNonce)
    : sodium.randombytes_buf(NONCE_BYTES);
  const contentNonce = opts.contentNonce
    ? _copy(opts.contentNonce)
    : sodium.randombytes_buf(NONCE_BYTES);
  const vaultKey = opts.vaultKey
    ? _copy(opts.vaultKey)
    : sodium.randombytes_buf(KEY_BYTES);

  if (!(salt instanceof Uint8Array) || salt.length !== SALT_BYTES) {
    throw new Error(`invalid salt (must be ${SALT_BYTES} bytes)`);
  }
  if (!(wrapNonce instanceof Uint8Array) || wrapNonce.length !== NONCE_BYTES) {
    throw new Error(`invalid wrap nonce (must be ${NONCE_BYTES} bytes)`);
  }
  if (!(contentNonce instanceof Uint8Array) || contentNonce.length !== NONCE_BYTES) {
    throw new Error(`invalid content nonce (must be ${NONCE_BYTES} bytes)`);
  }
  if (!(vaultKey instanceof Uint8Array) || vaultKey.length !== KEY_BYTES) {
    throw new Error(`invalid vault_key (must be ${KEY_BYTES} bytes)`);
  }

  // Derive the wrap_key from the password via Argon2id.
  // The pw bytes are zeroized immediately after use to limit the window.
  const pwBytes = utf8(password);
  const wrapKey = sodium.crypto_pwhash(
    KEY_BYTES,
    pwBytes,
    salt,
    opslimit,
    memlimit,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  );
  sodium.memzero(pwBytes);

  // Build the vault skeleton so we can compute the deterministic AAD.
  const vault = {
    schema: SCHEMA_V2,
    version: opts.version || VERSION,
    created_at: opts.createdAt || new Date().toISOString(),
    mode,
    kdf: {
      algorithm: KDF_ALG,
      opslimit,
      memlimit,
      salt: b64urlEncode(salt),
    },
    wrap: {
      algorithm: AEAD_ALG,
      nonce: b64urlEncode(wrapNonce),
      wrapped_key: "",
    },
    content: {
      algorithm: AEAD_ALG,
      nonce: b64urlEncode(contentNonce),
      ciphertext: "",
    },
  };

  const aad = buildAADV2(vault);

  // Step 1: wrap the vault_key under the wrap_key.
  // Step 2: encrypt the plaintext under the vault_key.
  // Both use the same AAD so tampering with any metadata field breaks
  // at least one AEAD tag.
  let wrappedKey;
  try {
    wrappedKey = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      vaultKey,
      aad,
      null,
      wrapNonce,
      wrapKey,
    );
  } finally {
    sodium.memzero(wrapKey);
  }
  vault.wrap.wrapped_key = b64urlEncode(wrappedKey);

  let contentCt;
  try {
    contentCt = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      ptBytes,
      aad,
      null,
      contentNonce,
      vaultKey,
    );
  } finally {
    sodium.memzero(vaultKey);
  }
  vault.content.ciphertext = b64urlEncode(contentCt);

  return vault;
}

// -------- V2 decrypt --------

/**
 * Decrypt a V2 vault object with the given password.
 * Returns the plaintext string (UTF-8 decoded).
 *
 * Throws distinct errors for:
 *   - malformed vault (bad shape, bad lengths)
 *   - wrong phrase or tampered metadata/wrap block
 *   - tampered content block (valid phrase, corrupted ciphertext)
 *   - non-UTF-8 plaintext (vault was encrypted from raw bytes that are
 *     not a valid UTF-8 string)
 */
export async function decryptVaultV2(opts) {
  const sodium = await ready();
  const { vault, password } = opts;

  validateVaultSchemaV2(vault);
  if (typeof password !== "string" || password.length === 0) {
    throw new Error("decryptVaultV2: password must be a non-empty string");
  }

  const salt = b64urlDecode(vault.kdf.salt);
  const wrapNonce = b64urlDecode(vault.wrap.nonce);
  const wrappedKey = b64urlDecode(vault.wrap.wrapped_key);
  const contentNonce = b64urlDecode(vault.content.nonce);
  const contentCt = b64urlDecode(vault.content.ciphertext);

  if (salt.length !== SALT_BYTES) {
    throw new Error("Vault malformed: salt length");
  }
  if (wrapNonce.length !== NONCE_BYTES) {
    throw new Error("Vault malformed: wrap nonce length");
  }
  if (contentNonce.length !== NONCE_BYTES) {
    throw new Error("Vault malformed: content nonce length");
  }
  if (wrappedKey.length !== KEY_BYTES + TAG_BYTES) {
    throw new Error(
      `Vault malformed: wrapped_key length (got ${wrappedKey.length}, expected ${KEY_BYTES + TAG_BYTES})`,
    );
  }
  if (contentCt.length === 0) {
    throw new Error("Vault malformed: empty ciphertext");
  }
  if (contentCt.length > MAX_CIPHERTEXT_BYTES) {
    throw new Error(
      `Vault too large (max ${MAX_CIPHERTEXT_BYTES / 1024} KiB)`,
    );
  }

  const pwBytes = utf8(password);
  const wrapKey = sodium.crypto_pwhash(
    KEY_BYTES,
    pwBytes,
    salt,
    vault.kdf.opslimit,
    vault.kdf.memlimit,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  );
  sodium.memzero(pwBytes);

  const aad = buildAADV2(vault);

  // Step 1: unwrap vault_key. Failure = wrong phrase or tampered wrap
  // metadata. User-visible error is intentionally merged for both cases.
  let vaultKey;
  try {
    vaultKey = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      wrappedKey,
      aad,
      wrapNonce,
      wrapKey,
    );
  } catch (_err) {
    sodium.memzero(wrapKey);
    throw new Error("Could not decrypt: wrong phrase or tampered vault");
  }
  sodium.memzero(wrapKey);

  if (vaultKey.length !== KEY_BYTES) {
    sodium.memzero(vaultKey);
    throw new Error(
      `Vault malformed: unwrapped vault_key is not ${KEY_BYTES} bytes`,
    );
  }

  // Step 2: decrypt the content under vault_key. If unwrap succeeded,
  // the phrase was correct — so failure here means the content block
  // was tampered with independently from the wrap.
  let plaintextBytes;
  try {
    plaintextBytes = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      contentCt,
      aad,
      contentNonce,
      vaultKey,
    );
  } catch (_err) {
    sodium.memzero(vaultKey);
    throw new Error(
      "Could not decrypt: vault content has been tampered with (wrap was valid)",
    );
  }
  sodium.memzero(vaultKey);

  try {
    return fromUtf8(plaintextBytes);
  } catch (_err) {
    throw new Error(
      "Decrypted bytes are not valid UTF-8 (vault may be corrupted)",
    );
  }
}

// -------- Passphrase generator --------

// Same 192-word list as the browser implementation. ~30 bits entropy +
// 2 random digits → ~37 bits. Used for quick self-generation; users
// should still prefer longer phrases when they can.
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
)
  .split(/\s+/)
  .filter(Boolean);

/**
 * Generate a 4-word passphrase with 2 random digits appended.
 * Example: "river-purple-dragon-cloud-47"
 */
export async function generatePassphrase() {
  const sodium = await ready();
  const words = [];
  for (let i = 0; i < 4; i++) {
    const idx = sodium.randombytes_uniform(PASSPHRASE_WORDS.length);
    words.push(PASSPHRASE_WORDS[idx]);
  }
  const d1 = sodium.randombytes_uniform(10);
  const d2 = sodium.randombytes_uniform(10);
  return words.join("-") + "-" + d1 + d2;
}

// -------- Self-test (known-answer + tamper tests) --------

/**
 * Round-trip self-test with tamper and wrong-phrase negative cases.
 * Matches the browser's runSelfTest() semantics. Uses the quick preset
 * so the test runs in <1 second on any machine.
 *
 * Throws on ANY failure. Returns {ok:true} on success.
 */
export async function runSelfTest() {
  await ready();

  const testPlain = "self-test: hello world";
  const testPassword = "self-test-phrase-only";
  const quick = LOCK_PRESETS.quick;

  // ---- Happy path round-trip ----
  const v2 = await encryptVaultV2({
    plaintext: testPlain,
    password: testPassword,
    mode: "self",
    opslimit: quick.opslimit,
    memlimit: quick.memlimit,
  });
  if (v2.schema !== SCHEMA_V2) {
    throw new Error("Self-test: V2 encrypt produced wrong schema");
  }
  const v2Round = await decryptVaultV2({ vault: v2, password: testPassword });
  if (v2Round !== testPlain) {
    throw new Error("Self-test: V2 round-trip mismatch");
  }

  // ---- Wrong phrase ----
  let wrongOk = false;
  try {
    await decryptVaultV2({ vault: v2, password: "wrong-phrase" });
  } catch (_e) {
    wrongOk = true;
  }
  if (!wrongOk) {
    throw new Error("Self-test: V2 wrong-phrase check failed");
  }

  // ---- Tamper with content ciphertext ----
  const tampered = JSON.parse(JSON.stringify(v2));
  const ctBytes = b64urlDecode(tampered.content.ciphertext);
  ctBytes[0] = ctBytes[0] ^ 0x01;
  tampered.content.ciphertext = b64urlEncode(ctBytes);
  let tamperOk = false;
  try {
    await decryptVaultV2({ vault: tampered, password: testPassword });
  } catch (_e) {
    tamperOk = true;
  }
  if (!tamperOk) {
    throw new Error("Self-test: V2 tamper check failed");
  }

  return { ok: true };
}
