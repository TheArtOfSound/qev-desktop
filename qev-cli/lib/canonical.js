// canonical.js — canonical JSON + base64url helpers.
//
// This MUST match the reference implementation in landing/vault/chat.js
// byte-for-byte. Any drift breaks cross-implementation vault compatibility,
// because the canonical JSON of a subset of the vault fields is fed
// directly into the AEAD's AAD parameter — meaning a one-character
// difference in key ordering or whitespace handling will make every
// vault produced by one implementation unreadable by the other.
//
// Canonical invariants:
//   1. Object keys are sorted recursively (not just at the top level).
//   2. No whitespace anywhere in the output.
//   3. Strings are JSON.stringify'd (so the encoder matches V8's escape
//      rules). Numbers, booleans, null go through JSON.stringify too,
//      but in practice we only feed strings + integers into AAD.
//   4. UTF-8 is used when the canonical JSON is converted to bytes.

/**
 * Recursive sorted-keys JSON serializer with no whitespace.
 *
 * NOT `JSON.stringify(obj, Object.keys(obj).sort())` — that only sorts the
 * top level and leaves nested objects in insertion order, which would
 * silently break cross-impl AAD equality on any nested object.
 */
export function canonicalJSON(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalJSON).join(",") + "]";
  }
  const keys = Object.keys(value).sort();
  const parts = keys.map((k) => JSON.stringify(k) + ":" + canonicalJSON(value[k]));
  return "{" + parts.join(",") + "}";
}

/**
 * UTF-8 encode a string to Uint8Array.
 */
export function utf8(s) {
  return new TextEncoder().encode(s);
}

/**
 * UTF-8 decode a Uint8Array to string. Throws on invalid UTF-8.
 */
export function fromUtf8(bytes) {
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

/**
 * Base64url (no padding) encode Uint8Array -> string.
 *
 * The vault format uses the URL-safe alphabet (`-` and `_` instead of
 * `+` and `/`) with no trailing `=` padding. This matches libsodium's
 * `base64_variants.URLSAFE_NO_PADDING` and what the browser reference
 * implementation emits.
 */
export function b64urlEncode(bytes) {
  // Use Buffer.from for speed, then transform to the URL-safe alphabet
  // and strip padding. Buffer is available in Node out of the box.
  const b64 = Buffer.from(bytes).toString("base64");
  return b64.replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

/**
 * Base64url (no padding) decode string -> Uint8Array.
 *
 * Tolerates padded inputs too (drops trailing `=`). Rejects inputs with
 * invalid alphabet characters.
 */
export function b64urlDecode(str) {
  if (typeof str !== "string") {
    throw new TypeError("b64urlDecode: input must be a string");
  }
  // Strict check: only URL-safe base64 characters, optional trailing '='.
  if (!/^[A-Za-z0-9_-]*=*$/.test(str)) {
    throw new Error("b64urlDecode: invalid character in input");
  }
  const b64 = str.replaceAll("-", "+").replaceAll("_", "/");
  // Buffer.from can handle missing padding on modern Node, but some
  // older versions are picky — pad up explicitly.
  const pad = b64.length % 4;
  const padded = pad === 0 ? b64 : b64 + "=".repeat(4 - pad);
  return new Uint8Array(Buffer.from(padded, "base64"));
}

/**
 * Build the AAD object for V2 vaults. This must match
 * landing/vault/chat.js buildAADV2 exactly.
 *
 * The key ordering here does NOT matter because canonicalJSON sorts keys
 * recursively, but we keep the original key order in the source for
 * easy diffing against the reference implementation.
 */
export function buildAADV2(vault) {
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
