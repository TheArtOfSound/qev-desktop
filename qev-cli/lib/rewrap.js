// rewrap.js — phrase rotation for QEV V2 vault envelopes.
//
// This intentionally rewraps only wrap.wrapped_key. It does NOT decrypt or
// re-encrypt the content ciphertext. For V2 compatibility, it preserves the
// existing KDF parameters, salt, wrap nonce, content nonce, and AAD-bound
// metadata. Changing those fields would change the content AEAD AAD and make
// the existing content ciphertext fail authentication.

import {
  ready,
  validateVaultSchemaV2,
  KEY_BYTES,
  TAG_BYTES,
} from "./vault.js";
import {
  b64urlDecode,
  b64urlEncode,
  buildAADV2,
  utf8,
} from "./canonical.js";

/**
 * Rewrap a QEV V2 vault from one phrase to another without re-encrypting the
 * content payload.
 *
 * @param {object} opts
 * @param {object} opts.vault       parsed QEV V2 vault object
 * @param {string} opts.oldPassword current phrase
 * @param {string} opts.newPassword new phrase
 * @returns {Promise<object>} a new vault object with updated wrap.wrapped_key
 */
export async function rewrapVaultV2(opts) {
  const sodium = await ready();
  const { vault, oldPassword, newPassword } = opts || {};

  validateVaultSchemaV2(vault);
  if (typeof oldPassword !== "string" || oldPassword.length === 0) {
    throw new Error("rewrapVaultV2: oldPassword must be a non-empty string");
  }
  if (typeof newPassword !== "string" || newPassword.length === 0) {
    throw new Error("rewrapVaultV2: newPassword must be a non-empty string");
  }
  if (oldPassword === newPassword) {
    throw new Error("rewrapVaultV2: new phrase must be different from old phrase");
  }

  const salt = b64urlDecode(vault.kdf.salt);
  const wrapNonce = b64urlDecode(vault.wrap.nonce);
  const wrappedKey = b64urlDecode(vault.wrap.wrapped_key);
  if (wrappedKey.length !== KEY_BYTES + TAG_BYTES) {
    throw new Error(
      `Vault malformed: wrapped_key length (got ${wrappedKey.length}, expected ${KEY_BYTES + TAG_BYTES})`,
    );
  }

  const aad = buildAADV2(vault);

  const oldPwBytes = utf8(oldPassword);
  const oldWrapKey = sodium.crypto_pwhash(
    KEY_BYTES,
    oldPwBytes,
    salt,
    vault.kdf.opslimit,
    vault.kdf.memlimit,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  );
  sodium.memzero(oldPwBytes);

  let vaultKey;
  try {
    vaultKey = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      wrappedKey,
      aad,
      wrapNonce,
      oldWrapKey,
    );
  } catch (_err) {
    sodium.memzero(oldWrapKey);
    throw new Error("Could not rewrap: old phrase is wrong or vault wrap is tampered");
  }
  sodium.memzero(oldWrapKey);

  if (vaultKey.length !== KEY_BYTES) {
    sodium.memzero(vaultKey);
    throw new Error(`Vault malformed: unwrapped vault_key is not ${KEY_BYTES} bytes`);
  }

  const newPwBytes = utf8(newPassword);
  const newWrapKey = sodium.crypto_pwhash(
    KEY_BYTES,
    newPwBytes,
    salt,
    vault.kdf.opslimit,
    vault.kdf.memlimit,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  );
  sodium.memzero(newPwBytes);

  let newWrappedKey;
  try {
    newWrappedKey = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      vaultKey,
      aad,
      null,
      wrapNonce,
      newWrapKey,
    );
  } finally {
    sodium.memzero(vaultKey);
    sodium.memzero(newWrapKey);
  }

  const out = JSON.parse(JSON.stringify(vault));
  out.wrap.wrapped_key = b64urlEncode(newWrappedKey);
  return out;
}
