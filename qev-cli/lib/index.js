// index.js — public API for programmatic consumers.
//
// Library users:
//
//   import { encryptVaultV2, decryptVaultV2, rewrapVaultV2, runSelfTest } from "@bryan237l/qev-cli";
//   await runSelfTest();
//   const v = await encryptVaultV2({ plaintext: "hi", password: "long phrase", mode: "self" });
//   const pt = await decryptVaultV2({ vault: v, password: "long phrase" });
//   const rotated = await rewrapVaultV2({ vault: v, oldPassword: "long phrase", newPassword: "new long phrase" });
//
// The "main" field in package.json points here so `import "@bryan237l/qev-cli"`
// pulls the crypto API but NOT the CLI front-end. The CLI is only loaded
// via the `bin` entry.

export {
  // core crypto
  encryptVaultV2,
  decryptVaultV2,
  validateVaultSchemaV2,
  runSelfTest,
  generatePassphrase,
  ready,
  // constants
  SCHEMA_V1,
  SCHEMA_V2,
  SCHEMA,
  VERSION,
  KDF_ALG,
  AEAD_ALG,
  DEFAULT_OPSLIMIT,
  DEFAULT_MEMLIMIT,
  MIN_OPSLIMIT,
  MAX_OPSLIMIT,
  MIN_MEMLIMIT,
  MAX_MEMLIMIT,
  SALT_BYTES,
  NONCE_BYTES,
  KEY_BYTES,
  TAG_BYTES,
  MAX_PLAINTEXT_BYTES,
  MAX_CIPHERTEXT_BYTES,
  LOCK_PRESETS,
  DEFAULT_PRESET_KEY,
} from "./vault.js";

export { rewrapVaultV2 } from "./rewrap.js";

export {
  canonicalJSON,
  buildAADV2,
  b64urlEncode,
  b64urlDecode,
  utf8,
  fromUtf8,
} from "./canonical.js";
