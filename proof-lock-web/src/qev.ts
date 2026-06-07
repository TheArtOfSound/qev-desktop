import sodium from "libsodium-wrappers";

export const SCHEMA_V2 = "BRY-NFET-SX-VAULT-V2";
export const VERSION = "0.29.0";
export const KDF_ALG = "argon2id";
export const AEAD_ALG = "XChaCha20-Poly1305";

const SALT_BYTES = 16;
const NONCE_BYTES = 24;
const KEY_BYTES = 32;
const TAG_BYTES = 16;
const MAX_PLAINTEXT_BYTES = 256 * 1024;
const MAX_CIPHERTEXT_BYTES = 1024 * 1024;

export const LOCK_PRESETS = {
  quick: { opslimit: 1, memlimit: 32 * 1024 * 1024, label: "quick", hint: "~1s" },
  strong: { opslimit: 4, memlimit: 96 * 1024 * 1024, label: "strong", hint: "~4s" },
  vault: { opslimit: 6, memlimit: 128 * 1024 * 1024, label: "vault", hint: "~7s" }
} as const;

export type PresetKey = keyof typeof LOCK_PRESETS;

export type QevVault = {
  schema: string;
  version: string;
  created_at: string;
  mode: "self" | "share";
  kdf: {
    algorithm: string;
    opslimit: number;
    memlimit: number;
    salt: string;
  };
  wrap: {
    algorithm: string;
    nonce: string;
    wrapped_key: string;
  };
  content: {
    algorithm: string;
    nonce: string;
    ciphertext: string;
  };
};

let readyPromise: Promise<void> | null = null;

export async function ready() {
  if (!readyPromise) {
    readyPromise = sodium.ready.then(() => undefined);
  }
  return readyPromise;
}

export function canonicalJSON(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalJSON).join(",") + "]";
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalJSON(obj[k])).join(",") + "}";
}

export function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

export function fromUtf8(bytes: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

export function b64urlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

export function b64urlDecode(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*=*$/.test(value)) {
    throw new Error("base64url: invalid character");
  }
  const b64 = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = b64.length % 4 === 0 ? b64 : b64 + "=".repeat(4 - (b64.length % 4));
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

export function buildAADV2(vault: QevVault): Uint8Array {
  return utf8(canonicalJSON({
    content: {
      algorithm: vault.content.algorithm,
      nonce: vault.content.nonce
    },
    created_at: vault.created_at,
    kdf: {
      algorithm: vault.kdf.algorithm,
      memlimit: vault.kdf.memlimit,
      opslimit: vault.kdf.opslimit,
      salt: vault.kdf.salt
    },
    mode: vault.mode,
    schema: vault.schema,
    version: vault.version,
    wrap: {
      algorithm: vault.wrap.algorithm,
      nonce: vault.wrap.nonce
    }
  }));
}

export function validateVaultSchemaV2(vault: unknown): asserts vault is QevVault {
  if (!vault || typeof vault !== "object") throw new Error("Vault malformed: not an object");
  const v = vault as QevVault;
  if (v.schema !== SCHEMA_V2) throw new Error(`Unsupported vault schema: ${String(v.schema)}`);
  if (typeof v.version !== "string") throw new Error("Vault malformed: missing version");
  if (typeof v.created_at !== "string") throw new Error("Vault malformed: missing created_at");
  if (v.mode !== "self" && v.mode !== "share") throw new Error("Vault malformed: mode must be self or share");
  if (!v.kdf || v.kdf.algorithm !== KDF_ALG) throw new Error("Vault malformed: unsupported kdf");
  if (!v.wrap || v.wrap.algorithm !== AEAD_ALG) throw new Error("Vault malformed: unsupported wrap algorithm");
  if (!v.content || v.content.algorithm !== AEAD_ALG) throw new Error("Vault malformed: unsupported content algorithm");
  if (!v.kdf.salt || !v.wrap.nonce || !v.wrap.wrapped_key || !v.content.nonce || !v.content.ciphertext) {
    throw new Error("Vault malformed: missing required field");
  }
}

export async function encryptVaultV2(opts: {
  plaintext: string | Uint8Array;
  password: string;
  mode?: "self" | "share";
  preset?: PresetKey;
}) {
  await ready();

  const mode = opts.mode ?? "self";
  const preset = LOCK_PRESETS[opts.preset ?? "strong"];
  const ptBytes = typeof opts.plaintext === "string" ? utf8(opts.plaintext) : opts.plaintext;

  if (!opts.password) throw new Error("password is required");
  if (ptBytes.length === 0) throw new Error("plaintext is empty");
  if (ptBytes.length > MAX_PLAINTEXT_BYTES) throw new Error("plaintext too large; max is 256 KiB");

  const salt = sodium.randombytes_buf(SALT_BYTES);
  const wrapNonce = sodium.randombytes_buf(NONCE_BYTES);
  const contentNonce = sodium.randombytes_buf(NONCE_BYTES);
  const vaultKey = sodium.randombytes_buf(KEY_BYTES);

  const passwordBytes = utf8(opts.password);
  const wrapKey = sodium.crypto_pwhash(
    KEY_BYTES,
    passwordBytes,
    salt,
    preset.opslimit,
    preset.memlimit,
    sodium.crypto_pwhash_ALG_ARGON2ID13
  );
  sodium.memzero(passwordBytes);

  const vault: QevVault = {
    schema: SCHEMA_V2,
    version: VERSION,
    created_at: new Date().toISOString(),
    mode,
    kdf: {
      algorithm: KDF_ALG,
      opslimit: preset.opslimit,
      memlimit: preset.memlimit,
      salt: b64urlEncode(salt)
    },
    wrap: {
      algorithm: AEAD_ALG,
      nonce: b64urlEncode(wrapNonce),
      wrapped_key: ""
    },
    content: {
      algorithm: AEAD_ALG,
      nonce: b64urlEncode(contentNonce),
      ciphertext: ""
    }
  };

  const aad = buildAADV2(vault);

  const wrappedKey = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    vaultKey,
    aad,
    null,
    wrapNonce,
    wrapKey
  );
  sodium.memzero(wrapKey);
  vault.wrap.wrapped_key = b64urlEncode(wrappedKey);

  const contentCiphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    ptBytes,
    aad,
    null,
    contentNonce,
    vaultKey
  );
  sodium.memzero(vaultKey);
  vault.content.ciphertext = b64urlEncode(contentCiphertext);

  return vault;
}

export async function decryptVaultV2(opts: { vault: QevVault; password: string }) {
  await ready();

  validateVaultSchemaV2(opts.vault);
  if (!opts.password) throw new Error("password is required");

  const vault = opts.vault;
  const salt = b64urlDecode(vault.kdf.salt);
  const wrapNonce = b64urlDecode(vault.wrap.nonce);
  const wrappedKey = b64urlDecode(vault.wrap.wrapped_key);
  const contentNonce = b64urlDecode(vault.content.nonce);
  const contentCiphertext = b64urlDecode(vault.content.ciphertext);

  if (salt.length !== SALT_BYTES) throw new Error("Vault malformed: salt length");
  if (wrapNonce.length !== NONCE_BYTES) throw new Error("Vault malformed: wrap nonce length");
  if (contentNonce.length !== NONCE_BYTES) throw new Error("Vault malformed: content nonce length");
  if (wrappedKey.length !== KEY_BYTES + TAG_BYTES) throw new Error("Vault malformed: wrapped key length");
  if (contentCiphertext.length === 0) throw new Error("Vault malformed: empty ciphertext");
  if (contentCiphertext.length > MAX_CIPHERTEXT_BYTES) throw new Error("Vault too large");

  const passwordBytes = utf8(opts.password);
  const wrapKey = sodium.crypto_pwhash(
    KEY_BYTES,
    passwordBytes,
    salt,
    vault.kdf.opslimit,
    vault.kdf.memlimit,
    sodium.crypto_pwhash_ALG_ARGON2ID13
  );
  sodium.memzero(passwordBytes);

  const aad = buildAADV2(vault);

  let vaultKey: Uint8Array;
  try {
    vaultKey = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      wrappedKey,
      aad,
      wrapNonce,
      wrapKey
    );
  } catch {
    sodium.memzero(wrapKey);
    throw new Error("Could not decrypt: wrong phrase or tampered vault");
  }
  sodium.memzero(wrapKey);

  let plaintextBytes: Uint8Array;
  try {
    plaintextBytes = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      contentCiphertext,
      aad,
      contentNonce,
      vaultKey
    );
  } catch {
    sodium.memzero(vaultKey);
    throw new Error("Could not decrypt: vault content has been tampered with");
  }
  sodium.memzero(vaultKey);

  return fromUtf8(plaintextBytes);
}

export async function generatePassphrase() {
  await ready();
  const words = "able acid acre add age aim air ant ape arm army art ask atom auto baby back bad bag bake ball band bank bar barn base bat bath bay beam bean bear beat bed bee beef bell belt bend best bid big bike bill bird bit blue boat body bold bolt bone book boot born boss both bow bowl box boy bran brave bread bring brown brush bug build burn bus bush busy buy cab cage cake calf calm camp can cap car card care cart case cash cast cat catch cave cell chair chalk charm cheap chest chief chin chip city claim clay clean clear click cliff cloak clock cloth cloud club coal coast coat coin cold come cook cool corn cost couch count court cow crab crew crop cross crown cry cup curl daisy damp dance dark dawn day deal deep deer desk dial dig dim dish dive dock dog doll door dot dove down draft drag draw dream dress drift drive drop drum dry duck dust eagle ear earth east easy edge egg eight elbow elf elm".split(/\s+/);
  const chosen: string[] = [];
  for (let i = 0; i < 4; i++) {
    chosen.push(words[sodium.randombytes_uniform(words.length)]);
  }
  return `${chosen.join("-")}-${sodium.randombytes_uniform(10)}${sodium.randombytes_uniform(10)}`;
}

export async function runSelfTest() {
  const phrase = "self-test-phrase-only";
  const plain = "self-test: hello world";
  const vault = await encryptVaultV2({ plaintext: plain, password: phrase, preset: "quick" });
  const roundTrip = await decryptVaultV2({ vault, password: phrase });
  if (roundTrip !== plain) throw new Error("round trip mismatch");

  const tampered = JSON.parse(JSON.stringify(vault)) as QevVault;
  tampered.content.ciphertext = tampered.content.ciphertext.slice(0, -3) + "abc";
  let tamperFailed = false;
  try {
    await decryptVaultV2({ vault: tampered, password: phrase });
  } catch {
    tamperFailed = true;
  }
  if (!tamperFailed) throw new Error("tamper test failed");

  let wrongFailed = false;
  try {
    await decryptVaultV2({ vault, password: "wrong phrase" });
  } catch {
    wrongFailed = true;
  }
  if (!wrongFailed) throw new Error("wrong phrase test failed");

  return { ok: true };
}
