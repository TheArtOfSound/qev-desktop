// vault.test.js — round-trip, tamper, wrong-phrase, schema rejection,
// and a deterministic known-answer vector to pin the V2 wire format.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  encryptVaultV2,
  decryptVaultV2,
  validateVaultSchemaV2,
  runSelfTest,
  SCHEMA_V2,
  SALT_BYTES,
  NONCE_BYTES,
  KEY_BYTES,
  LOCK_PRESETS,
} from "../lib/vault.js";
import { b64urlDecode, b64urlEncode, utf8 } from "../lib/canonical.js";

const QUICK = LOCK_PRESETS.quick;
const STRONG = LOCK_PRESETS.strong;

test("self-test passes", async () => {
  const result = await runSelfTest();
  assert.deepEqual(result, { ok: true });
});

test("round-trip: ASCII plaintext", async () => {
  const v = await encryptVaultV2({
    plaintext: "hello world",
    password: "correct-horse-battery-staple",
    mode: "self",
    opslimit: QUICK.opslimit,
    memlimit: QUICK.memlimit,
  });
  const pt = await decryptVaultV2({
    vault: v,
    password: "correct-horse-battery-staple",
  });
  assert.equal(pt, "hello world");
});

test("round-trip: UTF-8 with emoji", async () => {
  const msg = "héllo 🎉 世界 — naïve café";
  const v = await encryptVaultV2({
    plaintext: msg,
    password: "long-test-phrase-here",
    mode: "self",
    opslimit: QUICK.opslimit,
    memlimit: QUICK.memlimit,
  });
  const pt = await decryptVaultV2({
    vault: v,
    password: "long-test-phrase-here",
  });
  assert.equal(pt, msg);
});

test("round-trip: share mode", async () => {
  const v = await encryptVaultV2({
    plaintext: "message for bob",
    password: "the-phrase-we-agreed-on",
    mode: "share",
    opslimit: QUICK.opslimit,
    memlimit: QUICK.memlimit,
  });
  assert.equal(v.mode, "share");
  const pt = await decryptVaultV2({
    vault: v,
    password: "the-phrase-we-agreed-on",
  });
  assert.equal(pt, "message for bob");
});

test("wrong phrase fails with user-visible error", async () => {
  const v = await encryptVaultV2({
    plaintext: "secret",
    password: "right-phrase",
    mode: "self",
    opslimit: QUICK.opslimit,
    memlimit: QUICK.memlimit,
  });
  await assert.rejects(
    () => decryptVaultV2({ vault: v, password: "wrong-phrase" }),
    /wrong phrase or tampered vault/,
  );
});

test("tampered content ciphertext rejected (phrase still valid)", async () => {
  const v = await encryptVaultV2({
    plaintext: "original message",
    password: "test-phrase-for-tamper",
    mode: "self",
    opslimit: QUICK.opslimit,
    memlimit: QUICK.memlimit,
  });
  // Flip a bit in the content ciphertext
  const ct = b64urlDecode(v.content.ciphertext);
  ct[0] ^= 0x01;
  const tampered = { ...v, content: { ...v.content, ciphertext: b64urlEncode(ct) } };
  await assert.rejects(
    () => decryptVaultV2({ vault: tampered, password: "test-phrase-for-tamper" }),
    /tampered|wrong phrase/,
  );
});

test("tampered wrap nonce rejected (AAD binding catches it)", async () => {
  const v = await encryptVaultV2({
    plaintext: "x",
    password: "phrase-here",
    mode: "self",
    opslimit: QUICK.opslimit,
    memlimit: QUICK.memlimit,
  });
  // Swap in a different wrap nonce — the AAD is now wrong, so the
  // unwrap AEAD tag will reject.
  const bogusNonce = new Uint8Array(NONCE_BYTES); // all zeros
  const tampered = {
    ...v,
    wrap: { ...v.wrap, nonce: b64urlEncode(bogusNonce) },
  };
  await assert.rejects(
    () => decryptVaultV2({ vault: tampered, password: "phrase-here" }),
    /wrong phrase or tampered vault/,
  );
});

test("tampered kdf.salt rejected", async () => {
  const v = await encryptVaultV2({
    plaintext: "x",
    password: "phrase-here",
    mode: "self",
    opslimit: QUICK.opslimit,
    memlimit: QUICK.memlimit,
  });
  const bogusSalt = new Uint8Array(SALT_BYTES); // zeros
  const tampered = {
    ...v,
    kdf: { ...v.kdf, salt: b64urlEncode(bogusSalt) },
  };
  await assert.rejects(
    () => decryptVaultV2({ vault: tampered, password: "phrase-here" }),
    /wrong phrase or tampered vault/,
  );
});

test("schema mismatch rejected", async () => {
  const v = await encryptVaultV2({
    plaintext: "x",
    password: "phrase-here",
    mode: "self",
    opslimit: QUICK.opslimit,
    memlimit: QUICK.memlimit,
  });
  const bogus = { ...v, schema: "BRY-NFET-SX-VAULT-V99" };
  await assert.rejects(
    () => decryptVaultV2({ vault: bogus, password: "phrase-here" }),
    /Unsupported vault schema/,
  );
});

test("validateVaultSchemaV2: rejects missing kdf", () => {
  assert.throws(
    () =>
      validateVaultSchemaV2({
        schema: SCHEMA_V2,
        version: "0.28.1",
        created_at: "2026-04-15T00:00:00Z",
        mode: "self",
        // kdf missing
        wrap: { algorithm: "XChaCha20-Poly1305", nonce: "x", wrapped_key: "x" },
        content: { algorithm: "XChaCha20-Poly1305", nonce: "x", ciphertext: "x" },
      }),
    /missing kdf/,
  );
});

test("validateVaultSchemaV2: rejects bad opslimit", () => {
  const base = {
    schema: SCHEMA_V2,
    version: "0.28.1",
    created_at: "2026-04-15T00:00:00Z",
    mode: "self",
    kdf: { algorithm: "argon2id", opslimit: 99, memlimit: 96 * 1024 * 1024, salt: "AAAAAAAAAAAAAAAAAAAAAA" },
    wrap: { algorithm: "XChaCha20-Poly1305", nonce: "x", wrapped_key: "x" },
    content: { algorithm: "XChaCha20-Poly1305", nonce: "x", ciphertext: "x" },
  };
  assert.throws(() => validateVaultSchemaV2(base), /opslimit out of range/);
});

test("deterministic vector: same inputs produce byte-identical vaults", async () => {
  // Pin every random input so two encrypt calls produce the same vault.
  // This is the anchor for cross-implementation compatibility: when we
  // port the vault format to Rust (Tauri) or Python (backend tests), the
  // same inputs must produce the same bytes out.
  const salt = new Uint8Array(SALT_BYTES).fill(0x11);
  const wrapNonce = new Uint8Array(NONCE_BYTES).fill(0x22);
  const contentNonce = new Uint8Array(NONCE_BYTES).fill(0x33);
  const vaultKey = new Uint8Array(KEY_BYTES).fill(0x44);

  const baseOpts = {
    plaintext: "deterministic test vector",
    password: "fixed-phrase-for-vector",
    mode: "self",
    opslimit: QUICK.opslimit,
    memlimit: QUICK.memlimit,
    salt,
    wrapNonce,
    contentNonce,
    vaultKey,
    createdAt: "2026-04-15T22:00:00.000Z",
    version: "0.28.1",
  };

  const a = await encryptVaultV2(baseOpts);
  const b = await encryptVaultV2(baseOpts);
  assert.deepEqual(a, b, "same inputs must produce same vault");

  // Round-trip works
  const pt = await decryptVaultV2({ vault: a, password: "fixed-phrase-for-vector" });
  assert.equal(pt, "deterministic test vector");

  // Pin the exact wrapped_key and ciphertext so future refactors that
  // accidentally change the AAD or AEAD parameters get caught at CI
  // time. These values come from running this test once under Node 25
  // with libsodium-wrappers-sumo 0.7.16 and recording the output.
  //
  // CROSS-IMPL INVARIANT: if you port the vault format to another
  // language (Rust, Python, Swift, etc.), feed this same vector in and
  // verify the implementation produces these exact bytes. Any drift is
  // a vault-incompatibility bug.
  //
  // Regenerate with:
  //   node -e 'import("./lib/vault.js").then(async m => {
  //     const salt = new Uint8Array(16).fill(0x11);
  //     const wn = new Uint8Array(24).fill(0x22);
  //     const cn = new Uint8Array(24).fill(0x33);
  //     const vk = new Uint8Array(32).fill(0x44);
  //     const v = await m.encryptVaultV2({
  //       plaintext: "deterministic test vector",
  //       password: "fixed-phrase-for-vector",
  //       mode: "self", opslimit: 1, memlimit: 32*1024*1024,
  //       salt, wrapNonce: wn, contentNonce: cn, vaultKey: vk,
  //       createdAt: "2026-04-15T22:00:00.000Z", version: "0.28.1",
  //     });
  //     console.log(v.wrap.wrapped_key);
  //     console.log(v.content.ciphertext);
  //   })'
  assert.equal(
    a.wrap.wrapped_key,
    "KejB3m4cr9dGdYf3GEg9SMgsfSZY3bruqMhBIT5R2CX2PvVwFbDhxMKPORl8KJdN",
    "pinned wrapped_key (V2 wire format)",
  );
  assert.equal(
    a.content.ciphertext,
    "pnNGf5rAB1tYjfjg9eU9PlUU85MtfPCbNth5WwbnFlqSwucivXkPN70",
    "pinned content.ciphertext (V2 wire format)",
  );
  assert.equal(a.kdf.salt, "EREREREREREREREREREREQ");
  assert.equal(a.wrap.nonce, "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIi");
  assert.equal(a.content.nonce, "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMz");
  assert.equal(a.schema, "BRY-NFET-SX-VAULT-V2");
  assert.equal(a.kdf.algorithm, "argon2id");
  assert.equal(a.kdf.opslimit, QUICK.opslimit);
  assert.equal(a.kdf.memlimit, QUICK.memlimit);
  assert.equal(a.wrap.algorithm, "XChaCha20-Poly1305");
  assert.equal(a.content.algorithm, "XChaCha20-Poly1305");

  // Lengths are format-pinned regardless of value.
  assert.equal(b64urlDecode(a.kdf.salt).length, SALT_BYTES);
  assert.equal(b64urlDecode(a.wrap.nonce).length, NONCE_BYTES);
  assert.equal(b64urlDecode(a.content.nonce).length, NONCE_BYTES);
  // wrapped_key = 32 key bytes + 16 Poly1305 tag = 48 bytes
  assert.equal(b64urlDecode(a.wrap.wrapped_key).length, KEY_BYTES + 16);
  // ciphertext = plaintext + 16 Poly1305 tag
  const ptLen = utf8(baseOpts.plaintext).length;
  assert.equal(b64urlDecode(a.content.ciphertext).length, ptLen + 16);
});

test("large plaintext near the 256 KiB cap", async () => {
  const pt = "x".repeat(200 * 1024); // 200 KiB
  const v = await encryptVaultV2({
    plaintext: pt,
    password: "phrase",
    mode: "self",
    opslimit: QUICK.opslimit,
    memlimit: QUICK.memlimit,
  });
  const out = await decryptVaultV2({ vault: v, password: "phrase" });
  assert.equal(out.length, pt.length);
  assert.equal(out, pt);
});

test("plaintext over cap rejected", async () => {
  const pt = "x".repeat(300 * 1024); // 300 KiB > 256 KiB cap
  await assert.rejects(
    () =>
      encryptVaultV2({
        plaintext: pt,
        password: "phrase",
        mode: "self",
        opslimit: QUICK.opslimit,
        memlimit: QUICK.memlimit,
      }),
    /too large/,
  );
});

test("strong preset also round-trips", async () => {
  // Strong is the default preset (~4 seconds on typical hardware);
  // confirm the path works end-to-end with the real parameters we
  // ship. Not run-every-test-frequently fast but important to verify
  // at least once.
  const v = await encryptVaultV2({
    plaintext: "strong preset test",
    password: "a-strong-test-phrase-here",
    mode: "self",
    opslimit: STRONG.opslimit,
    memlimit: STRONG.memlimit,
  });
  const pt = await decryptVaultV2({
    vault: v,
    password: "a-strong-test-phrase-here",
  });
  assert.equal(pt, "strong preset test");
});
