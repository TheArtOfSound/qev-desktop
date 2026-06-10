// rewrap.test.js — phrase rotation without content re-encryption.

import { test } from "node:test";
import assert from "node:assert/strict";

import { encryptVaultV2, decryptVaultV2, LOCK_PRESETS } from "../lib/vault.js";
import { rewrapVaultV2 } from "../lib/rewrap.js";

const QUICK = LOCK_PRESETS.quick;

test("rewrap rotates phrase without changing content ciphertext", async () => {
  const vault = await encryptVaultV2({
    plaintext: "rewrap keeps content ciphertext stable",
    password: "old-long-phrase",
    mode: "self",
    opslimit: QUICK.opslimit,
    memlimit: QUICK.memlimit,
  });

  const rewrapped = await rewrapVaultV2({
    vault,
    oldPassword: "old-long-phrase",
    newPassword: "new-long-phrase",
  });

  assert.equal(
    rewrapped.content.ciphertext,
    vault.content.ciphertext,
    "rewrap must not re-encrypt content ciphertext",
  );
  assert.equal(rewrapped.content.nonce, vault.content.nonce);
  assert.equal(rewrapped.wrap.nonce, vault.wrap.nonce);
  assert.notEqual(
    rewrapped.wrap.wrapped_key,
    vault.wrap.wrapped_key,
    "rewrap must update only the wrapped content key",
  );

  await assert.rejects(
    () => decryptVaultV2({ vault: rewrapped, password: "old-long-phrase" }),
    /wrong phrase|tampered vault/,
  );

  const plaintext = await decryptVaultV2({
    vault: rewrapped,
    password: "new-long-phrase",
  });
  assert.equal(plaintext, "rewrap keeps content ciphertext stable");
});

test("rewrap rejects wrong old phrase", async () => {
  const vault = await encryptVaultV2({
    plaintext: "secret",
    password: "correct-old-phrase",
    mode: "self",
    opslimit: QUICK.opslimit,
    memlimit: QUICK.memlimit,
  });

  await assert.rejects(
    () =>
      rewrapVaultV2({
        vault,
        oldPassword: "wrong-old-phrase",
        newPassword: "new-long-phrase",
      }),
    /old phrase is wrong|tampered/,
  );
});
