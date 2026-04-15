// canonical.test.js — verify canonical JSON, base64url, and AAD builder
// match the browser reference implementation byte-for-byte.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  canonicalJSON,
  b64urlEncode,
  b64urlDecode,
  utf8,
  fromUtf8,
  buildAADV2,
} from "../lib/canonical.js";

test("canonicalJSON: primitives", () => {
  assert.equal(canonicalJSON(null), "null");
  assert.equal(canonicalJSON(true), "true");
  assert.equal(canonicalJSON(false), "false");
  assert.equal(canonicalJSON(42), "42");
  assert.equal(canonicalJSON("hello"), '"hello"');
  assert.equal(canonicalJSON(""), '""');
});

test("canonicalJSON: array preserves order, each element canonical", () => {
  assert.equal(canonicalJSON([1, 2, 3]), "[1,2,3]");
  assert.equal(canonicalJSON([{ b: 2, a: 1 }]), '[{"a":1,"b":2}]');
  assert.equal(canonicalJSON([]), "[]");
});

test("canonicalJSON: top-level key sort", () => {
  assert.equal(canonicalJSON({ b: 2, a: 1 }), '{"a":1,"b":2}');
  assert.equal(canonicalJSON({ z: 1, y: 2, x: 3 }), '{"x":3,"y":2,"z":1}');
});

test("canonicalJSON: nested key sort (the whole point of 'recursive')", () => {
  const input = {
    outer: { b: 2, a: 1 },
    outer2: { z: { y: 2, x: 1 } },
  };
  // Note: outer2 and outer are sorted at top level; nested objects are
  // sorted recursively. The result must be deterministic regardless of
  // insertion order.
  assert.equal(
    canonicalJSON(input),
    '{"outer":{"a":1,"b":2},"outer2":{"z":{"x":1,"y":2}}}',
  );
});

test("canonicalJSON: no whitespace", () => {
  const result = canonicalJSON({ a: 1, b: [2, 3], c: { d: 4 } });
  assert.equal(result, '{"a":1,"b":[2,3],"c":{"d":4}}');
  assert.ok(!/\s/.test(result), "no whitespace allowed");
});

test("canonicalJSON: string escaping matches JSON.stringify", () => {
  assert.equal(canonicalJSON("a\nb"), '"a\\nb"');
  assert.equal(canonicalJSON('with "quotes"'), '"with \\"quotes\\""');
});

test("b64url: round-trip all-byte values", () => {
  const bytes = new Uint8Array(256);
  for (let i = 0; i < 256; i++) bytes[i] = i;
  const enc = b64urlEncode(bytes);
  assert.ok(!enc.includes("="), "no padding");
  assert.ok(!enc.includes("+"), "URL-safe alphabet");
  assert.ok(!enc.includes("/"), "URL-safe alphabet");
  const dec = b64urlDecode(enc);
  assert.deepEqual(dec, bytes);
});

test("b64url: decode rejects invalid characters", () => {
  assert.throws(() => b64urlDecode("hello world!"), /invalid character/);
});

test("b64url: decode tolerates padded input", () => {
  // Same bytes, one padded, one not.
  const padded = Buffer.from("hello").toString("base64"); // aGVsbG8=
  const bare = padded.replace(/=+$/, ""); // aGVsbG8
  assert.deepEqual(
    b64urlDecode(padded),
    b64urlDecode(bare),
    "decoder tolerates both forms",
  );
  assert.equal(fromUtf8(b64urlDecode(bare)), "hello");
});

test("b64url: known-answer vectors from RFC 4648 §10", () => {
  // RFC vectors use the standard alphabet, not URL-safe. Convert to
  // URL-safe by replacing + -> - and / -> _.
  // "foobar" -> "Zm9vYmFy" (no padding needed)
  assert.equal(b64urlEncode(utf8("foobar")), "Zm9vYmFy");
  // "foob" -> "Zm9vYg" (2-byte pad in standard base64, stripped here)
  assert.equal(b64urlEncode(utf8("foob")), "Zm9vYg");
  // "fo" -> "Zm8" (1-byte pad, stripped)
  assert.equal(b64urlEncode(utf8("fo")), "Zm8");
});

test("buildAADV2: produces deterministic canonical JSON bytes", () => {
  const v1 = {
    schema: "BRY-NFET-SX-VAULT-V2",
    version: "0.28.1",
    created_at: "2026-04-15T00:00:00.000Z",
    mode: "self",
    kdf: {
      algorithm: "argon2id",
      opslimit: 4,
      memlimit: 100663296,
      salt: "AAAAAAAAAAAAAAAAAAAAAA",
    },
    wrap: {
      algorithm: "XChaCha20-Poly1305",
      nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      wrapped_key: "IGNORED",
    },
    content: {
      algorithm: "XChaCha20-Poly1305",
      nonce: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
      ciphertext: "IGNORED",
    },
  };
  // Same object with the top-level keys in a totally different insertion
  // order — the AAD bytes MUST be identical because canonicalJSON sorts.
  const v2 = {
    content: v1.content,
    wrap: v1.wrap,
    kdf: v1.kdf,
    mode: v1.mode,
    version: v1.version,
    created_at: v1.created_at,
    schema: v1.schema,
  };
  const a = buildAADV2(v1);
  const b = buildAADV2(v2);
  assert.deepEqual(a, b);

  // The AAD should NOT include wrap.wrapped_key or content.ciphertext —
  // those are output values that are not part of the bound metadata.
  const s = fromUtf8(a);
  assert.ok(!s.includes("IGNORED"), "AAD must not include wrapped_key/ciphertext");
  assert.ok(!s.includes("wrapped_key"), "AAD must not include the wrapped_key field name");
  assert.ok(!s.includes("ciphertext"), "AAD must not include the ciphertext field name");

  // It SHOULD include every bound field
  assert.ok(s.includes('"schema":"BRY-NFET-SX-VAULT-V2"'));
  assert.ok(s.includes('"mode":"self"'));
  assert.ok(s.includes('"opslimit":4'));
  assert.ok(s.includes('"memlimit":100663296'));
});
