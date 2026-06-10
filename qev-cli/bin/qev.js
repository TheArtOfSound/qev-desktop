#!/usr/bin/env node
// qev — command-line vault for offline encrypted envelopes.
//
// Subcommands:
//
//   qev lock    [--out FILE] [--mode self|share] [--strength quick|strong|vault]
//               Encrypt plaintext from stdin into a V2 vault. Prompts for
//               the phrase twice (with confirm) on an interactive TTY.
//               If --out is given, writes the vault JSON there; otherwise
//               writes it to stdout.
//
//   qev unlock  VAULT_FILE
//               Decrypt a V2 vault file. Prompts for the phrase. Writes
//               plaintext to stdout (so you can pipe it).
//
//   qev rewrap  VAULT_FILE [--out FILE]
//               Rotate the phrase by re-encrypting only wrap.wrapped_key.
//               The content ciphertext is not decrypted or re-encrypted.
//
//   qev gen-phrase
//               Print a freshly generated 4-word passphrase.
//
//   qev self-test
//               Run round-trip + tamper + wrong-phrase + rewrap self-tests.
//               Exits 0 on success, 1 on any failure.
//
//   qev version
//               Print the package version.
//
// SAFETY RULES (enforced here, not in lib/):
//   - No --phrase / --password flag. Phrases are always prompted on stdin.
//     The shell would otherwise record them in history and /proc.
//   - No stack traces on user errors. We print concise, categorized messages
//     and exit 1.
//   - Never log the phrase, plaintext, or derived key.

import { parseArgs } from "node:util";
import { readFile, writeFile } from "node:fs/promises";
import { stdout, stderr, exit } from "node:process";

import {
  encryptVaultV2,
  decryptVaultV2,
  generatePassphrase,
  runSelfTest,
  LOCK_PRESETS,
  DEFAULT_PRESET_KEY,
  VERSION,
} from "../lib/vault.js";
import { rewrapVaultV2 } from "../lib/rewrap.js";
import { b64urlDecode, b64urlEncode } from "../lib/canonical.js";
import {
  promptPhrase,
  promptPhraseConfirmed,
  promptPlaintext,
} from "../lib/prompt.js";

function die(msg) {
  stderr.write(`qev: error: ${msg}\n`);
  exit(1);
}

function bullet(line) {
  stderr.write(`  - ${line}\n`);
}

function check(line) {
  stderr.write(`  ✓ ${line}\n`);
}

function explainUnlockFailure(vaultPath, err) {
  const detail = err?.message || String(err || "unknown error");
  const lower = detail.toLowerCase();

  stderr.write(`qev: unlock failed: ${vaultPath}\n`);

  if (lower.includes("not valid json") || lower.includes("json")) {
    stderr.write("category: malformed vault file\n");
    bullet("The file could not be parsed as JSON.");
    bullet("Check that you selected the full .vault file and did not copy a partial snippet.");
  } else if (
    lower.includes("unsupported vault schema") ||
    lower.includes("unsupported schema") ||
    lower.includes("unsupported kdf") ||
    lower.includes("unsupported wrap") ||
    lower.includes("unsupported content") ||
    lower.includes("unsupported algorithm")
  ) {
    stderr.write("category: unsupported vault format\n");
    bullet("This CLI only opens supported QEV V2 vaults.");
    bullet("Open the file in inspect mode or update qev if the vault came from a newer release.");
  } else if (
    lower.includes("vault malformed") ||
    lower.includes("missing") ||
    lower.includes("length") ||
    lower.includes("too large") ||
    lower.includes("invalid character") ||
    lower.includes("out of range")
  ) {
    stderr.write("category: malformed or damaged vault\n");
    bullet("The vault JSON is present, but one or more required fields are missing, invalid, or outside safety limits.");
    bullet("Most likely causes: partial copy, damaged file, manual edit, unsupported generator, or transport corruption.");
  } else if (
    lower.includes("wrong phrase") ||
    lower.includes("tampered vault") ||
    lower.includes("could not decrypt") ||
    lower.includes("authentication") ||
    lower.includes("old phrase")
  ) {
    stderr.write("category: authentication check failed\n");
    bullet("Most likely causes: wrong phrase, edited vault metadata, damaged wrapped key, or tampered ciphertext.");
    bullet("For safety, QEV cannot always distinguish wrong phrase from tampering because authenticated encryption rejects both the same way.");
    bullet("Try the phrase again; if it still fails, treat the vault as damaged or modified.");
  } else if (lower.includes("utf-8")) {
    stderr.write("category: decoded plaintext is not valid UTF-8\n");
    bullet("The cryptographic unlock passed, but the plaintext bytes were not text.");
    bullet("This CLI path currently writes UTF-8 plaintext to stdout.");
  } else {
    stderr.write("category: unknown unlock error\n");
    bullet("The CLI did not recognize this failure mode. The technical detail below may help file a bug.");
  }

  stderr.write(`technical detail: ${detail}\n`);
  exit(1);
}

function usage(subcmd) {
  const lines = subcmd
    ? {
        lock:
          "qev lock [--out FILE] [--mode self|share] [--strength quick|strong|vault]",
        unlock: "qev unlock VAULT_FILE",
        rewrap: "qev rewrap VAULT_FILE [--out FILE]",
        "gen-phrase": "qev gen-phrase",
        "self-test": "qev self-test",
        version: "qev version",
      }[subcmd] || null
    : null;

  if (lines) {
    stderr.write(`usage: ${lines}\n`);
  } else {
    stderr.write(
      `qev — offline encrypted vault CLI (v${VERSION})

usage:
  qev lock    [--out FILE] [--mode self|share] [--strength quick|strong|vault]
  qev unlock  VAULT_FILE
  qev rewrap  VAULT_FILE [--out FILE]
  qev gen-phrase
  qev self-test
  qev version

Phrases are always prompted interactively. There is no --phrase flag
because the shell would leak it via history and /proc.

rewrap rotates the phrase by updating only wrap.wrapped_key. It does not
re-encrypt the content ciphertext.

vault format:  BRY-NFET-SX-VAULT-V2 (XChaCha20-Poly1305 + Argon2id)
compat:        desktop QEV (Mac/Windows) and secure.imagineqira.com/vault
`,
    );
  }
  exit(1);
}

async function cmdLock(argv) {
  const { values, positionals } = parseArgs({
    args: argv,
    options: {
      out: { type: "string", short: "o" },
      mode: { type: "string" },
      strength: { type: "string", short: "s" },
      help: { type: "boolean", short: "h" },
    },
    strict: true,
    allowPositionals: true,
  });

  if (values.help) usage("lock");
  if (positionals.length > 0) {
    die(`lock: unexpected positional argument '${positionals[0]}'`);
  }

  const mode = values.mode || "self";
  if (mode !== "self" && mode !== "share") {
    die(`lock: --mode must be 'self' or 'share' (got '${mode}')`);
  }

  const strengthKey = values.strength || DEFAULT_PRESET_KEY;
  const preset = LOCK_PRESETS[strengthKey];
  if (!preset) {
    die(`lock: --strength must be one of ${Object.keys(LOCK_PRESETS).join(", ")}`);
  }

  const plaintext = await promptPlaintext();
  if (!plaintext || plaintext.length === 0) {
    die("lock: empty plaintext — nothing to encrypt");
  }

  let phrase;
  try {
    phrase = await promptPhraseConfirmed();
  } catch (err) {
    die(err.message || "phrase prompt failed");
  }

  stderr.write(`locking with ${preset.label} preset (${preset.hint}) ...\n`);
  let vault;
  try {
    vault = await encryptVaultV2({
      plaintext,
      password: phrase,
      mode,
      opslimit: preset.opslimit,
      memlimit: preset.memlimit,
    });
  } catch (err) {
    die(err.message || "encryption failed");
  }

  const json = JSON.stringify(vault, null, 2) + "\n";
  if (values.out) {
    try {
      await writeFile(values.out, json, { encoding: "utf8" });
    } catch (err) {
      die(`lock: could not write ${values.out}: ${err.message}`);
    }
    stderr.write(`wrote ${values.out}\n`);
  } else {
    stdout.write(json);
  }
}

async function cmdUnlock(argv) {
  const { values, positionals } = parseArgs({
    args: argv,
    options: { help: { type: "boolean", short: "h" } },
    strict: true,
    allowPositionals: true,
  });

  if (values.help) usage("unlock");
  if (positionals.length !== 1) {
    die("unlock: expected exactly one VAULT_FILE argument");
  }
  const vaultPath = positionals[0];

  let vaultText;
  try {
    vaultText = await readFile(vaultPath, { encoding: "utf8" });
  } catch (err) {
    die(`unlock: could not read ${vaultPath}: ${err.message}`);
  }

  let vault;
  try {
    vault = JSON.parse(vaultText);
  } catch (err) {
    explainUnlockFailure(vaultPath, new Error(`not valid JSON: ${err.message}`));
  }

  let phrase;
  try {
    phrase = await promptPhrase();
  } catch (err) {
    die(err.message || "phrase prompt failed");
  }

  let plaintext;
  try {
    plaintext = await decryptVaultV2({ vault, password: phrase });
  } catch (err) {
    explainUnlockFailure(vaultPath, err);
  }

  stdout.write(plaintext);
  if (!plaintext.endsWith("\n") && stdout.isTTY) {
    stdout.write("\n");
  }
}

async function cmdRewrap(argv) {
  const { values, positionals } = parseArgs({
    args: argv,
    options: {
      out: { type: "string", short: "o" },
      help: { type: "boolean", short: "h" },
    },
    strict: true,
    allowPositionals: true,
  });

  if (values.help) usage("rewrap");
  if (positionals.length !== 1) {
    die("rewrap: expected exactly one VAULT_FILE argument");
  }
  const vaultPath = positionals[0];
  const outPath = values.out || vaultPath;

  let vaultText;
  try {
    vaultText = await readFile(vaultPath, { encoding: "utf8" });
  } catch (err) {
    die(`rewrap: could not read ${vaultPath}: ${err.message}`);
  }

  let vault;
  try {
    vault = JSON.parse(vaultText);
  } catch (err) {
    die(`rewrap: ${vaultPath} is not valid JSON: ${err.message}`);
  }

  stderr.write("Rewrap rotates the phrase by updating only wrap.wrapped_key.\n");
  stderr.write("The content ciphertext is not decrypted or re-encrypted.\n");

  let oldPhrase;
  let newPhrase;
  try {
    oldPhrase = await promptPhrase("Old phrase");
    newPhrase = await promptPhraseConfirmed("New phrase", "New phrase (confirm)");
  } catch (err) {
    die(err.message || "phrase prompt failed");
  }

  let rewrapped;
  try {
    rewrapped = await rewrapVaultV2({
      vault,
      oldPassword: oldPhrase,
      newPassword: newPhrase,
    });
  } catch (err) {
    explainUnlockFailure(vaultPath, err);
  }

  const json = JSON.stringify(rewrapped, null, 2) + "\n";
  try {
    await writeFile(outPath, json, { encoding: "utf8" });
  } catch (err) {
    die(`rewrap: could not write ${outPath}: ${err.message}`);
  }
  stderr.write(`rewrapped phrase; wrote ${outPath}\n`);
}

async function cmdGenPhrase(argv) {
  const { values } = parseArgs({
    args: argv,
    options: { help: { type: "boolean", short: "h" } },
    strict: true,
    allowPositionals: false,
  });
  if (values.help) usage("gen-phrase");

  const phrase = await generatePassphrase();
  stdout.write(phrase + "\n");
}

async function cmdSelfTest(argv) {
  const { values } = parseArgs({
    args: argv,
    options: { help: { type: "boolean", short: "h" } },
    strict: true,
    allowPositionals: false,
  });
  if (values.help) usage("self-test");

  stderr.write("qev self-test\n");
  try {
    const result = await runSelfTest();
    if (!result.ok) throw new Error("library self-test returned a non-ok result");
    check("library round-trip, wrong-phrase, and tamper checks passed");

    const testPlain = "self-test: explicit failure UX";
    const testPassword = "self-test-phrase-only";
    const newPassword = "self-test-new-phrase-only";
    const quick = LOCK_PRESETS.quick;

    const vault = await encryptVaultV2({
      plaintext: testPlain,
      password: testPassword,
      mode: "self",
      opslimit: quick.opslimit,
      memlimit: quick.memlimit,
    });
    check(`created ${vault.schema} vault with quick preset`);

    const roundTrip = await decryptVaultV2({ vault, password: testPassword });
    if (roundTrip !== testPlain) throw new Error("explicit round-trip mismatch");
    check("decrypted with the correct phrase");

    let wrongPhraseRejected = false;
    try { await decryptVaultV2({ vault, password: "definitely-wrong-phrase" }); }
    catch (_err) { wrongPhraseRejected = true; }
    if (!wrongPhraseRejected) throw new Error("wrong phrase was not rejected");
    check("rejected wrong phrase / authentication failure");

    const tampered = JSON.parse(JSON.stringify(vault));
    const ctBytes = b64urlDecode(tampered.content.ciphertext);
    ctBytes[0] = ctBytes[0] ^ 0x01;
    tampered.content.ciphertext = b64urlEncode(ctBytes);
    let tamperRejected = false;
    try { await decryptVaultV2({ vault: tampered, password: testPassword }); }
    catch (_err) { tamperRejected = true; }
    if (!tamperRejected) throw new Error("tampered ciphertext was not rejected");
    check("rejected damaged/tampered ciphertext");

    const unsupported = { ...vault, schema: "BRY-NFET-SX-VAULT-V99" };
    let schemaRejected = false;
    try { await decryptVaultV2({ vault: unsupported, password: testPassword }); }
    catch (_err) { schemaRejected = true; }
    if (!schemaRejected) throw new Error("unsupported schema was not rejected");
    check("rejected unsupported schema");

    const rewrapped = await rewrapVaultV2({
      vault,
      oldPassword: testPassword,
      newPassword,
    });
    if (rewrapped.content.ciphertext !== vault.content.ciphertext) {
      throw new Error("rewrap changed content ciphertext");
    }
    const afterRewrap = await decryptVaultV2({ vault: rewrapped, password: newPassword });
    if (afterRewrap !== testPlain) throw new Error("rewrap did not unlock with new phrase");
    let oldRejected = false;
    try { await decryptVaultV2({ vault: rewrapped, password: testPassword }); }
    catch (_err) { oldRejected = true; }
    if (!oldRejected) throw new Error("old phrase still unlocked after rewrap");
    check("rewrapped phrase without changing content ciphertext");

    stderr.write("result: ok\n");
    exit(0);
  } catch (err) {
    stderr.write("result: FAILED\n");
    stderr.write(`qev: error: ${err.message || err}\n`);
    exit(1);
  }
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length === 0 || args[0] === "--help" || args[0] === "-h") {
    usage();
  }
  const subcmd = args[0];
  const rest = args.slice(1);

  for (const a of rest) {
    if (/^--(phrase|password|pw)(=|$)/.test(a)) {
      die("phrases are never accepted on the command line — they leak to /proc and shell history. Run without --phrase and enter it at the prompt.");
    }
  }

  switch (subcmd) {
    case "lock": await cmdLock(rest); break;
    case "unlock": await cmdUnlock(rest); break;
    case "rewrap":
    case "change-phrase":
    case "rotate-phrase":
      await cmdRewrap(rest); break;
    case "gen-phrase":
    case "genphrase": await cmdGenPhrase(rest); break;
    case "self-test":
    case "selftest": await cmdSelfTest(rest); break;
    case "version":
    case "--version":
    case "-v": stdout.write(`qev ${VERSION}\n`); break;
    default: die(`unknown subcommand '${subcmd}' (try 'qev --help')`);
  }
}

main().catch((err) => {
  stderr.write(`qev: error: ${err.message || err}\n`);
  exit(1);
});
