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
//   qev gen-phrase
//               Print a freshly generated 4-word passphrase.
//
//   qev self-test
//               Run the round-trip + tamper + wrong-phrase self-test.
//               Exits 0 on success, 1 on any failure.
//
//   qev version
//               Print the package version.
//
// SAFETY RULES (enforced here, not in lib/):
//   - No --phrase / --password flag. Phrases are always prompted on stdin.
//     The shell would otherwise record them in history and /proc.
//   - No stack traces on user errors. We print a concise "qev: error: ..."
//     line and exit 1.
//   - Never log the phrase, plaintext, or derived key. The lib module
//     has the same rule; this file just never touches the values.

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
import {
  promptPhrase,
  promptPhraseConfirmed,
  promptPlaintext,
} from "../lib/prompt.js";

// ---- tiny helpers -----------------------------------------------------

/** Print `qev: error: <msg>` to stderr and exit 1. */
function die(msg) {
  stderr.write(`qev: error: ${msg}\n`);
  exit(1);
}

/** Print a usage line and exit. */
function usage(subcmd) {
  const lines = subcmd
    ? {
        lock:
          "qev lock [--out FILE] [--mode self|share] [--strength quick|strong|vault]",
        unlock: "qev unlock VAULT_FILE",
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
  qev gen-phrase
  qev self-test
  qev version

Phrases are always prompted interactively. There is no --phrase flag
because the shell would leak it via history and /proc.

vault format:  BRY-NFET-SX-VAULT-V2 (XChaCha20-Poly1305 + Argon2id)
compat:        desktop QEV (Mac/Windows) and secure.imagineqira.com/vault
`,
    );
  }
  exit(1);
}

// ---- subcommand: lock -------------------------------------------------

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
    die(
      `lock: --strength must be one of ${Object.keys(LOCK_PRESETS).join(", ")}`,
    );
  }

  // 1. Read plaintext from stdin (or prompt the user on a TTY).
  const plaintext = await promptPlaintext();
  if (!plaintext || plaintext.length === 0) {
    die("lock: empty plaintext — nothing to encrypt");
  }

  // 2. Prompt for the phrase twice. If the terminal isn't interactive,
  //    promptPhraseConfirmed will reject — which is the right failure
  //    mode for scripted foot-guns.
  let phrase;
  try {
    phrase = await promptPhraseConfirmed();
  } catch (err) {
    die(err.message || "phrase prompt failed");
  }

  // 3. Encrypt. Surface known errors; log bug-style errors to stderr.
  stderr.write(
    `locking with ${preset.label} preset (${preset.hint}) ...\n`,
  );
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

  // 4. Write the vault JSON. To a file if --out, otherwise stdout.
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

// ---- subcommand: unlock -----------------------------------------------

async function cmdUnlock(argv) {
  const { values, positionals } = parseArgs({
    args: argv,
    options: {
      help: { type: "boolean", short: "h" },
    },
    strict: true,
    allowPositionals: true,
  });

  if (values.help) usage("unlock");
  if (positionals.length !== 1) {
    die("unlock: expected exactly one VAULT_FILE argument");
  }
  const vaultPath = positionals[0];

  // 1. Load and parse the vault file.
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
    die(`unlock: ${vaultPath} is not valid JSON: ${err.message}`);
  }

  // 2. Prompt for the phrase.
  let phrase;
  try {
    phrase = await promptPhrase();
  } catch (err) {
    die(err.message || "phrase prompt failed");
  }

  // 3. Decrypt. On failure, print the specific error but never the
  //    phrase, plaintext, or any derived material.
  let plaintext;
  try {
    plaintext = await decryptVaultV2({ vault, password: phrase });
  } catch (err) {
    die(err.message || "decryption failed");
  }

  // 4. Write plaintext to stdout. The trailing newline keeps pipes
  //    behaving sanely (`qev unlock x.vault | less`).
  stdout.write(plaintext);
  if (!plaintext.endsWith("\n") && stdout.isTTY) {
    stdout.write("\n");
  }
}

// ---- subcommand: gen-phrase -------------------------------------------

async function cmdGenPhrase(argv) {
  const { values } = parseArgs({
    args: argv,
    options: {
      help: { type: "boolean", short: "h" },
    },
    strict: true,
    allowPositionals: false,
  });
  if (values.help) usage("gen-phrase");

  const phrase = await generatePassphrase();
  stdout.write(phrase + "\n");
}

// ---- subcommand: self-test --------------------------------------------

async function cmdSelfTest(argv) {
  const { values } = parseArgs({
    args: argv,
    options: {
      help: { type: "boolean", short: "h" },
    },
    strict: true,
    allowPositionals: false,
  });
  if (values.help) usage("self-test");

  stderr.write("qev self-test: encrypt → decrypt → tamper → wrong-phrase ... ");
  try {
    const result = await runSelfTest();
    if (result.ok) {
      stderr.write("ok\n");
      exit(0);
    }
  } catch (err) {
    stderr.write(`FAILED\nqev: error: ${err.message || err}\n`);
    exit(1);
  }
}

// ---- entry ------------------------------------------------------------

async function main() {
  const args = process.argv.slice(2);
  if (args.length === 0 || args[0] === "--help" || args[0] === "-h") {
    usage();
  }
  const subcmd = args[0];
  const rest = args.slice(1);

  // Reject any top-level --phrase / --password / --pw to discourage
  // shell-history leakage. This is defence-in-depth; none of the
  // subcommand parsers accept it, but we reject it explicitly here so
  // the error message is friendly.
  for (const a of rest) {
    if (/^--(phrase|password|pw)(=|$)/.test(a)) {
      die(
        "phrases are never accepted on the command line — they leak to /proc and shell history. Run without --phrase and enter it at the prompt.",
      );
    }
  }

  switch (subcmd) {
    case "lock":
      await cmdLock(rest);
      break;
    case "unlock":
      await cmdUnlock(rest);
      break;
    case "gen-phrase":
    case "genphrase":
      await cmdGenPhrase(rest);
      break;
    case "self-test":
    case "selftest":
      await cmdSelfTest(rest);
      break;
    case "version":
    case "--version":
    case "-v":
      stdout.write(`qev ${VERSION}\n`);
      break;
    default:
      die(`unknown subcommand '${subcmd}' (try 'qev --help')`);
  }
}

main().catch((err) => {
  // Last-line-of-defence error handler. Don't print stack traces — they
  // obscure the real message and aren't useful to end users.
  stderr.write(`qev: error: ${err.message || err}\n`);
  exit(1);
});
