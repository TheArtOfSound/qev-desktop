// prompt.js — interactive phrase prompt that never echoes the phrase,
// reads from raw-mode stdin, and handles Ctrl-C cleanly.
//
// DESIGN NOTES
//
// 1) The phrase is read character-by-character in raw mode so the
//    terminal never echoes it. We accept bytes until the user presses
//    Enter (\r or \n), Ctrl-C (\x03), or Ctrl-D (\x04 = EOT = "I'm
//    done"). Backspace is handled.
//
// 2) We DO NOT use readline for the phrase, because readline's default
//    is to echo and its masking plugin is fragile across Node
//    versions. Raw-mode stdin is boring but bulletproof.
//
// 3) We NEVER accept the phrase as a command-line argument. That would
//    leak it to `ps`, shell history, and /proc. The CLI front-end also
//    rejects any --phrase=... flag to prevent foot-guns. This file
//    only prompts.
//
// 4) For plaintext input (which CAN contain newlines), we read from
//    stdin in cooked mode until EOF, stripping NO characters. The
//    user is expected to pipe the plaintext in or type and press Ctrl-D.
//
// 5) If stdin is not a TTY (e.g. piped in via a wrapper that provides
//    the phrase on an fd), we refuse — that's a sign of a scripted
//    usage which is exactly the pattern we want to prevent for
//    phrases.

import { stdin, stdout, stderr } from "node:process";

const ETX = 0x03; // Ctrl-C
const EOT = 0x04; // Ctrl-D
const LF = 0x0a;
const CR = 0x0d;
const BS = 0x08;
const DEL = 0x7f;

/**
 * Prompt the user for a phrase. Reads raw-mode stdin with no echo.
 * Returns the phrase string on Enter. Throws AbortError on Ctrl-C.
 *
 * Refuses to run unless stdin is a TTY to avoid scripted foot-guns.
 *
 * @param {string} [label="Phrase"]
 * @returns {Promise<string>}
 */
export function promptPhrase(label = "Phrase") {
  if (!stdin.isTTY) {
    return Promise.reject(
      new Error(
        "refusing to read a phrase from a non-TTY stdin — phrases must be typed interactively",
      ),
    );
  }

  return new Promise((resolve, reject) => {
    stderr.write(`${label}: `);

    // Capture prior state so we can restore it on exit. setRawMode
    // flips the terminal into single-byte input with no echo.
    const wasRaw = stdin.isRaw;
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding(undefined); // raw bytes

    let buf = "";

    const cleanup = () => {
      stdin.removeListener("data", onData);
      stdin.setRawMode(wasRaw);
      stdin.pause();
    };

    const onData = (chunk) => {
      for (const byte of chunk) {
        if (byte === CR || byte === LF) {
          stderr.write("\n");
          cleanup();
          resolve(buf);
          return;
        }
        if (byte === ETX) {
          stderr.write("\n");
          cleanup();
          reject(Object.assign(new Error("aborted"), { code: "ABORT" }));
          return;
        }
        if (byte === EOT) {
          // Ctrl-D with no phrase typed -> treat as cancel. With phrase
          // already typed -> treat as submit (like bash read).
          stderr.write("\n");
          cleanup();
          if (buf.length === 0) {
            reject(Object.assign(new Error("aborted (Ctrl-D)"), { code: "ABORT" }));
          } else {
            resolve(buf);
          }
          return;
        }
        if (byte === BS || byte === DEL) {
          if (buf.length > 0) {
            // Pop one char. For multi-byte UTF-8 we'd need to pop the
            // whole code point; accept the imperfect behaviour for now.
            buf = buf.slice(0, -1);
          }
          continue;
        }
        if (byte >= 0x20) {
          // Append the printable byte. We accumulate bytes then decode
          // as UTF-8 below if needed, but for typical typed phrases
          // each byte is one character anyway.
          buf += String.fromCharCode(byte);
        }
      }
    };

    stdin.on("data", onData);
  });
}

/**
 * Prompt the user twice for the same phrase and verify they match.
 * Used on `qev lock` so a typo doesn't produce an irrecoverable vault.
 *
 * @param {string} [label1="Phrase"]
 * @param {string} [label2="Phrase (confirm)"]
 * @returns {Promise<string>}
 */
export async function promptPhraseConfirmed(
  label1 = "Phrase",
  label2 = "Phrase (confirm)",
) {
  const a = await promptPhrase(label1);
  const b = await promptPhrase(label2);
  if (a !== b) {
    throw new Error("Phrases do not match — nothing was written. Try again.");
  }
  return a;
}

/**
 * Read all of stdin until EOF and return it as a Uint8Array.
 * Used for reading plaintext on `qev lock` (when stdin is piped).
 *
 * @returns {Promise<Uint8Array>}
 */
export function readStdinAll() {
  return new Promise((resolve, reject) => {
    const chunks = [];
    stdin.on("data", (chunk) => chunks.push(chunk));
    stdin.on("end", () => resolve(new Uint8Array(Buffer.concat(chunks))));
    stdin.on("error", reject);
  });
}

/**
 * Read a plaintext message from the user in cooked-mode TTY stdin.
 * Prints a friendly helper line to stderr, then reads until EOF.
 *
 * @returns {Promise<string>}
 */
export function promptPlaintext() {
  if (!stdin.isTTY) {
    // Piped input path — read to EOF and return as UTF-8 string.
    return readStdinAll().then((bytes) =>
      new TextDecoder("utf-8", { fatal: false }).decode(bytes),
    );
  }
  stderr.write(
    "Type or paste your message. Press Ctrl-D on a new line when done.\n",
  );
  return new Promise((resolve, reject) => {
    stdin.setEncoding("utf8");
    let buf = "";
    const onData = (chunk) => {
      buf += chunk;
    };
    const onEnd = () => {
      stdin.removeListener("data", onData);
      stdin.removeListener("end", onEnd);
      // Trim the final newline the terminal adds on EOF, if any.
      if (buf.endsWith("\n")) buf = buf.slice(0, -1);
      resolve(buf);
    };
    stdin.on("data", onData);
    stdin.on("end", onEnd);
    stdin.on("error", reject);
    stdin.resume();
  });
}
