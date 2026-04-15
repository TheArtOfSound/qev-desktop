# `@imagineqira/qev-cli`

Command-line vault for offline encrypted message envelopes.

Same crypto and vault format as **QEV (Qira Encryption Vault)** on Mac,
Windows, and [`secure.imagineqira.com/vault`](https://secure.imagineqira.com/vault).
A vault locked here decrypts there, and vice versa. Zero network
access. One dependency.

```sh
npm install -g @imagineqira/qev-cli

echo "the secret message" | qev lock --out secret.vault
# Phrase: ************
# Phrase (confirm): ************
# locking with strong preset (~4s) ...
# wrote secret.vault

qev unlock secret.vault
# Phrase: ************
# the secret message
```

---

## What it is

A Node CLI that encrypts UTF-8 plaintext into a
[`BRY-NFET-SX-VAULT-V2`](#vault-format) JSON file and decrypts it back.
The vault format is the same one the desktop app and web app use, so
anywhere you can run QEV, you can read the file.

```
┌───────────┐   qev lock    ┌───────────────┐   qev unlock   ┌───────────┐
│ plaintext ├──────────────▶│ secret.vault  ├───────────────▶│ plaintext │
│  (stdin)  │   +phrase     │     (JSON)    │    +phrase     │  (stdout) │
└───────────┘               └───────────────┘                └───────────┘
```

## Why it exists

- **Sysadmins and scripts.** `qev lock` into a file you check into git.
  `qev unlock` on deploy. Similar to `sops` / `git-crypt`, friendlier.
- **Cross-platform.** The desktop QEV is Mac + Windows only. The CLI
  adds Linux coverage — any machine with Node 18.17+.
- **Pipe-friendly.** Input is stdin, output is stdout. Compose with
  every Unix tool you already use.
- **Same vault format.** A vault produced here decrypts in the desktop
  app or the web app, byte-for-byte. One format, four implementations.

## Install

```sh
npm install -g @imagineqira/qev-cli
```

Or run without installing:

```sh
npx @imagineqira/qev-cli self-test
```

## Commands

### `qev lock [--out FILE] [--mode self|share] [--strength quick|strong|vault]`

Encrypts plaintext from stdin. Prompts for the phrase twice with
confirmation. Writes the vault JSON to `--out FILE` or stdout.

```sh
# Interactive: type the message, Ctrl-D when done
qev lock --out note.vault

# Pipe-in: plaintext from any source
echo "wi-fi password: hunter2" | qev lock --out wifi.vault

# Larger files too (up to 256 KiB of plaintext):
cat secrets.txt | qev lock --out secrets.vault --strength vault
```

**Strength presets** (Argon2id parameters):

| preset   | opslimit | memlimit | roughly |
|----------|---------:|---------:|--------:|
| `quick`  | 1        | 32 MiB   | ~1 s    |
| `strong` (default) | 4 | 96 MiB | ~4 s    |
| `vault`  | 6        | 128 MiB  | ~7 s    |

### `qev unlock VAULT_FILE`

Decrypts a vault file. Prompts for the phrase. Writes plaintext to
stdout.

```sh
qev unlock note.vault

# Pipe into anything
qev unlock note.vault | less
qev unlock creds.vault | base64 -d > secrets.bin
```

### `qev gen-phrase`

Prints a freshly generated 4-word passphrase. Roughly ~37 bits of
entropy — use it as a starting point, or prefer a longer phrase you
chose yourself.

```sh
$ qev gen-phrase
river-purple-dragon-cloud-47
```

### `qev self-test`

Runs a round-trip + tamper + wrong-phrase self-test with the quick
preset. Exits 0 on success, 1 on any failure.

```sh
$ qev self-test
qev self-test: encrypt → decrypt → tamper → wrong-phrase ... ok
```

### `qev version`

```sh
$ qev version
qev 0.28.1
```

## Crypto

- **AEAD:** XChaCha20-Poly1305 (24-byte nonce, 16-byte Poly1305 MAC)
- **KDF:** Argon2id, default 4 opslimit / 96 MiB memlimit
- **Wrap pattern:** the phrase stretches into a wrap-key which encrypts
  a per-vault random 32-byte content key. The content key is what
  encrypts your plaintext. This means the phrase is never the
  content-encryption key itself — it's one unlock path for the data
  key. The format can grow additional unlock paths (recovery code,
  device-bound key) later without re-encrypting the data.
- **AAD binding:** the vault metadata (schema, version, created_at,
  mode, kdf block, algorithms, nonces) is fed into both AEAD
  operations as Additional Authenticated Data. Tampering with *any*
  bound field breaks at least one AEAD tag cleanly.
- **Library:** [`libsodium-wrappers-sumo`](https://www.npmjs.com/package/libsodium-wrappers-sumo)
  — the same libsodium WASM binary the browser implementation ships.
  Not a pure-JS reimplementation.

Primitives are not invented. No custom cryptography was written. The
value-add is the vault format, the cross-platform packaging, and the
honest framing.

## Vault format

```json
{
  "schema":     "BRY-NFET-SX-VAULT-V2",
  "version":    "0.28.1",
  "created_at": "2026-04-15T23:59:59.000Z",
  "mode":       "self",
  "kdf": {
    "algorithm": "argon2id",
    "opslimit":  4,
    "memlimit":  100663296,
    "salt":      "<b64url, 16 bytes>"
  },
  "wrap": {
    "algorithm":   "XChaCha20-Poly1305",
    "nonce":       "<b64url, 24 bytes>",
    "wrapped_key": "<b64url, 48 bytes (32-byte key + 16-byte MAC)>"
  },
  "content": {
    "algorithm":  "XChaCha20-Poly1305",
    "nonce":      "<b64url, 24 bytes>",
    "ciphertext": "<b64url>"
  }
}
```

All binary fields are base64url without padding. The AAD is NOT stored
— it's derived deterministically on both encrypt and decrypt by
canonical-JSON-serializing a fixed subset of vault metadata. The
canonical JSON serializer sorts object keys recursively with no
whitespace, so the AAD bytes are identical regardless of which
implementation produced the vault.

## Safety rules enforced by the CLI

1. **The phrase is never a command-line argument.** `qev lock --phrase "..."`
   is rejected explicitly. Shell history, `ps`, and `/proc` would leak
   it. The phrase is always typed at a raw-mode TTY prompt with no echo.
2. **Stdin phrase input is refused unless stdin is a TTY.** A scripted
   wrapper that pipes a phrase in would be a foot-gun pattern; the
   CLI refuses to read from non-TTY stdin for phrases.
3. **No logging of user data.** The library modules have a top-of-file
   rule and the CLI front-end never touches the phrase, plaintext, or
   derived key.
4. **Errors are concise, not stack-trace-dump.** Bug-style errors still
   go to stderr but user-visible ones are single-line `qev: error: ...`
   with a clean exit code 1.

## Threat model — honest caveats

**What this protects:**

- Confidentiality against an attacker who doesn't have the phrase, at
  the cost of Argon2id's hardness parameter.
- Integrity of the ciphertext, nonces, salt, KDF parameters, schema,
  version, mode, and `created_at` via AEAD AAD binding.
- Cross-platform portability — a vault made on one OS opens on
  another.

**What it does NOT protect against:**

- **A weak phrase.** Argon2id raises the cost; it does not eliminate
  it. A phrase the user can remember in 3 seconds is a phrase an
  attacker can guess in minutes with a GPU. Use `gen-phrase` or a
  longer self-chosen phrase.
- **A compromised endpoint.** Keyloggers, malware, shoulder surfers,
  terminal scrollback — the plaintext and the phrase both touch your
  machine. If the machine is compromised, so is your vault.
- **A forgotten phrase.** There is no reset, no backdoor, no recovery
  email. If you forget, the vault is unrecoverable. This is the point.
- **Transmission channel metadata.** The vault file can be sent over
  any channel, but the channel still sees who sent what to whom and
  when. If you want to hide that, use Signal.
- **A motivated adversary with the phrase.** Once the phrase is
  known, the vault is open. Share it in person or via a separate
  channel. Never in the same email as the vault file.
- **Backdoored `npm install`.** The supply chain is a risk. Pin
  versions, audit dependencies, prefer `npm ci` in CI. This package
  declares a single runtime dependency (`libsodium-wrappers-sumo`).

**What it is NOT:**

- **It is not a messenger.** No key exchange, no forward secrecy, no
  identity verification. It's a vault you can share the key to. If
  you need Signal's properties, use Signal.
- **It is not a password manager.** If you need autofill, browser
  integration, and a credential database, use Bitwarden or
  1Password.
- **It is not cloud storage encryption.** If you want to encrypt
  files inside Dropbox or Drive, use Cryptomator.

QEV fills the narrow gap between those tools: encrypt a single thing,
share it once, through any channel, without an account.

## Programmatic use

```js
import { encryptVaultV2, decryptVaultV2, runSelfTest } from "@imagineqira/qev-cli";

await runSelfTest(); // throws on any failure

const vault = await encryptVaultV2({
  plaintext: "hello",
  password: "a-reasonably-long-phrase",
  mode: "self",
  opslimit: 4,
  memlimit: 96 * 1024 * 1024,
});

const pt = await decryptVaultV2({ vault, password: "a-reasonably-long-phrase" });
console.log(pt); // "hello"
```

## Development

```sh
git clone https://github.com/TheArtOfSound/qev-desktop.git
cd qev-desktop/qev-cli
npm install
npm test              # 26 tests, ~900 ms
./bin/qev.js self-test
```

## License

MIT © Bryan Leonard / Qira LLC. libsodium is ISC licensed. See
`LICENSE` and `vendor/libsodium-license.txt` for the full texts.

## Support

- Desktop app: [`secure.imagineqira.com/downloads`](https://secure.imagineqira.com/downloads)
- Web app (preview): [`secure.imagineqira.com/vault`](https://secure.imagineqira.com/vault)
- Questions, bugs, refunds: `bryanleonard@imagineqira.com`
