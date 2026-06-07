import { useMemo, useState } from "react";
import {
  QevVault,
  PresetKey,
  decryptVaultV2,
  encryptVaultV2,
  generatePassphrase,
  runSelfTest
} from "./qev";

type Status = { kind: "idle" | "ok" | "bad"; text: string };

const defaultText = `Proof Lock Labs demo artifact

This text will be encrypted into a BRY-NFET-SX-VAULT-V2 JSON vault.

Change one character in the vault and verification should fail.`;

function download(name: string, text: string) {
  const blob = new Blob([text], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

export default function App() {
  const [plain, setPlain] = useState(defaultText);
  const [phrase, setPhrase] = useState("demo-passphrase-change-me");
  const [preset, setPreset] = useState<PresetKey>("quick");
  const [vaultText, setVaultText] = useState("");
  const [status, setStatus] = useState<Status>({ kind: "idle", text: "Ready." });
  const [decrypted, setDecrypted] = useState("");

  const vault = useMemo(() => {
    try {
      return vaultText.trim() ? JSON.parse(vaultText) as QevVault : null;
    } catch {
      return null;
    }
  }, [vaultText]);

  async function createVault() {
    setStatus({ kind: "idle", text: "Creating vault. Argon2id may take a few seconds..." });
    setDecrypted("");
    try {
      const created = await encryptVaultV2({ plaintext: plain, password: phrase, preset, mode: "self" });
      setVaultText(JSON.stringify(created, null, 2));
      setStatus({ kind: "ok", text: "Vault created. Download it or verify it below." });
    } catch (err) {
      setStatus({ kind: "bad", text: err instanceof Error ? err.message : String(err) });
    }
  }

  async function verifyVault() {
    if (!vault) {
      setStatus({ kind: "bad", text: "Paste or create a valid JSON vault first." });
      return;
    }
    setStatus({ kind: "idle", text: "Verifying vault..." });
    setDecrypted("");
    try {
      const text = await decryptVaultV2({ vault, password: phrase });
      setDecrypted(text);
      setStatus({ kind: "ok", text: "Valid vault. Phrase accepted. No tampering detected." });
    } catch (err) {
      setStatus({ kind: "bad", text: err instanceof Error ? err.message : String(err) });
    }
  }

  function tamperVault() {
    if (!vault) {
      setStatus({ kind: "bad", text: "Create a vault first." });
      return;
    }
    const modified = JSON.parse(JSON.stringify(vault)) as QevVault;
    modified.content.ciphertext = modified.content.ciphertext.slice(0, -4) + "AAAA";
    setVaultText(JSON.stringify(modified, null, 2));
    setDecrypted("");
    setStatus({ kind: "bad", text: "Vault was intentionally modified. Click Verify and it should fail." });
  }

  async function selfTest() {
    setStatus({ kind: "idle", text: "Running self-test..." });
    try {
      await runSelfTest();
      setStatus({ kind: "ok", text: "Self-test passed: encrypt → decrypt → tamper → wrong phrase." });
    } catch (err) {
      setStatus({ kind: "bad", text: err instanceof Error ? err.message : String(err) });
    }
  }

  async function newPhrase() {
    try {
      setPhrase(await generatePassphrase());
    } catch (err) {
      setStatus({ kind: "bad", text: err instanceof Error ? err.message : String(err) });
    }
  }

  return (
    <main>
      <nav>
        <div className="brand">Proof Lock Labs / QEV</div>
        <div className="links">
          <a href="#demo">Demo</a>
          <a href="#npm">npm</a>
          <a href="https://github.com/TheArtOfSound/qev-desktop">GitHub</a>
          <a href="https://www.npmjs.com/package/@bryan237l/qev-cli">Package</a>
        </div>
      </nav>

      <section className="hero">
        <div>
          <div className="kicker">local-first encrypted vaults</div>
          <h1>Lock proof into a file. Verify it later.</h1>
          <p className="lead">
            Create encrypted, tamper-evident vaults for AI outputs, notes, logs,
            research artifacts, screenshots, and sensitive records.
          </p>
          <p>
            This web app runs the vault workflow in your browser. The npm CLI is
            still the main production tool. No custom crypto claims.
          </p>
          <div className="buttons">
            <a className="button primary" href="#demo">Try the vault demo</a>
            <a className="button" href="#npm">Install CLI</a>
            <button className="button" onClick={selfTest}>Run self-test</button>
          </div>
        </div>

        <div className="panel terminal">
{`npm install -g @bryan237l/qev-cli
qev self-test

echo "important proof" | qev lock --out proof.vault
qev unlock proof.vault`}
        </div>
      </section>

      <section className="cards">
        <div className="card">
          <h3>No account required</h3>
          <p>Vaults are local JSON files. The CLI is offline by design.</p>
        </div>
        <div className="card">
          <h3>Tamper evident</h3>
          <p>Protected metadata and encrypted content are authenticated.</p>
        </div>
        <div className="card">
          <h3>npm available</h3>
          <p>Install globally or run with npx. Programmatic API included.</p>
        </div>
      </section>

      <section id="demo" className="panel">
        <div className="kicker">live vault demo</div>
        <h2>Create, verify, tamper-test</h2>
        <p>
          This demo creates BRY-NFET-SX-VAULT-V2 vault JSON using
          XChaCha20-Poly1305 and Argon2id through libsodium.
        </p>

        <div className="workspace">
          <div>
            <label>Text to lock</label>
            <textarea value={plain} onChange={(e) => setPlain(e.target.value)} />

            <label>Passphrase</label>
            <div className="row">
              <input value={phrase} onChange={(e) => setPhrase(e.target.value)} />
              <button className="button" onClick={newPhrase}>Generate</button>
            </div>

            <label>Strength</label>
            <select value={preset} onChange={(e) => setPreset(e.target.value as PresetKey)}>
              <option value="quick">quick — lower memory, faster demo</option>
              <option value="strong">strong — default CLI profile</option>
              <option value="vault">vault — higher cost profile</option>
            </select>

            <div className="buttons">
              <button className="button primary" onClick={createVault}>Create vault</button>
              <button className="button" onClick={verifyVault}>Verify vault</button>
              <button className="button danger" onClick={tamperVault}>Tamper test</button>
              <button className="button" onClick={() => download("proof.vault", vaultText || "{}")}>Download</button>
            </div>

            <div className={`status ${status.kind}`}>{status.text}</div>

            {decrypted && (
              <>
                <label>Decrypted preview</label>
                <pre className="output">{decrypted}</pre>
              </>
            )}
          </div>

          <div>
            <label>Vault JSON</label>
            <textarea className="vault" value={vaultText} onChange={(e) => setVaultText(e.target.value)} />
          </div>
        </div>
      </section>

      <section id="npm" className="panel">
        <div className="kicker">npm CLI</div>
        <h2>Install the production CLI</h2>
        <pre className="terminal">{`npm install -g @bryan237l/qev-cli
qev self-test

echo "important proof" | qev lock --out proof.vault
qev unlock proof.vault

npx @bryan237l/qev-cli self-test`}</pre>
      </section>

      <section className="cards two">
        <div className="card">
          <h3>Threat model</h3>
          <p>
            QEV protects exported vault files when the phrase stays secret and the
            device is trusted. It does not protect against weak phrases or a
            compromised machine.
          </p>
        </div>
        <div className="card">
          <h3>Technical model</h3>
          <p>
            Schema: BRY-NFET-SX-VAULT-V2. AEAD: XChaCha20-Poly1305. KDF:
            Argon2id. Runtime crypto: libsodium.
          </p>
        </div>
      </section>

      <footer>
        MIT © Bryan Leonard / Qira LLC. Proof Lock Labs is the public face of QEV.
      </footer>
    </main>
  );
}
