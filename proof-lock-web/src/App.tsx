import { useState } from "react";
import {
  QevVault,
  decryptVaultV2,
  encryptVaultV2,
  generatePassphrase
} from "./qev";

type Status = { kind: "idle" | "ok" | "bad"; text: string };

const defaultText = "This is proof I want to lock.";

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
  const [vaultText, setVaultText] = useState("");
  const [status, setStatus] = useState<Status>({ kind: "idle", text: "Ready." });
  const [decrypted, setDecrypted] = useState("");

  async function lockVault() {
    setStatus({ kind: "idle", text: "Locking..." });
    setDecrypted("");
    try {
      const created = await encryptVaultV2({
        plaintext: plain,
        password: phrase,
        preset: "quick",
        mode: "self"
      });
      setVaultText(JSON.stringify(created, null, 2));
      setStatus({ kind: "ok", text: "Locked. Download the vault or open it below." });
    } catch (err) {
      setStatus({ kind: "bad", text: err instanceof Error ? err.message : String(err) });
    }
  }

  async function openVault() {
    setStatus({ kind: "idle", text: "Opening..." });
    setDecrypted("");
    try {
      if (!vaultText.trim()) throw new Error("Create or paste a vault first.");
      const vault = JSON.parse(vaultText) as QevVault;
      const text = await decryptVaultV2({ vault, password: phrase });
      setDecrypted(text);
      setStatus({ kind: "ok", text: "Opened. Passphrase is correct and the vault was not changed." });
    } catch (err) {
      setStatus({ kind: "bad", text: err instanceof Error ? err.message : String(err) });
    }
  }

  function tamperVault() {
    try {
      if (!vaultText.trim()) throw new Error("Create a vault first.");
      const vault = JSON.parse(vaultText) as QevVault;
      vault.content.ciphertext = vault.content.ciphertext.slice(0, -4) + "AAAA";
      setVaultText(JSON.stringify(vault, null, 2));
      setDecrypted("");
      setStatus({ kind: "bad", text: "Changed one part of the vault. Now try Open — it should fail." });
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
        <div className="brand">Proof Lock</div>
        <div className="links">
          <a href="#demo">Try it</a>
          <a href="#npm">npm</a>
          <a href="https://github.com/TheArtOfSound/qev-desktop">GitHub</a>
        </div>
      </nav>

      <section className="hero">
        <div className="kicker">QEV vaults</div>
        <h1>Lock text into a file. Open it later.</h1>
        <p className="lead">
          QEV turns text into a password-locked vault file. If the file is changed,
          it will not open.
        </p>
        <div className="buttons">
          <a className="button primary" href="#demo">Try it now</a>
          <a className="button" href="#npm">Install CLI</a>
        </div>
      </section>

      <section id="demo" className="panel demo-panel">
        <div className="section-head">
          <div>
            <div className="kicker">demo</div>
            <h2>Lock. Download. Open.</h2>
          </div>
          <button className="button small" onClick={newPhrase}>New phrase</button>
        </div>

        <label>Text</label>
        <textarea value={plain} onChange={(e) => setPlain(e.target.value)} />

        <label>Passphrase</label>
        <input value={phrase} onChange={(e) => setPhrase(e.target.value)} />

        <div className="buttons main-actions">
          <button className="button primary" onClick={lockVault}>Lock</button>
          <button className="button" onClick={openVault}>Open</button>
          <button className="button" onClick={() => download("proof.vault", vaultText || "{}")} disabled={!vaultText}>Download</button>
          <button className="button danger" onClick={tamperVault} disabled={!vaultText}>Tamper test</button>
        </div>

        <div className={`status ${status.kind}`}>{status.text}</div>

        {decrypted && (
          <div className="result">
            <div className="labelish">Opened text</div>
            <pre>{decrypted}</pre>
          </div>
        )}

        <details className="vault-box" open={Boolean(vaultText)}>
          <summary>Vault file contents</summary>
          <textarea value={vaultText} onChange={(e) => setVaultText(e.target.value)} />
        </details>
      </section>

      <section id="npm" className="panel npm-panel">
        <div className="kicker">npm</div>
        <h2>Install the CLI</h2>
        <pre>npm i -g @bryan237l/qev-cli</pre>
        <p>Then run <code>qev</code>.</p>
      </section>

      <footer>
        QEV uses the BRY-NFET-SX-VAULT-V2 format with libsodium. No account. No cloud.
      </footer>
    </main>
  );
}
