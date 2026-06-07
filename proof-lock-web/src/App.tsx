import { useState } from "react";
import {
  QevVault,
  decryptVaultV2,
  encryptVaultV2,
  generatePassphrase
} from "./qev";

type Status = { kind: "idle" | "ok" | "bad"; text: string };

type Template = {
  id: string;
  title: string;
  text: string;
};

const templates: Template[] = [
  {
    id: "ai-output",
    title: "AI output",
    text: `AI OUTPUT RECORD
Date:
Tool/model:
Prompt:
Result:
Notes:
Why I locked this:`
  },
  {
    id: "client-handoff",
    title: "Client handoff",
    text: `CLIENT HANDOFF
Client:
Job/project:
What was delivered:
Important terms:
Next step:
Locked by:`
  },
  {
    id: "private-note",
    title: "Private note",
    text: `PRIVATE NOTE
Date:
Subject:
Details:
Decision:
Reminder:`
  },
  {
    id: "incident-log",
    title: "Incident log",
    text: `INCIDENT LOG
Date/time:
People involved:
What happened:
Evidence:
Actions taken:
Notes:`
  }
];

const defaultText = templates[0].text;

function download(name: string, text: string) {
  const blob = new Blob([text], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

function vaultName() {
  const stamp = new Date().toISOString().slice(0, 10);
  return `proof-lock-${stamp}.vault`;
}

export default function App() {
  const [plain, setPlain] = useState(defaultText);
  const [phrase, setPhrase] = useState("demo-passphrase-change-me");
  const [vaultText, setVaultText] = useState("");
  const [status, setStatus] = useState<Status>({ kind: "idle", text: "Ready." });
  const [decrypted, setDecrypted] = useState("");

  function useTemplate(template: Template) {
    setPlain(template.text);
    setDecrypted("");
    setStatus({ kind: "idle", text: `${template.title} template loaded.` });
  }

  async function lockVault() {
    setStatus({ kind: "idle", text: "Locking locally..." });
    setDecrypted("");
    try {
      const created = await encryptVaultV2({
        plaintext: plain,
        password: phrase,
        preset: "quick",
        mode: "self"
      });
      const text = JSON.stringify(created, null, 2);
      setVaultText(text);
      setStatus({ kind: "ok", text: "Vault ready. Download it or test-open it below." });
    } catch (err) {
      setStatus({ kind: "bad", text: err instanceof Error ? err.message : String(err) });
    }
  }

  async function openVault() {
    setStatus({ kind: "idle", text: "Opening locally..." });
    setDecrypted("");
    try {
      if (!vaultText.trim()) throw new Error("Paste, upload, or create a vault first.");
      const vault = JSON.parse(vaultText) as QevVault;
      const text = await decryptVaultV2({ vault, password: phrase });
      setDecrypted(text);
      setStatus({ kind: "ok", text: "Opened. Password matched and the vault was not changed." });
    } catch (err) {
      setStatus({ kind: "bad", text: err instanceof Error ? err.message : String(err) });
    }
  }

  async function copyVault() {
    try {
      if (!vaultText) throw new Error("No vault to copy yet.");
      await navigator.clipboard.writeText(vaultText);
      setStatus({ kind: "ok", text: "Vault copied to clipboard." });
    } catch (err) {
      setStatus({ kind: "bad", text: err instanceof Error ? err.message : String(err) });
    }
  }

  async function loadVaultFile(file: File | null) {
    if (!file) return;
    try {
      const text = await file.text();
      setVaultText(text);
      setDecrypted("");
      setStatus({ kind: "idle", text: `${file.name} loaded. Enter its passphrase and open it.` });
    } catch (err) {
      setStatus({ kind: "bad", text: err instanceof Error ? err.message : String(err) });
    }
  }

  function tamperVault() {
    try {
      if (!vaultText.trim()) throw new Error("Create or load a vault first.");
      const vault = JSON.parse(vaultText) as QevVault;
      vault.content.ciphertext = vault.content.ciphertext.slice(0, -4) + "AAAA";
      setVaultText(JSON.stringify(vault, null, 2));
      setDecrypted("");
      setStatus({ kind: "bad", text: "One piece of the vault was changed. Opening should now fail." });
    } catch (err) {
      setStatus({ kind: "bad", text: err instanceof Error ? err.message : String(err) });
    }
  }

  async function newPhrase() {
    try {
      setPhrase(await generatePassphrase());
      setStatus({ kind: "idle", text: "New passphrase generated. Save it before downloading a vault." });
    } catch (err) {
      setStatus({ kind: "bad", text: err instanceof Error ? err.message : String(err) });
    }
  }

  return (
    <main>
      <nav>
        <div className="brand">Proof Lock</div>
        <div className="links">
          <a href="#tool">Tool</a>
          <a href="#uses">Uses</a>
          <a href="#npm">CLI</a>
          <a href="https://github.com/TheArtOfSound/qev-desktop">GitHub</a>
        </div>
      </nav>

      <section className="hero">
        <p className="eyebrow">QEV local vault tool</p>
        <h1>Put proof in a file you can verify later.</h1>
        <p className="lead">
          Write or paste something important, lock it with a passphrase, and download a vault.
          If the vault is edited later, it fails to open.
        </p>
      </section>

      <section id="tool" className="tool">
        <div className="column write-column">
          <div className="section-title">
            <span>1</span>
            <h2>Write what you need to preserve</h2>
          </div>

          <div className="templates" aria-label="Use case templates">
            {templates.map((template) => (
              <button key={template.id} onClick={() => useTemplate(template)}>
                {template.title}
              </button>
            ))}
          </div>

          <label htmlFor="plain">Text to lock</label>
          <textarea
            id="plain"
            value={plain}
            onChange={(e) => setPlain(e.target.value)}
            spellCheck={false}
          />

          <label htmlFor="phrase">Passphrase</label>
          <div className="phrase-row">
            <input
              id="phrase"
              value={phrase}
              onChange={(e) => setPhrase(e.target.value)}
              spellCheck={false}
            />
            <button onClick={newPhrase}>Generate</button>
          </div>

          <div className="actions primary-actions">
            <button className="black" onClick={lockVault}>Lock vault</button>
            <button onClick={() => download(vaultName(), vaultText)} disabled={!vaultText}>Download</button>
          </div>
        </div>

        <div className="column open-column">
          <div className="section-title">
            <span>2</span>
            <h2>Open or verify a vault</h2>
          </div>

          <label htmlFor="file">Upload .vault file</label>
          <input
            id="file"
            className="file-input"
            type="file"
            accept=".vault,application/json,.json,text/plain"
            onChange={(e) => loadVaultFile(e.target.files?.[0] ?? null)}
          />

          <label htmlFor="vault">Vault JSON</label>
          <textarea
            id="vault"
            className="vault-area"
            value={vaultText}
            onChange={(e) => setVaultText(e.target.value)}
            spellCheck={false}
            placeholder="Create a vault, paste one here, or upload a .vault file."
          />

          <div className="actions">
            <button className="black" onClick={openVault}>Open vault</button>
            <button onClick={copyVault} disabled={!vaultText}>Copy</button>
            <button onClick={tamperVault} disabled={!vaultText}>Tamper test</button>
          </div>

          <div className={`status ${status.kind}`}>{status.text}</div>

          {decrypted && (
            <div className="opened">
              <div className="small-label">Opened text</div>
              <pre>{decrypted}</pre>
            </div>
          )}
        </div>
      </section>

      <section id="uses" className="uses">
        <h2>What this is actually for</h2>
        <div className="use-grid">
          <article>
            <h3>AI work receipts</h3>
            <p>Lock prompts, outputs, edits, and decisions so you can prove what you saved at that time.</p>
          </article>
          <article>
            <h3>Client notes</h3>
            <p>Seal handoffs, instructions, scope notes, and records before sending or archiving them.</p>
          </article>
          <article>
            <h3>Personal records</h3>
            <p>Keep a private note, incident timeline, or decision log in a file that detects tampering.</p>
          </article>
        </div>
      </section>

      <section id="npm" className="cli">
        <h2>Command line</h2>
        <pre>npm i -g @bryan237l/qev-cli</pre>
        <p>Use the CLI when you want this workflow outside the browser.</p>
      </section>

      <footer>
        Local browser workflow. No account. No upload. Keep your passphrase; no one can recover it for you.
      </footer>
    </main>
  );
}
