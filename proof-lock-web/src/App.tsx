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
  help: string;
  text: string;
};

const templates: Template[] = [
  {
    id: "ai-output",
    title: "AI output",
    help: "Save a prompt, answer, edit log, or research result as a locked receipt.",
    text: `AI OUTPUT RECORD
Date:
Tool/model:
Prompt:
Result:
Edits made:
Why this matters:`
  },
  {
    id: "client-handoff",
    title: "Client handoff",
    help: "Seal job notes, scope, delivery notes, or instructions before sending or archiving.",
    text: `CLIENT HANDOFF
Client:
Job/project:
Delivered:
Important terms:
Next step:
Locked by:`
  },
  {
    id: "private-note",
    title: "Private note",
    help: "Keep a private decision, reminder, or sensitive note in a tamper-evident file.",
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
    help: "Create a dated record of what happened, who was involved, and what evidence exists.",
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

function Help({ text }: { text: string }) {
  return (
    <span className="help" tabIndex={0} aria-label={text}>
      ?
      <span className="bubble">{text}</span>
    </span>
  );
}

export default function App() {
  const [plain, setPlain] = useState(defaultText);
  const [lockPhrase, setLockPhrase] = useState("demo-passphrase-change-me");
  const [openPhrase, setOpenPhrase] = useState("demo-passphrase-change-me");
  const [vaultText, setVaultText] = useState("");
  const [status, setStatus] = useState<Status>({ kind: "idle", text: "Ready." });
  const [decrypted, setDecrypted] = useState("");
  const [dragging, setDragging] = useState(false);

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
        password: lockPhrase,
        preset: "quick",
        mode: "self"
      });
      const text = JSON.stringify(created, null, 2);
      setVaultText(text);
      setOpenPhrase(lockPhrase);
      setStatus({ kind: "ok", text: "Vault created. Download it, copy it, or open it to verify." });
    } catch (err) {
      setStatus({ kind: "bad", text: err instanceof Error ? err.message : String(err) });
    }
  }

  async function openVault() {
    setStatus({ kind: "idle", text: "Opening locally..." });
    setDecrypted("");
    try {
      if (!vaultText.trim()) throw new Error("Paste, drop, upload, or create a vault first.");
      const vault = JSON.parse(vaultText) as QevVault;
      const text = await decryptVaultV2({ vault, password: openPhrase });
      setDecrypted(text);
      setStatus({ kind: "ok", text: "Opened. Passphrase matched and the vault was not changed." });
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
      setStatus({ kind: "idle", text: `${file.name} loaded. Enter its opening passphrase.` });
    } catch (err) {
      setStatus({ kind: "bad", text: err instanceof Error ? err.message : String(err) });
    }
  }

  function dropVault(event: React.DragEvent<HTMLLabelElement>) {
    event.preventDefault();
    setDragging(false);
    const file = event.dataTransfer.files?.[0] ?? null;
    void loadVaultFile(file);
  }

  function tamperVault() {
    try {
      if (!vaultText.trim()) throw new Error("Create or load a vault first.");
      const vault = JSON.parse(vaultText) as QevVault;
      vault.content.ciphertext = vault.content.ciphertext.slice(0, -4) + "AAAA";
      setVaultText(JSON.stringify(vault, null, 2));
      setDecrypted("");
      setStatus({ kind: "bad", text: "One part of the vault was changed. Opening should now fail." });
    } catch (err) {
      setStatus({ kind: "bad", text: err instanceof Error ? err.message : String(err) });
    }
  }

  async function newPhrase() {
    try {
      const phrase = await generatePassphrase();
      setLockPhrase(phrase);
      setStatus({ kind: "idle", text: "New locking passphrase generated. Save it before downloading." });
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
        <p className="eyebrow">QEV local vault utility</p>
        <h1>Make a locked record. Verify it later.</h1>
        <p className="lead">
          Use this page to turn notes, AI outputs, handoffs, and logs into a downloadable
          <code>.vault</code> file. Nothing is uploaded. If the vault is edited later, it will not open.
        </p>
      </section>

      <section id="tool" className="tool">
        <div className="column write-column">
          <div className="section-title">
            <span>1</span>
            <h2>Create vault</h2>
          </div>

          <div className="templates" aria-label="Use case templates">
            {templates.map((template) => (
              <button key={template.id} onClick={() => useTemplate(template)}>
                {template.title}
                <Help text={template.help} />
              </button>
            ))}
          </div>

          <label htmlFor="plain">
            Record text
            <Help text="Write or paste the exact content you want locked into the vault file." />
          </label>
          <textarea
            id="plain"
            value={plain}
            onChange={(e) => setPlain(e.target.value)}
            spellCheck={false}
          />

          <label htmlFor="lockPhrase">
            Locking passphrase
            <Help text="This passphrase creates the vault. Save it. Without it, the vault cannot be opened." />
          </label>
          <div className="phrase-row">
            <input
              id="lockPhrase"
              value={lockPhrase}
              onChange={(e) => setLockPhrase(e.target.value)}
              spellCheck={false}
            />
            <button onClick={newPhrase}>Generate</button>
          </div>

          <div className="actions primary-actions">
            <button className="black" onClick={lockVault}>Lock</button>
            <button onClick={() => download(vaultName(), vaultText)} disabled={!vaultText}>Download</button>
          </div>
        </div>

        <div className="column open-column">
          <div className="section-title">
            <span>2</span>
            <h2>Open vault</h2>
          </div>

          <label
            htmlFor="file"
            className={`dropzone ${dragging ? "dragging" : ""}`}
            onDragOver={(event) => {
              event.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={dropVault}
          >
            <strong>Drop .vault file here</strong>
            <em>or click to choose a file</em>
            <input
              id="file"
              type="file"
              accept=".vault,application/json,.json,text/plain"
              onChange={(e) => loadVaultFile(e.target.files?.[0] ?? null)}
            />
          </label>

          <label htmlFor="openPhrase">
            Opening passphrase
            <Help text="Use the passphrase that was used when the vault was created. This can be different from the left side." />
          </label>
          <input
            id="openPhrase"
            value={openPhrase}
            onChange={(e) => setOpenPhrase(e.target.value)}
            spellCheck={false}
          />

          <label htmlFor="vault">
            Vault JSON
            <Help text="Paste vault JSON here, edit it for tamper testing, or load it by dropping a .vault file above." />
          </label>
          <textarea
            id="vault"
            className="vault-area"
            value={vaultText}
            onChange={(e) => setVaultText(e.target.value)}
            spellCheck={false}
            placeholder="Paste vault JSON here or drop a .vault file above."
          />

          <div className="actions">
            <button className="black" onClick={openVault}>Open</button>
            <button onClick={copyVault} disabled={!vaultText}>Copy JSON</button>
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
        <h2>Use it when the record matters</h2>
        <div className="use-grid">
          <article>
            <h3>AI work receipts <Help text="Useful for saving prompts, generated outputs, revisions, and decisions." /></h3>
            <p>Lock prompts, outputs, edits, and decisions into a file you can verify later.</p>
          </article>
          <article>
            <h3>Client handoffs <Help text="Useful for scope notes, delivered instructions, records, and approvals." /></h3>
            <p>Seal handoffs, instructions, scope notes, and records before sending or archiving.</p>
          </article>
          <article>
            <h3>Private records <Help text="Useful for private notes, incident timelines, and dated decision logs." /></h3>
            <p>Keep a private note, incident timeline, or decision log in a tamper-evident file.</p>
          </article>
        </div>
      </section>

      <section id="npm" className="cli">
        <h2>Command line</h2>
        <pre>npm i -g @bryan237l/qev-cli</pre>
        <p>Use the CLI when you want the same vault workflow outside the browser.</p>
      </section>

      <footer>
        Local browser workflow. No account. No upload. Keep your passphrase; no one can recover it for you.
      </footer>
    </main>
  );
}
