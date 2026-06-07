import { useEffect, useState } from "react";
import type { DragEvent } from "react";
import {
  QevVault,
  decryptVaultV2,
  encryptVaultV2,
  generatePassphrase
} from "./qev";

type Status = { kind: "idle" | "ok" | "bad"; text: string };
type Page = "start" | "tool" | "uses" | "cli" | "security";

type Template = {
  id: string;
  title: string;
  help: string;
  text: string;
};

const pages: { id: Page; label: string }[] = [
  { id: "start", label: "Start" },
  { id: "tool", label: "Tool" },
  { id: "uses", label: "Use cases" },
  { id: "cli", label: "CLI" },
  { id: "security", label: "Security" }
];

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

function getPageFromHash(): Page {
  const raw = window.location.hash.replace(/^#\/?/, "");
  return pages.some((page) => page.id === raw) ? (raw as Page) : "start";
}

function go(page: Page) {
  window.location.hash = `/${page}`;
}

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

function StartPage() {
  return (
    <section className="page start-page">
      <p className="eyebrow">QEV local vault utility</p>
      <h1>Write it. Lock it. Prove it later.</h1>
      <p className="lead">
        Proof Lock turns a text record into a downloadable <code>.vault</code> file.
        Keep the passphrase. If someone edits the vault, it will not open.
      </p>

      <div className="quick-strip" aria-label="Quick walkthrough">
        <div><b>1</b><span>Write or paste a record.</span></div>
        <div><b>2</b><span>Lock it with a passphrase.</span></div>
        <div><b>3</b><span>Download the vault.</span></div>
        <div><b>4</b><span>Drop it back in to verify.</span></div>
      </div>

      <div className="start-actions">
        <button className="black" onClick={() => go("tool")}>Open the tool</button>
        <button onClick={() => go("uses")}>See use cases</button>
      </div>

      <div className="walkthrough">
        <h2>Understand it in 10 seconds</h2>
        <div className="walk-grid">
          <article>
            <h3>The vault is the proof file.</h3>
            <p>It contains encrypted text plus authenticated metadata.</p>
          </article>
          <article>
            <h3>The passphrase is the key.</h3>
            <p>Save it somewhere safe. There is no recovery button.</p>
          </article>
          <article>
            <h3>Verification is the test.</h3>
            <p>If the vault or password is wrong, opening fails.</p>
          </article>
        </div>
      </div>
    </section>
  );
}

function UsesPage() {
  const normalUses = [
    ["AI receipts", "Save prompts, outputs, edits, and final decisions before sharing or publishing."],
    ["Client or work handoffs", "Lock scope notes, delivered instructions, job summaries, or approval records."],
    ["Repair records", "Save what a mechanic, contractor, or support person said and when they said it."],
    ["Private agreements", "Keep a dated text record of a roommate, family, or small business agreement."],
    ["Incident timelines", "Write what happened, who was involved, and what action was taken."],
    ["Personal notes", "Store sensitive notes in a file that detects edits later."],
    ["School or research notes", "Lock citations, drafts, observations, or study notes after a session."],
    ["Pet, home, or vehicle logs", "Keep dated plain-text records for everyday things that still matter."],
    ["Before/after summaries", "Write a short record of condition, work done, and next steps."],
  ];

  return (
    <section className="page">
      <p className="eyebrow">Use cases</p>
      <h1>For records that need to stay honest.</h1>
      <p className="lead">Proof Lock is not just for developers. It is for any text record you may need to trust later.</p>

      <div className="use-list">
        {normalUses.map(([title, body]) => (
          <article key={title}>
            <h3>{title}</h3>
            <p>{body}</p>
          </article>
        ))}
      </div>

      <div className="note-box">
        <b>Best fit:</b> notes, logs, receipts, AI outputs, decisions, instructions, and handoffs.
        <br />
        <b>Not a fit:</b> password recovery, legal notarization, cloud backup, or large file storage.
      </div>
    </section>
  );
}

function CliPage() {
  return (
    <section className="page cli-page">
      <p className="eyebrow">Command line</p>
      <h1>Use QEV from terminal.</h1>
      <p className="lead">The browser tool is for quick vaults. The CLI is for repeatable local workflows.</p>
      <pre>npm i -g @bryan237l/qev-cli</pre>
      <div className="terminal-grid">
        <article>
          <h3>Check install</h3>
          <pre>qev self-test</pre>
        </article>
        <article>
          <h3>Create vault</h3>
          <pre>{`echo "important record" | qev lock --out proof.vault`}</pre>
        </article>
        <article>
          <h3>Open vault</h3>
          <pre>qev unlock proof.vault</pre>
        </article>
      </div>
    </section>
  );
}

function SecurityPage() {
  return (
    <section className="page security-page">
      <p className="eyebrow">Security model</p>
      <h1>Local first. Passphrase required. No account.</h1>
      <div className="rule-list">
        <article>
          <h3>No upload</h3>
          <p>The browser workflow runs locally. The vault text is processed in your browser.</p>
        </article>
        <article>
          <h3>No recovery</h3>
          <p>If the passphrase is lost, the vault cannot be opened from this page.</p>
        </article>
        <article>
          <h3>Tamper detection</h3>
          <p>If encrypted content or protected metadata is changed, opening fails.</p>
        </article>
        <article>
          <h3>Use a trusted device</h3>
          <p>This does not protect you from malware, screenshots, keyloggers, or weak passphrases.</p>
        </article>
      </div>
    </section>
  );
}

function ToolPage() {
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

  function dropVault(event: DragEvent<HTMLLabelElement>) {
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
    <section className="page tool-page">
      <div className="tool-head">
        <div>
          <p className="eyebrow">Tool</p>
          <h1>Create or open a vault.</h1>
        </div>
        <div className="mini-how">
          <span>Write</span><span>Lock</span><span>Download</span><span>Open</span>
        </div>
      </div>

      <section className="tool">
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

          <label htmlFor="plain">Record text <Help text="Write or paste the exact content you want locked into the vault file." /></label>
          <textarea id="plain" value={plain} onChange={(e) => setPlain(e.target.value)} spellCheck={false} />

          <label htmlFor="lockPhrase">Locking passphrase <Help text="This passphrase creates the vault. Save it. Without it, the vault cannot be opened." /></label>
          <div className="phrase-row">
            <input id="lockPhrase" value={lockPhrase} onChange={(e) => setLockPhrase(e.target.value)} spellCheck={false} />
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
            onDragOver={(event) => { event.preventDefault(); setDragging(true); }}
            onDragLeave={() => setDragging(false)}
            onDrop={dropVault}
          >
            <strong>Drop .vault file here</strong>
            <em>or click to choose a file</em>
            <input id="file" type="file" accept=".vault,application/json,.json,text/plain" onChange={(e) => loadVaultFile(e.target.files?.[0] ?? null)} />
          </label>

          <label htmlFor="openPhrase">Opening passphrase <Help text="Use the passphrase that was used when the vault was created." /></label>
          <input id="openPhrase" value={openPhrase} onChange={(e) => setOpenPhrase(e.target.value)} spellCheck={false} />

          <label htmlFor="vault">Vault JSON <Help text="Paste vault JSON here, edit it for tamper testing, or load it by dropping a .vault file above." /></label>
          <textarea id="vault" className="vault-area" value={vaultText} onChange={(e) => setVaultText(e.target.value)} spellCheck={false} placeholder="Paste vault JSON here or drop a .vault file above." />

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
    </section>
  );
}

export default function App() {
  const [page, setPage] = useState<Page>(getPageFromHash);

  useEffect(() => {
    const onHash = () => setPage(getPageFromHash());
    window.addEventListener("hashchange", onHash);
    if (!window.location.hash) window.location.hash = "/start";
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  return (
    <main>
      <nav className="topbar">
        <a className="brand" href="#/start">Proof Lock</a>
        <div className="top-links">
          <a href="#/tool">Open Tool</a>
          <a href="https://github.com/TheArtOfSound/qev-desktop">GitHub</a>
        </div>
      </nav>

      <div className="docs-layout">
        <aside className="sidebar">
          <div className="side-label">Docs</div>
          {pages.map((item) => (
            <a key={item.id} className={page === item.id ? "active" : ""} href={`#/${item.id}`}>{item.label}</a>
          ))}
        </aside>

        <div className="content">
          {page === "start" && <StartPage />}
          {page === "tool" && <ToolPage />}
          {page === "uses" && <UsesPage />}
          {page === "cli" && <CliPage />}
          {page === "security" && <SecurityPage />}
        </div>
      </div>

      <footer>
        Local browser workflow. No account. No upload. Keep your passphrase; no one can recover it for you.
      </footer>
    </main>
  );
}
