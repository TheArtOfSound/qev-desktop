// QEV — Qira Encryption Vault
//
// Shared entry point for desktop (Mac, Windows) AND mobile (Android,
// iOS when added). This used to be main.rs, but Tauri v2 Android
// builds require the app crate to be a library so it can link into
// the Android Gradle project as a cdylib/staticlib.
//
// main.rs is now a one-line binary shim that calls into `run()` here,
// and the Android build invokes `run_mobile()` via `#[tauri::mobile_entry_point]`.
//
// The same three native bridges are exposed on every platform:
//
//   save_vault_file(filename, text)  — native save dialog, write UTF-8
//   copy_to_clipboard(text)          — native clipboard write
//   pick_vault_file()                — native open dialog, return text
//
// There is NO network code here, NO persistence beyond the user's
// explicit Save action, and NO cryptography. The Rust side never
// sees the user's phrase or plaintext. The only bytes that cross the
// IPC boundary are the already-encrypted vault bytes on save and the
// still-encrypted vault bytes on open.

use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tauri::{Emitter, Manager};
use tauri_plugin_clipboard_manager::ClipboardExt;
use tauri_plugin_dialog::{DialogExt, FilePath};
use tokio::sync::oneshot;

// Phase 2: device pairing + P2P vault transfer.
// The pairing crate owns the crypto; this file just wires it into
// Tauri commands so the UI can drive the flow.
use qev_pairing::{
    chat_store::{chat_store_path, new_message_id, now_ms, ChatMessage, ChatStore},
    invite::PairingInvite,
    peer_store::{store_path, PeerStore, StoredPeer, TrustLevel},
    safety_number,
    ChannelExt, Initiator, QevMessage, Responder, StaticKeypair,
};

// Phase 3: federated relay for offline delivery.
use qev_relay::RelayClient;

mod relay_defaults;
use std::net::SocketAddr;
use std::path::PathBuf as StdPathBuf;
use std::sync::Mutex;
use tokio::net::{TcpListener, TcpStream};

// ------------ Phase 2: peer store state ------------
//
// The persistent peer store lives at
// <app_data_dir>/peers.json. We keep it in Tauri's managed state
// behind a Mutex so the four pairing commands can read + write
// without stepping on each other. All writes flush to disk
// immediately so the store survives a crash.

struct PeerStoreState {
    /// Absolute path to peers.json.
    path: StdPathBuf,
    /// In-memory copy of the store. Mutex-guarded.
    store: Mutex<PeerStore>,
}

impl PeerStoreState {
    fn new(path: StdPathBuf) -> Result<Self, String> {
        let store = PeerStore::load_or_empty(&path).map_err(|e| e.to_string())?;
        Ok(Self {
            path,
            store: Mutex::new(store),
        })
    }

    /// Run a closure with a mutable reference to the store, then
    /// persist to disk. Use this for any write.
    fn with_write<F, T>(&self, f: F) -> Result<T, String>
    where
        F: FnOnce(&mut PeerStore) -> Result<T, String>,
    {
        let result = {
            let mut guard = self
                .store
                .lock()
                .map_err(|e| format!("peer store mutex poisoned: {e}"))?;
            f(&mut guard)?
        };
        // Save with a fresh read of the store.
        let guard = self
            .store
            .lock()
            .map_err(|e| format!("peer store mutex poisoned: {e}"))?;
        guard.save(&self.path).map_err(|e| e.to_string())?;
        Ok(result)
    }

    /// Read-only snapshot of the store. Cheap because the store
    /// is small (< 100 KB even with hundreds of peers).
    fn snapshot(&self) -> Result<PeerStore, String> {
        let guard = self
            .store
            .lock()
            .map_err(|e| format!("peer store mutex poisoned: {e}"))?;
        Ok(guard.clone())
    }
}

/// Persistent chat history store. Wraps ChatStore with the same
/// pattern as PeerStoreState: Mutex-guarded, write-through to disk.
struct ChatStoreState {
    path: StdPathBuf,
    store: Mutex<ChatStore>,
}

impl ChatStoreState {
    fn new(path: StdPathBuf) -> Result<Self, String> {
        let store = ChatStore::load_or_empty(&path)?;
        Ok(Self {
            path,
            store: Mutex::new(store),
        })
    }

    fn with_write<F, T>(&self, f: F) -> Result<T, String>
    where
        F: FnOnce(&mut ChatStore) -> Result<T, String>,
    {
        let result = {
            let mut guard = self
                .store
                .lock()
                .map_err(|e| format!("chat store mutex poisoned: {e}"))?;
            f(&mut guard)?
        };
        let guard = self
            .store
            .lock()
            .map_err(|e| format!("chat store mutex poisoned: {e}"))?;
        guard.save(&self.path)?;
        Ok(result)
    }

    fn snapshot(&self) -> Result<ChatStore, String> {
        let guard = self
            .store
            .lock()
            .map_err(|e| format!("chat store mutex poisoned: {e}"))?;
        Ok(guard.clone())
    }
}

// ------------ Command payloads ------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavePayload {
    /// Suggested default filename, e.g. "vault-2026-04-15.vault.json".
    /// The user can override via the save dialog.
    pub filename: String,
    /// UTF-8 content to write to the chosen path. For QEV this is
    /// always JSON or plain text — never base64, never binary.
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveResult {
    /// True if the user picked a path and the file was written.
    pub saved: bool,
    /// Absolute path of the written file, or None if cancelled.
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenResult {
    /// True if the user picked a file and it was read successfully.
    pub loaded: bool,
    /// UTF-8 contents of the selected file, or None if cancelled.
    pub text: Option<String>,
    /// Original filename for display in the UI.
    pub filename: Option<String>,
}

// ------------ Commands ------------

/// Save a text payload to disk.
///
/// **Desktop (Mac/Windows):** Shows a native save dialog via the Tauri
/// dialog plugin, writes to the user-chosen path with `fs::write`.
///
/// **Mobile (Android/iOS):** The dialog plugin returns a content URI
/// that `fs::write` can't handle. Instead, we write to the app's
/// local data directory (which is always a real filesystem path), then
/// show a message dialog telling the user where the file was saved.
/// The user can then share the file from that location via the
/// system share sheet.
///
/// This split is the pragmatic fix for Android scoped storage. A
/// future version can use the Storage Access Framework via JNI for
/// a native-feeling save-to-Downloads flow.
#[tauri::command]
async fn save_vault_file(
    app: tauri::AppHandle,
    payload: SavePayload,
) -> Result<SaveResult, String> {
    // On mobile, skip the save dialog and write directly to the
    // app's data directory. This always works because Android
    // grants the app full access to its own data dir.
    #[cfg(mobile)]
    {
        let data_dir = app
            .path()
            .app_data_dir()
            .map_err(|e| format!("app_data_dir: {e}"))?;
        let vaults_dir = data_dir.join("saved-vaults");
        fs::create_dir_all(&vaults_dir)
            .map_err(|e| format!("mkdir saved-vaults: {e}"))?;
        let out_path = vaults_dir.join(&payload.filename);
        fs::write(&out_path, payload.text.as_bytes())
            .map_err(|e| format!("write failed: {e}"))?;

        // Show a dialog telling the user where the file was saved.
        let msg = format!(
            "Saved to:\n{}\n\nYou can share this file from your file manager.",
            out_path.display()
        );
        app.dialog()
            .message(msg)
            .title("Vault saved")
            .blocking_show();

        return Ok(SaveResult {
            saved: true,
            path: Some(out_path.to_string_lossy().into_owned()),
        });
    }

    // Desktop path: native save dialog.
    #[cfg(desktop)]
    {
        let ext = if payload.filename.to_lowercase().ends_with(".txt") {
            "txt"
        } else {
            "json"
        };

        let (tx, rx) = oneshot::channel::<Option<FilePath>>();

        let mut builder = app
            .dialog()
            .file()
            .set_title("Save vault file")
            .set_file_name(&payload.filename)
            .add_filter(
                if ext == "txt" { "Recovery sheet" } else { "Vault" },
                &[ext],
            );
        if let Some(dir) = dirs_downloads() {
            builder = builder.set_directory(dir);
        }

        builder.save_file(move |path: Option<FilePath>| {
            let _ = tx.send(path);
        });

        let selection = rx
            .await
            .map_err(|e| format!("save dialog channel closed: {e}"))?;

        let Some(file_path) = selection else {
            return Ok(SaveResult {
                saved: false,
                path: None,
            });
        };

        let path_buf: PathBuf = file_path
            .into_path()
            .map_err(|e| format!("invalid path: {e}"))?;

        fs::write(&path_buf, payload.text.as_bytes())
            .map_err(|e| format!("write failed: {e}"))?;

        Ok(SaveResult {
            saved: true,
            path: Some(path_buf.to_string_lossy().into_owned()),
        })
    }
}

/// Write a UTF-8 string to the system clipboard.
#[tauri::command]
async fn copy_to_clipboard(app: tauri::AppHandle, text: String) -> Result<(), String> {
    app.clipboard()
        .write_text(text)
        .map_err(|e| format!("clipboard write failed: {e}"))
}

/// Open a native file picker and return the UTF-8 contents of the
/// selected file. Used for the "Open a vault" flow.
///
/// On Android, `FilePath` may be a content URI. We try `into_path()`
/// first (works on desktop), and if that fails (Android content URI),
/// we try reading the raw path string as a content URI via a
/// fallback that constructs the path differently.
#[tauri::command]
async fn pick_vault_file(app: tauri::AppHandle) -> Result<OpenResult, String> {
    let (tx, rx) = oneshot::channel::<Option<FilePath>>();

    app.dialog()
        .file()
        .set_title("Open a vault")
        .add_filter("Vault", &["json", "vault", "txt"])
        .pick_file(move |path: Option<FilePath>| {
            let _ = tx.send(path);
        });

    let selection = rx
        .await
        .map_err(|e| format!("open dialog channel closed: {e}"))?;

    let Some(file_path) = selection else {
        return Ok(OpenResult {
            loaded: false,
            text: None,
            filename: None,
        });
    };

    // Try the standard path first (works on desktop).
    // If into_path() fails (Android content URI), try reading
    // from the FilePath's string representation directly.
    let (text, filename) = match file_path.clone().into_path() {
        Ok(path_buf) => {
            let bytes = fs::read(&path_buf).map_err(|e| format!("read failed: {e}"))?;
            let text = String::from_utf8(bytes)
                .map_err(|e| format!("file is not valid UTF-8: {e}"))?;
            let filename = path_buf
                .file_name()
                .and_then(|s| s.to_str())
                .map(String::from);
            (text, filename)
        }
        Err(_) => {
            // Android content URI fallback: the FilePath's Display
            // representation is the raw URI string. On Android,
            // Tauri's dialog plugin reads the file contents and
            // returns them via the response. Since we can't access
            // the content URI from Rust, prompt the user to paste
            // the vault content instead.
            //
            // For now, return an error suggesting paste. A proper
            // fix requires JNI ContentResolver access.
            return Err(
                "On Android, use the paste box in the 'Open a vault' tab instead of the file picker. \
                 Copy the vault JSON from your email/messenger and paste it into the text area."
                    .into(),
            );
        }
    };

    Ok(OpenResult {
        loaded: true,
        text: Some(text),
        filename,
    })
}

// ------------ Helpers ------------

fn dirs_downloads() -> Option<PathBuf> {
    // Platform-specific ~/Downloads resolution. On Android this is
    // irrelevant — the Storage Access Framework picks the directory —
    // so the fallback is fine. On macOS/Windows the env-var walk
    // below resolves to the real Downloads folder.
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        let dl = home.join("Downloads");
        if dl.is_dir() {
            return Some(dl);
        }
        return Some(home);
    }
    // Windows fallback
    if let Some(userprofile) = std::env::var_os("USERPROFILE").map(PathBuf::from) {
        let dl = userprofile.join("Downloads");
        if dl.is_dir() {
            return Some(dl);
        }
        return Some(userprofile);
    }
    None
}

// ------------ Phase 2: pairing commands ------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingQrResult {
    /// Base64url CBOR invite payload — what the UI renders as a QR.
    pub qr_text: String,
    /// SVG of the rendered QR, ready to drop into an <img src="data:...">.
    pub qr_svg: String,
    /// Hex of the listener's public static key, shown in the UI
    /// next to the QR so the user can double-check it.
    pub own_public_hex: String,
    /// TCP port the responder is listening on. Ephemeral; dies
    /// when the command returns.
    pub listen_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairedPeer {
    /// Hex of the peer's static public key. Used as a peer ID.
    pub id: String,
    /// The name the peer chose for themselves.
    pub peer_name: String,
    /// The device label the peer advertised.
    pub peer_device: String,
    /// The 30-digit safety number for in-person verification.
    pub safety_number: String,
    /// Addresses from the peer's invite (for future direct sends).
    pub peer_addrs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvitePreview {
    pub name: String,
    pub device: String,
    pub public_hex: String,
    pub addrs: Vec<String>,
    pub expires_at: String,
}

/// Start a pairing session as the RESPONDER (the device that shows
/// the QR code). Binds a random high port, loads-or-generates the
/// device's persistent static keypair, builds an invite, and waits
/// for an initiator to connect.
///
/// The responder's static key is PERSISTENT — once a device has
/// generated one, the same key appears in every invite this device
/// emits forever. That means a remote peer who has paired with us
/// before can recognise us by the public key hex alone.
///
/// Returns a [`PairingQrResult`] immediately (with the QR to display),
/// then continues to listen in the background. The UI receives the
/// completed pairing via a Tauri event `pairing://complete` when the
/// handshake finishes.
#[tauri::command]
async fn pairing_show_qr(
    app: tauri::AppHandle,
    state: tauri::State<'_, PeerStoreState>,
    name: String,
    device: String,
) -> Result<PairingQrResult, String> {
    // Ensure the device has a persistent identity, loading it if
    // present and generating one otherwise. The user-provided
    // name/device are applied to the freshly-generated identity
    // OR refreshed on the existing one (so renaming is allowed).
    let keypair = state.with_write(|s| {
        let kp = s.ensure_own_identity(&name, &device).map_err(|e| e.to_string())?;
        s.set_own_name(name.clone());
        s.set_own_device(device.clone());
        Ok(kp)
    })?;
    let own_pk_hex = keypair.public_hex();

    // Bind to :0 so the OS picks a free port.
    let listener = TcpListener::bind("0.0.0.0:0")
        .await
        .map_err(|e| format!("bind: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("local_addr: {e}"))?
        .port();

    // Enumerate the local non-loopback IPv4 addresses. For the
    // first cut we only advertise IPv4; IPv6 link-local is a
    // phase 2.x follow-up.
    let addrs = local_ipv4_addrs(port);
    if addrs.is_empty() {
        return Err("no non-loopback IPv4 addresses available — is this host on a network?".into());
    }

    let invite = PairingInvite::new(keypair.public, name, device, addrs.clone())
        .map_err(|e| e.to_string())?;
    let qr_text = invite.encode_qr().map_err(|e| e.to_string())?;
    let qr_svg = invite.render_qr_svg().map_err(|e| e.to_string())?;

    // Spawn the handshake task. It runs in the background; when
    // it completes it persists the new peer and emits a Tauri
    // event that the UI subscribes to.
    let handshake_key = keypair.clone();
    let app_for_task = app.clone();
    let spawn_name = invite.name.clone();
    let spawn_device = invite.device.clone();
    tokio::spawn(async move {
        let result = accept_one_pairing(listener, handshake_key, spawn_name, spawn_device).await;
        let event_payload = match result {
            Ok(peer) => {
                // Persist the new peer (or update the existing
                // record if we've seen this ID before).
                // Best-effort: if the disk write fails, the UI
                // still gets the success event via the
                // PairedPeer payload and the session-scoped
                // pairing is still usable.
                if let Some(store_state) = app_for_task.try_state::<PeerStoreState>() {
                    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
                    use base64::Engine;
                    // Convert the hex peer id back to bytes, then
                    // re-encode as base64url for the on-disk
                    // format (matches invite.static_pk encoding).
                    if let Ok(pk_bytes) = hex_to_32(&peer.id) {
                        let stored = StoredPeer {
                            id: peer.id.clone(),
                            name: peer.peer_name.clone(),
                            device: peer.peer_device.clone(),
                            static_pk: URL_SAFE_NO_PAD.encode(pk_bytes),
                            paired_at: iso_now(),
                            last_seen_at: iso_now(),
                            trust: TrustLevel::Unverified,
                            last_addrs: peer.peer_addrs.clone(),
                        };
                        let _ = store_state.with_write(|s| {
                            s.upsert_peer(stored);
                            Ok(())
                        });
                    }
                }
                serde_json::json!({ "status": "ok", "peer": peer })
            }
            Err(e) => serde_json::json!({ "status": "error", "error": format!("{e}") }),
        };
        let _ = app_for_task.emit("pairing://complete", event_payload);
    });

    Ok(PairingQrResult {
        qr_text,
        qr_svg,
        own_public_hex: own_pk_hex,
        listen_port: port,
    })
}

/// Scan a QR code payload (from the other device) and return a
/// preview that the UI can show BEFORE committing to the pairing.
/// The preview includes the peer's chosen name/device, public key
/// hex, advertised addresses, and expiry. The user can bail out
/// here if the preview looks wrong (expired, wrong name, etc.).
#[tauri::command]
async fn pairing_preview_invite(qr_text: String) -> Result<InvitePreview, String> {
    let invite = PairingInvite::decode_qr(&qr_text).map_err(|e| e.to_string())?;
    invite
        .check_expiry(std::time::SystemTime::now())
        .map_err(|e| e.to_string())?;
    let pk = invite.static_pk_array().map_err(|e| e.to_string())?;
    let public_hex = pk.iter().fold(String::with_capacity(64), |mut s, b| {
        s.push_str(&format!("{b:02x}"));
        s
    });
    Ok(InvitePreview {
        name: invite.name,
        device: invite.device,
        public_hex,
        addrs: invite.addrs,
        expires_at: invite.expires_at,
    })
}

/// Accept a scanned invite: use our persistent static key,
/// connect to the peer's listener, run the Noise XK handshake as
/// initiator, persist the peer, and return a [`PairedPeer`] with
/// the safety number.
///
/// The user is expected to compare the safety number out loud
/// with the peer and call [`pairing_verify_peer`] to upgrade the
/// trust level to `verified`.
#[tauri::command]
async fn pairing_accept_invite(
    state: tauri::State<'_, PeerStoreState>,
    qr_text: String,
    own_name: String,
    own_device: String,
) -> Result<PairedPeer, String> {
    let invite = PairingInvite::decode_qr(&qr_text).map_err(|e| e.to_string())?;
    invite
        .check_expiry(std::time::SystemTime::now())
        .map_err(|e| e.to_string())?;
    let peer_pk = invite.static_pk_array().map_err(|e| e.to_string())?;
    let addrs = invite.addrs_parsed().map_err(|e| e.to_string())?;

    // Load or generate OUR persistent identity. This is the
    // same key we'll use when acting as responder too, so the
    // peer recognises us across roles.
    let own = state.with_write(|s| {
        let kp = s.ensure_own_identity(&own_name, &own_device).map_err(|e| e.to_string())?;
        Ok(kp)
    })?;

    // Try each advertised address in order until one accepts.
    let mut last_err = None;
    let stream = 'connect: {
        for addr in &addrs {
            match TcpStream::connect(addr).await {
                Ok(s) => break 'connect Some(s),
                Err(e) => last_err = Some(format!("{addr}: {e}")),
            }
        }
        None
    };
    let stream = stream.ok_or_else(|| {
        format!(
            "could not connect to any advertised address: {}",
            last_err.unwrap_or_else(|| "no addrs".into())
        )
    })?;

    let initiator = Initiator::new(&own, peer_pk).map_err(|e| e.to_string())?;
    let mut channel = initiator.run(stream).await.map_err(|e| e.to_string())?;

    // Identity exchange: order mirrors the responder side.
    // Responder sends first, initiator reads first, then responds.
    let their_identity = channel.recv_msg().await.map_err(|e| format!("recv identity: {e}"))?;
    if !matches!(their_identity, QevMessage::Identity { .. }) {
        return Err(format!("expected Identity from responder, got {their_identity:?}"));
    }
    let our_identity = QevMessage::Identity {
        name: own_name.clone(),
        device: own_device.clone(),
    };
    channel.send_msg(&our_identity).await.map_err(|e| format!("send identity: {e}"))?;

    let sn = safety_number(&own.public, &peer_pk);
    let id = invite.static_pk.iter().fold(String::with_capacity(64), |mut s, b| {
        s.push_str(&format!("{b:02x}"));
        s
    });

    // Persist the new peer. upsert_peer preserves any
    // previously-set trust level on re-pair.
    let stored = StoredPeer {
        id: id.clone(),
        name: invite.name.clone(),
        device: invite.device.clone(),
        static_pk: {
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            use base64::Engine;
            URL_SAFE_NO_PAD.encode(invite.static_pk.as_slice())
        },
        paired_at: iso_now(),
        last_seen_at: iso_now(),
        trust: TrustLevel::Unverified,
        last_addrs: invite.addrs.clone(),
    };
    state.with_write(|s| {
        s.upsert_peer(stored);
        Ok(())
    })?;

    // Don't hold on to the channel — send_vault opens a fresh
    // one each time it's called. This keeps the command layer
    // stateless and avoids connection-lifetime issues.
    drop(channel);

    Ok(PairedPeer {
        id,
        peer_name: invite.name,
        peer_device: invite.device,
        safety_number: sn,
        peer_addrs: invite.addrs,
    })
}

/// List all persisted peers. Called by the UI to populate the
/// "Send to paired peer" picker on the Lock tab.
#[tauri::command]
async fn pairing_peers_list(
    state: tauri::State<'_, PeerStoreState>,
) -> Result<Vec<PairedPeerBrief>, String> {
    let snap = state.snapshot()?;
    Ok(snap
        .peers
        .into_iter()
        .map(|p| PairedPeerBrief {
            id: p.id,
            peer_name: p.name,
            peer_device: p.device,
            trust: match p.trust {
                TrustLevel::Verified => "verified".into(),
                TrustLevel::Unverified => "unverified".into(),
            },
            peer_addrs: p.last_addrs,
            last_seen_at: p.last_seen_at,
        })
        .collect())
}

/// Mark a peer as trust=verified. Called after the user confirms
/// the safety number in person.
#[tauri::command]
async fn pairing_verify_peer(
    state: tauri::State<'_, PeerStoreState>,
    peer_id: String,
) -> Result<(), String> {
    state.with_write(|s| {
        if !s.set_trust(&peer_id, TrustLevel::Verified) {
            return Err(format!("peer not found: {peer_id}"));
        }
        Ok(())
    })
}

/// Remove a peer from the store. One-way delete — no undo.
#[tauri::command]
async fn pairing_unpair(
    state: tauri::State<'_, PeerStoreState>,
    peer_id: String,
) -> Result<(), String> {
    state.with_write(|s| {
        if !s.remove(&peer_id) {
            return Err(format!("peer not found: {peer_id}"));
        }
        Ok(())
    })
}

/// Return our own static public key hex. Used by the UI to derive
/// the symmetric chat key: both devices hash sort(own_pk, peer_pk)
/// with the shared phrase, producing the same AEAD key on each side.
#[tauri::command]
async fn pairing_own_public_hex(
    state: tauri::State<'_, PeerStoreState>,
) -> Result<String, String> {
    let own = state.with_write(|s| {
        s.ensure_own_identity("", "").map_err(|e| e.to_string())
    })?;
    let mut s = String::with_capacity(64);
    for b in &own.public {
        s.push_str(&format!("{b:02x}"));
    }
    Ok(s)
}

/// Compute the safety number for a peer. Symmetric — both devices
/// see the same 30-digit string. Users compare out loud in person.
#[tauri::command]
async fn pairing_safety_number(
    state: tauri::State<'_, PeerStoreState>,
    peer_id: String,
) -> Result<String, String> {
    let own = state.with_write(|s| {
        s.ensure_own_identity("", "").map_err(|e| e.to_string())
    })?;
    let peer_pk: [u8; 32] = {
        let snap = state.snapshot()?;
        let peer = snap
            .find(&peer_id)
            .ok_or_else(|| format!("unknown peer: {peer_id}"))?
            .clone();
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let v = URL_SAFE_NO_PAD
            .decode(peer.static_pk.as_bytes())
            .map_err(|e| format!("bad peer static_pk: {e}"))?;
        v.as_slice().try_into().map_err(|_| "peer static_pk not 32 bytes".to_string())?
    };
    Ok(qev_pairing::safety_number(&own.public, &peer_pk))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairedPeerBrief {
    pub id: String,
    pub peer_name: String,
    pub peer_device: String,
    pub trust: String,
    pub peer_addrs: Vec<String>,
    pub last_seen_at: String,
}

fn iso_now() -> String {
    use time::format_description::well_known::Iso8601;
    use time::OffsetDateTime;
    let odt: OffsetDateTime = std::time::SystemTime::now().into();
    odt.format(&Iso8601::DEFAULT)
        .unwrap_or_else(|_| "1970-01-01T00:00:00.000000000Z".to_string())
}

/// Directly send a vault to a peer we've previously paired with.
/// Looks the peer up in the persistent store, opens a fresh TCP
/// connection to one of the known addresses, runs a fresh Noise
/// XK handshake with our persistent static identity, sends the
/// vault, closes.
#[tauri::command]
async fn pairing_send_vault(
    state: tauri::State<'_, PeerStoreState>,
    peer_id: String,
    vault_bytes: Vec<u8>,
    filename: String,
    note: Option<String>,
) -> Result<(), String> {
    // Look the peer up. Error if unknown — the UI should only
    // call this with peer_ids from pairing_peers_list.
    let (peer_pk, peer_addrs) = {
        let snap = state.snapshot()?;
        let peer = snap
            .find(&peer_id)
            .ok_or_else(|| format!("unknown peer: {peer_id}"))?
            .clone();
        // Convert the base64url public key back into bytes.
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let pk_bytes = URL_SAFE_NO_PAD
            .decode(peer.static_pk.as_bytes())
            .map_err(|e| format!("bad peer static_pk in store: {e}"))?;
        if pk_bytes.len() != 32 {
            return Err(format!(
                "peer static_pk wrong length: {}",
                pk_bytes.len()
            ));
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&pk_bytes);
        (pk, peer.last_addrs)
    };

    // Use our persistent identity rather than generating a fresh
    // one per send. This matters because the receiver may
    // recognise us by the static key from a previous pairing.
    let own = state.with_write(|s| {
        let kp = s.ensure_own_identity("", "").map_err(|e| e.to_string())?;
        Ok(kp)
    })?;

    let mut last_err = None;
    let stream = 'connect: {
        for a in &peer_addrs {
            let sa: SocketAddr = match a.parse() {
                Ok(s) => s,
                Err(e) => {
                    last_err = Some(format!("bad addr {a}: {e}"));
                    continue;
                }
            };
            match TcpStream::connect(sa).await {
                Ok(s) => break 'connect Some(s),
                Err(e) => last_err = Some(format!("{a}: {e}")),
            }
        }
        None
    };
    let stream = stream.ok_or_else(|| {
        format!(
            "could not reach any peer address: {}",
            last_err.unwrap_or_else(|| "no addrs".into())
        )
    })?;

    let initiator = Initiator::new(&own, peer_pk).map_err(|e| e.to_string())?;
    let mut channel = initiator.run(stream).await.map_err(|e| e.to_string())?;

    let msg = QevMessage::VaultTransfer {
        filename,
        vault_bytes,
        note,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0),
    };
    channel.send_msg(&msg).await.map_err(|e| e.to_string())?;
    Ok(())
}

// ------------ Pairing helpers ------------

/// Enumerate non-loopback IPv4 addresses on this host and pair
/// them with the given port. Used to build the `addrs` field of
/// a pairing invite.
fn local_ipv4_addrs(port: u16) -> Vec<SocketAddr> {
    use std::net::{IpAddr, Ipv4Addr};
    let mut out = Vec::new();
    // On a Mac/Linux dev host, `getifaddrs` is the cleanest way
    // to enumerate interfaces. For portability (including Android
    // where getifaddrs works but permissions may restrict), we
    // use the `netdev` strategy of trying common addresses.
    //
    // Simplest: bind a UDP socket to a reachable address and read
    // back the local endpoint. That reveals which interface the
    // OS picks for outbound traffic.
    if let Ok(s) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if s.connect("8.8.8.8:80").is_ok() {
            if let Ok(local) = s.local_addr() {
                if let IpAddr::V4(v4) = local.ip() {
                    if !v4.is_loopback() && !v4.is_unspecified() {
                        out.push(SocketAddr::new(IpAddr::V4(v4), port));
                    }
                }
            }
        }
    }
    // Fallback: if nothing resolved above, still give the UI SOMETHING
    // to show. 127.0.0.1 at least allows same-host pairing tests.
    if out.is_empty() {
        out.push(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            port,
        ));
    }
    out
}

/// Run a single Noise XK responder accept on the given listener
/// and return a [`PairedPeer`] record on success. After the
/// handshake the responder exchanges an Identity message with the
/// initiator so both sides learn each other's human-readable name.
async fn accept_one_pairing(
    listener: TcpListener,
    own: StaticKeypair,
    own_name: String,
    own_device: String,
) -> std::result::Result<PairedPeer, String> {
    let (stream, _remote) = listener
        .accept()
        .await
        .map_err(|e| format!("accept: {e}"))?;

    let responder = Responder::new(&own).map_err(|e| e.to_string())?;
    let mut channel = responder.run(stream).await.map_err(|e| e.to_string())?;

    // Send our identity over the Noise channel, then read theirs.
    // The relative send/recv order must mirror the initiator side.
    let our_identity = QevMessage::Identity {
        name: own_name.clone(),
        device: own_device.clone(),
    };
    channel.send_msg(&our_identity).await.map_err(|e| format!("send identity: {e}"))?;
    let their_identity = channel.recv_msg().await.map_err(|e| format!("recv identity: {e}"))?;
    let (peer_name, peer_device) = match their_identity {
        QevMessage::Identity { name, device } => (name, device),
        other => return Err(format!("expected Identity, got {other:?}")),
    };

    let peer_pk = channel.peer_static_pk();
    let sn = safety_number(&own.public, &peer_pk);
    let id = peer_pk.iter().fold(String::with_capacity(64), |mut s, b| {
        s.push_str(&format!("{b:02x}"));
        s
    });

    Ok(PairedPeer {
        id,
        peer_name,
        peer_device,
        safety_number: sn,
        peer_addrs: vec![],
    })
}

// ------------ Phase 3: relay commands ------------

/// Relay-send a vault to a paired peer through the default
/// relay at `secure.imagineqira.com:7892`. The vault bytes are
/// delivered to the peer's static public key inbox on the relay;
/// the peer picks them up on their next `relay_fetch_inbox` call.
///
/// This is an offline-delivery alternative to the direct P2P
/// `pairing_send_vault` for when the peer isn't on the same LAN.
#[tauri::command]
async fn relay_send_to_peer(
    state: tauri::State<'_, PeerStoreState>,
    peer_id: String,
    vault_bytes: Vec<u8>,
    filename: String,
    note: Option<String>,
) -> Result<String, String> {
    // Look up peer for their static_pk
    let (peer_pk, _peer_addrs) = {
        let snap = state.snapshot()?;
        let peer = snap
            .find(&peer_id)
            .ok_or_else(|| format!("unknown peer: {peer_id}"))?
            .clone();
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let pk_bytes = URL_SAFE_NO_PAD
            .decode(peer.static_pk.as_bytes())
            .map_err(|e| format!("bad peer static_pk: {e}"))?;
        if pk_bytes.len() != 32 {
            return Err(format!("peer static_pk wrong length: {}", pk_bytes.len()));
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&pk_bytes);
        (pk, peer.last_addrs)
    };

    // Load own identity for the relay handshake
    let own = state.with_write(|s| {
        s.ensure_own_identity("", "").map_err(|e| e.to_string())
    })?;

    // Build the relay client against the hardcoded default relay.
    // SocketAddr::parse() only accepts IP:PORT — resolve DNS first.
    let server_pk = relay_defaults::relay_server_public_key_bytes()?;
    let relay_addr = relay_defaults::relay_socket_addr().await?;

    let client = RelayClient::new(relay_addr, server_pk, own);

    // Build the envelope: wrap the vault transfer as the opaque
    // bytes the relay stores. For v1 the "envelope" is just the
    // raw vault JSON bytes plus a small JSON wrapper with filename
    // and note. The relay doesn't care what's inside — it's opaque.
    let vault_b64 = {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&vault_bytes)
    };
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let envelope_payload = serde_json::to_vec(&serde_json::json!({
        "type": "vault-transfer",
        "filename": filename,
        "note": note,
        "vault_bytes_b64": vault_b64,
        "timestamp": ts,
    }))
    .map_err(|e| format!("envelope encode: {e}"))?;

    let id = client
        .deliver(&peer_pk, envelope_payload)
        .await
        .map_err(|e| format!("relay deliver: {e}"))?;

    let id_hex = id.iter().fold(String::with_capacity(32), |mut s, b| {
        s.push_str(&format!("{b:02x}"));
        s
    });

    Ok(id_hex)
}

/// Fetch pending envelopes from the default relay addressed to
/// this device's own static public key. Returns a list of
/// envelope payloads; the UI should display them and let the
/// user enter the phrase to decrypt each one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayEnvelope {
    /// Hex envelope ID from the relay.
    pub id: String,
    /// Hex of the sender's static public key.
    pub from_hex: String,
    /// Raw envelope bytes (opaque JSON payload from the sender).
    pub payload: String,
    /// Unix ms timestamp when the relay received the envelope.
    pub created_at: u64,
}

#[tauri::command]
async fn relay_fetch_inbox(
    state: tauri::State<'_, PeerStoreState>,
) -> Result<Vec<RelayEnvelope>, String> {
    let own = state.with_write(|s| {
        s.ensure_own_identity("", "").map_err(|e| e.to_string())
    })?;

    let server_pk = relay_defaults::relay_server_public_key_bytes()?;
    let relay_addr = relay_defaults::relay_socket_addr().await?;

    let client = RelayClient::new(relay_addr, server_pk, own);
    let fetch = client.fetch(50).await.map_err(|e| format!("relay fetch: {e}"))?;

    let mut out = Vec::with_capacity(fetch.envelopes.len());
    for env in fetch.envelopes {
        let id_hex = env.id.iter().fold(String::with_capacity(32), |mut s, b| {
            s.push_str(&format!("{b:02x}"));
            s
        });
        let from_hex = env.from.iter().fold(String::with_capacity(64), |mut s, b| {
            s.push_str(&format!("{b:02x}"));
            s
        });
        out.push(RelayEnvelope {
            id: id_hex,
            from_hex,
            payload: String::from_utf8_lossy(&env.bytes).into_owned(),
            created_at: env.created_at,
        });
    }
    Ok(out)
}

/// Tell the relay to delete envelopes by their hex IDs. Call
/// this after the client has successfully received and decoded
/// the envelopes so the relay doesn't hold them forever.
#[tauri::command]
async fn relay_ack_envelopes(
    state: tauri::State<'_, PeerStoreState>,
    ids_hex: Vec<String>,
) -> Result<u32, String> {
    let own = state.with_write(|s| {
        s.ensure_own_identity("", "").map_err(|e| e.to_string())
    })?;

    let server_pk = relay_defaults::relay_server_public_key_bytes()?;
    let relay_addr = relay_defaults::relay_socket_addr().await?;

    let client = RelayClient::new(relay_addr, server_pk, own);

    let mut ids = Vec::with_capacity(ids_hex.len());
    for hex in &ids_hex {
        if hex.len() != 32 {
            return Err(format!("envelope id hex wrong length: {}", hex.len()));
        }
        let mut id = [0u8; 16];
        for i in 0..16 {
            id[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|e| format!("hex id byte {i}: {e}"))?;
        }
        ids.push(id);
    }

    let deleted = client.ack(&ids).await.map_err(|e| format!("relay ack: {e}"))?;
    Ok(deleted)
}

// ------------ Phase 4: per-message seal commands ------------

/// Seal a vault JSON string with an additional phrase. Returns
/// a JSON string that looks like `{"schema":"QEV-SEAL-V1",...}`.
/// The recipient needs BOTH the seal phrase AND the vault phrase
/// to read the message — two-factor protection.
#[tauri::command]
async fn seal_vault_cmd(
    inner_vault_json: String,
    seal_phrase: String,
) -> Result<String, String> {
    qev_pairing::seal_vault(&inner_vault_json, &seal_phrase)
        .await
        .map_err(|e| e.to_string())
}

/// Unseal a sealed vault JSON string using the seal phrase.
/// Returns the inner vault JSON (still phrase-locked with the
/// original vault phrase).
#[tauri::command]
async fn unseal_vault_cmd(
    sealed_json: String,
    seal_phrase: String,
) -> Result<String, String> {
    qev_pairing::unseal_vault(&sealed_json, &seal_phrase)
        .await
        .map_err(|e| e.to_string())
}

/// Check if a JSON string looks like a sealed vault. The UI
/// calls this to decide whether to show the "Enter seal phrase"
/// prompt before the normal vault-phrase prompt.
#[tauri::command]
async fn is_sealed_cmd(json_str: String) -> Result<bool, String> {
    Ok(qev_pairing::is_sealed(&json_str))
}

// ------------ Identity backup commands ------------
//
// These wrap the `qev_pairing::identity_backup` module for the
// UI. Export produces an encrypted blob the user saves externally
// (1Password, USB, email-to-self); import installs it onto a fresh
// machine. Without a backup, losing the Mac means losing the
// private key and needing to re-pair every peer.

/// Summary state the Diagnostics / Onboarding UI uses to decide
/// whether to show the "back up your identity" nudge.
#[derive(Debug, Clone, serde::Serialize)]
struct IdentityBackupStatus {
    /// True once the user has generated a QEV keypair. False on
    /// a truly fresh install with no peers yet.
    has_identity: bool,
    /// True when `last_backup_at` is None — the user has never
    /// exported their identity. This is the condition that drives
    /// the big at-risk banner.
    has_never_backed_up: bool,
    /// ISO 8601 of the most recent export, or empty string if none.
    last_backup_at: String,
    /// Number of paired peers — used in the banner copy to make
    /// the stakes tangible ("if you lose this Mac, you'll need to
    /// re-pair all 3 of your devices").
    peer_count: u32,
}

/// Return the current backup state so the UI can decide whether
/// to nudge the user.
///
/// This handler is declared SYNC (not `async`) because the work is
/// purely CPU — grab a std::sync::Mutex, read four fields, done.
/// Keeping it sync lets Tauri dispatch it on a worker thread via
/// its normal sync-command path instead of the async path, which
/// avoids a subtle deadlock: any other `async` command that holds
/// `PeerStoreState`'s std::sync::Mutex across an `.await` would
/// block ALL pending async commands, including this one. A sync
/// command can't hit that footgun.
#[tauri::command]
fn identity_backup_status(
    state: tauri::State<'_, PeerStoreState>,
) -> Result<IdentityBackupStatus, String> {
    let snap = state.snapshot()?;
    Ok(IdentityBackupStatus {
        has_identity: snap.own_identity.is_some(),
        has_never_backed_up: snap.last_backup_at.is_none(),
        last_backup_at: snap.last_backup_at.unwrap_or_default(),
        peer_count: snap.peers.len() as u32,
    })
}

/// Export the full identity (own keypair + paired-peer list) as
/// a passphrase-locked JSON blob. Returns the blob text so the UI
/// can hand it to `save_vault_file` with a suggested filename.
///
/// Updates `last_backup_at` on success so the at-risk banner can
/// stop nagging.
///
/// On macOS this triggers a Keychain-access prompt the first time
/// QEV tries to read its own secret (it's added itself to the ACL
/// during pairing, but some older installs or migrations may
/// require a re-approval). That prompt is benign.
#[tauri::command]
async fn export_identity_backup(
    state: tauri::State<'_, PeerStoreState>,
    passphrase: String,
) -> Result<String, String> {
    // Pull the current state.
    let snap = state.snapshot()?;
    let own = snap
        .own_identity
        .clone()
        .ok_or_else(|| "no identity yet — pair a device first".to_string())?;

    // Resolve the secret (from Keychain if needed) — this is the
    // only place where the raw private key touches memory outside
    // the handshake path.
    let own_with_secret = own.with_unwrapped_secret().map_err(|e| e.to_string())?;

    let envelope =
        qev_pairing::identity_backup::export_backup(own_with_secret, snap.peers, &passphrase)
            .map_err(|e| e.to_string())?;

    // Record that a backup exists.
    let now_iso = {
        use time::format_description::well_known::Iso8601;
        use time::OffsetDateTime;
        let odt: OffsetDateTime = std::time::SystemTime::now().into();
        odt.format(&Iso8601::DEFAULT)
            .unwrap_or_else(|_| "1970-01-01T00:00:00.000000000Z".to_string())
    };
    state.with_write(|s| {
        s.last_backup_at = Some(now_iso);
        Ok(())
    })?;

    Ok(envelope)
}

/// Result of an `import_identity_backup` call — the UI uses this
/// to show a confirmation banner ("Restored 3 peers from
/// 2026-04-15 backup").
#[derive(Debug, Clone, serde::Serialize)]
struct ImportIdentityBackupResult {
    /// 64-char hex of the restored own-public-key.
    own_public_hex: String,
    /// Display name from the restored identity.
    name: String,
    /// Device label from the restored identity.
    device: String,
    /// How many peers were installed (includes union with existing).
    peers_restored: u32,
    /// ISO 8601 from the backup's `created_at`.
    backup_created_at: String,
}

/// Import a passphrase-locked identity backup and install it onto
/// this machine's PeerStore.
///
/// WARNING: this REPLACES the local own-identity. Any keypair this
/// machine already generated is discarded — the user becomes the
/// identity encoded in the backup. Peers are unioned (existing
/// peers not in the backup are kept).
///
/// On macOS the restored secret is written into the Keychain via
/// the normal migration path, so subsequent launches behave
/// identically to a natively-paired install.
#[tauri::command]
async fn import_identity_backup(
    state: tauri::State<'_, PeerStoreState>,
    envelope_json: String,
    passphrase: String,
) -> Result<ImportIdentityBackupResult, String> {
    let payload = qev_pairing::identity_backup::import_backup(&envelope_json, &passphrase)
        .map_err(|e| e.to_string())?;

    let name = payload.own_identity.name.clone();
    let device = payload.own_identity.device.clone();
    let backup_created_at = payload.own_identity.created_at.clone();

    // Decode own-public-hex for the UI's confirmation blurb.
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let pub_bytes = URL_SAFE_NO_PAD
        .decode(payload.own_identity.public.as_bytes())
        .map_err(|e| format!("decode own_identity.public: {e}"))?;
    let own_public_hex = pub_bytes
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            s.push_str(&format!("{b:02x}"));
            s
        });

    // Install the payload into the live store.
    let peers_restored = state.with_write(|store| {
        let incoming_count = payload.peers.len() as u32;
        qev_pairing::identity_backup::apply_backup(store, payload);
        // Migrate the just-installed plaintext secret into the OS
        // keystore so subsequent launches don't need the file copy.
        if let Some(id) = store.own_identity.as_mut() {
            id.migrate_to_keystore();
        }
        Ok(incoming_count)
    })?;

    Ok(ImportIdentityBackupResult {
        own_public_hex,
        name,
        device,
        peers_restored,
        backup_created_at,
    })
}

// ------------ Chat commands ------------
//
// Messages are encrypted in the UI with a shared phrase and passed
// to the relay as opaque bytes. The Rust side never sees plaintext;
// it persists the encrypted envelope strings to chat-messages.json
// and ships them through relay_send_to_peer with a JSON envelope
// tagged "chat-v1" so the receiver knows how to route them.

#[tauri::command]
async fn chat_send(
    peer_state: tauri::State<'_, PeerStoreState>,
    chat_state: tauri::State<'_, ChatStoreState>,
    peer_id: String,
    text: String,
) -> Result<String, String> {
    let msg_id = new_message_id();
    let ts = now_ms();

    // 1. Store locally as "sending".
    let local = ChatMessage {
        id: msg_id.clone(),
        direction: "outgoing".into(),
        text: text.clone(),
        timestamp: ts,
        status: "sending".into(),
    };
    chat_state.with_write(|s| {
        s.add_message(&peer_id, local);
        Ok(())
    })?;

    // 2. Look up peer pk, build relay client, deliver.
    let peer_pk: [u8; 32] = {
        let snap = peer_state.snapshot()?;
        let peer = snap
            .find(&peer_id)
            .ok_or_else(|| format!("unknown peer: {peer_id}"))?
            .clone();
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let v = URL_SAFE_NO_PAD
            .decode(peer.static_pk.as_bytes())
            .map_err(|e| format!("bad peer static_pk: {e}"))?;
        v.as_slice().try_into().map_err(|_| "peer static_pk not 32 bytes".to_string())?
    };

    let own = peer_state.with_write(|s| {
        s.ensure_own_identity("", "").map_err(|e| e.to_string())
    })?;

    let server_pk = relay_defaults::relay_server_public_key_bytes()?;
    let relay_addr = relay_defaults::relay_socket_addr().await?;
    let client = RelayClient::new(relay_addr, server_pk, own);

    let envelope = serde_json::to_vec(&serde_json::json!({
        "type": "chat-v1",
        "msg_id": msg_id,
        "text": text,
        "timestamp": ts,
    }))
    .map_err(|e| format!("envelope encode: {e}"))?;

    let send_result = client.deliver(&peer_pk, envelope).await;

    // 3. Update status based on delivery outcome.
    let status = match &send_result {
        Ok(_) => "sent",
        Err(_) => "failed",
    };
    chat_state.with_write(|s| {
        s.update_status(&peer_id, &msg_id, status);
        Ok(())
    })?;

    send_result.map_err(|e| format!("relay deliver: {e}"))?;
    Ok(msg_id)
}

#[tauri::command]
async fn chat_get_history(
    chat_state: tauri::State<'_, ChatStoreState>,
    peer_id: String,
) -> Result<Vec<ChatMessage>, String> {
    let store = chat_state.snapshot()?;
    Ok(store.get_messages(&peer_id))
}

#[tauri::command]
async fn chat_mark_read(
    chat_state: tauri::State<'_, ChatStoreState>,
    peer_id: String,
) -> Result<(), String> {
    chat_state.with_write(|s| {
        s.mark_all_read(&peer_id);
        Ok(())
    })
}

#[tauri::command]
async fn chat_unread_counts(
    chat_state: tauri::State<'_, ChatStoreState>,
) -> Result<std::collections::HashMap<String, usize>, String> {
    let store = chat_state.snapshot()?;
    let mut out = std::collections::HashMap::new();
    for peer_id in store.conversations.keys() {
        out.insert(peer_id.clone(), store.unread_count(peer_id));
    }
    Ok(out)
}

/// Fetch pending chat-v1 envelopes from the relay, decode, append
/// to history, ack to the relay. Returns the count of new messages.
#[tauri::command]
async fn chat_fetch_relay_messages(
    peer_state: tauri::State<'_, PeerStoreState>,
    chat_state: tauri::State<'_, ChatStoreState>,
) -> Result<u32, String> {
    let own = peer_state.with_write(|s| {
        s.ensure_own_identity("", "").map_err(|e| e.to_string())
    })?;
    let server_pk = relay_defaults::relay_server_public_key_bytes()?;
    let relay_addr = relay_defaults::relay_socket_addr().await?;
    let client = RelayClient::new(relay_addr, server_pk, own);
    let fetch = client.fetch(50).await.map_err(|e| format!("relay fetch: {e}"))?;

    let mut chat_ids_to_ack: Vec<[u8; 16]> = Vec::new();
    let mut new_count: u32 = 0;

    for env in fetch.envelopes {
        // Attempt to parse as a chat-v1 envelope. Any other type is
        // left in the inbox for a different handler (e.g. vault-transfer).
        let payload_str = String::from_utf8_lossy(&env.bytes);
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&payload_str) else {
            continue;
        };
        if v.get("type").and_then(|t| t.as_str()) != Some("chat-v1") {
            continue;
        }
        let text = v.get("text").and_then(|t| t.as_str()).unwrap_or("").to_string();
        let msg_id = v
            .get("msg_id")
            .and_then(|t| t.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(new_message_id);
        let timestamp = v.get("timestamp").and_then(|t| t.as_u64()).unwrap_or_else(now_ms);

        let from_hex = env.from.iter().fold(String::with_capacity(64), |mut s, b| {
            s.push_str(&format!("{b:02x}"));
            s
        });

        chat_state.with_write(|s| {
            s.add_message(
                &from_hex,
                ChatMessage {
                    id: msg_id,
                    direction: "incoming".into(),
                    text,
                    timestamp,
                    status: "delivered".into(),
                },
            );
            Ok(())
        })?;
        chat_ids_to_ack.push(env.id);
        new_count += 1;
    }

    if !chat_ids_to_ack.is_empty() {
        let _ = client.ack(&chat_ids_to_ack).await;
    }

    Ok(new_count)
}

fn hex_to_32(hex: &str) -> std::result::Result<[u8; 32], String> {
    if hex.len() != 64 {
        return Err(format!("public_hex wrong length: {} (expected 64)", hex.len()));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("hex byte {i}: {e}"))?;
    }
    Ok(out)
}

// ------------ Entry point ------------

/// Desktop + mobile shared run function. `main.rs` calls this for
/// Mac/Windows builds; Android's Gradle project calls `run_mobile()`
/// below (which is just `run()` wrapped in the mobile_entry_point
/// attribute).
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .invoke_handler(tauri::generate_handler![
            save_vault_file,
            copy_to_clipboard,
            pick_vault_file,
            pairing_show_qr,
            pairing_preview_invite,
            pairing_accept_invite,
            pairing_send_vault,
            pairing_peers_list,
            pairing_verify_peer,
            pairing_unpair,
            pairing_own_public_hex,
            pairing_safety_number,
            relay_send_to_peer,
            relay_fetch_inbox,
            relay_ack_envelopes,
            seal_vault_cmd,
            unseal_vault_cmd,
            is_sealed_cmd,
            identity_backup_status,
            export_identity_backup,
            import_identity_backup,
            chat_send,
            chat_get_history,
            chat_mark_read,
            chat_unread_counts,
            chat_fetch_relay_messages,
        ])
        .setup(|app| {
            #[cfg(desktop)]
            if let Some(win) = app.get_webview_window("main") {
                let _ = win.show();
                let _ = win.set_focus();
            }

            // Initialize the peer store at the canonical location
            // under app_data_dir. On first launch the store is
            // empty; on subsequent launches it loads the
            // persisted keypair + peers.
            let data_dir = app
                .path()
                .app_data_dir()
                .map_err(|e| format!("app_data_dir: {e}"))?;
            let path = store_path(&data_dir);
            let state = PeerStoreState::new(path)
                .map_err(|e| format!("peer store init: {e}"))?;
            app.manage(state);

            // Chat store sits alongside the peer store.
            let chat_path = chat_store_path(&data_dir);
            let chat_state = ChatStoreState::new(chat_path)
                .map_err(|e| format!("chat store init: {e}"))?;
            app.manage(chat_state);

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running QEV");
}
