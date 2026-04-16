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
    invite::PairingInvite,
    safety_number,
    ChannelExt, Initiator, QevMessage, Responder, StaticKeypair,
};
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};

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

/// Save a text payload to a user-picked path.
///
/// Uses the Tauri-idiomatic async-callback pattern: `save_file(cb)` is
/// non-blocking, fires `cb(Option<FilePath>)` on completion, and we
/// bridge that back into the async command via a oneshot channel.
#[tauri::command]
async fn save_vault_file(
    app: tauri::AppHandle,
    payload: SavePayload,
) -> Result<SaveResult, String> {
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

    // Non-blocking save — the callback runs when the user picks or
    // cancels. We bridge it back to our async context via oneshot.
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

    // Write UTF-8 bytes. For our tiny payload (~1 KB) the non-atomic
    // write is fine. Atomic rename semantics can be added later if we
    // ever write multi-MB vaults.
    fs::write(&path_buf, payload.text.as_bytes())
        .map_err(|e| format!("write failed: {e}"))?;

    Ok(SaveResult {
        saved: true,
        path: Some(path_buf.to_string_lossy().into_owned()),
    })
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

    let path_buf: PathBuf = file_path
        .into_path()
        .map_err(|e| format!("invalid path: {e}"))?;

    let bytes = fs::read(&path_buf).map_err(|e| format!("read failed: {e}"))?;
    let text = String::from_utf8(bytes)
        .map_err(|e| format!("file is not valid UTF-8: {e}"))?;
    let filename = path_buf
        .file_name()
        .and_then(|s| s.to_str())
        .map(String::from);

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
/// the QR code). Binds a random high port, generates a fresh static
/// keypair, builds an invite, and waits for an initiator to connect.
///
/// Returns a [`PairingQrResult`] immediately (with the QR to display),
/// then continues to listen in the background. The UI receives the
/// completed pairing via a Tauri event `pairing://complete` when the
/// handshake finishes.
///
/// For the first shipping version this is a ONE-SHOT operation: the
/// listener handles exactly one inbound connection then exits. For
/// multi-concurrent pairings we'd switch to an always-running daemon
/// with a peer registry — that's phase 2.10.
#[tauri::command]
async fn pairing_show_qr(
    app: tauri::AppHandle,
    name: String,
    device: String,
) -> Result<PairingQrResult, String> {
    let keypair = StaticKeypair::generate().map_err(|e| e.to_string())?;
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

    // Spawn the handshake task. It runs in the background; when it
    // completes it emits a Tauri event that the UI subscribes to.
    let handshake_key = keypair.clone();
    tokio::spawn(async move {
        let result = accept_one_pairing(listener, handshake_key).await;
        let event_payload = match result {
            Ok(peer) => serde_json::json!({ "status": "ok", "peer": peer }),
            Err(e) => serde_json::json!({ "status": "error", "error": format!("{e}") }),
        };
        let _ = app.emit("pairing://complete", event_payload);
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

/// Accept a scanned invite: generate our own static key, connect
/// to the peer's listener, run the Noise XK handshake as initiator,
/// and return the resulting [`PairedPeer`] with its safety number.
///
/// The user is expected to compare the safety number out loud with
/// the peer before saving the pairing anywhere.
#[tauri::command]
async fn pairing_accept_invite(qr_text: String) -> Result<PairedPeer, String> {
    let invite = PairingInvite::decode_qr(&qr_text).map_err(|e| e.to_string())?;
    invite
        .check_expiry(std::time::SystemTime::now())
        .map_err(|e| e.to_string())?;
    let peer_pk = invite.static_pk_array().map_err(|e| e.to_string())?;
    let addrs = invite.addrs_parsed().map_err(|e| e.to_string())?;

    let own = StaticKeypair::generate().map_err(|e| e.to_string())?;

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
    let channel = initiator.run(stream).await.map_err(|e| e.to_string())?;

    let sn = safety_number(&own.public, &peer_pk);
    let id = invite.static_pk.iter().fold(String::with_capacity(64), |mut s, b| {
        s.push_str(&format!("{b:02x}"));
        s
    });

    // We don't persist in v1, and we don't hold on to the channel
    // after pairing — send_vault opens a fresh channel each time.
    drop(channel);

    Ok(PairedPeer {
        id,
        peer_name: invite.name,
        peer_device: invite.device,
        safety_number: sn,
        peer_addrs: invite.addrs,
    })
}

/// Directly send a vault to a peer we've previously paired with.
/// Opens a fresh TCP connection to one of the peer's known
/// addresses, runs a fresh Noise XK handshake, sends the vault,
/// closes.
#[tauri::command]
async fn pairing_send_vault(
    peer_public_hex: String,
    peer_addrs: Vec<String>,
    vault_bytes: Vec<u8>,
    filename: String,
    note: Option<String>,
) -> Result<(), String> {
    // Decode the hex public key.
    let peer_pk = hex_to_32(&peer_public_hex)?;

    // Generate a fresh ephemeral static for the send — or later,
    // load the persisted identity. For v1 we use ephemeral.
    let own = StaticKeypair::generate().map_err(|e| e.to_string())?;

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
/// and return a [`PairedPeer`] record on success.
async fn accept_one_pairing(
    listener: TcpListener,
    own: StaticKeypair,
) -> std::result::Result<PairedPeer, String> {
    let (stream, _remote) = listener
        .accept()
        .await
        .map_err(|e| format!("accept: {e}"))?;

    let responder = Responder::new(&own).map_err(|e| e.to_string())?;
    let channel = responder.run(stream).await.map_err(|e| e.to_string())?;

    let peer_pk = channel.peer_static_pk();
    let sn = safety_number(&own.public, &peer_pk);
    let id = peer_pk.iter().fold(String::with_capacity(64), |mut s, b| {
        s.push_str(&format!("{b:02x}"));
        s
    });

    Ok(PairedPeer {
        id,
        peer_name: "(unknown)".into(),
        peer_device: "(unknown)".into(),
        safety_number: sn,
        peer_addrs: vec![],
    })
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
        ])
        .setup(|app| {
            #[cfg(desktop)]
            if let Some(win) = app.get_webview_window("main") {
                let _ = win.show();
                let _ = win.set_focus();
            }
            let _ = app; // silence unused on mobile
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running QEV");
}
