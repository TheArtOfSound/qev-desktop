// Prevents a console window from appearing on Windows release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! QEV — Qira Encryption Vault
//!
//! Cross-platform (macOS + Windows) Tauri launcher for the browser
//! vault HTML. All cryptography runs in the WebView; this file is a
//! small host that provides three native bridges:
//!
//!   save_vault_file(filename, text)  — native save dialog, write UTF-8
//!   copy_to_clipboard(text)          — native clipboard write
//!   pick_vault_file()                — native open dialog, return text
//!
//! There is NO network code here, NO persistence beyond the user's
//! explicit Save action, and NO cryptography. The Rust side never
//! sees the user's phrase or plaintext. The only bytes that cross
//! the IPC boundary are the already-encrypted vault bytes on save
//! and the still-encrypted vault bytes on open.
//!
//! The identical ui/ assets (index.html, app.js, chat.js, sodium.js,
//! styles.css) are bundled verbatim from landing/chat/ via the Swift
//! version's working copy.

use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tauri::Manager;
use tauri_plugin_clipboard_manager::ClipboardExt;
use tauri_plugin_dialog::{DialogExt, FilePath};
use tokio::sync::oneshot;

// ------------ Command payloads ------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SavePayload {
    /// Suggested default filename, e.g. "vault-2026-04-15.vault.json".
    /// The user can override via the save dialog.
    filename: String,
    /// UTF-8 content to write to the chosen path. For QEV this is
    /// always JSON or plain text — never base64, never binary.
    text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SaveResult {
    /// True if the user picked a path and the file was written.
    saved: bool,
    /// Absolute path of the written file, or None if cancelled.
    path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OpenResult {
    /// True if the user picked a file and it was read successfully.
    loaded: bool,
    /// UTF-8 contents of the selected file, or None if cancelled.
    text: Option<String>,
    /// Original filename for display in the UI.
    filename: Option<String>,
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
    // Platform-specific ~/Downloads resolution. Falls back to the
    // user's home directory if Downloads doesn't exist.
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

// ------------ Entry point ------------

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .invoke_handler(tauri::generate_handler![
            save_vault_file,
            copy_to_clipboard,
            pick_vault_file,
        ])
        .setup(|app| {
            if let Some(win) = app.get_webview_window("main") {
                let _ = win.show();
                let _ = win.set_focus();
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running QEV");
}
