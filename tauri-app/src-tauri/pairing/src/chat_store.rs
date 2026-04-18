//! Chat message store — persistent per-peer conversation history.
//!
//! Each paired peer has a conversation thread. Messages are stored
//! in a single JSON file at `<app_data>/chat-messages.json`. The
//! file is loaded into memory on app startup and written back on
//! every new message (atomic write with rename).
//!
//! ## Message lifecycle
//!
//! 1. User types a message in the Chat tab and hits Send
//! 2. The message is stored locally as `status: "sending"`
//! 3. Delivery is attempted (direct P2P first, relay fallback)
//! 4. On success: status → "sent"
//! 5. On receive: stored as `direction: "incoming"`, status = "delivered"
//! 6. User taps the message in the thread → reads it
//!
//! ## Schema
//!
//! ```json
//! {
//!   "schema": "QEV-CHAT-V1",
//!   "conversations": {
//!     "<peer_id_hex>": [
//!       {
//!         "id": "<uuid>",
//!         "direction": "outgoing" | "incoming",
//!         "text": "the plaintext message",
//!         "timestamp": 1717171717000,
//!         "status": "sending" | "sent" | "delivered" | "read" | "failed"
//!       },
//!       ...
//!     ]
//!   }
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Current schema tag.
pub const CHAT_SCHEMA: &str = "QEV-CHAT-V1";

/// Maximum messages to keep per conversation before trimming
/// the oldest. Prevents unbounded file growth.
pub const MAX_MESSAGES_PER_PEER: usize = 500;

/// A single chat message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatMessage {
    /// Unique message ID (UUID v4 hex, 32 chars).
    pub id: String,
    /// "outgoing" (we sent it) or "incoming" (we received it).
    pub direction: String,
    /// Plaintext message content.
    pub text: String,
    /// Unix milliseconds when the message was created/received.
    pub timestamp: u64,
    /// Delivery status: "sending", "sent", "delivered", "read", "failed".
    pub status: String,
}

/// The full on-disk chat store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatStore {
    /// Schema tag.
    pub schema: String,
    /// Map from peer_id (hex) to ordered list of messages (oldest first).
    pub conversations: HashMap<String, Vec<ChatMessage>>,
}

impl ChatStore {
    /// Empty store.
    pub fn empty() -> Self {
        Self {
            schema: CHAT_SCHEMA.to_string(),
            conversations: HashMap::new(),
        }
    }

    /// Load from disk, or return empty if the file doesn't exist.
    pub fn load_or_empty(path: &Path) -> Result<Self, String> {
        match fs::read(path) {
            Ok(bytes) => {
                let store: Self = serde_json::from_slice(&bytes)
                    .map_err(|e| format!("chat store decode: {e}"))?;
                if store.schema != CHAT_SCHEMA {
                    return Err(format!(
                        "unsupported chat schema: {} (expected {})",
                        store.schema, CHAT_SCHEMA
                    ));
                }
                Ok(store)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::empty()),
            Err(e) => Err(format!("chat store read: {e}")),
        }
    }

    /// Persist to disk atomically.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("mkdir: {e}"))?;
        }
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| format!("chat store encode: {e}"))?;
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, &json).map_err(|e| format!("write: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
        }
        fs::rename(&tmp, path).map_err(|e| format!("rename: {e}"))?;
        Ok(())
    }

    /// Add a message to a conversation. Trims to MAX_MESSAGES_PER_PEER.
    pub fn add_message(&mut self, peer_id: &str, msg: ChatMessage) {
        let convo = self
            .conversations
            .entry(peer_id.to_string())
            .or_insert_with(Vec::new);
        convo.push(msg);
        // Trim oldest if over cap
        while convo.len() > MAX_MESSAGES_PER_PEER {
            convo.remove(0);
        }
    }

    /// Get messages for a peer, newest last.
    pub fn get_messages(&self, peer_id: &str) -> Vec<ChatMessage> {
        self.conversations
            .get(peer_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Update a message's status by ID.
    pub fn update_status(&mut self, peer_id: &str, msg_id: &str, status: &str) -> bool {
        if let Some(convo) = self.conversations.get_mut(peer_id) {
            if let Some(msg) = convo.iter_mut().find(|m| m.id == msg_id) {
                msg.status = status.to_string();
                return true;
            }
        }
        false
    }

    /// Count unread incoming messages for a peer.
    pub fn unread_count(&self, peer_id: &str) -> usize {
        self.conversations
            .get(peer_id)
            .map(|convo| {
                convo
                    .iter()
                    .filter(|m| m.direction == "incoming" && m.status != "read")
                    .count()
            })
            .unwrap_or(0)
    }

    /// Mark all incoming messages for a peer as read.
    pub fn mark_all_read(&mut self, peer_id: &str) {
        if let Some(convo) = self.conversations.get_mut(peer_id) {
            for msg in convo.iter_mut() {
                if msg.direction == "incoming" && msg.status != "read" {
                    msg.status = "read".to_string();
                }
            }
        }
    }
}

/// Canonical path for the chat store file.
pub fn chat_store_path(app_data_dir: &Path) -> PathBuf {
    app_data_dir.join("chat-messages.json")
}

/// Generate a simple UUID-like message ID.
pub fn new_message_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    format!("{:016x}{:08x}", ts, pid)
}

/// Current unix milliseconds.
pub fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_get_messages() {
        let mut store = ChatStore::empty();
        store.add_message(
            "aaa",
            ChatMessage {
                id: "m1".into(),
                direction: "outgoing".into(),
                text: "hello".into(),
                timestamp: 100,
                status: "sent".into(),
            },
        );
        store.add_message(
            "aaa",
            ChatMessage {
                id: "m2".into(),
                direction: "incoming".into(),
                text: "hi back".into(),
                timestamp: 200,
                status: "delivered".into(),
            },
        );
        let msgs = store.get_messages("aaa");
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].text, "hello");
        assert_eq!(msgs[1].text, "hi back");
    }

    #[test]
    fn unread_count_and_mark_read() {
        let mut store = ChatStore::empty();
        store.add_message(
            "bbb",
            ChatMessage {
                id: "m1".into(),
                direction: "incoming".into(),
                text: "hey".into(),
                timestamp: 100,
                status: "delivered".into(),
            },
        );
        store.add_message(
            "bbb",
            ChatMessage {
                id: "m2".into(),
                direction: "incoming".into(),
                text: "yo".into(),
                timestamp: 200,
                status: "delivered".into(),
            },
        );
        assert_eq!(store.unread_count("bbb"), 2);
        store.mark_all_read("bbb");
        assert_eq!(store.unread_count("bbb"), 0);
    }

    #[test]
    fn trims_to_max() {
        let mut store = ChatStore::empty();
        for i in 0..600 {
            store.add_message(
                "ccc",
                ChatMessage {
                    id: format!("m{i}"),
                    direction: "outgoing".into(),
                    text: format!("msg {i}"),
                    timestamp: i as u64,
                    status: "sent".into(),
                },
            );
        }
        assert_eq!(store.get_messages("ccc").len(), MAX_MESSAGES_PER_PEER);
        // Oldest should be trimmed — first message should be m100
        assert_eq!(store.get_messages("ccc")[0].id, "m100");
    }

    #[test]
    fn save_load_round_trip() {
        let dir = std::env::temp_dir().join(format!(
            "qev-chat-test-{}",
            std::process::id()
        ));
        let _ = fs::create_dir_all(&dir);
        let path = chat_store_path(&dir);

        let mut store = ChatStore::empty();
        store.add_message(
            "ddd",
            ChatMessage {
                id: "m1".into(),
                direction: "outgoing".into(),
                text: "persisted".into(),
                timestamp: 42,
                status: "sent".into(),
            },
        );
        store.save(&path).unwrap();

        let loaded = ChatStore::load_or_empty(&path).unwrap();
        assert_eq!(loaded.get_messages("ddd").len(), 1);
        assert_eq!(loaded.get_messages("ddd")[0].text, "persisted");

        let _ = fs::remove_dir_all(&dir);
    }
}
