//! JSON-backed persistent store for paired peers and the local
//! identity keypair.
//!
//! This is the minimum-viable persistence layer for Phase 2. It
//! writes a single JSON file per user data directory, e.g.:
//!
//! - macOS:   `~/Library/Application Support/com.imagineqira.qev/peers.json`
//! - Windows: `%APPDATA%\com.imagineqira.qev\peers.json`
//! - Linux:   `$XDG_DATA_HOME/com.imagineqira.qev/peers.json`
//! - Android: `/data/data/com.imagineqira.qev/files/peers.json`
//!
//! The store is trivially small for the foreseeable future — even
//! an active user with hundreds of paired peers is under 100 KB of
//! JSON. Reading the whole file on every load is fine. No
//! concurrent-writer story: the Tauri app is the sole writer, and
//! a single tokio mutex serializes writes from the command layer.
//!
//! ## Schema v1
//!
//! ```json
//! {
//!   "schema": "QEV-PEER-STORE-V1",
//!   "version": "0.29.0",
//!   "own_identity": {
//!     "public": "<b64url, 32 bytes>",
//!     "secret": "<b64url, 32 bytes>",
//!     "name":    "alice",
//!     "device":  "alice-laptop",
//!     "created_at": "2026-04-15T23:59:59Z"
//!   },
//!   "peers": [
//!     {
//!       "id":            "<hex of static_pk>",
//!       "name":          "bob",
//!       "device":        "bob-phone",
//!       "static_pk":     "<b64url, 32 bytes>",
//!       "paired_at":     "2026-04-15T23:59:59Z",
//!       "last_seen_at":  "2026-04-15T23:59:59Z",
//!       "trust":         "unverified" | "verified",
//!       "last_addrs":    ["192.168.1.42:7891"]
//!     },
//!     ...
//!   ]
//! }
//! ```
//!
//! ## Private key at rest
//!
//! For v1 the private key is stored in plaintext inside the JSON
//! file, which is placed in the user's app-data directory with
//! default filesystem permissions (0600 on Unix via the
//! `set_permissions` call below). This is adequate for a single-
//! user developer machine or a phone where the OS already isolates
//! per-app data directories.
//!
//! Future work (phase 2.x):
//! - macOS Keychain wrap via `security-framework`
//! - Windows DPAPI wrap via `windows-sys` ProtectData
//! - Android EncryptedSharedPreferences wrap via JNI
//! - Linux libsecret wrap
//!
//! Until that lands, a user who wants hardware-backed key storage
//! should use the desktop-only flow and not run QEV on a shared
//! machine.

use crate::error::{Error, Result};
use crate::identity::StaticKeypair;
use crate::{STATIC_KEY_BYTES, STATIC_SK_BYTES};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Current schema identifier. Written into every saved file.
pub const STORE_SCHEMA: &str = "QEV-PEER-STORE-V1";

/// Trust level for a paired peer.
///
/// - `Unverified` — handshake completed but the user didn't compare
///   the safety number with the other party (or answered "different").
/// - `Verified` — safety number match confirmed by the user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustLevel {
    /// Pairing handshake succeeded but no safety-number confirmation.
    Unverified,
    /// User confirmed the safety number match with the peer.
    Verified,
}

impl Default for TrustLevel {
    fn default() -> Self {
        TrustLevel::Unverified
    }
}

/// A single paired peer record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredPeer {
    /// Hex of the peer's static public key. Used as a unique ID.
    pub id: String,
    /// Display name the peer chose.
    pub name: String,
    /// Device label the peer advertised.
    pub device: String,
    /// 32-byte X25519 static public key, base64url encoded.
    pub static_pk: String,
    /// ISO 8601 timestamp of the initial pairing.
    pub paired_at: String,
    /// ISO 8601 timestamp of the most recent interaction
    /// (pairing refresh or successful vault transfer).
    pub last_seen_at: String,
    /// Whether the user verified the safety number in person.
    #[serde(default)]
    pub trust: TrustLevel,
    /// Addresses the peer last advertised. Used as a starting
    /// point for future direct sends. Not authoritative.
    pub last_addrs: Vec<String>,
}

/// The local device's own long-term identity.
///
/// The private scalar is stored in the OS keystore when available
/// (macOS Keychain today; Windows/Android coming). On platforms
/// without keystore support the scalar falls back to the `secret`
/// JSON field — so older installs keep working without migration
/// pain, and upgrades move the secret into the keystore on first
/// load after the upgrade.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnIdentity {
    /// 32-byte X25519 public key, base64url.
    pub public: String,
    /// 32-byte X25519 private scalar, base64url. Populated only when
    /// the OS keystore is not available on this platform (or the
    /// record is waiting for migration). When the keystore owns the
    /// secret, this field is an empty string (and skipped on
    /// serialize) — the scalar lives in Keychain/DPAPI instead.
    #[serde(default)]
    pub secret: String,
    /// User-chosen display name attached to every invite this
    /// device emits.
    pub name: String,
    /// User-chosen device label.
    pub device: String,
    /// ISO 8601 timestamp when the identity was first generated.
    pub created_at: String,
}

impl OwnIdentity {
    /// Convert the base64url public + secret back into a
    /// `StaticKeypair` suitable for the handshake layer.
    ///
    /// Resolution order for the secret (intentionally file-first to
    /// avoid Keychain prompts on every rebuild of an ad-hoc-signed
    /// binary — each rebuild gets a new signature, so Keychain
    /// treats it as "a different app" and re-prompts):
    ///
    ///   1. The `secret` field inside the JSON store (silent, fast)
    ///   2. OS keystore (macOS Keychain) — only reached when the
    ///      file field is empty, e.g. legacy installs that migrated
    ///      to Keychain in an older QEV build and cleared the field
    ///
    /// Once a signed-with-Apple-Developer-ID shipping build exists,
    /// the code-signing identity is stable and Keychain prompts
    /// don't repeat. At that point we can reverse this order safely.
    /// Until then, "file first" is the correct default for alpha.
    pub fn to_keypair(&self) -> Result<StaticKeypair> {
        let pub_bytes = URL_SAFE_NO_PAD
            .decode(self.public.as_bytes())
            .map_err(|e| Error::Internal(format!("own_identity.public base64: {e}")))?;
        if pub_bytes.len() != STATIC_KEY_BYTES {
            return Err(Error::Internal(format!(
                "own_identity.public wrong length: {}",
                pub_bytes.len()
            )));
        }
        let mut public = [0u8; STATIC_KEY_BYTES];
        public.copy_from_slice(&pub_bytes);

        let mut secret = [0u8; STATIC_SK_BYTES];

        // 1. File first. Populated on every save in modern builds.
        if !self.secret.is_empty() {
            let sec_bytes = URL_SAFE_NO_PAD
                .decode(self.secret.as_bytes())
                .map_err(|e| Error::Internal(format!("own_identity.secret base64: {e}")))?;
            if sec_bytes.len() != STATIC_SK_BYTES {
                return Err(Error::Internal(format!(
                    "own_identity.secret wrong length: {}",
                    sec_bytes.len()
                )));
            }
            secret.copy_from_slice(&sec_bytes);
            return Ok(StaticKeypair { public, secret });
        }

        // 2. Legacy-install fallback: secret was written only to
        // Keychain by an older QEV that cleared the file. This path
        // WILL prompt once on macOS if the running binary isn't on
        // the Keychain item's ACL — a cost we pay once to recover,
        // and the user can "Always Allow" to skip forever.
        let keystore_secret = crate::keystore::load_secret(
            crate::keystore::KEYCHAIN_SERVICE,
            crate::keystore::KEYCHAIN_ACCOUNT,
        );
        match keystore_secret {
            Ok(Some(s)) => {
                secret.copy_from_slice(&s);
                Ok(StaticKeypair { public, secret })
            }
            Ok(None) | Err(_) => Err(Error::Internal(
                "own_identity has no secret (file empty, keystore also empty)".into(),
            )),
        }
    }

    /// Build an `OwnIdentity` record from a `StaticKeypair` plus
    /// the user-chosen name and device label.
    ///
    /// The secret is ALWAYS embedded in the record (base64url in the
    /// `secret` field). On platforms with a keystore we ALSO write a
    /// copy to the OS keychain as a belt-and-suspenders backup — but
    /// the file copy is always the primary source (see `to_keypair`
    /// for the load-order rationale). Duplicating the secret this
    /// way is safe: the file is owner-only 0600 and the keychain is
    /// unlocked whenever the user is logged in, so the effective
    /// security is identical.
    pub fn from_keypair(kp: &StaticKeypair, name: String, device: String) -> Self {
        let public = URL_SAFE_NO_PAD.encode(kp.public);
        let created_at = iso8601_now();

        // Always populate the file secret. Best-effort keychain copy
        // for future "one-click export to other device" flows and
        // for signed shipping builds that want keychain-first later.
        if crate::keystore::is_available() {
            let _ = crate::keystore::store_secret(
                crate::keystore::KEYCHAIN_SERVICE,
                crate::keystore::KEYCHAIN_ACCOUNT,
                &kp.secret,
            );
        }
        let secret = URL_SAFE_NO_PAD.encode(kp.secret);

        Self {
            public,
            secret,
            name,
            device,
            created_at,
        }
    }

    /// Return a clone of self with `secret` guaranteed populated,
    /// pulling from the OS keystore if the JSON field is empty.
    /// Used by the identity-backup export flow which must put the
    /// raw private scalar into the encrypted blob.
    ///
    /// This WILL trigger a Keychain prompt on macOS if the caller
    /// isn't already on the item's ACL. Gate accordingly in the UI.
    pub fn with_unwrapped_secret(&self) -> Result<Self> {
        let kp = self.to_keypair()?;
        let secret_b64 = URL_SAFE_NO_PAD.encode(kp.secret);
        Ok(Self {
            public: self.public.clone(),
            secret: secret_b64,
            name: self.name.clone(),
            device: self.device.clone(),
            created_at: self.created_at.clone(),
        })
    }

    /// Migrate a legacy file-based secret into the OS keystore if
    /// one is available. Idempotent — safe to call on every load.
    /// Returns true if migration actually happened (and therefore
    /// the store should be saved back to disk with the empty
    /// `secret` field).
    pub fn migrate_to_keystore(&mut self) -> bool {
        if !crate::keystore::is_available() {
            return false;
        }
        if self.secret.is_empty() {
            return false; // Nothing to migrate.
        }
        let sec_bytes = match URL_SAFE_NO_PAD.decode(self.secret.as_bytes()) {
            Ok(b) if b.len() == STATIC_SK_BYTES => b,
            _ => return false, // Malformed — leave as-is.
        };
        let mut secret_arr = [0u8; STATIC_SK_BYTES];
        secret_arr.copy_from_slice(&sec_bytes);
        // Best-effort keystore copy. We INTENTIONALLY do NOT clear
        // `self.secret` afterwards: clearing it forces every future
        // load to hit the Keychain, which in ad-hoc-signed alpha
        // builds triggers a "QEV wants to use your confidential
        // information" prompt on every rebuild. Keeping the file
        // copy as the primary source means the prompt never fires.
        let _ = crate::keystore::store_secret(
            crate::keystore::KEYCHAIN_SERVICE,
            crate::keystore::KEYCHAIN_ACCOUNT,
            &secret_arr,
        );
        // Return false: from the caller's perspective ("should we
        // re-save the store because something changed?") nothing
        // user-visible changed. Caller can skip the save round-trip.
        false
    }

    /// One-time self-heal for installs that ran an older QEV which
    /// migrated the secret into Keychain and CLEARED the `secret`
    /// field in the file. Pulls the secret back from Keychain into
    /// the file so subsequent launches don't need the Keychain
    /// (and don't trigger the "QEV wants to use your confidential
    /// information" prompt on every rebuild).
    ///
    /// Returns true if we actually recovered the secret from
    /// Keychain, meaning the caller should persist the store back
    /// to disk. On macOS this WILL trigger the Keychain ACL prompt
    /// once — the price of recovery. After one successful
    /// "Always Allow" click, the secret lives in the file and this
    /// method's early-return short-circuits on all future launches.
    pub fn recover_secret_from_keystore(&mut self) -> bool {
        if !self.secret.is_empty() {
            return false; // File already has it; no recovery needed.
        }
        if !crate::keystore::is_available() {
            return false;
        }
        match crate::keystore::load_secret(
            crate::keystore::KEYCHAIN_SERVICE,
            crate::keystore::KEYCHAIN_ACCOUNT,
        ) {
            Ok(Some(secret)) => {
                self.secret = URL_SAFE_NO_PAD.encode(secret);
                true
            }
            _ => false,
        }
    }
}

/// The full on-disk store state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerStore {
    /// Schema tag. Matches [`STORE_SCHEMA`] for valid stores.
    pub schema: String,
    /// QEV version that produced this store file.
    pub version: String,
    /// The device's own long-term identity, if it has been
    /// generated yet. `None` on a brand-new install.
    pub own_identity: Option<OwnIdentity>,
    /// All paired peers known to this device.
    pub peers: Vec<StoredPeer>,
    /// ISO 8601 timestamp of the most recent successful
    /// identity-backup export. `None` means the user has never
    /// backed up — the UI surfaces this as a prominent banner
    /// because a Mac wipe without a backup means the user loses
    /// their identity permanently.
    ///
    /// Serialized with `#[serde(default)]` so existing store files
    /// without this field load cleanly (older QEV installs that
    /// pre-date the backup feature).
    #[serde(default)]
    pub last_backup_at: Option<String>,
}

impl PeerStore {
    /// Empty store with the current schema string.
    pub fn empty() -> Self {
        Self {
            schema: STORE_SCHEMA.to_string(),
            version: crate::QEV_VERSION.to_string(),
            own_identity: None,
            peers: Vec::new(),
            last_backup_at: None,
        }
    }

    /// Validate the schema string after deserialization.
    fn validate(&self) -> Result<()> {
        if self.schema != STORE_SCHEMA {
            return Err(Error::Internal(format!(
                "unsupported store schema: {} (expected {})",
                self.schema, STORE_SCHEMA
            )));
        }
        Ok(())
    }

    /// Load a store from the given file path, returning `empty()`
    /// if the file does not yet exist.
    ///
    /// On every load we run two complementary repair steps:
    ///
    ///   **Forward-sync (belt-and-suspenders):** if the file has a
    ///   plaintext `secret` AND the OS has a keystore, write a
    ///   keystore backup. Never clears the file field — keeping the
    ///   file as the primary source avoids the "prompt on every
    ///   rebuild" problem for ad-hoc-signed alpha builds.
    ///
    ///   **Legacy-install recovery:** if the file's `secret` is
    ///   EMPTY (an older QEV build migrated it out and cleared the
    ///   field) BUT the keystore still has it, pull the secret back
    ///   into the file. This triggers a single Keychain "Always
    ///   Allow" prompt once, but all subsequent launches are silent
    ///   because the secret now lives in the file.
    ///
    /// Both steps are idempotent and safe to call on every launch.
    pub fn load_or_empty(path: &Path) -> Result<Self> {
        match fs::read(path) {
            Ok(bytes) => {
                let mut store: Self = serde_json::from_slice(&bytes)
                    .map_err(|e| Error::Internal(format!("store decode: {e}")))?;
                store.validate()?;
                let mut should_resave = false;
                if let Some(id) = store.own_identity.as_mut() {
                    // Forward-sync: file → keystore, silent.
                    id.migrate_to_keystore();
                    // Legacy recovery: keystore → file, one-time.
                    if id.secret.is_empty() && id.recover_secret_from_keystore() {
                        should_resave = true;
                    }
                }
                if should_resave {
                    let _ = store.save(path);
                }
                Ok(store)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::empty()),
            Err(e) => Err(Error::Io(e)),
        }
    }

    /// Persist the store to disk atomically.
    ///
    /// Writes to `<path>.tmp` first, then renames over the target.
    /// This avoids half-written files if the process dies mid-write.
    /// On Unix, sets permissions to 0600 so the file is only
    /// readable by the owning user — important because the file
    /// contains the private static key in plaintext.
    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(Error::Io)?;
        }
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| Error::Internal(format!("store encode: {e}")))?;
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, &json).map_err(Error::Io)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
                .map_err(Error::Io)?;
        }

        fs::rename(&tmp, path).map_err(Error::Io)?;
        Ok(())
    }

    /// Insert or update a peer record. Matches by `id`.
    ///
    /// Returns true if the peer was new, false if an existing
    /// record was updated in place (keeping the original
    /// `paired_at` and `trust`).
    pub fn upsert_peer(&mut self, peer: StoredPeer) -> bool {
        if let Some(existing) = self.peers.iter_mut().find(|p| p.id == peer.id) {
            // Preserve the original pairing timestamp and trust
            // level on re-pair. Users who previously verified
            // shouldn't lose that state on a re-handshake.
            existing.name = peer.name;
            existing.device = peer.device;
            existing.static_pk = peer.static_pk;
            existing.last_seen_at = peer.last_seen_at;
            existing.last_addrs = peer.last_addrs;
            false
        } else {
            self.peers.push(peer);
            true
        }
    }

    /// Look up a peer by its hex ID.
    pub fn find(&self, id: &str) -> Option<&StoredPeer> {
        self.peers.iter().find(|p| p.id == id)
    }

    /// Mark a peer as verified (user confirmed the safety number).
    pub fn set_trust(&mut self, id: &str, trust: TrustLevel) -> bool {
        if let Some(p) = self.peers.iter_mut().find(|p| p.id == id) {
            p.trust = trust;
            true
        } else {
            false
        }
    }

    /// Remove a peer from the store.
    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.peers.len();
        self.peers.retain(|p| p.id != id);
        self.peers.len() != before
    }

    /// Ensure an own-identity exists. Returns the stored keypair;
    /// generates + stores a fresh one on first call.
    ///
    /// The `name` and `device` args are only used when generating
    /// a fresh identity — subsequent calls ignore them and return
    /// the existing one. To change the name/device label of an
    /// existing identity, call [`set_own_name`] / [`set_own_device`].
    pub fn ensure_own_identity(
        &mut self,
        name: &str,
        device: &str,
    ) -> Result<StaticKeypair> {
        if let Some(id) = &self.own_identity {
            return id.to_keypair();
        }
        let kp = StaticKeypair::generate()?;
        self.own_identity = Some(OwnIdentity::from_keypair(&kp, name.to_string(), device.to_string()));
        Ok(kp)
    }

    /// Update the display name in the stored own-identity. Does
    /// nothing if there is no identity yet.
    pub fn set_own_name(&mut self, name: String) {
        if let Some(id) = self.own_identity.as_mut() {
            id.name = name;
        }
    }

    /// Update the device label in the stored own-identity.
    pub fn set_own_device(&mut self, device: String) {
        if let Some(id) = self.own_identity.as_mut() {
            id.device = device;
        }
    }
}

/// Canonical store path for the given app data directory.
///
/// Call sites typically obtain the dir from Tauri's path resolver
/// (`app_handle.path().app_data_dir()`), but this function works
/// with any directory — tests pass a tempdir.
pub fn store_path(app_data_dir: &Path) -> PathBuf {
    app_data_dir.join("peers.json")
}

/// Produce a hex ID from a static public key.
///
/// 64 lowercase characters. Used as the primary key for peer
/// records so it's stable, human-copyable, and distinct from
/// base64url encodings used on the wire.
pub fn pk_to_hex(pk: &[u8; STATIC_KEY_BYTES]) -> String {
    let mut s = String::with_capacity(64);
    for b in pk {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Format `SystemTime::now()` as an RFC 3339 / ISO 8601 UTC string
/// for writing into store records. Uses the `time` crate from the
/// same dep set as the invite module.
fn iso8601_now() -> String {
    use time::format_description::well_known::Iso8601;
    use time::OffsetDateTime;
    let odt: OffsetDateTime = SystemTime::now().into();
    odt.format(&Iso8601::DEFAULT)
        .unwrap_or_else(|_| "1970-01-01T00:00:00.000000000Z".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn tempdir() -> PathBuf {
        // Use std::env::temp_dir() + a random-ish suffix. Avoids
        // pulling a tempfile dep for one-file tests.
        let mut p = env::temp_dir();
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        p.push(format!("qev-pairing-test-{pid}-{nanos}"));
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn sample_peer(seed: u8, id_text: &str) -> StoredPeer {
        let mut pk = [0u8; 32];
        for (i, b) in pk.iter_mut().enumerate() {
            *b = seed.wrapping_add(i as u8);
        }
        let now = iso8601_now();
        StoredPeer {
            id: id_text.to_string(),
            name: "alice".into(),
            device: "alice-phone".into(),
            static_pk: URL_SAFE_NO_PAD.encode(pk),
            paired_at: now.clone(),
            last_seen_at: now,
            trust: TrustLevel::Unverified,
            last_addrs: vec!["192.168.1.10:7891".into()],
        }
    }

    #[test]
    fn empty_store_is_valid() {
        let s = PeerStore::empty();
        assert_eq!(s.schema, STORE_SCHEMA);
        assert!(s.peers.is_empty());
        assert!(s.own_identity.is_none());
    }

    #[test]
    fn upsert_inserts_new_peer_then_updates_existing() {
        let mut s = PeerStore::empty();
        let p1 = sample_peer(1, "aaaa");
        assert!(s.upsert_peer(p1.clone()), "first upsert returns true (new)");
        assert_eq!(s.peers.len(), 1);

        let mut p1_updated = p1.clone();
        p1_updated.name = "alice-renamed".into();
        assert!(!s.upsert_peer(p1_updated.clone()), "second upsert returns false (existing)");
        assert_eq!(s.peers.len(), 1);
        assert_eq!(s.peers[0].name, "alice-renamed");
    }

    #[test]
    fn upsert_preserves_trust_on_re_pair() {
        let mut s = PeerStore::empty();
        s.upsert_peer(sample_peer(1, "aaaa"));
        s.set_trust("aaaa", TrustLevel::Verified);
        assert_eq!(s.peers[0].trust, TrustLevel::Verified);

        // Re-pair: should NOT downgrade trust to Unverified.
        let mut updated = sample_peer(1, "aaaa");
        updated.trust = TrustLevel::Unverified;
        s.upsert_peer(updated);
        assert_eq!(
            s.peers[0].trust,
            TrustLevel::Verified,
            "trust preserved across re-pair"
        );
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = tempdir();
        let path = store_path(&dir);

        let mut s1 = PeerStore::empty();
        s1.upsert_peer(sample_peer(1, "aaaa"));
        s1.upsert_peer(sample_peer(2, "bbbb"));
        s1.save(&path).unwrap();

        let s2 = PeerStore::load_or_empty(&path).unwrap();
        assert_eq!(s2.peers.len(), 2);
        assert_eq!(s2.peers[0].id, "aaaa");
        assert_eq!(s2.peers[1].id, "bbbb");

        // Cleanup
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_or_empty_on_missing_file_returns_empty() {
        let dir = tempdir();
        let path = dir.join("nonexistent.json");
        let s = PeerStore::load_or_empty(&path).unwrap();
        assert!(s.peers.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_rejects_wrong_schema() {
        let dir = tempdir();
        let path = store_path(&dir);
        // Hand-craft a file with a bogus schema.
        let bogus = r#"{"schema":"NOT-A-REAL-SCHEMA","version":"0.1.0","own_identity":null,"peers":[]}"#;
        fs::write(&path, bogus).unwrap();
        let err = PeerStore::load_or_empty(&path).unwrap_err();
        assert!(format!("{err}").contains("unsupported store schema"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg_attr(target_os = "macos", ignore = "touches real Keychain — run with --ignored")]
    #[test]
    fn ensure_own_identity_is_idempotent() {
        let mut s = PeerStore::empty();
        let k1 = s.ensure_own_identity("alice", "alice-laptop").unwrap();
        let k2 = s.ensure_own_identity("ignored", "ignored").unwrap();
        // Same keys on the second call — we don't regenerate.
        assert_eq!(k1.public, k2.public);
        assert_eq!(k1.secret, k2.secret);
        // And the original name/device are preserved.
        let id = s.own_identity.as_ref().unwrap();
        assert_eq!(id.name, "alice");
        assert_eq!(id.device, "alice-laptop");
    }

    #[cfg_attr(target_os = "macos", ignore = "touches real Keychain — run with --ignored")]
    #[test]
    fn ensure_own_identity_persists_across_save_load() {
        let dir = tempdir();
        let path = store_path(&dir);
        let mut s1 = PeerStore::empty();
        let k1 = s1.ensure_own_identity("alice", "alice-laptop").unwrap();
        s1.save(&path).unwrap();

        let mut s2 = PeerStore::load_or_empty(&path).unwrap();
        let k2 = s2.ensure_own_identity("should-be-ignored", "ignored").unwrap();
        assert_eq!(k1.public, k2.public);
        assert_eq!(k1.secret, k2.secret);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn find_and_remove_work_as_expected() {
        let mut s = PeerStore::empty();
        s.upsert_peer(sample_peer(1, "aaaa"));
        s.upsert_peer(sample_peer(2, "bbbb"));
        s.upsert_peer(sample_peer(3, "cccc"));
        assert!(s.find("bbbb").is_some());
        assert!(s.find("zzzz").is_none());
        assert!(s.remove("bbbb"));
        assert_eq!(s.peers.len(), 2);
        assert!(s.find("bbbb").is_none());
        assert!(!s.remove("bbbb"), "double-remove is a no-op");
    }

    #[test]
    fn pk_to_hex_produces_64_lowercase() {
        let mut pk = [0u8; 32];
        for (i, b) in pk.iter_mut().enumerate() {
            *b = i as u8;
        }
        let h = pk_to_hex(&pk);
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert!(h.starts_with("000102030405"));
    }

    #[cfg_attr(target_os = "macos", ignore = "touches real Keychain — run with --ignored")]
    #[cfg(unix)]
    #[test]
    fn saved_file_has_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir();
        let path = store_path(&dir);
        let mut s = PeerStore::empty();
        s.ensure_own_identity("alice", "alice-laptop").unwrap();
        s.save(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "store file must be owner-read-write only");
        let _ = fs::remove_dir_all(&dir);
    }

    // ---- Keystore-backed identity tests (macOS only) ----
    //
    // These tests TOUCH THE REAL macOS Keychain. They use a
    // dedicated test-only service name to avoid colliding with any
    // real QEV install on the same machine. Each test cleans up
    // its own entry at the end.

    #[cfg(target_os = "macos")]
    fn cleanup_test_keychain_entry() {
        let _ = crate::keystore::delete_secret(
            crate::keystore::KEYCHAIN_SERVICE,
            crate::keystore::KEYCHAIN_ACCOUNT,
        );
    }

    #[cfg(target_os = "macos")]
    #[ignore = "touches real Keychain — run with --ignored after approving prompts"]
    #[test]
    fn new_identity_goes_into_keychain_not_file() {
        cleanup_test_keychain_entry();
        let mut s = PeerStore::empty();
        let kp = s.ensure_own_identity("alice", "alice-laptop").unwrap();
        let id = s.own_identity.as_ref().unwrap();
        assert!(
            id.secret.is_empty(),
            "secret field in store should be empty when keystore owns the scalar"
        );
        // The keypair loaded from ensure_own_identity must match what
        // to_keypair() returns after serialization.
        let kp2 = id.to_keypair().unwrap();
        assert_eq!(kp.public, kp2.public);
        assert_eq!(kp.secret, kp2.secret);
        cleanup_test_keychain_entry();
    }

    #[cfg(target_os = "macos")]
    #[ignore = "touches real Keychain — run with --ignored after approving prompts"]
    #[test]
    fn legacy_plaintext_secret_migrates_on_load() {
        cleanup_test_keychain_entry();
        let dir = tempdir();
        let path = store_path(&dir);

        // Write a legacy v1-style store with a plaintext secret.
        let legacy_json = r#"{
          "schema": "QEV-PEER-STORE-V1",
          "version": "0.29.0",
          "own_identity": {
            "public": "qKqQ7vZbg_Y0NzumNJ912-KnSgd_Utn1hGcdbHs9Zl0",
            "secret": "M93B5OnBvKb43N9wMOUyo9aD20PTw5czVcw99aSxaCs",
            "name": "legacy-user",
            "device": "legacy-laptop",
            "created_at": "2026-04-15T00:00:00Z"
          },
          "peers": []
        }"#;
        fs::create_dir_all(&dir).unwrap();
        fs::write(&path, legacy_json).unwrap();

        // Load → migration should move the secret into Keychain.
        let store = PeerStore::load_or_empty(&path).unwrap();
        assert!(
            store.own_identity.as_ref().unwrap().secret.is_empty(),
            "after migration the file secret field should be empty"
        );

        // The file on disk should now also have an empty secret.
        let reloaded = PeerStore::load_or_empty(&path).unwrap();
        assert!(reloaded.own_identity.as_ref().unwrap().secret.is_empty());

        // to_keypair should still work — secret comes from Keychain.
        let kp = reloaded.own_identity.as_ref().unwrap().to_keypair().unwrap();
        assert_eq!(kp.secret.len(), 32);

        cleanup_test_keychain_entry();
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "macos")]
    #[ignore = "touches real Keychain — run with --ignored after approving prompts"]
    #[test]
    fn keychain_removal_leaves_identity_with_clear_error() {
        cleanup_test_keychain_entry();
        let mut s = PeerStore::empty();
        s.ensure_own_identity("alice", "alice-laptop").unwrap();
        // Simulate manual keychain-item deletion outside our control.
        cleanup_test_keychain_entry();
        // to_keypair must now fail loudly rather than silently
        // generating a new keypair or returning random bytes.
        let err = s.own_identity.as_ref().unwrap().to_keypair().unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("no secret"),
            "expected explicit no-secret error, got: {msg}"
        );
    }
}
