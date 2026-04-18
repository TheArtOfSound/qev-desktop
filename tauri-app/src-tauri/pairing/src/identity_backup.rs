//! Passphrase-locked export + import of the full QEV identity.
//!
//! # What this solves
//!
//! Without a backup, the user's QEV identity lives only in the
//! OS keystore (macOS Keychain) + the per-user `peers.json`. If
//! the machine dies or is wiped, the private key is gone and the
//! user can't prove they're the same "them" to their paired peers —
//! they'd have to re-pair every device.
//!
//! This module produces a single JSON file the user can save
//! anywhere (1Password, encrypted USB, email-to-self, etc.) that,
//! combined with a passphrase they chose, restores the full
//! identity on a new machine.
//!
//! # Backup format (QEV-IDENTITY-BACKUP-V1)
//!
//! ```json
//! {
//!   "schema": "QEV-IDENTITY-BACKUP-V1",
//!   "created_at": "2026-04-17T20:30:00Z",
//!   "app_version": "0.29.0",
//!   "nonce":      "<base64url 24 bytes>",
//!   "ciphertext": "<base64url XChaCha20-Poly1305 sealed payload>"
//! }
//! ```
//!
//! The ciphertext decrypts to a `BackupPayload` (see below) using:
//! - **KDF**: `BLAKE2b-512("QEV-IDENTITY-BACKUP-V1-KDF:" || passphrase)`,
//!   first 32 bytes → AEAD key.
//! - **AEAD**: XChaCha20-Poly1305 with AAD = `"QEV-IDENTITY-BACKUP-V1"`.
//!
//! # Why BLAKE2b-only KDF (not Argon2id)
//!
//! Matches the pattern in `seal.rs`. No new Rust crate deps
//! needed — Argon2id would pull in a non-trivial transitive graph.
//! The BLAKE2b KDF is fast, which means brute-force is cheap — the
//! backup file's security depends ENTIRELY on passphrase strength.
//!
//! The UI SHOULD require a strong passphrase (we recommend
//! 4+ words, 20+ chars) and warn users that weak passphrases
//! mean the backup is effectively plaintext to an attacker who
//! obtains the file.
//!
//! # Restoration trust model
//!
//! Importing a backup REPLACES the current `PeerStore` on the
//! target machine. Peers in the backup are installed; the target
//! machine's own identity becomes the one in the backup. This is
//! what you want for "I got a new Mac and want to be me again."
//!
//! Callers that want to MERGE (e.g. "add these peers to my
//! existing identity") need a different flow we haven't built.

use crate::error::{Error, Result};
use crate::peer_store::{OwnIdentity, PeerStore, StoredPeer, STORE_SCHEMA};
use crate::QEV_VERSION;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Schema tag written into every backup file. Bump when the
/// backup payload structure changes incompatibly.
pub const BACKUP_SCHEMA: &str = "QEV-IDENTITY-BACKUP-V1";

/// AAD string fed into the AEAD so a file from a different
/// schema version can't decrypt here even with the same passphrase.
const AAD: &[u8] = b"QEV-IDENTITY-BACKUP-V1";

/// KDF label prefixed to the passphrase before hashing. Keeps this
/// key-derivation domain-separate from any other BLAKE2b usage in
/// the crate (e.g. seal.rs uses its own prefix).
const KDF_LABEL: &[u8] = b"QEV-IDENTITY-BACKUP-V1-KDF:";

/// Minimum recommended passphrase length. Enforced in `export` as a
/// refusal (the UI should gate earlier with a strength meter).
const MIN_PASSPHRASE_LEN: usize = 12;

/// The outer envelope written to disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupEnvelope {
    /// Must equal [`BACKUP_SCHEMA`] exactly.
    pub schema: String,
    /// ISO 8601 UTC timestamp when the backup was made. Purely
    /// informational — we don't enforce any freshness.
    pub created_at: String,
    /// The QEV version that produced this file. Again informational
    /// — old backups are accepted by any newer version that can
    /// read the schema.
    pub app_version: String,
    /// Base64url-encoded 24-byte XChaCha20-Poly1305 nonce.
    pub nonce: String,
    /// Base64url-encoded sealed payload (`BackupPayload` JSON bytes).
    pub ciphertext: String,
}

/// Inner cleartext — what the passphrase unlocks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupPayload {
    /// Schema tag so imports can detect payload-level version drift.
    pub schema: String,
    /// Full own-identity record (public, secret, name, device, created_at).
    pub own_identity: OwnIdentity,
    /// All paired peers known to this device at backup time.
    pub peers: Vec<StoredPeer>,
}

/// Export the full identity (own keypair + paired-peer list) as a
/// passphrase-locked backup envelope.
///
/// `passphrase` must be at least `MIN_PASSPHRASE_LEN` bytes long.
/// The UI should gate earlier with a strength check; this is a
/// floor, not a recommendation — pick something much stronger.
///
/// The `own_identity.secret` field must be populated before calling
/// this (use `PeerStore::unwrap_identity_for_backup()` to resolve
/// it from the OS keystore first). This function does NOT touch
/// the keystore directly — it just encrypts whatever keypair you
/// hand it.
pub fn export_backup(
    own_identity: OwnIdentity,
    peers: Vec<StoredPeer>,
    passphrase: &str,
) -> Result<String> {
    if passphrase.len() < MIN_PASSPHRASE_LEN {
        return Err(Error::Internal(format!(
            "passphrase must be at least {MIN_PASSPHRASE_LEN} characters"
        )));
    }
    if own_identity.secret.is_empty() {
        return Err(Error::Internal(
            "cannot back up an OwnIdentity with an empty secret — \
             unwrap from the keystore first"
                .into(),
        ));
    }

    // 1. Build + serialize the inner payload.
    let payload = BackupPayload {
        schema: STORE_SCHEMA.to_string(),
        own_identity,
        peers,
    };
    let plaintext = serde_json::to_vec(&payload)
        .map_err(|e| Error::Internal(format!("payload json: {e}")))?;

    // 2. Derive key from passphrase via BLAKE2b-256.
    let key = derive_key(passphrase);

    // 3. Random 24-byte XChaCha20-Poly1305 nonce.
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let xnonce = XNonce::from_slice(&nonce);

    // 4. AEAD-encrypt.
    let cipher = XChaCha20Poly1305::new((&key[..]).into());
    let ciphertext = cipher
        .encrypt(xnonce, Payload { msg: &plaintext, aad: AAD })
        .map_err(|e| Error::Internal(format!("backup encrypt: {e}")))?;

    // 5. Pack as envelope JSON.
    let env = BackupEnvelope {
        schema: BACKUP_SCHEMA.to_string(),
        created_at: iso8601_now(),
        app_version: QEV_VERSION.to_string(),
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    };
    serde_json::to_string_pretty(&env)
        .map_err(|e| Error::Internal(format!("envelope json: {e}")))
}

/// Import a backup envelope using the matching passphrase.
///
/// Returns the decrypted payload. Callers are responsible for
/// merging / replacing into the live `PeerStore` and persisting
/// the own-identity secret back into the OS keystore.
pub fn import_backup(envelope_json: &str, passphrase: &str) -> Result<BackupPayload> {
    if passphrase.is_empty() {
        return Err(Error::Internal("passphrase must not be empty".into()));
    }
    let env: BackupEnvelope = serde_json::from_str(envelope_json)
        .map_err(|e| Error::Internal(format!("envelope parse: {e}")))?;
    if env.schema != BACKUP_SCHEMA {
        return Err(Error::Internal(format!(
            "unsupported backup schema: {} (expected {})",
            env.schema, BACKUP_SCHEMA
        )));
    }
    let nonce = URL_SAFE_NO_PAD
        .decode(env.nonce.as_bytes())
        .map_err(|e| Error::Internal(format!("nonce decode: {e}")))?;
    if nonce.len() != 24 {
        return Err(Error::Internal(format!(
            "nonce wrong length: {} (expected 24)",
            nonce.len()
        )));
    }
    let ciphertext = URL_SAFE_NO_PAD
        .decode(env.ciphertext.as_bytes())
        .map_err(|e| Error::Internal(format!("ciphertext decode: {e}")))?;

    let key = derive_key(passphrase);
    let cipher = XChaCha20Poly1305::new((&key[..]).into());
    let xnonce = XNonce::from_slice(&nonce);
    let plaintext = cipher
        .decrypt(xnonce, Payload { msg: &ciphertext, aad: AAD })
        .map_err(|_| Error::Internal("wrong passphrase or corrupted backup".into()))?;

    let payload: BackupPayload = serde_json::from_slice(&plaintext)
        .map_err(|e| Error::Internal(format!("payload parse: {e}")))?;
    Ok(payload)
}

/// Apply an imported `BackupPayload` to a live `PeerStore`:
/// replaces `own_identity`, upserts every peer from the backup.
/// Existing peers not in the backup are LEFT ALONE — this is a
/// union, not a replacement, so partial backups don't nuke data.
pub fn apply_backup(store: &mut PeerStore, payload: BackupPayload) {
    store.own_identity = Some(payload.own_identity);
    for peer in payload.peers {
        store.upsert_peer(peer);
    }
}

// ---- Helpers ----

fn derive_key(passphrase: &str) -> [u8; 32] {
    type Blake2b256 = Blake2b<U32>;
    let mut hasher = Blake2b256::new();
    hasher.update(KDF_LABEL);
    hasher.update(passphrase.as_bytes());
    hasher.finalize().into()
}

fn iso8601_now() -> String {
    use time::format_description::well_known::Iso8601;
    use time::OffsetDateTime;
    let odt: OffsetDateTime = SystemTime::now().into();
    odt.format(&Iso8601::DEFAULT)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_store::TrustLevel;

    fn sample_own() -> OwnIdentity {
        OwnIdentity {
            public: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            secret: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            name: "alice".into(),
            device: "alice-mac".into(),
            created_at: "2026-04-17T00:00:00Z".into(),
        }
    }

    fn sample_peers() -> Vec<StoredPeer> {
        vec![StoredPeer {
            id: "deadbeef".repeat(8),
            name: "bob".into(),
            device: "bob-phone".into(),
            static_pk: "cccccccccccccccccccccccccccccccccccccccccccc".into(),
            paired_at: "2026-04-17T00:00:00Z".into(),
            last_seen_at: "2026-04-17T00:00:00Z".into(),
            trust: TrustLevel::Verified,
            last_addrs: vec!["192.168.1.42:7891".into()],
        }]
    }

    #[test]
    fn round_trip_with_correct_passphrase() {
        let env = export_backup(sample_own(), sample_peers(), "correct-horse-battery").unwrap();
        let payload = import_backup(&env, "correct-horse-battery").unwrap();
        assert_eq!(payload.own_identity.name, "alice");
        assert_eq!(payload.peers.len(), 1);
        assert_eq!(payload.peers[0].name, "bob");
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let env = export_backup(sample_own(), sample_peers(), "correct-horse-battery").unwrap();
        let err = import_backup(&env, "wrong-passphrase").unwrap_err();
        assert!(format!("{err}").contains("wrong passphrase"));
    }

    #[test]
    fn short_passphrase_is_refused() {
        let err = export_backup(sample_own(), sample_peers(), "short").unwrap_err();
        assert!(format!("{err}").contains("at least"));
    }

    #[test]
    fn empty_secret_is_refused() {
        let mut id = sample_own();
        id.secret = String::new();
        let err = export_backup(id, sample_peers(), "correct-horse-battery").unwrap_err();
        assert!(format!("{err}").contains("empty secret"));
    }

    #[test]
    fn envelope_is_valid_json() {
        let env = export_backup(sample_own(), sample_peers(), "correct-horse-battery").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&env).unwrap();
        assert_eq!(parsed["schema"], BACKUP_SCHEMA);
        assert!(parsed["created_at"].is_string());
        assert!(parsed["nonce"].is_string());
        assert!(parsed["ciphertext"].is_string());
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let env = export_backup(sample_own(), sample_peers(), "correct-horse-battery").unwrap();
        let mut parsed: serde_json::Value = serde_json::from_str(&env).unwrap();
        // Flip a character in the base64url ciphertext.
        let mut ct: String = parsed["ciphertext"].as_str().unwrap().into();
        let first = ct.chars().next().unwrap();
        let alt = if first == 'A' { 'B' } else { 'A' };
        ct.replace_range(0..1, &alt.to_string());
        parsed["ciphertext"] = serde_json::json!(ct);
        let tampered = serde_json::to_string(&parsed).unwrap();
        let err = import_backup(&tampered, "correct-horse-battery").unwrap_err();
        assert!(format!("{err}").contains("wrong passphrase"));
    }

    #[test]
    fn apply_backup_installs_own_identity_and_unions_peers() {
        let mut store = PeerStore::empty();
        let payload = BackupPayload {
            schema: STORE_SCHEMA.to_string(),
            own_identity: sample_own(),
            peers: sample_peers(),
        };
        apply_backup(&mut store, payload);
        assert!(store.own_identity.is_some());
        assert_eq!(store.own_identity.as_ref().unwrap().name, "alice");
        assert_eq!(store.peers.len(), 1);
    }

    #[test]
    fn schema_mismatch_is_rejected() {
        let mut parsed = serde_json::json!({
            "schema": "QEV-IDENTITY-BACKUP-V99-future",
            "created_at": "2026-04-17T00:00:00Z",
            "app_version": "0.99.0",
            "nonce": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "ciphertext": "aa",
        });
        let json = serde_json::to_string(&parsed).unwrap();
        let err = import_backup(&json, "any-passphrase").unwrap_err();
        assert!(format!("{err}").contains("unsupported backup schema"));
        let _ = parsed;
    }
}
