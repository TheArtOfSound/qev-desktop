//! qev-pairing — QR-based device pairing and direct P2P vault transfer
//! over a Noise XK channel.
//!
//! See `docs/qev/phase-2-pairing.md` for the full design rationale.
//!
//! ## Module map
//!
//! - [`identity`] — long-term static X25519 keypair generation and
//!   serialization. Each device has exactly one identity; it's the
//!   anchor for all of that device's pairings.
//! - [`invite`] — `PairingInvite` struct, CBOR encoding, base64url,
//!   and QR code rendering. This is what gets displayed on screen
//!   during the in-person pairing step.
//! - [`handshake`] — the [Noise XK](https://noiseprotocol.org/noise.html#handshake-patterns-identifiers)
//!   initiator and responder, wrapping the `snow` crate with a
//!   convenient async API that plays well with `tokio::io`.
//! - [`transport`] — post-handshake framed messaging. Each message
//!   is a CBOR-encoded `QevMessage`, length-prefixed, then passed
//!   through the Noise session's encrypt/decrypt.
//! - [`safety`] — 30-digit safety number derivation (BLAKE2b over
//!   both static public keys, sorted) for the in-person verification
//!   step. Same technique Signal uses for its "safety numbers".
//!
//! ## High-level flow
//!
//! ```text
//!   Alice                                     Bob
//!   ─────                                     ───
//!   1. identity::StaticKeypair::generate()    (already has one)
//!   2. invite::PairingInvite::new(...)
//!   3. invite.encode_qr()  →  [QR shown on screen]
//!                                              4. scan QR → invite
//!                                              5. invite.decode_cbor()
//!                                              6. handshake::Initiator::new(
//!                                                     invite.static_pk,
//!                                                     &own_keypair
//!                                                 )
//!   7. handshake::Responder::new(&own_keypair)
//!   8.   <- Noise XK handshake (3 msgs total) ->
//!   9. channel = handshake.complete(io)
//!                                              9. channel = handshake.complete(io)
//!  10. safety_number = channel.safety_number()
//!  11.   "Does your device show 12345-67890-...?" → user confirms
//!  12.   persist peer with trust = "verified"
//!  13. channel.send(QevMessage::VaultTransfer { ... }).await
//!                                             13. let msg = channel.recv().await
//!                                                 // vault_bytes decoded and
//!                                                 // handed to chat.js for
//!                                                 // phrase-based decrypt
//! ```
//!
//! ## Security boundaries
//!
//! Things Noise XK gives us:
//! - Mutual authentication (both sides prove they hold the static keys
//!   that appeared in the QR codes)
//! - Confidentiality on the wire (ephemeral X25519 → forward secrecy)
//! - Integrity (ChaCha20-Poly1305 AEAD on every transport message)
//!
//! Things Noise XK does NOT give us:
//! - Protection against the scanner displaying a QR with the wrong
//!   static_pk. The safety number verification step is the
//!   user-facing mitigation.
//! - Protection against malware on either endpoint. See the threat
//!   model section in phase-2-pairing.md.
//! - Offline delivery. That's Phase 3.
//!
//! ## Constants (pinned invariants)
//!
//! Any drift in these constants breaks cross-implementation pairing.

#![deny(unsafe_code)]
#![warn(missing_docs)]

/// Noise protocol pattern we use for pairing. XK = responder static
/// key is pre-known to the initiator (via the scanned QR code).
pub const NOISE_PATTERN: &str = "Noise_XK_25519_ChaChaPoly_BLAKE2b";

/// Length of a static X25519 public key in bytes.
pub const STATIC_KEY_BYTES: usize = 32;

/// Length of a static X25519 private key in bytes.
pub const STATIC_SK_BYTES: usize = 32;

/// Maximum size of a single QEV transport message before
/// fragmentation. Matches the Noise spec's MSG_LIMIT of 65535 bytes
/// minus the 16-byte AEAD tag.
pub const MAX_TRANSPORT_MSG: usize = 65535 - 16;

/// Maximum total vault size accepted by the transport layer.
/// Matches the MAX_CIPHERTEXT_BYTES cap in the vault layer.
pub const MAX_VAULT_BYTES: usize = 1024 * 1024;

/// Current pairing invite schema version. Bump when the on-wire
/// format changes incompatibly.
pub const INVITE_SCHEMA: &str = "QEV-PAIRING-V1";

/// QEV version that produced the invite. Cosmetic; used for display
/// in UI so users can see "Alice's QEV v0.29.0 is pairing with..."
pub const QEV_VERSION: &str = "0.29.0";

pub mod chat_store;
pub mod error;
pub mod handshake;
pub mod identity;
pub mod identity_backup;
pub mod invite;
pub mod keystore;
pub mod mdns;
pub mod peer_store;
pub mod push;
pub mod safety;
pub mod seal;
pub mod transport;

pub use crate::error::{Error, Result};
pub use crate::handshake::{Channel, Initiator, Responder};
pub use crate::identity::StaticKeypair;
pub use crate::invite::PairingInvite;
pub use crate::peer_store::{pk_to_hex, store_path, OwnIdentity, PeerStore, StoredPeer, TrustLevel};
pub use crate::safety::safety_number;
pub use crate::seal::{is_sealed, seal_vault, unseal_vault};
pub use crate::transport::{ChannelExt, QevMessage};
