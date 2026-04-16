//! qev-relay — federated store-and-forward for offline vault delivery.
//!
//! See `docs/qev/phase-3-relay.md` for the full design rationale.
//!
//! ## Module map
//!
//! - [`message`] — the `RelayMessage` CBOR RPC enum and its
//!   encode/decode helpers. Shared between the client and server.
//! - [`store`] — `EnvelopeStore` trait + `InMemoryStore` impl.
//!   Owned by the server; the client never touches it.
//! - [`client`] — `RelayClient` type. Opens a Noise XK session to
//!   a relay, sends one request, reads the response, closes.
//! - [`service`] — `RelayService` struct. Wraps a `TcpListener`
//!   and handles one inbound connection per spawned task.
//! - [`config`] — TOML config loader for the server binary.
//!
//! ## Protocol
//!
//! Client ↔ relay is **Noise XK over raw TCP**, reusing the entire
//! pairing crate's handshake + transport code. Inside that Noise
//! channel is a single length-prefixed CBOR `RelayMessage`.
//!
//! ```text
//! client                                relay
//! ──────                                ─────
//! TCP connect                        →
//!                                       TCP accept
//! Noise XK initiator (3 msgs)        ⇆  Noise XK responder
//!                                       (server learns client pk from msg 3)
//! CBOR RelayMessage::Deliver {         ⇆
//!   to: <recipient_pk>,
//!   envelope: <opaque>,
//! }                                     server stores envelope,
//!                                       assigns an id
//! CBOR RelayMessage::DeliverResult   ←
//!   { id: <16 bytes> }
//! TCP close
//! ```
//!
//! The server NEVER sees the envelope bytes as anything but opaque
//! — they're already Noise-wrapped by the sender for the final
//! recipient, and the relay's role is strictly to index by
//! `recipient_pk` and hand the bytes back on demand.
//!
//! ## Auth
//!
//! Auth is by Noise XK handshake. The server learns the client's
//! static public key in msg 3 of the handshake; every subsequent
//! RPC in the session is attributed to that key. No separate
//! token auth, no password, no JWT.
//!
//! ## Not goals for phase 3.0
//!
//! - Persistent store (we use in-memory for v1)
//! - Multi-relay federation
//! - Push notifications
//! - Web client bridge (web needs WebSocket, deferred)

#![deny(unsafe_code)]
#![warn(missing_docs)]

/// Current protocol version. Bump when `RelayMessage` changes
/// incompatibly.
pub const PROTOCOL_VERSION: &str = "QEV-RELAY-V1";

/// Maximum envelope size the server will accept in one Deliver
/// request. Matches the Phase 2 vault-size cap with a small
/// envelope for the Noise wrap overhead.
pub const MAX_ENVELOPE_BYTES: usize = 1_048_576 + 4096;

/// Envelope ID length in bytes. 16 random bytes = 128 bits of
/// entropy, uniformly distributed; collision probability is
/// negligible for any realistic server load.
pub const ENVELOPE_ID_BYTES: usize = 16;

/// Default listening port for a qev-relay server.
/// Not privileged, not conflicting with common services.
pub const DEFAULT_PORT: u16 = 7892;

pub mod client;
pub mod config;
pub mod error;
pub mod message;
pub mod service;
pub mod sqlite_store;
pub mod store;
pub mod ws_bridge;

pub use crate::client::RelayClient;
pub use crate::config::{Config, ServerConfig};
pub use crate::error::{Error, Result};
pub use crate::message::{RelayMessage, WireEnvelope};
pub use crate::service::RelayService;
pub use crate::sqlite_store::SqliteStore;
pub use crate::store::{Envelope, EnvelopeStore, InMemoryStore};
