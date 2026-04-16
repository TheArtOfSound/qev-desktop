//! WebSocket bridge for web clients that can't speak raw TCP.
//!
//! The web vault at `secure.imagineqira.com/vault` runs in a
//! browser, which can only do HTTP/HTTPS/WS/WSS — not raw TCP.
//! This module adds a WebSocket listener that bridges WS frames
//! to the existing Noise XK relay protocol:
//!
//! ```text
//!   Browser (WS)  ←→  ws_bridge  ←→  Noise channel  ←→  relay store
//! ```
//!
//! Each WebSocket connection maps 1:1 to a Noise XK session.
//! The bridge:
//! 1. Accepts a WS connection on a configurable port (default 7893)
//! 2. Runs the Noise XK handshake with the server's static key
//!    (the same key used by the TCP listener)
//! 3. Forwards binary WS frames as Noise channel messages
//! 4. Forwards Noise channel messages as binary WS frames
//!
//! The browser-side JS would need a small adapter that wraps the
//! Noise handshake + CBOR encoding inside WS frames. That adapter
//! is NOT part of this crate — it lives in the landing/vault/ JS
//! bundle and is a phase 3.x follow-up.
//!
//! ## Status
//!
//! This module is a **stub**: the API is defined but the
//! implementation requires adding `tokio-tungstenite` as a dep
//! and writing ~100 lines of bidirectional frame relay. Deferred
//! until the web vault actually needs relay access (currently it
//! only does offline encryption/decryption with no network).

/// Default WebSocket bridge port.
pub const DEFAULT_WS_PORT: u16 = 7893;

/// Start the WebSocket bridge.
///
/// Stub: returns an error until the feature is implemented.
pub async fn start_ws_bridge(
    _ws_port: u16,
    _relay_addr: std::net::SocketAddr,
    _server_pk: [u8; 32],
) -> Result<(), String> {
    Err("WebSocket bridge not yet implemented (stub only)".into())
}
