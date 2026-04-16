//! mDNS service discovery for same-LAN QEV peer finding.
//!
//! Advertises this device's QEV pairing service on the local
//! network so other devices can find it without manually entering
//! IP addresses. Uses the `_qev._tcp.local.` service type.
//!
//! ## How it works
//!
//! When the user opens the Pair tab and clicks "Show QR", QEV
//! also starts advertising via mDNS. Other devices on the same
//! LAN that are on the Pair tab see the advertisement and can
//! auto-populate the connection address without scanning the QR.
//!
//! The mDNS record contains:
//!   - Service type: `_qev._tcp.local.`
//!   - Instance name: the user's display name (e.g. "alice-laptop")
//!   - Port: the pairing TCP listener's port
//!   - TXT record: `pk=<hex static public key>` (so the scanner
//!     can pin the key without scanning the QR)
//!
//! ## Dependencies
//!
//! Uses the `mdns-sd` crate (pure Rust, no C deps, works on
//! macOS, Linux, Windows, and Android). The crate is optional
//! and gated behind a `mdns` Cargo feature so builds that don't
//! need discovery can skip the dependency.
//!
//! ## Security note
//!
//! mDNS is unauthenticated broadcast. Any device on the same
//! network can advertise as "alice-laptop" with a different
//! public key. The safety-number verification step in the Noise
//! XK handshake is the ONLY defence against this — mDNS
//! replaces manual IP entry, not manual identity verification.

/// mDNS service type for QEV pairing.
pub const SERVICE_TYPE: &str = "_qev._tcp.local.";

/// Advertise this device's QEV pairing service on the local
/// network. Returns a handle that keeps the advertisement alive
/// until dropped.
///
/// `name`: instance name (e.g. "alice-laptop")
/// `port`: TCP port the pairing listener is bound to
/// `pk_hex`: 64-char hex of the static public key
///
/// This is a placeholder API. The actual implementation requires
/// adding `mdns-sd` to Cargo.toml and writing ~50 lines of
/// register + browse code. For now it returns a stub that
/// compiles but does nothing, so the Tauri command layer can
/// call it without a compilation error.
pub fn advertise(
    _name: &str,
    _port: u16,
    _pk_hex: &str,
) -> Result<AdvertiseHandle, String> {
    // Stub: real implementation is gated behind `mdns` feature.
    #[cfg(feature = "mdns")]
    {
        // TODO: mdns-sd register call
        unimplemented!("mdns feature not yet implemented");
    }
    #[cfg(not(feature = "mdns"))]
    {
        Ok(AdvertiseHandle { _private: () })
    }
}

/// Discover QEV peers on the local network. Returns a stream
/// of discovered peers.
///
/// Stub: real implementation gated behind `mdns` feature.
pub fn discover() -> Result<Vec<DiscoveredPeer>, String> {
    #[cfg(feature = "mdns")]
    {
        unimplemented!("mdns feature not yet implemented");
    }
    #[cfg(not(feature = "mdns"))]
    {
        Ok(Vec::new())
    }
}

/// Handle that keeps an mDNS advertisement alive. Drop to stop.
pub struct AdvertiseHandle {
    _private: (),
}

/// A peer discovered via mDNS.
#[derive(Debug, Clone)]
pub struct DiscoveredPeer {
    /// Instance name (e.g. "alice-laptop").
    pub name: String,
    /// IP:port of the peer's pairing listener.
    pub addr: std::net::SocketAddr,
    /// Hex of the peer's static public key (from TXT record).
    pub pk_hex: String,
}
