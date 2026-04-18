//! Hardcoded production relay defaults for the QEV app.
//!
//! The relay at `secure.imagineqira.com:7892` has a fixed
//! long-term X25519 static public key. Every QEV client pins
//! this key at compile time; if the remote server ever presents
//! a different key, the Noise XK handshake will fail and the
//! client will refuse to deliver or fetch. This is the standard
//! pinned-public-key pattern — equivalent in effect to pinning
//! a TLS certificate, but without the CA ceremony.
//!
//! ## How to rotate
//!
//! If the private key ever leaks or needs rotation:
//!
//! 1. Generate a fresh `data/qev-relay-server-static.json` on a
//!    trusted dev machine by running `qev-relay-server` once.
//! 2. Copy the public key hex into [`RELAY_SERVER_PUBLIC_KEY_HEX`]
//!    below and commit the change.
//! 3. Tag a new release (any version bump) and rebuild the
//!    distributed artifacts so the new pinned key ships.
//! 4. Upload the new private key file to the server and restart
//!    `qev-relay-server`.
//! 5. Old clients will fail to connect to the new server and
//!    should show a "relay key changed — update QEV" hint in
//!    the UI. (TODO: that hint is not yet implemented.)

/// DNS name of the default relay.
pub const RELAY_HOST: &str = "secure.imagineqira.com";

/// TCP port the default relay listens on. Matches the crate-
/// level default in `qev-relay`.
pub const RELAY_PORT: u16 = 7892;

/// Hex-encoded 32-byte X25519 public key of the default relay.
///
/// Generated 2026-04-16 by running `qev-relay-server` locally
/// with `QEV_RELAY_IDENTITY=data/qev-relay-server-static.json`.
/// The corresponding private key is deployed to the server and
/// is NOT committed to this repository.
pub const RELAY_SERVER_PUBLIC_KEY_HEX: &str =
    "b6b77291e633e4ed98918a5ac90e4b2e5083da2a787497785677150d9fcf3749";

/// Resolve the relay's DNS name to a SocketAddr. `SocketAddr::parse`
/// only accepts IP:PORT — it cannot resolve DNS names. We use DNS
/// lookup to resolve `secure.imagineqira.com` to an IP and return
/// the first resolved address. This is the critical fix — without
/// it, every relay command fails with "bad relay addr".
pub async fn relay_socket_addr() -> Result<std::net::SocketAddr, String> {
    use tokio::net::lookup_host;
    let host_port = format!("{}:{}", RELAY_HOST, RELAY_PORT);
    let mut addrs = lookup_host(&host_port)
        .await
        .map_err(|e| format!("DNS lookup failed for {host_port}: {e}"))?;
    addrs
        .next()
        .ok_or_else(|| format!("no addresses resolved for {host_port}"))
}

/// Convert [`RELAY_SERVER_PUBLIC_KEY_HEX`] to its 32-byte
/// binary representation. Returns an error if the constant is
/// malformed — which would be a bug caught at compile/run time
/// the first time any relay command runs.
pub fn relay_server_public_key_bytes() -> Result<[u8; 32], String> {
    if RELAY_SERVER_PUBLIC_KEY_HEX.len() != 64 {
        return Err(format!(
            "RELAY_SERVER_PUBLIC_KEY_HEX wrong length: {}",
            RELAY_SERVER_PUBLIC_KEY_HEX.len()
        ));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&RELAY_SERVER_PUBLIC_KEY_HEX[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("hex byte {i}: {e}"))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_key_hex_parses_to_32_bytes() {
        let bytes = relay_server_public_key_bytes().expect("valid hex");
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[0], 0xb6);
        assert_eq!(bytes[31], 0x49);
    }
}
