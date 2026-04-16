//! Static X25519 keypair — the device's long-term identity.
//!
//! Every QEV device that participates in pairing has exactly one
//! `StaticKeypair`, generated once on first run and persisted in
//! the device's local database (with OS-keystore wrapping of the
//! private key where available).
//!
//! The public half ends up in every pairing QR code this device
//! emits. The private half never leaves the device.
//!
//! Key generation delegates to the Noise protocol framework's
//! random key generator so we don't accidentally use a weak RNG.
//! `snow::Keypair::generate()` internally uses
//! `rand_core::OsRng` on desktop/mobile/WASM, falling back to the
//! platform `getrandom` syscall.

use crate::error::{Error, Result};
use crate::{STATIC_KEY_BYTES, STATIC_SK_BYTES};
use serde::{Deserialize, Serialize};

/// Long-term static X25519 keypair for a QEV device.
///
/// The `secret` half is 32 bytes of X25519 private scalar. The
/// `public` half is 32 bytes of X25519 public key (the result of
/// `Curve25519(secret, base)`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticKeypair {
    /// 32-byte X25519 public key. Safe to publish.
    #[serde(with = "serde_bytes_array_32")]
    pub public: [u8; STATIC_KEY_BYTES],
    /// 32-byte X25519 private scalar. MUST NOT leave the device
    /// in plaintext. UI + persistence layers are responsible for
    /// wrapping this with the OS keystore.
    #[serde(with = "serde_bytes_array_32")]
    pub secret: [u8; STATIC_SK_BYTES],
}

impl StaticKeypair {
    /// Generate a fresh static keypair using the system RNG.
    ///
    /// Uses the Noise crate's internal key generation, which
    /// delegates to `rand_core::OsRng`. This is the only correct
    /// source of X25519 keys — don't roll your own.
    pub fn generate() -> Result<Self> {
        let builder = snow::Builder::new(
            crate::NOISE_PATTERN
                .parse()
                .map_err(|_| Error::Internal("bad Noise pattern".into()))?,
        );
        let keypair = builder
            .generate_keypair()
            .map_err(|e| Error::Internal(format!("key generation failed: {e}")))?;
        if keypair.public.len() != STATIC_KEY_BYTES || keypair.private.len() != STATIC_SK_BYTES {
            return Err(Error::Internal(format!(
                "unexpected key length: pk={} sk={}",
                keypair.public.len(),
                keypair.private.len()
            )));
        }
        let mut public = [0u8; STATIC_KEY_BYTES];
        let mut secret = [0u8; STATIC_SK_BYTES];
        public.copy_from_slice(&keypair.public);
        secret.copy_from_slice(&keypair.private);
        Ok(Self { public, secret })
    }

    /// Deterministically reconstruct a keypair from a raw 32-byte
    /// secret. Used on app startup to load the persisted identity.
    ///
    /// The public key is derived from the secret via X25519 scalar
    /// multiplication; we recompute it rather than storing it
    /// separately (avoids drift between secret and public in the
    /// database).
    pub fn from_secret(secret: [u8; STATIC_SK_BYTES]) -> Result<Self> {
        // x25519-dalek would be the clean answer but we don't want
        // another crypto dependency. Instead we use snow's raw
        // resolver to compute the DH public.
        //
        // snow exposes a DH trait we can drive directly via the
        // DefaultResolver — it returns a trait object with set() and
        // pubkey() methods.
        use snow::resolvers::{CryptoResolver, DefaultResolver};
        use snow::params::DHChoice;

        let resolver = DefaultResolver::default();
        let mut dh = resolver
            .resolve_dh(&DHChoice::Curve25519)
            .ok_or_else(|| Error::Internal("Curve25519 DH not available".into()))?;
        dh.set(&secret);

        let pub_bytes = dh.pubkey();
        if pub_bytes.len() != STATIC_KEY_BYTES {
            return Err(Error::Internal(format!(
                "DH public key wrong length: {}",
                pub_bytes.len()
            )));
        }
        let mut public = [0u8; STATIC_KEY_BYTES];
        public.copy_from_slice(pub_bytes);

        Ok(Self { public, secret })
    }

    /// Hex encoding of the public key (64 lowercase characters).
    /// Used for debugging and peer identification in logs.
    pub fn public_hex(&self) -> String {
        self.public.iter().fold(String::with_capacity(64), |mut acc, b| {
            acc.push_str(&format!("{b:02x}"));
            acc
        })
    }
}

// Serde helper for fixed-size byte arrays. ciborium doesn't support
// serializing [u8; N] as a byte string by default — it encodes as a
// CBOR array of 32 individual integers, which is 4x bigger on the
// wire. This helper maps through serde_bytes so the CBOR output is
// compact.
mod serde_bytes_array_32 {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 32], D::Error> {
        let v: Vec<u8> = serde_bytes::deserialize(de)?;
        if v.len() != 32 {
            return Err(serde::de::Error::invalid_length(v.len(), &"32 bytes"));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        Ok(out)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_valid_32_byte_keys() {
        let k = StaticKeypair::generate().expect("generate ok");
        assert_eq!(k.public.len(), 32);
        assert_eq!(k.secret.len(), 32);
        // The secret should NOT be all zeros (infinitesimal chance
        // in a correctly seeded RNG, essentially unreachable).
        assert!(k.secret.iter().any(|&b| b != 0));
    }

    #[test]
    fn generate_twice_produces_different_keys() {
        let a = StaticKeypair::generate().unwrap();
        let b = StaticKeypair::generate().unwrap();
        assert_ne!(a.public, b.public);
        assert_ne!(a.secret, b.secret);
    }

    #[test]
    fn from_secret_recomputes_public_deterministically() {
        let k1 = StaticKeypair::generate().unwrap();
        let k2 = StaticKeypair::from_secret(k1.secret).unwrap();
        assert_eq!(k1.public, k2.public);
        assert_eq!(k1.secret, k2.secret);
    }

    #[test]
    fn public_hex_has_64_lowercase_chars() {
        let k = StaticKeypair::generate().unwrap();
        let h = k.public_hex();
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }
}
