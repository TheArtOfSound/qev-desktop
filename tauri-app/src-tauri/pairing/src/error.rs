//! Error type for the pairing crate.
//!
//! Each variant is a distinct failure mode that the UI layer may want
//! to present differently to the user. Noise handshake failures and
//! malformed invite parsing get their own variants so the UI can
//! show "Could not decrypt the invite — is the QR readable?" vs.
//! "The other device didn't respond — same network?"

use thiserror::Error;

/// Unified error type for the pairing crate.
#[derive(Debug, Error)]
pub enum Error {
    /// Pairing invite was malformed (bad base64, bad CBOR, missing
    /// required fields, wrong schema version).
    #[error("malformed invite: {0}")]
    Invite(String),

    /// Pairing invite has expired. The expiry is a client-side
    /// policy — invites are valid for 10 minutes by default.
    #[error("invite expired at {0}")]
    InviteExpired(String),

    /// Noise handshake failed. Includes the failure phase for
    /// diagnostic display.
    #[error("Noise handshake failed: {0}")]
    Handshake(String),

    /// Noise transport message could not be decrypted. This is
    /// reported distinctly from handshake failures because once
    /// the channel is established, transport failures usually mean
    /// the peer is sending something bogus.
    #[error("transport message decrypt failed: {0}")]
    TransportDecrypt(String),

    /// A message exceeded the maximum transport frame size.
    #[error("transport message too large: {size} bytes (max {max})")]
    TransportTooLarge {
        /// Size of the offending message.
        size: usize,
        /// Maximum allowed size.
        max: usize,
    },

    /// I/O error (socket closed, read timeout, etc.).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// CBOR encoding/decoding error.
    #[error("cbor: {0}")]
    Cbor(String),

    /// Internal invariant violation — should never happen in a
    /// correct implementation. Always a bug.
    #[error("internal bug: {0}")]
    Internal(String),
}

impl From<snow::Error> for Error {
    fn from(e: snow::Error) -> Self {
        Error::Handshake(e.to_string())
    }
}

impl<T> From<ciborium::ser::Error<T>> for Error
where
    T: std::fmt::Display + std::fmt::Debug,
{
    fn from(e: ciborium::ser::Error<T>) -> Self {
        Error::Cbor(format!("encode: {e}"))
    }
}

impl<T> From<ciborium::de::Error<T>> for Error
where
    T: std::fmt::Display + std::fmt::Debug,
{
    fn from(e: ciborium::de::Error<T>) -> Self {
        Error::Cbor(format!("decode: {e}"))
    }
}

/// Result type alias using this crate's [`Error`].
pub type Result<T> = std::result::Result<T, Error>;
