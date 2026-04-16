//! Error type for the relay crate. Distinct variants for each
//! failure mode so the UI + logs can present them differently.

use thiserror::Error;

/// Unified error for the relay crate.
#[derive(Debug, Error)]
pub enum Error {
    /// Network I/O error (connect, read, write, close).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// Noise handshake or transport error bubbled up from
    /// qev-pairing.
    #[error("pairing: {0}")]
    Pairing(#[from] qev_pairing::Error),

    /// CBOR encode/decode failure.
    #[error("cbor: {0}")]
    Cbor(String),

    /// Server returned an explicit error response for a request
    /// that was otherwise well-formed.
    #[error("relay: {code}: {msg}")]
    Server {
        /// Error code the server returned.
        code: String,
        /// Human-readable message the server attached.
        msg: String,
    },

    /// Protocol violation — the server sent a response type the
    /// client wasn't expecting for the sent request.
    #[error("protocol: unexpected response: {0}")]
    Protocol(String),

    /// Rate limit exceeded for this client. The UI should show
    /// a retry-after hint.
    #[error("rate limited: {0}")]
    RateLimited(String),

    /// Envelope exceeded the server's maximum size cap.
    #[error("envelope too large: {size} bytes (max {max})")]
    TooLarge {
        /// The rejected envelope size.
        size: usize,
        /// The server's maximum.
        max: usize,
    },

    /// Internal invariant violation. Should never happen in
    /// correct code.
    #[error("internal: {0}")]
    Internal(String),
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
