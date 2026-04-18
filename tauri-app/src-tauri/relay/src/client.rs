//! RelayClient — the client-side half of the relay protocol.
//!
//! Each method opens a fresh TCP connection, runs the Noise XK
//! handshake against the relay's well-known static public key,
//! sends one `RelayMessage` request, reads the response, closes.
//! No persistent connection pool — reconnect is cheap and keeps
//! the command layer stateless.
//!
//! Two flavours:
//!
//! 1. `new(addr, server_pk, own)` — real TCP to a remote relay.
//! 2. `new_with_stream(stream, server_pk, own)` — internal helper
//!    used by tests to drive the protocol over a `tokio::io::duplex`
//!    pair. The public API uses `new`; tests use the helper.

use crate::error::{Error, Result};
use crate::message::{check_id_bytes, check_pk_bytes, RelayMessage, WireEnvelope};
use crate::{ENVELOPE_ID_BYTES};

use qev_pairing::{Initiator, StaticKeypair};
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

/// Client handle to a specific relay server.
///
/// Holds the remote address, the pinned server static public
/// key, and the client's own static keypair. Cheap to clone
/// (just three fields plus a `SocketAddr`).
#[derive(Clone)]
pub struct RelayClient {
    /// TCP address of the relay.
    pub addr: SocketAddr,
    /// Pinned server static public key. If the server presents a
    /// different key during the handshake, the connection is
    /// rejected — classic MITM protection.
    pub server_pk: [u8; 32],
    /// The client's own long-term static keypair. The relay
    /// learns the public half during the Noise XK handshake
    /// (msg 3) and uses it as the auth principal for every
    /// request in the session.
    pub own: StaticKeypair,
}

/// Result of a Fetch request.
#[derive(Debug, Clone)]
pub struct FetchResult {
    /// Pending envelopes, oldest first.
    pub envelopes: Vec<FetchedEnvelope>,
    /// True if more envelopes are queued beyond this batch.
    pub has_more: bool,
}

/// One envelope returned to a Fetch caller.
#[derive(Debug, Clone)]
pub struct FetchedEnvelope {
    /// 16-byte opaque envelope ID.
    pub id: [u8; ENVELOPE_ID_BYTES],
    /// Sender's 32-byte static public key.
    pub from: [u8; 32],
    /// Opaque envelope bytes. The caller is expected to unwrap
    /// this using their own decryption path (e.g. feed it to the
    /// vault decrypt after the phrase prompt).
    pub bytes: Vec<u8>,
    /// Unix milliseconds when the server received the envelope.
    pub created_at: u64,
}

impl RelayClient {
    /// Construct a client with a real TCP address.
    pub fn new(addr: SocketAddr, server_pk: [u8; 32], own: StaticKeypair) -> Self {
        Self {
            addr,
            server_pk,
            own,
        }
    }

    /// Deliver an envelope to a recipient pk. Returns the
    /// server-assigned envelope ID.
    pub async fn deliver(
        &self,
        to: &[u8; 32],
        envelope_bytes: Vec<u8>,
    ) -> Result<[u8; ENVELOPE_ID_BYTES]> {
        // Pre-flight size check so we don't open a TCP
        // connection just to discover the payload is too big.
        // RelayMessage::encode also enforces this server-side
        // but catching it early saves the round trip.
        if envelope_bytes.len() > crate::MAX_ENVELOPE_BYTES {
            return Err(Error::TooLarge {
                size: envelope_bytes.len(),
                max: crate::MAX_ENVELOPE_BYTES,
            });
        }
        let request = RelayMessage::Deliver {
            to: to.to_vec(),
            envelope: envelope_bytes,
        };
        let response = self.one_shot(request).await?;
        match response {
            RelayMessage::DeliverResult { id } => {
                check_id_bytes("DeliverResult.id", &id).map_err(Into::into)
            }
            RelayMessage::Error { code, msg } => Err(Error::Server { code, msg }),
            other => Err(Error::Protocol(format!(
                "expected DeliverResult, got {:?}",
                discriminant(&other)
            ))),
        }
    }

    /// Fetch up to `limit` pending envelopes addressed to our
    /// own pk. Pass 0 for the server's default limit.
    pub async fn fetch(&self, limit: u32) -> Result<FetchResult> {
        let request = RelayMessage::Fetch { limit };
        let response = self.one_shot(request).await?;
        match response {
            RelayMessage::FetchResult {
                envelopes,
                has_more,
            } => {
                let mut parsed = Vec::with_capacity(envelopes.len());
                for wenv in envelopes {
                    parsed.push(wire_to_fetched(wenv)?);
                }
                Ok(FetchResult {
                    envelopes: parsed,
                    has_more,
                })
            }
            RelayMessage::Error { code, msg } => Err(Error::Server { code, msg }),
            other => Err(Error::Protocol(format!(
                "expected FetchResult, got {:?}",
                discriminant(&other)
            ))),
        }
    }

    /// Tell the server it can delete the given envelope IDs from
    /// our inbox. Call this after successfully saving / decrypting
    /// the envelope on the client side. Returns the number
    /// actually deleted (typically == ids.len()).
    pub async fn ack(&self, ids: &[[u8; ENVELOPE_ID_BYTES]]) -> Result<u32> {
        let request = RelayMessage::Ack {
            ids: ids.iter().map(|id| id.to_vec()).collect(),
        };
        let response = self.one_shot(request).await?;
        match response {
            RelayMessage::AckResult { deleted } => Ok(deleted),
            RelayMessage::Error { code, msg } => Err(Error::Server { code, msg }),
            other => Err(Error::Protocol(format!(
                "expected AckResult, got {:?}",
                discriminant(&other)
            ))),
        }
    }

    /// Open a fresh TCP connection to the relay, run the Noise
    /// XK handshake, send one request, read one response, close.
    /// Internal helper shared by `deliver`, `fetch`, and `ack`.
    async fn one_shot(&self, request: RelayMessage) -> Result<RelayMessage> {
        let stream = TcpStream::connect(self.addr).await?;
        Self::one_shot_on_stream(stream, self.server_pk, &self.own, request).await
    }

    /// Same as `one_shot` but driven against a caller-supplied
    /// async stream. Used by the integration tests to exercise
    /// the protocol over `tokio::io::duplex` without opening a
    /// real TCP socket.
    pub async fn one_shot_on_stream<S>(
        stream: S,
        server_pk: [u8; 32],
        own: &StaticKeypair,
        request: RelayMessage,
    ) -> Result<RelayMessage>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let initiator = Initiator::new(own, server_pk)?;
        let mut channel = initiator.run(stream).await?;
        let request_bytes = request.encode()?;
        channel.send(&request_bytes).await?;
        let response_bytes = channel.recv().await?;
        Ok(RelayMessage::decode(&response_bytes)?)
    }
}

fn wire_to_fetched(w: WireEnvelope) -> Result<FetchedEnvelope> {
    let id = check_id_bytes("envelope.id", &w.id)?;
    let from = check_pk_bytes("envelope.from", &w.from)?;
    Ok(FetchedEnvelope {
        id,
        from,
        bytes: w.envelope,
        created_at: w.created_at,
    })
}

fn discriminant(m: &RelayMessage) -> &'static str {
    match m {
        RelayMessage::Deliver { .. } => "Deliver",
        RelayMessage::DeliverResult { .. } => "DeliverResult",
        RelayMessage::Fetch { .. } => "Fetch",
        RelayMessage::FetchResult { .. } => "FetchResult",
        RelayMessage::Ack { .. } => "Ack",
        RelayMessage::AckResult { .. } => "AckResult",
        RelayMessage::Error { .. } => "Error",
        RelayMessage::Hello { .. } => "Hello",
        RelayMessage::LinkAttach { .. } => "LinkAttach",
        RelayMessage::LinkAttachAck { .. } => "LinkAttachAck",
        RelayMessage::LinkTunnel { .. } => "LinkTunnel",
        RelayMessage::LinkInbound { .. } => "LinkInbound",
        RelayMessage::LinkUnreachable { .. } => "LinkUnreachable",
    }
}
