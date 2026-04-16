//! RelayService — the server-side accept loop and per-connection
//! request dispatcher.
//!
//! Spawns a tokio task per inbound connection. Each task:
//!
//! 1. Runs the Noise XK responder handshake against the client,
//!    pinning the server static keypair.
//! 2. Reads one `RelayMessage` request from the Noise channel.
//! 3. Dispatches to the store and builds a response.
//! 4. Sends the response through the Noise channel.
//! 5. Closes the connection.
//!
//! There is no session multiplexing in phase 3.0 — one request,
//! one response, one connection. Reconnect overhead is ~100 ms
//! per transaction including the Noise handshake, which is fine
//! for offline delivery. If we need high throughput later we
//! can add a stream-mode RPC inside the same Noise channel.

use crate::error::{Error, Result};
use crate::message::{check_id_bytes, check_pk_bytes, RelayMessage, WireEnvelope};
use crate::store::{Envelope, EnvelopeStore};
use crate::{ENVELOPE_ID_BYTES, MAX_ENVELOPE_BYTES};

use qev_pairing::{Responder, StaticKeypair};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

/// How many envelopes to return in a single fetch batch when the
/// client asks for "default." Also the max a client can ask for
/// in one Fetch request.
const DEFAULT_FETCH_LIMIT: u32 = 50;

/// The core relay service: holds the server's long-term static
/// keypair and a shared reference to the envelope store.
pub struct RelayService<S>
where
    S: EnvelopeStore + 'static,
{
    /// Long-term static keypair this server identifies as.
    pub keypair: StaticKeypair,
    /// Shared store. Wrapped in `Arc` so the accept loop can
    /// clone it into every spawned task.
    pub store: Arc<S>,
}

impl<S> RelayService<S>
where
    S: EnvelopeStore + 'static,
{
    /// Construct a new service.
    pub fn new(keypair: StaticKeypair, store: Arc<S>) -> Self {
        Self { keypair, store }
    }

    /// Bind a TCP listener and run the accept loop until
    /// `shutdown` fires. Each inbound connection is handled
    /// concurrently.
    pub async fn serve(
        self: Arc<Self>,
        addr: SocketAddr,
        mut shutdown: tokio::sync::oneshot::Receiver<()>,
    ) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;
        let actual = listener.local_addr()?;
        info!(%actual, "qev-relay listening");

        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown => {
                    info!("shutdown signal received, stopping accept loop");
                    break;
                }
                accept = listener.accept() => {
                    match accept {
                        Ok((stream, remote)) => {
                            let this = Arc::clone(&self);
                            tokio::spawn(async move {
                                if let Err(e) = this.handle_connection(stream, remote).await {
                                    warn!(?e, %remote, "connection handler failed");
                                }
                            });
                        }
                        Err(e) => {
                            error!(?e, "listener accept failed");
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Handle one inbound connection: Noise XK handshake, one
    /// request, one response, close.
    async fn handle_connection<T>(
        &self,
        stream: T,
        remote: SocketAddr,
    ) -> Result<()>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        let responder = Responder::new(&self.keypair)?;
        let mut channel = responder.run(stream).await?;
        let peer_pk = channel.peer_static_pk();
        info!(
            %remote,
            peer_pk = %hex32(&peer_pk),
            "handshake completed"
        );

        // Read one framed Noise message from the channel, decode
        // it as a RelayMessage, dispatch, and respond.
        let request_bytes = channel.recv().await?;
        let request = RelayMessage::decode(&request_bytes)?;

        let response = match self.dispatch(&peer_pk, request).await {
            Ok(r) => r,
            Err(e) => {
                let code = match &e {
                    Error::TooLarge { .. } => "too_large",
                    Error::RateLimited(_) => "rate_limited",
                    _ => "internal",
                };
                RelayMessage::error(code, format!("{e}"))
            }
        };

        let response_bytes = response.encode()?;
        channel.send(&response_bytes).await?;
        Ok(())
    }

    /// Dispatch a single request to the store and build a
    /// response. The requester's static pk from the Noise
    /// handshake is the auth principal.
    async fn dispatch(
        &self,
        requester_pk: &[u8; 32],
        request: RelayMessage,
    ) -> Result<RelayMessage> {
        match request {
            RelayMessage::Deliver { to, envelope } => {
                let to_pk = check_pk_bytes("to", &to)?;
                if envelope.len() > MAX_ENVELOPE_BYTES {
                    return Err(Error::TooLarge {
                        size: envelope.len(),
                        max: MAX_ENVELOPE_BYTES,
                    });
                }
                let now_ms = now_ms();
                let env = Envelope {
                    id: [0u8; ENVELOPE_ID_BYTES],
                    to: to_pk,
                    from: *requester_pk,
                    bytes: envelope,
                    created_at: now_ms,
                };
                let id = self.store.put(env).await?;
                Ok(RelayMessage::DeliverResult { id: id.to_vec() })
            }

            RelayMessage::Fetch { limit } => {
                let take = if limit == 0 || limit > DEFAULT_FETCH_LIMIT {
                    DEFAULT_FETCH_LIMIT as usize
                } else {
                    limit as usize
                };
                let (batch, has_more) = self.store.get_pending(requester_pk, take).await?;
                let envelopes: Vec<WireEnvelope> = batch
                    .into_iter()
                    .map(|e| WireEnvelope {
                        id: e.id.to_vec(),
                        from: e.from.to_vec(),
                        envelope: e.bytes,
                        created_at: e.created_at,
                    })
                    .collect();
                Ok(RelayMessage::FetchResult {
                    envelopes,
                    has_more,
                })
            }

            RelayMessage::Ack { ids } => {
                let mut parsed: Vec<[u8; ENVELOPE_ID_BYTES]> = Vec::with_capacity(ids.len());
                for (i, id) in ids.iter().enumerate() {
                    parsed.push(check_id_bytes(&format!("ids[{i}]"), id)?);
                }
                let deleted = self.store.delete(requester_pk, &parsed).await?;
                Ok(RelayMessage::AckResult {
                    deleted: deleted as u32,
                })
            }

            // Server → client messages aren't valid as requests.
            RelayMessage::DeliverResult { .. }
            | RelayMessage::FetchResult { .. }
            | RelayMessage::AckResult { .. }
            | RelayMessage::Error { .. }
            | RelayMessage::Hello { .. } => Err(Error::Protocol(
                "client sent a server-only message variant".into(),
            )),
        }
    }
}

// ---- Helpers ----

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().fold(String::with_capacity(64), |mut s, b| {
        s.push_str(&format!("{b:02x}"));
        s
    })
}

