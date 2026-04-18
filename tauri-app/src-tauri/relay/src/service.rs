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
use crate::{ENVELOPE_ID_BYTES, MAX_ENVELOPE_BYTES, MAX_LINK_PAYLOAD_BYTES, PROTOCOL_VERSION};

use qev_pairing::{Responder, StaticKeypair};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, trace, warn};

/// In-memory registry of currently-attached Qira Link live
/// sessions, keyed by the session's pk (learned from the Noise
/// handshake). Maps to an mpsc sender that the forwarding path
/// uses to deliver inbound packets to that session's writer loop.
type LiveSessions = Arc<Mutex<HashMap<[u8; 32], mpsc::UnboundedSender<RelayMessage>>>>;

/// Per-client rate limiter using a sliding-window counter.
/// Tokens refill at `max_per_minute / 60` per second.
struct RateLimiter {
    buckets: Mutex<HashMap<[u8; 32], RateBucket>>,
    max_per_minute: u32,
}

struct RateBucket {
    tokens: f64,
    last: Instant,
}

impl RateLimiter {
    fn new(max_per_minute: u32) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            max_per_minute,
        }
    }

    /// Consume one token for the given pk. Returns Ok(()) if
    /// allowed, Err with a message if rate-limited.
    async fn check(&self, pk: &[u8; 32]) -> std::result::Result<(), String> {
        let mut map = self.buckets.lock().await;
        let now = Instant::now();
        let refill_rate = self.max_per_minute as f64 / 60.0;
        let max = self.max_per_minute as f64;

        let bucket = map.entry(*pk).or_insert(RateBucket {
            tokens: max,
            last: now,
        });

        // Refill tokens based on elapsed time.
        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * refill_rate).min(max);
        bucket.last = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            Err(format!(
                "rate limited: max {} per minute",
                self.max_per_minute
            ))
        }
    }
}

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
    /// Per-sender delivery rate limiter.
    deliver_limiter: RateLimiter,
    /// Per-recipient fetch rate limiter.
    fetch_limiter: RateLimiter,
    /// Currently-attached Qira Link live sessions. Shared across
    /// every spawned connection task so one peer's LinkTunnel
    /// message can reach another peer's live session.
    live_sessions: LiveSessions,
}

impl<S> RelayService<S>
where
    S: EnvelopeStore + 'static,
{
    /// Construct a new service with default rate limits.
    pub fn new(keypair: StaticKeypair, store: Arc<S>) -> Self {
        Self::with_limits(keypair, store, 30, 60)
    }

    /// Construct with custom rate limits (requests per minute).
    pub fn with_limits(
        keypair: StaticKeypair,
        store: Arc<S>,
        deliver_per_min: u32,
        fetch_per_min: u32,
    ) -> Self {
        Self {
            keypair,
            store,
            deliver_limiter: RateLimiter::new(deliver_per_min),
            fetch_limiter: RateLimiter::new(fetch_per_min),
            live_sessions: Arc::new(Mutex::new(HashMap::new())),
        }
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

    /// Handle one inbound connection.
    ///
    /// After the Noise XK handshake, the first client message
    /// selects the session mode:
    ///
    /// - `LinkAttach` → live mode (Qira Link). The connection
    ///   stays open and the server forwards `LinkTunnel` messages
    ///   between this session and other attached sessions.
    /// - anything else → one-shot mode (legacy QEV vault
    ///   Deliver/Fetch/Ack). One request, one response, close.
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

        let request_bytes = channel.recv().await?;
        let request = RelayMessage::decode(&request_bytes)?;

        // Branch on mode. LinkAttach opens a live-mode loop that
        // doesn't return until the connection closes.
        if matches!(request, RelayMessage::LinkAttach {}) {
            return self.handle_live_session(peer_pk, channel).await;
        }

        // One-shot mode: dispatch the first request, send one
        // response, close.
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

    /// Run a Qira Link live session.
    ///
    /// Registers `peer_pk` in the live-session registry so other
    /// attached peers can target it. Enters a select loop that:
    ///
    /// 1. Reads `LinkTunnel` messages from the client and forwards
    ///    them to the recipient's mpsc (or replies `LinkUnreachable`
    ///    if no such recipient is attached).
    /// 2. Drains inbound `LinkInbound` messages from other sessions
    ///    and writes them out on this Noise channel.
    ///
    /// Exits cleanly on connection close or any write/read error.
    /// Always unregisters on exit.
    async fn handle_live_session<T>(
        &self,
        peer_pk: [u8; 32],
        mut channel: qev_pairing::Channel<T>,
    ) -> Result<()>
    where
        T: AsyncRead + AsyncWrite + Unpin,
    {
        // Create the mailbox the server-side forwarding path uses
        // to deliver inbound packets to this session.
        let (tx, mut rx) = mpsc::unbounded_channel::<RelayMessage>();

        // Register, atomically, refusing duplicates.
        {
            let mut map = self.live_sessions.lock().await;
            if map.contains_key(&peer_pk) {
                // Another live session already owns this pk.
                // Tell the new client and close the connection.
                drop(map);
                let err = RelayMessage::error(
                    "already_attached",
                    "another live session is already attached for this pk",
                );
                let _ = channel.send(&err.encode()?).await;
                return Ok(());
            }
            map.insert(peer_pk, tx);
        }

        // Acknowledge the attach.
        let ack = RelayMessage::LinkAttachAck {
            version: PROTOCOL_VERSION.to_string(),
            max_payload_bytes: MAX_LINK_PAYLOAD_BYTES as u32,
        };
        if let Err(e) = channel.send(&ack.encode()?).await {
            warn!(peer_pk = %hex32(&peer_pk), error = %e, "attach ack write failed");
            self.live_sessions.lock().await.remove(&peer_pk);
            return Err(e.into());
        }

        info!(peer_pk = %hex32(&peer_pk), "link live session attached");

        // Select loop: read-from-client OR deliver-from-mpsc.
        // `biased` drains outbound first when both are ready — this
        // keeps our latency low for the typical "many packets flowing"
        // case where mpsc is rarely idle.
        let result: Result<()> = loop {
            tokio::select! {
                biased;
                // Inbound from other sessions → write out to this client.
                maybe_msg = rx.recv() => {
                    let Some(msg) = maybe_msg else { break Ok(()); };
                    match msg.encode() {
                        Ok(bytes) => {
                            if let Err(e) = channel.send(&bytes).await {
                                debug!(peer_pk = %hex32(&peer_pk), error = %e, "live session send failed");
                                break Err(e.into());
                            }
                        }
                        Err(e) => {
                            warn!(peer_pk = %hex32(&peer_pk), error = %e, "encoding outbound LinkInbound failed");
                        }
                    }
                }
                // From-client → forward or respond LinkUnreachable.
                recv = channel.recv() => {
                    let bytes = match recv {
                        Ok(b) => b,
                        Err(e) => {
                            debug!(peer_pk = %hex32(&peer_pk), error = %e, "live session recv ended");
                            break Ok(());
                        }
                    };
                    match RelayMessage::decode(&bytes) {
                        Ok(RelayMessage::LinkTunnel { to, payload }) => {
                            if let Err(e) = self
                                .forward_link_tunnel(&peer_pk, to, payload)
                                .await
                            {
                                // Delivery failure → tell the sender.
                                match e {
                                    ForwardError::Unreachable(to_bytes) => {
                                        let reply = RelayMessage::LinkUnreachable { to: to_bytes };
                                        if let Err(e2) = channel.send(&reply.encode()?).await {
                                            break Err(e2.into());
                                        }
                                    }
                                    ForwardError::InvalidTo => {
                                        let reply = RelayMessage::error(
                                            "invalid_to",
                                            "LinkTunnel.to must be a 32-byte pk",
                                        );
                                        if let Err(e2) = channel.send(&reply.encode()?).await {
                                            break Err(e2.into());
                                        }
                                    }
                                    ForwardError::TooLarge(sz) => {
                                        let reply = RelayMessage::error(
                                            "too_large",
                                            format!("LinkTunnel payload {sz} bytes exceeds cap {MAX_LINK_PAYLOAD_BYTES}"),
                                        );
                                        if let Err(e2) = channel.send(&reply.encode()?).await {
                                            break Err(e2.into());
                                        }
                                    }
                                }
                            }
                        }
                        Ok(RelayMessage::LinkAttach {}) => {
                            // Duplicate attach on same session; ignore.
                            trace!(peer_pk = %hex32(&peer_pk), "duplicate LinkAttach in live session, ignored");
                        }
                        Ok(_other) => {
                            // Any other variant is invalid in live mode.
                            let reply = RelayMessage::error(
                                "protocol",
                                "live session only accepts LinkTunnel messages",
                            );
                            if let Err(e) = channel.send(&reply.encode()?).await {
                                break Err(e.into());
                            }
                        }
                        Err(e) => {
                            warn!(peer_pk = %hex32(&peer_pk), error = %e, "malformed live-mode message");
                        }
                    }
                }
            }
        };

        // Unregister on exit, regardless of outcome.
        self.live_sessions.lock().await.remove(&peer_pk);
        info!(peer_pk = %hex32(&peer_pk), "link live session detached");

        result
    }

    /// Try to deliver a LinkTunnel payload to the recipient's
    /// attached mpsc sender.
    async fn forward_link_tunnel(
        &self,
        from: &[u8; 32],
        to: Vec<u8>,
        payload: Vec<u8>,
    ) -> std::result::Result<(), ForwardError> {
        if payload.len() > MAX_LINK_PAYLOAD_BYTES {
            return Err(ForwardError::TooLarge(payload.len()));
        }
        if to.len() != 32 {
            return Err(ForwardError::InvalidTo);
        }
        let mut to_pk = [0u8; 32];
        to_pk.copy_from_slice(&to);

        let map = self.live_sessions.lock().await;
        let Some(sender) = map.get(&to_pk) else {
            return Err(ForwardError::Unreachable(to));
        };
        let inbound = RelayMessage::LinkInbound {
            from: from.to_vec(),
            payload,
        };
        // If the send fails the recipient's session is shutting
        // down — treat as unreachable so the sender is notified.
        sender
            .send(inbound)
            .map_err(|_| ForwardError::Unreachable(to))?;
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
                // Rate limit: per-sender delivery cap.
                self.deliver_limiter
                    .check(requester_pk)
                    .await
                    .map_err(Error::RateLimited)?;
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
                // Rate limit: per-recipient fetch cap.
                self.fetch_limiter
                    .check(requester_pk)
                    .await
                    .map_err(Error::RateLimited)?;
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
            | RelayMessage::Hello { .. }
            | RelayMessage::LinkAttachAck { .. }
            | RelayMessage::LinkInbound { .. }
            | RelayMessage::LinkUnreachable { .. } => Err(Error::Protocol(
                "client sent a server-only message variant".into(),
            )),

            // LinkAttach is handled earlier by `handle_connection`
            // before it reaches `dispatch` — if it slips through
            // here something is wrong.
            RelayMessage::LinkAttach {} => Err(Error::Protocol(
                "LinkAttach must be the first message on a session".into(),
            )),

            // LinkTunnel outside a live session has no context.
            RelayMessage::LinkTunnel { .. } => Err(Error::Protocol(
                "LinkTunnel only valid inside a live session".into(),
            )),
        }
    }
}

/// Error from `forward_link_tunnel`. Distinguished from the main
/// `Error` type because unreachable recipients aren't a fatal
/// problem for the live session — we just tell the sender and
/// keep going.
#[derive(Debug)]
enum ForwardError {
    /// The recipient is not currently attached.
    Unreachable(Vec<u8>),
    /// The `to` field wasn't 32 bytes.
    InvalidTo,
    /// The payload exceeded the max per-packet cap.
    TooLarge(usize),
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

