# Phase 3 — Federated relay for offline delivery

**Status:** design, code starting  
**Target:** QEV desktop + Android + CLI + web  
**Dependencies:** Phase 2 (Noise XK + pair + persistent peer store) complete  
**Estimated work:** 2–3 weeks of focused work for a usable MVP  
**Ship criterion:** Alice can send Bob a vault at 10:00 am via a QEV-hosted relay; Bob's phone comes online at 3:00 pm and pulls the envelope down. Same end-to-end safety properties as a direct P2P send — the relay only sees opaque ciphertext plus the minimum metadata to route.

---

## What Phase 3 adds

Phase 2 requires both paired devices to be on the same LAN **at the same moment** for a transfer to land. Phase 3 removes that requirement by introducing a store-and-forward relay: a QEV-hosted server that accepts encrypted envelopes addressed to a recipient's static public key, holds them until the recipient is online, then delivers them on request.

Critically, the relay sees only:

- The **recipient's static public key** (needed to route)
- The **sender's static public key** (needed for spam mitigation and abuse reporting)
- An **opaque byte blob** containing the Noise-wrapped vault bytes
- A **timestamp** (when the envelope was deposited)
- The envelope's **size**

The relay does NOT see:

- The vault bytes (they're inside a Noise ciphertext addressed to the recipient's pk)
- The recipient's phrase (Phase 0 property — the phrase never leaves the endpoint)
- The sender-recipient relationship graph, beyond the pair of public keys on each envelope
- Plaintext message contents, filenames, sender notes — all inside the Noise wrap
- User identities (names, device labels) — those only appear inside the Noise wrap

A user who distrusts the relay operator can run their own; the protocol is pure store-and-forward and a compatible server is ~500 lines of Rust.

---

## Why not use Phase 2 direct P2P as a fallback

Phase 2 works only on the same LAN. Typical failure modes on mobile:

- Alice is at home, Bob is at the office (different networks)
- Alice is on cellular, Bob is on Wi-Fi (can't route to each other)
- Bob's phone is asleep when Alice sends (no listener accepting)
- A firewall blocks inbound connections on the recipient's side (NAT)

A federated relay handles all four. The alternative is no offline delivery, which is a huge usability gap in the "messenger-like" framing.

---

## Protocol choice — Noise XK over raw TCP, not HTTP

The relay is NOT an HTTP server. It's a raw TCP service speaking Noise XK with a length-prefixed CBOR RPC layer on top. Three reasons:

1. **Reuse Phase 2 code.** qev-pairing already has `Initiator`, `Responder`, `Channel`, `ChannelExt`, and `QevMessage`. The relay reuses all of it — the client's existing handshake + transport code talks to the relay with zero new primitives.
2. **Authentication by identity.** The relay's Noise XK handshake learns the client's static public key as part of the handshake (msg 3). Every subsequent RPC is authenticated as "the device owning this static key" — no separate token auth, no JWT, no password. The recipient's pk is the routing key AND the auth principal.
3. **No HTTPS ceremony.** TLS inside Noise would be double encryption. The relay's well-known static public key takes the role of a TLS server certificate: the client pins it at build time, and a MITM who swapped in a different key would fail the handshake. No certificate authority needed.

Trade-off: browsers can't speak raw TCP, so the web vault at `secure.imagineqira.com/vault` can NOT directly talk to the relay without a bridge. Desktop + Android + CLI can. For Phase 3.0 we accept this and document it; Phase 3.x adds a WebSocket bridge for the web client.

---

## Wire format — RPC messages over the Noise channel

The Noise channel carries length-prefixed framed messages; we add a new CBOR-encoded `RelayMessage` enum on top of `QevMessage` for the RPC layer.

```cbor
RelayMessage = {
    "type": "deliver-v1",
    "to":            bytes(32),   ; recipient's static public key
    "envelope":      bytes(<=1MiB); Noise-wrapped vault bytes
}
  | {
    "type": "fetch-v1",
                                  ; (no body — server uses our static
                                  ;  pk from the handshake to route)
}
  | {
    "type": "fetch-result-v1",
    "envelopes": [
        {
            "id":         bytes(16),  ; opaque envelope id
            "from":       bytes(32),  ; sender's static public key
            "envelope":   bytes,      ; Noise-wrapped payload
            "created_at": uint,       ; unix ms
        },
        ...
    ],
    "has_more": bool,
}
  | {
    "type": "ack-v1",
    "ids": [ bytes(16), ... ],  ; envelope ids to delete
}
  | {
    "type": "ack-result-v1",
    "deleted": uint,
}
  | {
    "type": "error-v1",
    "code": "rate_limited" | "too_large" | "invalid_to" | "internal",
    "msg": string,
}
```

The relay is stateless from the RPC perspective — no session cookies, no server-side state beyond the envelope store. Each client reconnects a fresh Noise XK session on demand.

---

## Server design

### Module layout

```
qev-relay/
├── Cargo.toml
├── src/
│   ├── lib.rs          # re-exports + Config type
│   ├── store.rs        # EnvelopeStore trait + InMemoryStore + (later) SqliteStore
│   ├── service.rs      # RelayService: accept + handshake + handle RPC
│   ├── config.rs       # Config loading (TOML + env overrides)
│   └── main.rs         # binary entry point (qev-relay-server)
└── tests/
    └── e2e.rs          # in-process client+server integration test
```

The crate lives at `tauri-app/src-tauri/relay/` as a sibling of `pairing/`.

### Envelope store trait

```rust
#[async_trait]
pub trait EnvelopeStore: Send + Sync {
    /// Store an envelope for a given recipient pk.
    /// Returns the assigned envelope id (16 random bytes).
    async fn put(&self, env: Envelope) -> Result<[u8; 16]>;

    /// Return all pending envelopes for a recipient pk,
    /// up to `limit`. Oldest first.
    async fn get_pending(&self, to: &[u8; 32], limit: usize) -> Result<Vec<Envelope>>;

    /// Delete envelopes by id (after ack).
    async fn delete(&self, ids: &[[u8; 16]]) -> Result<usize>;

    /// Count envelopes pending for a recipient (for rate limiting).
    async fn count_pending(&self, to: &[u8; 32]) -> Result<usize>;
}

pub struct Envelope {
    pub id: [u8; 16],
    pub to: [u8; 32],
    pub from: [u8; 32],
    pub bytes: Vec<u8>,
    pub created_at: u64,   // unix ms
}
```

v1 ships with `InMemoryStore` backed by `RwLock<HashMap<[u8; 32], VecDeque<Envelope>>>`. Small — maybe 1000 envelopes in flight at a time — with an eviction policy: drop oldest past 30 days, drop oldest past 100 per recipient. A phase 3.x follow-up replaces this with SQLite for persistence across server restarts.

### Service loop

```
listen on 0.0.0.0:{port}
for each inbound connection:
    spawn task {
        responder = Responder::new(relay_static_keypair)
        channel = responder.run(stream).await?
        loop {
            request = channel.recv_relay_message().await?
            response = handle(request, channel.peer_static_pk(), store).await?
            channel.send_relay_message(response).await?
        }
    }
```

Rate limits are enforced per `from` (sender pk):
- Deliver: ≤ 30 envelopes / minute per sender
- Fetch: ≤ 60 fetches / minute per recipient
- Envelope size: ≤ 1 MiB

Violations return `RelayMessage::Error { code: "rate_limited" }` but do NOT close the connection — the client can retry after a back-off.

### Configuration

```toml
# /etc/qev-relay/config.toml
[server]
listen = "0.0.0.0:7892"
# Path to the long-term server static keypair.
# If missing, generated on first launch and written here with 0600.
identity_path = "/var/lib/qev-relay/server-static.json"

[store]
type = "in-memory"
max_per_recipient = 100
retention_hours = 720    # 30 days

[limits]
deliver_per_minute = 30
fetch_per_minute = 60
max_envelope_bytes = 1048576
```

Env var overrides: `QEV_RELAY_LISTEN`, `QEV_RELAY_IDENTITY`, etc.

---

## Client design (inside `qev-pairing::relay`)

```rust
pub struct RelayClient {
    base: SocketAddr,
    server_pk: [u8; 32],
    own: StaticKeypair,
}

impl RelayClient {
    /// Construct a client against a specific relay.
    pub fn new(base: SocketAddr, server_pk: [u8; 32], own: StaticKeypair) -> Self;

    /// Deliver an envelope to a recipient. Returns the envelope id.
    pub async fn deliver(
        &self,
        to: &[u8; 32],
        envelope_bytes: Vec<u8>,
    ) -> Result<[u8; 16]>;

    /// Fetch pending envelopes addressed to our own static pk.
    /// Returns a list plus a "has_more" flag.
    pub async fn fetch(&self) -> Result<FetchResult>;

    /// Ack a batch of envelope ids (tells the server to delete).
    pub async fn ack(&self, ids: &[[u8; 16]]) -> Result<usize>;
}
```

Internally each method opens a new TCP connection, runs the Noise XK handshake, sends one `RelayMessage`, reads the response, closes. There's no persistent connection pool in v1 — reconnect is cheap and the common case is "occasional offline delivery," not a chat thread with high message rate.

---

## Where the client gets the relay address + server_pk

Three options:

1. **Hardcoded in the binary.** Simplest. Default relay = `secure.imagineqira.com:7892` with a pinned server static key. Users who distrust us run their own relay and override via CLI or config.
2. **User-configurable in a settings screen.** Phase 3.x polish.
3. **DNS-advertised.** Query a TXT record to discover a relay for a given domain. Far-future federation.

Phase 3.0 ships option 1. The hardcoded values live in a `relay_defaults` module that's easy to find and override.

---

## What ships in Phase 3.0

- [ ] `qev-relay` crate with: store trait, in-memory store, service loop, config loader, server binary
- [ ] `qev-pairing::relay` module with `RelayClient` + `RelayMessage` enum + CBOR encoding
- [ ] In-process integration test: client + server over a `tokio::io::duplex` pair
- [ ] Real-TCP integration test: client + server on localhost random port
- [ ] Tauri commands: `relay_send_to_peer(peer_id, vault_bytes)`, `relay_fetch_inbox()`
- [ ] `local_envelope_handler`: on receive, run the Noise wrap open, extract the vault bytes, emit an event the UI can listen for
- [ ] Hardcoded default relay (secure.imagineqira.com:7892 + pinned pk)
- [ ] Systemd unit file for `qev-relay-server`
- [ ] Nginx TCP stream-proxy config (or raw-TCP port exposure if nginx isn't in the path)
- [ ] Deployment script to secure.imagineqira.com

Not in Phase 3.0 (deferred to Phase 3.x):

- SQLite-backed envelope store (replaces in-memory for persistence)
- Rate limiting with a real backing store (phase 3.0 uses in-memory counters that reset on restart)
- WebSocket bridge for the web client
- Multi-relay federation (clients pick a preferred relay per peer)
- Push notifications for Android "new envelope waiting"
- mDNS-style relay discovery

---

## Threat model delta

**What Phase 3 adds to the adversary's surface:**

- The relay operator can see which pk sends to which pk, when, and how big the envelope is. That's a metadata graph of who talks to whom. It's a real privacy leak compared to same-LAN direct delivery.
- A compromised relay could drop, delay, or reorder envelopes (denial of service). It cannot modify content — the Noise wrap tag would fail.
- A compromised relay could replay envelopes to the same recipient (the Noise transport counter prevents replay within a session, but the relay could store an envelope and re-deliver it after the client acks). Mitigation: each envelope has a unique id; the client keeps a bloom filter of recently-acked ids and drops duplicates locally.
- A malicious sender could deliver unsolicited envelopes to a target pk (spam). Mitigation: client-side filter that only accepts envelopes from peers in the paired-peer list.

**What Phase 3 preserves from the Phase 2 model:**

- The Noise wrap is end-to-end; the relay never sees plaintext.
- The recipient's phrase is still the content gatekeeper.
- Forward secrecy on the wrap (each envelope is its own Noise session, derived from a fresh ephemeral DH).
- Mutual authentication on every relay connection (by the client's static key, learned in msg 3 of the handshake).

**Explicit non-goal:** QEV is NOT anonymous. The relay knows who sends to whom. Users who need anonymity should use Tor + Session + a paranoid burner OS, not QEV. QEV's value proposition is "self-sovereign, no accounts, no servers holding content" — and now, as of Phase 3, "no-servers AND offline delivery via a courier that sees metadata but not content."

---

## Sequencing

Rough week-by-week:

- **Week 1:** `qev-relay` crate skeleton, `EnvelopeStore` trait + `InMemoryStore`, service loop, in-process integration test.
- **Week 2:** `qev-pairing::relay::RelayClient`, real-TCP integration test, Tauri commands.
- **Week 3:** UI wiring (relay inbox badge, "send via relay" option), deployment scripts, nginx config, initial relay running at secure.imagineqira.com.

Ship criterion for Phase 3.0: send from Mac, receive on Android, both devices paired, 5 minutes apart, through the hosted relay. Take a screenshot of both sides showing the same vault content decrypted from the same phrase.
