# Phase 2 — QR-pairing and direct P2P vault transfer

**Status:** design in progress, no code yet
**Target:** QEV Android + Desktop (Mac/Windows) simultaneously
**Dependencies:** Phase 1 (Android APK) must be green and distributable
**Estimated work:** 2–3 weeks focused
**Ship criterion:** Alice and Bob can pair once with a QR scan and thereafter transfer vaults directly without routing through a third-party server.

## Goal, restated without marketing language

Two QEV instances (phones, desktops, or a mix) can:

1. **Pair once, in person**, by scanning each other's QR code. This exchanges long-term Noise XK static public keys, a human-friendly pairing name, and a trust decision the user makes explicitly ("Yes, this is really Alice's phone").
2. **Transfer vault files directly** over a local Wi-Fi network after pairing. No SMS, no email, no Signal, no Matrix. Just a TCP connection between two devices on the same LAN.
3. **Resume transfers** from the other device's scanned identity forever after. You scan Alice once; from that point on, you can send her vaults whenever you're on the same network.

Notably, the vault file itself is unchanged — it's still `BRY-NFET-SX-VAULT-V2` format, still requires a phrase to decrypt. Phase 2 replaces the "how does the file get from A to B" question (currently: email/Signal/AirDrop/USB) with "send it directly over the LAN." The phrase is still the gatekeeper on the content.

## Non-goals

This phase does NOT:

- Replace the vault's phrase-based encryption with an automatic key system. The phrase is still required; it's the second factor on top of the pairing.
- Provide offline delivery (when the recipient isn't on the same LAN). That's Phase 3 (federated relay).
- Generate random per-message phrases for the user. The phrase-per-message UX trap (discussed in the Phase 2/3/4 framing document) is avoided: pairing gives you a Noise channel, Noise gives you a secure transport, but the vault inside the Noise channel is still phrase-locked by the user.
- Add identity verification beyond "we scanned each other in person." Fancier identity verification (safety numbers, short-authentication-strings, TOFU) is Phase 2.5+ if needed.
- Interop with Signal / Matrix / Wire / any existing messenger. QEV stays its own protocol; Phase 3 adds federation via existing protocols as a separate layer.

## Why Noise XK

The [Noise Protocol Framework](https://noiseprotocol.org/) is the right foundation for this for four reasons:

1. **Formally analysed.** The handshake patterns have been modelled in tools like Tamarin and CryptoVerif. We inherit "this is correct" for free.
2. **One-round-trip mutual authentication.** In XK, the responder's static key is known to the initiator in advance (via the QR code), so the handshake is 2 messages (`-> e, es` then `<- e, ee, s, se`). Both sides know each other's static keys after the handshake completes.
3. **Strong secrecy properties.** The transport phase has forward secrecy (the session keys are ephemeral and derived from ephemeral Diffie-Hellman), so a compromise of the long-term static key does NOT decrypt past traffic.
4. **Tiny implementation.** The `snow` crate is ~2500 lines of Rust with no unsafe code, no C deps, and uses the same libsodium primitives our vault format uses (`X25519`, `ChaCha20-Poly1305`, `BLAKE2b`).

Alternative patterns we rejected:

- **Noise NN** (no static keys either side) — pairing would have to trust TOFU, no resumable identity, susceptible to MITM without a separate verification step.
- **Noise KK** (static keys both sides known in advance) — requires pre-distribution of public keys, which QR-pairing is exactly the mechanism for. Switching to KK after the first pairing round is an optimization we can make later.
- **Noise IK** (initiator's static key transmitted in handshake) — one fewer round trip than XK but the initiator's static key isn't encrypted against the responder's static key on the first exchange, which is slightly worse privacy.

Noise XK is the sweet spot for "scan once, trust forever, direct channel."

## QR code contents

The QR code is the ONE time a user's identity leaves their device. Contents must be complete (no back-channel required), portable (scannable from any phone camera), and small enough to render as a readable QR.

Payload format (versioned, CBOR-encoded, then base64url):

```cbor
{
  "schema": "QEV-PAIRING-V1",
  "version": "0.29.0",
  "static_pk":  bytes(32),    ; X25519 static public key
  "name":       "alice",      ; user-chosen display name, 1..32 chars
  "device":     "alice-phone", ; device label, 1..32 chars
  "addrs":      [
    "192.168.1.42:7891",      ; IPv4:port the initiator should connect to
    "[fe80::...]:7891"        ; optional IPv6 link-local for direct LAN
  ],
  "created_at": "2026-05-01T12:00:00Z",
  "expires_at": "2026-05-01T12:10:00Z"  ; QR is only valid for 10 minutes
}
```

The QR embeds ALL the information the other side needs to establish a Noise XK session. No network call, no registry lookup, no server. It's a fully self-contained credential.

Design choices:

- **CBOR over JSON** because CBOR produces ~40% smaller payloads, which matters for QR readability. A JSON-encoded version would push into QR level M/H or require a bigger physical QR.
- **Base64url over hex** for the same reason — base64url is 33% smaller than hex.
- **Short expiry (10 minutes)** prevents a lost/photographed QR from being reused weeks later. The static key is long-lived but the address info is fresh.
- **Multiple addresses** handle multi-interface devices (laptop on Ethernet + Wi-Fi, phone with IPv4 + IPv6 link-local).

Size budget: a typical payload is ~180 bytes binary → ~240 bytes base64url → a QR code at error-correction level M with version 11 (roughly a 61×61 grid). Scannable from 30 cm on a modern phone camera. Acceptable.

## Transport

Three candidates evaluated:

### Option A: TCP over local Wi-Fi (chosen for v1)

- Responder listens on a random high port (e.g. 7891).
- Initiator reads the address from the QR and connects directly.
- Plain TCP, Noise XK handshake as the first 96 bytes, then length-framed Noise transport messages.
- Works on any IP network where both devices can route to each other. Same LAN is the common case.

**Pros:** simplest possible. No BLE pairing dance, no platform-specific APIs, no external signaling server. The Noise handshake gives us confidentiality + integrity + authentication in ~2 round trips on top of raw TCP.

**Cons:** requires both devices on the same LAN. If they're on different networks (Wi-Fi vs. cellular), no connection. That's the gap Phase 3 fills.

### Option B: BLE via `btleplug`

- Responder advertises a GATT service with a characteristic the initiator subscribes to.
- Much more involved: Android BLE permissions (FINE_LOCATION, BLUETOOTH_CONNECT), iOS CoreBluetooth when we add it, etc.
- Range: ~10 meters, works only when both devices are physically close.

Rejected for v1 because the extra platform complexity and permission surface is large relative to "open the same Wi-Fi network" for the common case.

### Option C: WebRTC DataChannel with signaling server

- Best NAT traversal. Works across networks. Carries arbitrary binary data over peer-to-peer.
- Requires a signaling server to exchange SDP offers/answers and ICE candidates.
- Signaling server is a centralization point — we'd be running infrastructure.

Rejected for v1 because it brings back the "centralization" anti-feature that QEV exists to avoid. This is deferred to Phase 3 and we'll look at it alongside the federated relay option.

### Decision

**Ship Option A in Phase 2.** Document the LAN-only limitation prominently. Offer Phase 3 (Matrix relay OR self-hosted QEV relay) for cross-network delivery. The phases ship independently — users who only need in-house pairing (same household, same office network) never need the relay.

## State machine

```
 ┌──────────────┐
 │   Unpaired   │
 └──────┬───────┘
        │ generateStaticKey()
        ▼
 ┌──────────────┐     showQR()      ┌──────────────┐
 │  Awaiting QR ├───────────────────▶│  QR visible  │
 └──────────────┘                    │              │
                                     │  ┌─────────┐ │
                                     │  │ scanner │ │
                                     │  └────┬────┘ │
                                     └───────┼──────┘
                                             │ scan + user confirms
                                             ▼
                                    ┌────────────────┐
                                    │ Noise XK       │
                                    │ handshake      │
                                    └───────┬────────┘
                                            │ handshake ok
                                            ▼
                                    ┌────────────────┐
                                    │ Paired (stored │
                                    │ in local DB)   │
                                    └───────┬────────┘
                                            │ sendVault(peer, vault)
                                            ▼
                                    ┌────────────────┐
                                    │ Transport msg  │
                                    │ delivered over │
                                    │ Noise channel  │
                                    └────────────────┘
```

Persistence: one SQLite table `peers` with columns `(id TEXT PK, name TEXT, device TEXT, static_pk BLOB, paired_at INTEGER, last_seen_at INTEGER)`. On re-pairing, we UPDATE by `static_pk` rather than creating a duplicate.

## Trust model and the verification step

A QR scan alone isn't verification. If Alice scans a QR from a phone that's NOT Bob's phone (Bob's evil twin, or a phone Bob was handed by a compromised network), Alice will cheerfully pair with the wrong device.

Mitigation: after the Noise handshake completes, both devices display a **safety number** derived from both static keys (same technique Signal uses). Users are prompted "Verify that the safety number on the other device matches what's on yours." Only after both users confirm does the peer get stored as `paired`.

Safety number format: 6 groups of 5 digits (30 digits total), derived from `BLAKE2b-300(static_pk_a || static_pk_b)`. The `||` concatenation is sorted by byte value so both sides produce the same number.

Users who skip verification get a peer saved with `trust: "unverified"`. Vaults from unverified peers show a "not verified" badge. They can always verify later.

## Wire format

After handshake completes, both sides use Noise transport messages. Each message is a QEV protocol message:

```cbor
{
  "type": "vault-transfer-v1",
  "vault_bytes": bytes(<=1 MiB),
  "filename": "note-2026-05-01.vault.json",
  "sender_note": "here's the thing you asked for",  ; optional
  "timestamp": 1717171717
}
```

Noise transport framing: 2-byte big-endian length prefix, then 16384-byte max Noise packet (MSG_LIMIT per spec), so very large vaults fragment into multiple Noise packets. QEV vault files are capped at 1 MiB so this is ~64 fragments worst case — trivial.

## Implementation modules

### `qev-pairing` Rust crate

New workspace member at `tauri-app/src-tauri/pairing/`. Deps:

```toml
[dependencies]
snow = "0.9"                 # Noise protocol
ciborium = "0.2"             # CBOR encode/decode
qrcodegen = "1.8"            # QR generation (no QR scanning — that's done in JS)
sha2 = "0.10"                # BLAKE2b for safety numbers (or blake2 crate)
rand_core = { version = "0.6", features = ["std"] }
serde = { version = "1", features = ["derive"] }
tokio = { version = "1", features = ["net", "io-util"] }
```

Public API:

```rust
pub struct StaticKeypair {
    pub public: [u8; 32],
    pub secret: [u8; 32],
}
impl StaticKeypair { pub fn generate() -> Self }

pub struct PairingInvite {
    pub version: &'static str,
    pub static_pk: [u8; 32],
    pub name: String,
    pub device: String,
    pub addrs: Vec<SocketAddr>,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
}
impl PairingInvite {
    pub fn encode_cbor_b64url(&self) -> String;
    pub fn decode_cbor_b64url(s: &str) -> Result<Self>;
    pub fn render_qr_ascii(&self) -> String;
    pub fn render_qr_svg(&self) -> String;
}

pub struct Handshaker { ... }
impl Handshaker {
    pub fn initiator(remote_static: [u8; 32], local: &StaticKeypair) -> Self;
    pub fn responder(local: &StaticKeypair) -> Self;
    pub async fn run<T: AsyncRead + AsyncWrite>(self, io: T) -> Result<Channel<T>>;
}

pub struct Channel<T> { ... }
impl<T: AsyncRead + AsyncWrite> Channel<T> {
    pub async fn send(&mut self, msg: &QevMessage) -> Result<()>;
    pub async fn recv(&mut self) -> Result<QevMessage>;
    pub fn safety_number(&self) -> String;  // 30-digit grouped
}

pub enum QevMessage {
    VaultTransfer { vault_bytes: Vec<u8>, filename: String, note: Option<String>, timestamp: u64 },
    Ping,
    Pong,
}
```

### `tauri-app/src-tauri/src/lib.rs` additions

Four new Tauri commands:

```rust
#[tauri::command] async fn pairing_generate_invite(...) -> Result<String, String>;
#[tauri::command] async fn pairing_scan_invite(qr_text: String) -> Result<PairingPreview, String>;
#[tauri::command] async fn pairing_accept(invite: String, local_name: String) -> Result<PairedPeer, String>;
#[tauri::command] async fn transfer_send_vault(peer_id: String, vault_bytes: Vec<u8>) -> Result<(), String>;
```

These run on a tokio runtime inside the Tauri app and use the `qev-pairing` crate internally.

### UI additions

Two new screens in `tauri-app/ui/`:

1. **"Pair with another device"** — generates a QR, displays it full-screen, listens for incoming handshake. After pair completes, shows the safety number and an "Verified" checkbox.
2. **"Scan to pair"** — uses `getUserMedia` + `jsQR` (a ~50 KB pure-JS QR decoder) to scan a QR from the camera. Vendor `jsQR` in `ui/vendor/` to keep the "no external network" promise.

Third addition: in the existing Encrypt tab, after a vault is locked, a new "Send to paired peer..." button appears next to "Save" and "Copy." Clicking it shows a list of paired peers and lets the user pick one.

### Database

SQLite table for paired peers, created at `~/Library/Application Support/com.imagineqira.qev/peers.db` on Mac, `%APPDATA%\com.imagineqira.qev\peers.db` on Windows, `/data/data/com.imagineqira.qev/databases/peers.db` on Android.

```sql
CREATE TABLE IF NOT EXISTS peers (
    id           TEXT PRIMARY KEY,        -- BLAKE2b(static_pk) base64url
    name         TEXT NOT NULL,
    device       TEXT NOT NULL,
    static_pk    BLOB NOT NULL,           -- 32 bytes
    paired_at    INTEGER NOT NULL,        -- unix time ms
    last_seen_at INTEGER,
    trust        TEXT NOT NULL DEFAULT 'unverified'  -- 'unverified' | 'verified'
);
CREATE TABLE IF NOT EXISTS own_identity (
    static_pk  BLOB PRIMARY KEY,
    static_sk  BLOB NOT NULL,             -- stored at rest; guarded by OS keystore when available
    created_at INTEGER NOT NULL,
    name       TEXT NOT NULL,
    device     TEXT NOT NULL
);
```

The private static key lives in this file in plaintext for v1. Future: wrap it with the OS keystore (macOS Keychain, Windows DPAPI, Android EncryptedSharedPreferences). That's important but not phase-2 blocking.

## Threat model delta from Phase 1

**What Phase 2 adds to the model:**

- Forward secrecy on the transport. A compromise of `peers.db` does not retroactively decrypt previous vault transfers.
- Mutual authentication on the transport. Bob knows he's talking to Alice's device (the device that owns the static_pk Alice showed him) and vice versa.
- No third-party sees the vault bytes in transit. Previously a user might email a vault via Gmail; Gmail's servers see the ciphertext (which is already encrypted, but they see metadata: sender, recipient, timestamp, size). Phase 2 eliminates that metadata leak for same-LAN transfers.

**What Phase 2 does NOT add:**

- Offline delivery. If Alice is not on the same network as Bob, there's no way to deliver.
- Identity rotation. If Alice's static key leaks, she has to re-pair with every contact (new static key, fresh QR).
- Defence against a malicious scanner that displays a QR with a different static_pk than it claims (the safety number step is the mitigation — users MUST verify or the pairing stays `unverified`).
- Protection against malware on either endpoint. The usual caveat: if Alice's phone is compromised, the attacker can already read every vault she decrypts. No protocol fixes that.
- Cross-room routing. If Alice and Bob are in different rooms with different subnets, QEV has no magic to find each other. mDNS service discovery is a nice-to-have for same-subnet auto-discovery but not first-round Noise.

## Testing strategy

1. **Unit tests** for `qev-pairing`:
   - CBOR round-trip of PairingInvite
   - Base64url QR encoding is deterministic
   - Noise XK handshake success (happy path)
   - Safety number generation is symmetric (both sides produce the same number regardless of role)
   - Handshake fails if the remote static_pk in the QR doesn't match what the responder presents
   - Transport message serialization round-trip

2. **Integration tests** with a pair of in-process instances:
   - Start two tokio tasks, one as initiator and one as responder, connected via a `tokio::io::duplex` pair.
   - Run the full flow: generate invite → scan → handshake → send vault → receive vault.
   - Verify safety numbers match on both sides.
   - Verify the transferred vault round-trips through `decryptVaultV2`.

3. **Two-emulator test** for Android:
   - Spin up two Android emulators on the same host.
   - Install QEV on both.
   - Use `adb shell` to drive the UI programmatically: generate QR on device A, scan via test hook on device B (QR content injected via a test command), verify pairing completes.
   - Send a vault from A to B, decrypt on B with the known phrase.

4. **Cross-platform pairing test**:
   - Desktop Mac ↔ Android emulator.
   - Same flow as above but across platforms.

## Open design questions

1. **What address does the QR advertise?** A device has multiple network interfaces. We could enumerate all IPv4/IPv6 addresses or use mDNS service discovery to let the initiator find the responder. For v1, probably just enumerate `all non-loopback, non-link-local` IPv4 addresses and let the initiator try each one.

2. **Connection lifetime.** After pairing, do devices maintain a persistent connection, or do they open fresh connections per-transfer? Per-transfer is simpler. Persistent gives faster subsequent sends but adds "online status" semantics (which leak metadata).

3. **Simultaneous pairing.** If Alice and Bob both try to scan each other, only one direction should complete. Standard Noise-style tiebreaker: the party with the lexicographically lower static_pk is the initiator.

4. **Multi-device pairing.** Alice has a phone AND a laptop. She pairs both with Bob. When she sends Bob a vault, which device does it come from? Both should work — Bob adds both of Alice's devices as separate peers, but ideally the UI groups them as "Alice (2 devices)".

5. **Unpair.** How does Alice remove Bob from her peer list? Simple DELETE on the row + UI. No notification to Bob; Bob will see "failed to deliver" next time he tries to send.

## What ships in Phase 2.0

The minimum to call Phase 2 "done":

- [ ] `qev-pairing` Rust crate with working Noise XK handshake
- [ ] PairingInvite encoding/decoding (CBOR + base64url + QR ASCII/SVG)
- [ ] Four Tauri commands exposed to the UI
- [ ] SQLite `peers` + `own_identity` tables
- [ ] Unit tests for crate (handshake + QR + safety numbers)
- [ ] Integration test with two in-process instances
- [ ] **UI: "Pair with another device" screen** (generates QR, listens for handshake)
- [ ] **UI: "Scan to pair" screen** (camera + jsQR)
- [ ] **UI: "Send to paired peer..." button in the Encrypt flow**
- [ ] Safety number verification step in the UI
- [ ] Documented LAN-only limitation on the /downloads page and in the in-app help text

Phase 2.1–2.x follow-ups that are NOT required to ship:

- mDNS service discovery
- OS keystore wrapping of the private static key
- Simultaneous pairing tiebreaker
- Unpair UX
- Multi-device grouping ("Alice (2 devices)")
- Background re-pairing when a peer's static key rotates

## Risks and mitigations (top 5)

1. **Rust async plumbing on Android is fragile.** Tauri's mobile entry point runs on the main Android thread, not a tokio runtime. Fix: spawn a long-lived tokio runtime inside the Rust side and post handshake tasks to it from Tauri commands. Same pattern `tauri-plugin-sql` uses.

2. **WebView → native camera access is permission-hell.** Android Camera API requires runtime permission, JS `getUserMedia` needs a permission grant from Android, iOS WKWebView needs an info.plist entry. Fix: use Tauri's scope system to pre-declare the permission in the app manifest, wrap `getUserMedia` with a pre-check that triggers the permission dialog.

3. **QR scanner UX on a small screen.** jsQR decodes at about 20 fps on modern phones but struggles with poor lighting. Fix: add a flashlight toggle and a "enter invite text manually" fallback (user taps "Paste instead" and the initiator enters the base64url string directly).

4. **Two-device testing friction.** Real-life testing needs two devices on the same network. Fix: the in-process tokio integration test covers the protocol, and we do a final smoke test on two real phones before ship.

5. **snow crate version pinning.** The Noise protocol is stable but snow has had breaking API changes. Pin to a minor version (0.9.x) and document the upgrade pathway.

## Deferred to Phase 3 (not Phase 2)

- Federated relay for offline delivery (Matrix or self-hosted)
- Address-rendezvous registry (so peers can find each other across networks)
- Push notifications for new vault delivery

## Sequencing

Rough week-by-week breakdown:

- **Week 1:** `qev-pairing` crate skeleton + Noise XK handshake + unit tests. Should be runnable as `cargo test -p qev-pairing` on any dev machine.
- **Week 2:** PairingInvite format + QR render + CBOR encoding + the four Tauri commands. Ship a desktop-only test build where users can pair two Mac instances running locally.
- **Week 3:** UI screens (generate QR, scan QR, peer list, send-to-peer). Integration tests. Smoke test on two real phones.

If any week goes over, drop scope from the Phase 2.0 shipping list (defer to Phase 2.1) rather than cut quality.
