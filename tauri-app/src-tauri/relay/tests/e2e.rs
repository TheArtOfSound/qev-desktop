//! End-to-end integration test for the qev-relay crate.
//!
//! Spins up an `InMemoryStore` + `RelayService` on a random
//! localhost TCP port, then uses `RelayClient` to exercise the
//! full RPC surface:
//!
//!   1. Alice (a remote sender) delivers an envelope addressed to
//!      Bob's static public key.
//!   2. Bob calls fetch() and sees the envelope (with Alice's pk
//!      as the sender).
//!   3. Bob acks the envelope and a follow-up fetch returns empty.
//!   4. Carol (a third party) fetches from the same relay and
//!      sees nothing — envelopes are scoped to the addressee.
//!   5. Oversize envelopes are rejected at the client encode step.
//!
//! All steps happen inside one test process with one tokio
//! runtime, so we can shut the server down cleanly after.

use qev_pairing::StaticKeypair;
use qev_relay::{Envelope, EnvelopeStore, InMemoryStore, RelayClient, RelayService};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

async fn spawn_server() -> (
    SocketAddr,
    StaticKeypair,
    Arc<InMemoryStore>,
    tokio::sync::oneshot::Sender<()>,
) {
    // Bind to :0 so the OS picks a free port. Then pull the
    // actual port out and pass it to the real service.
    let pre = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = pre.local_addr().unwrap();
    drop(pre); // release the port so the real service can bind it

    let server_kp = StaticKeypair::generate().unwrap();
    let store = Arc::new(InMemoryStore::default());
    let service = Arc::new(RelayService::new(server_kp.clone(), Arc::clone(&store)));

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    {
        let service = Arc::clone(&service);
        tokio::spawn(async move {
            let _ = service.serve(addr, rx).await;
        });
    }

    // Give the accept loop a moment to bind the listener.
    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, server_kp, store, tx)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deliver_fetch_ack_round_trip() {
    let (addr, server_kp, store, shutdown) = spawn_server().await;

    let alice = StaticKeypair::generate().unwrap();
    let bob = StaticKeypair::generate().unwrap();

    // ---- 1. Alice delivers an envelope to Bob ----
    let alice_client = RelayClient::new(addr, server_kp.public, alice.clone());
    let envelope_bytes = b"opaque Noise-wrapped vault bytes".to_vec();
    let deliver_id = alice_client
        .deliver(&bob.public, envelope_bytes.clone())
        .await
        .expect("deliver ok");

    // Sanity: the store now has one envelope for bob.
    let count = store.count_pending(&bob.public).await.unwrap();
    assert_eq!(count, 1);

    // ---- 2. Bob fetches his inbox ----
    let bob_client = RelayClient::new(addr, server_kp.public, bob.clone());
    let fetch = bob_client.fetch(50).await.expect("fetch ok");
    assert_eq!(fetch.envelopes.len(), 1);
    assert!(!fetch.has_more);
    let got = &fetch.envelopes[0];
    assert_eq!(got.id, deliver_id);
    assert_eq!(got.from, alice.public);
    assert_eq!(got.bytes, envelope_bytes);

    // ---- 3. Bob acks the envelope; follow-up fetch is empty ----
    let deleted = bob_client.ack(&[got.id]).await.expect("ack ok");
    assert_eq!(deleted, 1);
    let fetch2 = bob_client.fetch(50).await.expect("second fetch ok");
    assert_eq!(fetch2.envelopes.len(), 0);

    // ---- 4. Carol (unrelated) sees no envelopes ----
    let carol = StaticKeypair::generate().unwrap();
    let carol_client = RelayClient::new(addr, server_kp.public, carol);
    let carol_fetch = carol_client.fetch(50).await.expect("carol fetch ok");
    assert_eq!(carol_fetch.envelopes.len(), 0);

    // ---- 5. Clean shutdown ----
    let _ = shutdown.send(());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversize_envelope_rejected_at_client() {
    // The client's RelayMessage::encode enforces the size cap
    // before the request ever hits the wire. Build a
    // too-big envelope and confirm the deliver call returns
    // TooLarge without contacting the server.
    use qev_relay::{Error as RelayError, MAX_ENVELOPE_BYTES};

    let alice = StaticKeypair::generate().unwrap();
    let bob = StaticKeypair::generate().unwrap();
    // Use a dummy address/pk — we never connect.
    let dummy = "127.0.0.1:1".parse().unwrap();
    let client = RelayClient::new(dummy, [0u8; 32], alice);

    let huge = vec![0u8; MAX_ENVELOPE_BYTES + 100];
    let err = client.deliver(&bob.public, huge).await.unwrap_err();
    assert!(matches!(err, RelayError::TooLarge { .. }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_server_pk_rejected_by_handshake() {
    // The client pins a server_pk at construction time. If the
    // server actually uses a different keypair, the Noise XK
    // handshake fails at the read-message step because the ES
    // token can't be decrypted.
    let (addr, _server_kp, _store, shutdown) = spawn_server().await;

    let impostor_pk = StaticKeypair::generate().unwrap().public;
    let alice = StaticKeypair::generate().unwrap();
    let bob = StaticKeypair::generate().unwrap();
    let client = RelayClient::new(addr, impostor_pk, alice);

    let result = client.deliver(&bob.public, b"x".to_vec()).await;
    assert!(result.is_err(), "wrong server pk must fail the handshake");

    let _ = shutdown.send(());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multiple_envelopes_preserve_order() {
    let (addr, server_kp, _store, shutdown) = spawn_server().await;

    let alice = StaticKeypair::generate().unwrap();
    let bob = StaticKeypair::generate().unwrap();
    let alice_client = RelayClient::new(addr, server_kp.public, alice);
    let bob_client = RelayClient::new(addr, server_kp.public, bob.clone());

    // Deliver three envelopes in sequence with distinct content.
    for i in 0..3u8 {
        let mut bytes = vec![0u8; 32];
        bytes[0] = i;
        alice_client.deliver(&bob.public, bytes).await.unwrap();
    }

    let fetch = bob_client.fetch(50).await.unwrap();
    assert_eq!(fetch.envelopes.len(), 3);
    for (i, env) in fetch.envelopes.iter().enumerate() {
        assert_eq!(
            env.bytes[0], i as u8,
            "envelope {i} should have byte {i} as the first byte"
        );
    }

    let _ = shutdown.send(());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_store_put_also_fetchable_through_relay() {
    // Prove the in-memory store and the RPC layer agree: put
    // an envelope directly into the store (as if it came from
    // a separate deliver session), then fetch it via the real
    // RelayClient, and confirm the same bytes round-trip.
    let (addr, server_kp, store, shutdown) = spawn_server().await;
    let alice_pk = {
        let kp = StaticKeypair::generate().unwrap();
        kp.public
    };
    let bob = StaticKeypair::generate().unwrap();

    let put_id = store
        .put(Envelope {
            id: [0u8; 16],
            to: bob.public,
            from: alice_pk,
            bytes: b"pre-seeded directly".to_vec(),
            created_at: 42,
        })
        .await
        .unwrap();

    let bob_client = RelayClient::new(addr, server_kp.public, bob);
    let fetch = bob_client.fetch(50).await.unwrap();
    assert_eq!(fetch.envelopes.len(), 1);
    assert_eq!(fetch.envelopes[0].id, put_id);
    assert_eq!(fetch.envelopes[0].from, alice_pk);
    assert_eq!(fetch.envelopes[0].bytes, b"pre-seeded directly");

    let _ = shutdown.send(());
}
