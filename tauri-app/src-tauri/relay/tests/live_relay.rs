//! LIVE PRODUCTION RELAY E2E TEST
//!
//! This test talks to the REAL relay running at
//! secure.imagineqira.com:7892. Only run it when the relay is
//! actually deployed; `cargo test --ignored` will pick it up.
//!
//! To run: `cargo test --test live_relay -- --ignored`
//!
//! It's marked `#[ignore]` so normal `cargo test` skips it and
//! CI doesn't depend on the relay being up.

use qev_pairing::StaticKeypair;
use qev_relay::RelayClient;
use std::net::SocketAddr;

const SERVER_PK_HEX: &str =
    "b6b77291e633e4ed98918a5ac90e4b2e5083da2a787497785677150d9fcf3749";

fn server_pk() -> [u8; 32] {
    let mut pk = [0u8; 32];
    for i in 0..32 {
        pk[i] = u8::from_str_radix(&SERVER_PK_HEX[i * 2..i * 2 + 2], 16).unwrap();
    }
    pk
}

fn relay_addr() -> SocketAddr {
    // Use the DNS name resolved to IP to avoid depending on
    // DNS resolution in the test environment. The IP is the
    // same DigitalOcean droplet that hosts everything.
    "198.211.100.37:7892".parse().unwrap()
}

#[tokio::test]
#[ignore] // Only run manually against the live relay
async fn deliver_fetch_ack_against_live_relay() {
    let pk = server_pk();
    let addr = relay_addr();
    let alice = StaticKeypair::generate().unwrap();
    let bob = StaticKeypair::generate().unwrap();

    // 1. Alice delivers an envelope to Bob's pk
    let alice_client = RelayClient::new(addr, pk, alice.clone());
    let envelope = b"LIVE RELAY TEST PAYLOAD 2026-04-16".to_vec();
    let id = alice_client
        .deliver(&bob.public, envelope.clone())
        .await
        .expect("deliver to live relay");
    assert_ne!(id, [0u8; 16], "server assigned a non-zero ID");

    // 2. Bob fetches
    let bob_client = RelayClient::new(addr, pk, bob.clone());
    let fetch = bob_client.fetch(50).await.expect("fetch from live relay");
    assert_eq!(
        fetch.envelopes.len(),
        1,
        "exactly one envelope pending for bob"
    );
    assert_eq!(fetch.envelopes[0].id, id);
    assert_eq!(fetch.envelopes[0].from, alice.public);
    assert_eq!(fetch.envelopes[0].bytes, envelope);

    // 3. Bob acks
    let deleted = bob_client
        .ack(&[fetch.envelopes[0].id])
        .await
        .expect("ack on live relay");
    assert_eq!(deleted, 1);

    // 4. Second fetch is empty
    let fetch2 = bob_client.fetch(50).await.expect("second fetch");
    assert_eq!(fetch2.envelopes.len(), 0);

    println!("=== LIVE RELAY E2E: deliver → fetch → ack → empty ===");
}
