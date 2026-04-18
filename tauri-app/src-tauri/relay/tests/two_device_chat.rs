//! TWO-DEVICE PAIR + ENCRYPTED CHAT ROUND-TRIP
//!
//! Full end-to-end verification that the entire QEV stack works:
//!
//!   1. Alice shows QR (local TCP listener + Noise XK responder)
//!   2. Bob scans and connects as Noise XK initiator
//!   3. Both exchange Identity messages over the encrypted channel
//!   4. Both compute safety numbers — verify they match
//!   5. Alice sends Bob a chat-v1 envelope through the LIVE relay
//!   6. Bob fetches it back, acks, and verifies the payload
//!   7. Alice verifies the envelope is gone from the relay
//!
//! This is the ship gate: if this is green, the end-to-end flow
//! the user experiences (pair in person + chat via relay) works.
//!
//! `#[ignore]` because it requires the live relay. Run with:
//!   cargo test --test two_device_chat -- --ignored

use qev_pairing::{safety_number, ChannelExt, Initiator, PairingInvite, QevMessage, Responder, StaticKeypair};
use qev_relay::RelayClient;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};

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
    "198.211.100.37:7892".parse().unwrap()
}

#[tokio::test]
#[ignore]
async fn full_pair_plus_chat_through_live_relay() {
    // ---- 1. Identities ----
    let alice_kp = StaticKeypair::generate().unwrap();
    let bob_kp = StaticKeypair::generate().unwrap();
    let alice_pk = alice_kp.public;
    let bob_pk = bob_kp.public;

    // ---- 2. Alice binds a listener and builds an invite ----
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let addr_str = format!("127.0.0.1:{port}");
    let invite = PairingInvite::new(
        alice_pk,
        "alice".into(),
        "alice-mac".into(),
        vec![addr_str.parse::<SocketAddr>().unwrap()],
    )
    .unwrap();
    let qr = invite.encode_qr().unwrap();

    // ---- 3. Spawn Alice's responder task ----
    let alice_key = alice_kp.clone();
    let alice_task = tokio::spawn(async move {
        let (stream, _remote) = listener.accept().await.unwrap();
        let responder = Responder::new(&alice_key).unwrap();
        let mut channel = responder.run(stream).await.unwrap();
        // Send our identity first, then receive theirs — order matches lib.rs.
        let our_id = QevMessage::Identity {
            name: "alice".into(),
            device: "alice-mac".into(),
        };
        channel.send_msg(&our_id).await.unwrap();
        let their_id = channel.recv_msg().await.unwrap();
        (channel.peer_static_pk(), their_id)
    });

    // ---- 4. Bob decodes the QR, connects, runs Noise XK initiator ----
    let decoded = PairingInvite::decode_qr(&qr).unwrap();
    let alice_pk_from_invite = decoded.static_pk_array().unwrap();
    assert_eq!(alice_pk_from_invite, alice_pk, "invite pk should match alice");

    let stream = TcpStream::connect(&addr_str).await.unwrap();
    let initiator = Initiator::new(&bob_kp, alice_pk_from_invite).unwrap();
    let mut channel = initiator.run(stream).await.unwrap();
    // Receive alice's identity first, then send ours.
    let alice_id = channel.recv_msg().await.unwrap();
    let our_id = QevMessage::Identity {
        name: "bob".into(),
        device: "bob-android".into(),
    };
    channel.send_msg(&our_id).await.unwrap();

    let bob_peer_from_handshake = channel.peer_static_pk();
    assert_eq!(bob_peer_from_handshake, alice_pk, "bob should see alice's pk");

    // Confirm identity message on Bob's side.
    match alice_id {
        QevMessage::Identity { name, device } => {
            assert_eq!(name, "alice");
            assert_eq!(device, "alice-mac");
        }
        other => panic!("expected Identity from alice, got {other:?}"),
    }

    // Wait for Alice's task to complete.
    let (alice_peer_pk, bob_id_received) = alice_task.await.unwrap();
    assert_eq!(alice_peer_pk, bob_pk, "alice should see bob's pk");
    match bob_id_received {
        QevMessage::Identity { name, device } => {
            assert_eq!(name, "bob");
            assert_eq!(device, "bob-android");
        }
        other => panic!("expected Identity from bob, got {other:?}"),
    }

    // ---- 5. Verify safety numbers match on both sides ----
    let alice_sn = safety_number(&alice_pk, &bob_pk);
    let bob_sn = safety_number(&bob_pk, &alice_pk);
    assert_eq!(alice_sn, bob_sn, "safety number must be symmetric");
    assert_eq!(alice_sn.len(), 35, "30 digits + 5 spaces");

    // ---- 6. Alice sends a chat-v1 envelope to Bob via the LIVE relay ----
    let server = server_pk();
    let relay = relay_addr();

    let alice_client = RelayClient::new(relay, server, alice_kp.clone());
    let bob_client = RelayClient::new(relay, server, bob_kp.clone());

    // Clear any pending for bob from prior test runs.
    let drain = bob_client.fetch(50).await.unwrap();
    if !drain.envelopes.is_empty() {
        let ids: Vec<[u8; 16]> = drain.envelopes.iter().map(|e| e.id).collect();
        let _ = bob_client.ack(&ids).await;
    }

    // Unique chat content so we can identify this test's envelope.
    let test_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let msg_id = format!("test-msg-{test_ts}");
    let secret_text = format!("hello bob from alice at {test_ts}");
    let envelope_json = serde_json::to_vec(&serde_json::json!({
        "type": "chat-v1",
        "msg_id": msg_id,
        "text": secret_text,
        "timestamp": test_ts as u64,
    }))
    .unwrap();

    let _env_id = alice_client.deliver(&bob_pk, envelope_json.clone()).await.unwrap();

    // ---- 7. Bob fetches and verifies ----
    // Relay writes are durable but may take a tick; fetch with a small retry.
    let mut fetched = None;
    for _ in 0..6 {
        let f = bob_client.fetch(50).await.unwrap();
        if !f.envelopes.is_empty() {
            fetched = Some(f);
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let fetch = fetched.expect("bob did not receive envelope from alice via relay");
    assert_eq!(fetch.envelopes.len(), 1, "should be exactly one envelope");
    let env = &fetch.envelopes[0];
    assert_eq!(env.from, alice_pk, "envelope must be from alice");

    let v: serde_json::Value = serde_json::from_slice(&env.bytes).unwrap();
    assert_eq!(v.get("type").and_then(|t| t.as_str()), Some("chat-v1"));
    assert_eq!(v.get("msg_id").and_then(|t| t.as_str()), Some(msg_id.as_str()));
    assert_eq!(v.get("text").and_then(|t| t.as_str()), Some(secret_text.as_str()));

    // ---- 8. Ack and verify clean inbox ----
    let deleted = bob_client.ack(&[env.id]).await.unwrap();
    assert_eq!(deleted, 1, "ack should delete exactly one envelope");

    let empty = bob_client.fetch(50).await.unwrap();
    assert_eq!(empty.envelopes.len(), 0, "inbox should be empty after ack");

    // Drop the pairing channel explicitly (not strictly needed but mirrors app flow).
    drop(channel);
}
