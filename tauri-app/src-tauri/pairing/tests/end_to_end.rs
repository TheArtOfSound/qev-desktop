//! End-to-end integration test for the full Phase 2 stack.
//!
//! Runs the complete pair + transfer flow using TWO in-process
//! QEV instances over real localhost TCP (not just a duplex pipe).
//! Exercises:
//!
//! 1. Both sides generate persistent identities via a `PeerStore`
//!    backed by a temp file (proving save + load works).
//! 2. Side A binds a real TCP listener, generates a PairingInvite,
//!    encodes + decodes via base64url CBOR (round-tripping the QR
//!    wire format).
//! 3. Side B decodes the invite, connects to the advertised
//!    address, runs the Noise XK initiator.
//! 4. Side A runs the Noise XK responder.
//! 5. Both sides compute safety numbers; they match.
//! 6. Side B sends a large (~100 KiB) vault through the Noise
//!    channel using the typed QevMessage layer.
//! 7. Side A receives and decodes it, verifies the bytes round-
//!    tripped unchanged.
//! 8. Both sides persist the new peer into their respective stores
//!    and verify the entries survive a save + load round trip.
//!
//! If any step fails, the test panics with a clear message. This
//! is the ship gate for Phase 2 — if this test is green, the
//! entire pair + transfer flow is functional end to end.

use qev_pairing::{
    peer_store::{pk_to_hex, store_path, PeerStore, StoredPeer, TrustLevel},
    ChannelExt, Initiator, PairingInvite, QevMessage, Responder, StaticKeypair,
};
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};

fn tempdir(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    p.push(format!("qev-e2e-{tag}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&p).unwrap();
    p
}

fn sample_vault_bytes(size: usize) -> Vec<u8> {
    // Deterministic pattern so the receiver can byte-compare
    // against the original.
    (0..size).map(|i| ((i * 13 + 7) % 256) as u8).collect()
}

#[tokio::test]
async fn full_pair_and_transfer_roundtrip() {
    // ---- 1. Build two persistent peer stores in temp dirs ----
    let alice_dir = tempdir("alice");
    let bob_dir = tempdir("bob");
    let alice_path = store_path(&alice_dir);
    let bob_path = store_path(&bob_dir);

    let mut alice_store = PeerStore::load_or_empty(&alice_path).unwrap();
    let alice_kp = alice_store
        .ensure_own_identity("alice", "alice-laptop")
        .unwrap();
    alice_store.save(&alice_path).unwrap();
    // Reload to prove persistence.
    let mut alice_store = PeerStore::load_or_empty(&alice_path).unwrap();
    let alice_kp_reload = alice_store
        .ensure_own_identity("ignored", "ignored")
        .unwrap();
    assert_eq!(
        alice_kp.public, alice_kp_reload.public,
        "own identity survived save + load"
    );

    let mut bob_store = PeerStore::load_or_empty(&bob_path).unwrap();
    let bob_kp = bob_store.ensure_own_identity("bob", "bob-phone").unwrap();
    bob_store.save(&bob_path).unwrap();

    // ---- 2. Alice binds a real TCP listener and builds an invite ----
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = listener.local_addr().unwrap();

    let invite = PairingInvite::new(
        alice_kp.public,
        "alice".into(),
        "alice-laptop".into(),
        vec![SocketAddr::from((
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            listen_addr.port(),
        ))],
    )
    .unwrap();

    // Serialize → deserialize via the real QR wire format. This
    // catches any encode/decode asymmetry.
    let qr_text = invite.encode_qr().unwrap();
    let decoded = PairingInvite::decode_qr(&qr_text).unwrap();
    assert_eq!(invite, decoded);
    let invite = decoded;

    // ---- 3. Spawn both sides ----
    let alice_task = tokio::spawn(async move {
        let (stream, _remote) = listener.accept().await.unwrap();
        let responder = Responder::new(&alice_kp).unwrap();
        let mut channel = responder.run(stream).await.unwrap();
        let sn = channel.safety_number();
        let peer_pk = channel.peer_static_pk();

        // Alice receives the vault message.
        let incoming = channel.recv_msg().await.unwrap();
        (sn, peer_pk, incoming)
    });

    let bob_task = tokio::spawn(async move {
        // Small delay to let the listener come up. In production
        // the timing is driven by user action (scan + tap), not
        // a race.
        tokio::time::sleep(Duration::from_millis(20)).await;

        let peer_pk = invite.static_pk_array().unwrap();
        let addrs = invite.addrs_parsed().unwrap();
        let stream = TcpStream::connect(addrs[0]).await.unwrap();
        let initiator = Initiator::new(&bob_kp, peer_pk).unwrap();
        let mut channel = initiator.run(stream).await.unwrap();
        let sn = channel.safety_number();
        let bob_peer_pk = channel.peer_static_pk();

        // Bob sends a ~100 KiB vault.
        let vault = sample_vault_bytes(100 * 1024);
        let msg = QevMessage::VaultTransfer {
            filename: "e2e.vault.json".into(),
            vault_bytes: vault.clone(),
            note: Some("integration test".into()),
            timestamp: 1717171717,
        };
        channel.send_msg(&msg).await.unwrap();

        (sn, bob_peer_pk, vault)
    });

    let (alice_sn, alice_peer_pk, received) = alice_task.await.unwrap();
    let (bob_sn, bob_peer_pk, sent_vault) = bob_task.await.unwrap();

    // ---- 4. Safety numbers match on both sides ----
    assert_eq!(
        alice_sn, bob_sn,
        "safety numbers must be identical on both sides (Noise XK msg 3 transmits initiator static)"
    );
    assert_eq!(alice_sn.len(), 35);

    // ---- 5. Received vault round-trips byte-for-byte ----
    match received {
        QevMessage::VaultTransfer {
            filename,
            vault_bytes,
            note,
            timestamp,
        } => {
            assert_eq!(filename, "e2e.vault.json");
            assert_eq!(vault_bytes, sent_vault);
            assert_eq!(note.as_deref(), Some("integration test"));
            assert_eq!(timestamp, 1717171717);
        }
        other => panic!("expected VaultTransfer, got {other:?}"),
    }

    // ---- 6. Persist the peer into both stores ----
    let now = "2026-04-15T23:59:59.000000000Z".to_string();
    let alice_peer_record = StoredPeer {
        id: pk_to_hex(&alice_peer_pk),
        name: "bob".into(),
        device: "bob-phone".into(),
        static_pk: {
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            use base64::Engine;
            URL_SAFE_NO_PAD.encode(alice_peer_pk)
        },
        paired_at: now.clone(),
        last_seen_at: now.clone(),
        trust: TrustLevel::Unverified,
        last_addrs: vec![],
    };
    let bob_peer_record = StoredPeer {
        id: pk_to_hex(&bob_peer_pk),
        name: "alice".into(),
        device: "alice-laptop".into(),
        static_pk: {
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            use base64::Engine;
            URL_SAFE_NO_PAD.encode(bob_peer_pk)
        },
        paired_at: now.clone(),
        last_seen_at: now,
        trust: TrustLevel::Unverified,
        last_addrs: vec!["127.0.0.1:7891".into()],
    };

    alice_store.upsert_peer(alice_peer_record);
    bob_store.upsert_peer(bob_peer_record);
    alice_store.save(&alice_path).unwrap();
    bob_store.save(&bob_path).unwrap();

    // ---- 7. Reload both stores and verify the peer records ----
    let alice_reload = PeerStore::load_or_empty(&alice_path).unwrap();
    let bob_reload = PeerStore::load_or_empty(&bob_path).unwrap();
    assert_eq!(alice_reload.peers.len(), 1);
    assert_eq!(bob_reload.peers.len(), 1);
    assert_eq!(alice_reload.peers[0].name, "bob");
    assert_eq!(bob_reload.peers[0].name, "alice");

    // ---- 8. Verify the safety number matches the store ID ----
    // The pk_to_hex of the peer's static key should be the peer
    // record id — that's our primary key / stable identifier.
    assert_eq!(alice_reload.peers[0].id, pk_to_hex(&alice_peer_pk));
    assert_eq!(bob_reload.peers[0].id, pk_to_hex(&bob_peer_pk));

    // Cleanup
    let _ = fs::remove_dir_all(&alice_dir);
    let _ = fs::remove_dir_all(&bob_dir);
}

#[tokio::test]
async fn second_pairing_reuses_same_identity() {
    // Prove that the same device generates the SAME static public
    // key on a second invite. This is the property that lets a
    // previously-paired peer recognise us across sessions.
    let dir = tempdir("reuse");
    let path = store_path(&dir);

    let mut store = PeerStore::load_or_empty(&path).unwrap();
    let k1 = store.ensure_own_identity("alice", "alice-laptop").unwrap();
    let invite1 = PairingInvite::new(
        k1.public,
        "alice".into(),
        "alice-laptop".into(),
        vec!["127.0.0.1:7891".parse().unwrap()],
    )
    .unwrap();
    store.save(&path).unwrap();

    // Simulate an app restart.
    let mut store2 = PeerStore::load_or_empty(&path).unwrap();
    let k2 = store2
        .ensure_own_identity("ignored", "ignored")
        .unwrap();
    let invite2 = PairingInvite::new(
        k2.public,
        "alice".into(),
        "alice-laptop".into(),
        vec!["127.0.0.1:7891".parse().unwrap()],
    )
    .unwrap();

    assert_eq!(k1.public, k2.public, "same pk across restart");
    assert_eq!(invite1.static_pk, invite2.static_pk);

    // The invites themselves differ in created_at/expires_at but
    // the key contents match byte-for-byte.
    let _ = fs::remove_dir_all(&dir);
}
