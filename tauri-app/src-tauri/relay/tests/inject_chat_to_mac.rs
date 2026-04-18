//! VISUAL VERIFICATION: send a real chat message to the running Mac app.
//!
//! This test:
//!   1. Reads Mac's peer store to discover its own static pk
//!   2. Generates a test peer keypair
//!   3. Writes the test peer into Mac's peers.json so Mac recognizes us
//!   4. Delivers a chat-v1 envelope to Mac's pk through the LIVE relay
//!   5. On next relay poll (≤8s), Mac's Chat tab will show the message
//!
//! Run while the Mac QEV app is NOT running (needs exclusive peer-store write):
//!   pkill -f QEV; cargo test --test inject_chat_to_mac -- --ignored; open /Applications/QEV.app

use qev_pairing::peer_store::{PeerStore, StoredPeer, TrustLevel};
use qev_pairing::StaticKeypair;
use qev_relay::RelayClient;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const SERVER_PK_HEX: &str =
    "b6b77291e633e4ed98918a5ac90e4b2e5083da2a787497785677150d9fcf3749";

fn server_pk() -> [u8; 32] {
    let mut pk = [0u8; 32];
    for i in 0..32 {
        pk[i] = u8::from_str_radix(&SERVER_PK_HEX[i * 2..i * 2 + 2], 16).unwrap();
    }
    pk
}

fn mac_store_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap();
    PathBuf::from(format!(
        "{home}/Library/Application Support/com.imagineqira.qev/peers.json"
    ))
}

fn iso_now() -> String {
    use time::format_description::well_known::Iso8601;
    use time::OffsetDateTime;
    let odt: OffsetDateTime = SystemTime::now().into();
    odt.format(&Iso8601::DEFAULT).unwrap()
}

#[tokio::test]
#[ignore]
async fn inject_a_chat_message_into_running_mac_app() {
    // ---- 1. Load Mac's peer store ----
    let path = mac_store_path();
    let mut store = PeerStore::load_or_empty(&path).expect("load Mac peer store");
    let mac_pk_b64 = store
        .own_identity
        .as_ref()
        .expect("Mac has no own_identity — open the app once to generate")
        .public
        .clone();

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let mac_pk_bytes = URL_SAFE_NO_PAD.decode(mac_pk_b64.as_bytes()).unwrap();
    let mut mac_pk = [0u8; 32];
    mac_pk.copy_from_slice(&mac_pk_bytes);

    // ---- 2. Generate a test-peer keypair ----
    let test_peer = StaticKeypair::generate().unwrap();
    let test_pk = test_peer.public;
    let test_pk_b64 = URL_SAFE_NO_PAD.encode(&test_pk);
    let test_pk_hex = test_pk
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            s.push_str(&format!("{b:02x}"));
            s
        });

    // ---- 3. Inject test-peer into Mac's peer store ----
    let stored = StoredPeer {
        id: test_pk_hex.clone(),
        name: "test-sender".to_string(),
        device: "integration-test".to_string(),
        static_pk: test_pk_b64,
        paired_at: iso_now(),
        last_seen_at: iso_now(),
        trust: TrustLevel::Unverified,
        last_addrs: vec![],
    };
    store.upsert_peer(stored);
    store.save(&path).expect("save Mac peer store");
    println!("[inject] wrote test peer {test_pk_hex} into Mac's peers.json");

    // ---- 4. Deliver a chat-v1 envelope via the live relay ----
    let relay: SocketAddr = "198.211.100.37:7892".parse().unwrap();
    let client = RelayClient::new(relay, server_pk(), test_peer);

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // Build the same chat ciphertext envelope the UI produces.
    // Key derivation must match chat-ui.js exactly:
    //   blake2b(32, phrase || "QEV-CHAT-V1:" || lower_hex || ":" || higher_hex)
    // where lower/higher are the lex-sorted lowercase hex strings of the
    // two static public keys.
    let phrase = "test-phrase";
    let mac_pk_hex = mac_pk.iter().fold(String::new(), |mut s, b| {
        s.push_str(&format!("{b:02x}"));
        s
    });
    let (id_lower, id_higher) = if test_pk_hex <= mac_pk_hex {
        (&test_pk_hex, &mac_pk_hex)
    } else {
        (&mac_pk_hex, &test_pk_hex)
    };
    let context = format!("QEV-CHAT-V1:{id_lower}:{id_higher}");
    let mut blake = blake2::Blake2b::<blake2::digest::typenum::U32>::new();
    use blake2::Digest;
    blake.update(phrase.as_bytes());
    blake.update(context.as_bytes());
    let key_bytes: [u8; 32] = blake.finalize().into();

    let plaintext = format!("Hello from integration test at {ts}!");

    // XChaCha20-Poly1305 encrypt with a random 24-byte nonce.
    use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305, XNonce};
    let cipher = XChaCha20Poly1305::new((&key_bytes).into());
    let mut nonce_bytes = [0u8; 24];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ct = cipher.encrypt(nonce, plaintext.as_bytes()).unwrap();

    // UI uses URL-safe base64 without padding for both nonce and ct.
    let inner = serde_json::json!({
        "v": 1,
        "nonce": URL_SAFE_NO_PAD.encode(nonce_bytes),
        "ct": URL_SAFE_NO_PAD.encode(&ct),
    })
    .to_string();

    let envelope = serde_json::to_vec(&serde_json::json!({
        "type": "chat-v1",
        "msg_id": format!("inject-{ts}"),
        "text": inner,
        "timestamp": ts,
    }))
    .unwrap();

    let id = client.deliver(&mac_pk, envelope).await.expect("deliver");
    let id_hex = id.iter().fold(String::new(), |mut s, b| {
        s.push_str(&format!("{b:02x}"));
        s
    });

    println!("[inject] delivered envelope {id_hex} to Mac");
    println!("[inject] plaintext: {plaintext}");
    println!("[inject] phrase:    {phrase}");
    println!("[inject] open Mac QEV → Chat tab → test-sender will appear within 8s");
}
