use qev_pairing::StaticKeypair;
use qev_relay::RelayClient;
use std::net::SocketAddr;
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

#[tokio::test]
#[ignore]
async fn deliver_test_envelope_to_mac_pk() {
    let mac_pk_hex = "014c993773c0b0c8d4022d6f0732d5b4e7ce899e43da34ade9e935f35dbf7e7e";
    let mut mac_pk = [0u8; 32];
    for i in 0..32 {
        mac_pk[i] = u8::from_str_radix(&mac_pk_hex[i * 2..i * 2 + 2], 16).unwrap();
    }

    let addr: SocketAddr = "198.211.100.37:7892".parse().unwrap();
    let sender = StaticKeypair::generate().unwrap();
    let client = RelayClient::new(addr, server_pk(), sender.clone());

    let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
    let envelope = serde_json::json!({
        "type": "chat-message",
        "text": "test-from-harness",
        "msg_id": "test-harness-msg-id",
        "timestamp": now_ms,
    });
    let bytes = serde_json::to_vec(&envelope).unwrap();

    let id = client.deliver(&mac_pk, bytes).await.expect("deliver");
    println!("Delivered test envelope to Mac pk {}", mac_pk_hex);
    println!("Envelope ID (hex): {}", id.iter().map(|b| format!("{:02x}", b)).collect::<String>());
    println!("Sender pk: {}", sender.public.iter().map(|b| format!("{:02x}", b)).collect::<String>());
}
