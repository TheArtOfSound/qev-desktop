//! Transport layer — typed CBOR messages on top of the raw Noise
//! byte channel.
//!
//! The [`Channel`](crate::handshake::Channel) exposes raw bytes up
//! to [`MAX_TRANSPORT_MSG`](crate::MAX_TRANSPORT_MSG) per Noise
//! message. QEV vaults can be up to 1 MiB, so this module adds a
//! simple fragmentation layer:
//!
//! 1. CBOR-encode the [`QevMessage`] to a byte buffer.
//! 2. Split into chunks of at most `MAX_TRANSPORT_MSG - 8` bytes.
//!    (The 8-byte overhead is a fragment header: 4 bytes total
//!    length + 4 bytes fragment index.)
//! 3. Send each chunk as one Noise transport message.
//! 4. On receive, read chunks until the expected total length is
//!    reached, then CBOR-decode.
//!
//! Every fragment carries the same total length in its header, so
//! a receiver that joins mid-stream (shouldn't happen in TCP, but
//! defensive design) can still reject partial messages.
//!
//! ## Message types
//!
//! For v1 we ship only two variants:
//!
//!   - [`QevMessage::VaultTransfer`] — the payload we care about.
//!     Carries the raw vault bytes (already phrase-encrypted), a
//!     filename hint, an optional note, and a timestamp.
//!   - [`QevMessage::Ping`] / [`QevMessage::Pong`] — channel
//!     liveness check. Used by the UI to show "connected" status
//!     without touching the transfer state.
//!
//! Future variants (peer metadata exchange, file request, delete
//! request, etc.) go in a `V2` enum with a schema bump.

use crate::error::{Error, Result};
use crate::handshake::Channel;
use crate::{MAX_TRANSPORT_MSG, MAX_VAULT_BYTES};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};

/// Header size in bytes at the start of each fragment:
/// 4 bytes total length + 4 bytes fragment sequence number.
const FRAG_HEADER_BYTES: usize = 8;

/// Effective fragment payload capacity per Noise message.
pub const FRAG_PAYLOAD_MAX: usize = MAX_TRANSPORT_MSG - FRAG_HEADER_BYTES;

/// Hard cap on the whole reassembled message. Prevents a malicious
/// peer from feeding an unbounded length and exhausting memory.
/// Matches [`MAX_VAULT_BYTES`] with a small envelope for CBOR
/// overhead + filename + note.
pub const MAX_MESSAGE_BYTES: usize = MAX_VAULT_BYTES + 4096;

/// Typed message sent over a paired channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum QevMessage {
    /// A vault file being delivered from one paired device to
    /// another. `vault_bytes` is the raw bytes of a
    /// `BRY-NFET-SX-VAULT-V2` JSON file (already phrase-encrypted).
    #[serde(rename = "vault-transfer-v1")]
    VaultTransfer {
        /// Suggested filename for the receiver's UI (may be
        /// displayed but should not be used as a path directly —
        /// the receiver writes to its own downloads directory).
        filename: String,
        /// Raw vault bytes.
        #[serde(with = "serde_bytes")]
        vault_bytes: Vec<u8>,
        /// Optional sender note shown next to the incoming vault
        /// card in the UI.
        note: Option<String>,
        /// Unix ms timestamp when the sender composed the message.
        /// Used for display only — the receiver does not trust it.
        timestamp: u64,
    },

    /// Connection-liveness ping. Sent periodically by either side.
    #[serde(rename = "ping-v1")]
    Ping,

    /// Connection-liveness pong. Sent in response to a Ping.
    #[serde(rename = "pong-v1")]
    Pong,
}

impl QevMessage {
    /// CBOR-encode this message to bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(128);
        ciborium::ser::into_writer(self, &mut buf)?;
        if buf.len() > MAX_MESSAGE_BYTES {
            return Err(Error::TransportTooLarge {
                size: buf.len(),
                max: MAX_MESSAGE_BYTES,
            });
        }
        Ok(buf)
    }

    /// Decode a CBOR-encoded message from bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(Error::TransportTooLarge {
                size: bytes.len(),
                max: MAX_MESSAGE_BYTES,
            });
        }
        Ok(ciborium::de::from_reader(bytes)?)
    }
}

/// Extension trait that adds typed `send_msg` / `recv_msg` methods
/// to a [`Channel`] so callers can work with `QevMessage` values
/// instead of raw bytes.
///
/// Implemented as an extension trait rather than methods on
/// `Channel` to keep the crypto layer in `handshake.rs` ignorant
/// of the message schema.
#[allow(async_fn_in_trait)]
pub trait ChannelExt {
    /// Encode, fragment, and send a [`QevMessage`] over the Noise
    /// channel.
    async fn send_msg(&mut self, msg: &QevMessage) -> Result<()>;

    /// Receive a complete [`QevMessage`], reassembling fragments
    /// as needed.
    async fn recv_msg(&mut self) -> Result<QevMessage>;
}

impl<S> ChannelExt for Channel<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    async fn send_msg(&mut self, msg: &QevMessage) -> Result<()> {
        let body = msg.encode()?;
        let total_len = body.len() as u32;
        let n_frags = (body.len() + FRAG_PAYLOAD_MAX - 1) / FRAG_PAYLOAD_MAX;
        let n_frags = n_frags.max(1);

        for (i, chunk) in body.chunks(FRAG_PAYLOAD_MAX).enumerate() {
            let mut framed = Vec::with_capacity(FRAG_HEADER_BYTES + chunk.len());
            framed.extend_from_slice(&total_len.to_be_bytes());
            framed.extend_from_slice(&(i as u32).to_be_bytes());
            framed.extend_from_slice(chunk);
            self.send(&framed).await?;
        }

        // Zero-length message edge case: still need at least one
        // fragment so the receiver can see the header.
        if body.is_empty() {
            let mut framed = Vec::with_capacity(FRAG_HEADER_BYTES);
            framed.extend_from_slice(&0u32.to_be_bytes());
            framed.extend_from_slice(&0u32.to_be_bytes());
            self.send(&framed).await?;
        }

        let _ = n_frags; // silence unused in release
        Ok(())
    }

    async fn recv_msg(&mut self) -> Result<QevMessage> {
        // Read the first fragment to learn the total length.
        let first = self.recv().await?;
        if first.len() < FRAG_HEADER_BYTES {
            return Err(Error::TransportDecrypt(format!(
                "fragment too short: {} bytes",
                first.len()
            )));
        }
        let total_len = u32::from_be_bytes([first[0], first[1], first[2], first[3]]) as usize;
        let seq0 = u32::from_be_bytes([first[4], first[5], first[6], first[7]]);
        if seq0 != 0 {
            return Err(Error::TransportDecrypt(format!(
                "expected fragment 0, got {seq0}"
            )));
        }
        if total_len > MAX_MESSAGE_BYTES {
            return Err(Error::TransportTooLarge {
                size: total_len,
                max: MAX_MESSAGE_BYTES,
            });
        }

        let mut buf = Vec::with_capacity(total_len);
        buf.extend_from_slice(&first[FRAG_HEADER_BYTES..]);

        let mut next_seq: u32 = 1;
        while buf.len() < total_len {
            let frag = self.recv().await?;
            if frag.len() < FRAG_HEADER_BYTES {
                return Err(Error::TransportDecrypt(format!(
                    "fragment too short: {} bytes",
                    frag.len()
                )));
            }
            let this_total =
                u32::from_be_bytes([frag[0], frag[1], frag[2], frag[3]]) as usize;
            let this_seq = u32::from_be_bytes([frag[4], frag[5], frag[6], frag[7]]);
            if this_total != total_len {
                return Err(Error::TransportDecrypt(format!(
                    "fragment total_len mismatch: {this_total} vs {total_len}"
                )));
            }
            if this_seq != next_seq {
                return Err(Error::TransportDecrypt(format!(
                    "out-of-order fragment: got {this_seq}, expected {next_seq}"
                )));
            }
            buf.extend_from_slice(&frag[FRAG_HEADER_BYTES..]);
            next_seq += 1;
        }

        if buf.len() != total_len {
            return Err(Error::TransportDecrypt(format!(
                "reassembled length {} != expected {}",
                buf.len(),
                total_len
            )));
        }

        QevMessage::decode(&buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{Initiator, Responder};
    use crate::identity::StaticKeypair;
    use tokio::io::duplex;

    fn sample_vault(size: usize) -> Vec<u8> {
        // Simulate vault bytes with a predictable pattern so we
        // can byte-compare after a round trip.
        (0..size).map(|i| (i * 7 % 256) as u8).collect()
    }

    #[tokio::test]
    async fn round_trip_small_message() {
        let alice = StaticKeypair::generate().unwrap();
        let bob = StaticKeypair::generate().unwrap();
        let bob_static = bob.public;
        let (a_side, b_side) = duplex(256 * 1024);

        let msg = QevMessage::VaultTransfer {
            filename: "note.vault.json".into(),
            vault_bytes: sample_vault(1024),
            note: Some("for your eyes only".into()),
            timestamp: 1717171717,
        };
        let expected = msg.clone();

        let alice_task = tokio::spawn(async move {
            let mut ch = Initiator::new(&alice, bob_static)
                .unwrap()
                .run(a_side)
                .await
                .unwrap();
            ch.send_msg(&msg).await.unwrap();
        });

        let bob_task = tokio::spawn(async move {
            let mut ch = Responder::new(&bob).unwrap().run(b_side).await.unwrap();
            ch.recv_msg().await.unwrap()
        });

        alice_task.await.unwrap();
        let got = bob_task.await.unwrap();
        assert_eq!(got, expected);
    }

    #[tokio::test]
    async fn round_trip_large_fragmented_vault() {
        // 512 KiB vault forces ~8 fragments at MAX_TRANSPORT_MSG-8
        // payload per fragment. Verifies reassembly.
        let alice = StaticKeypair::generate().unwrap();
        let bob = StaticKeypair::generate().unwrap();
        let bob_static = bob.public;
        let (a_side, b_side) = duplex(2 * 1024 * 1024);

        let msg = QevMessage::VaultTransfer {
            filename: "big.vault.json".into(),
            vault_bytes: sample_vault(512 * 1024),
            note: None,
            timestamp: 1717171717,
        };
        let expected = msg.clone();

        let alice_task = tokio::spawn(async move {
            let mut ch = Initiator::new(&alice, bob_static)
                .unwrap()
                .run(a_side)
                .await
                .unwrap();
            ch.send_msg(&msg).await.unwrap();
        });

        let bob_task = tokio::spawn(async move {
            let mut ch = Responder::new(&bob).unwrap().run(b_side).await.unwrap();
            ch.recv_msg().await.unwrap()
        });

        alice_task.await.unwrap();
        let got = bob_task.await.unwrap();
        assert_eq!(got, expected);
    }

    #[tokio::test]
    async fn ping_pong_liveness() {
        let alice = StaticKeypair::generate().unwrap();
        let bob = StaticKeypair::generate().unwrap();
        let bob_static = bob.public;
        let (a_side, b_side) = duplex(64 * 1024);

        let alice_task = tokio::spawn(async move {
            let mut ch = Initiator::new(&alice, bob_static)
                .unwrap()
                .run(a_side)
                .await
                .unwrap();
            ch.send_msg(&QevMessage::Ping).await.unwrap();
            ch.recv_msg().await.unwrap()
        });

        let bob_task = tokio::spawn(async move {
            let mut ch = Responder::new(&bob).unwrap().run(b_side).await.unwrap();
            let incoming = ch.recv_msg().await.unwrap();
            assert_eq!(incoming, QevMessage::Ping);
            ch.send_msg(&QevMessage::Pong).await.unwrap();
        });

        bob_task.await.unwrap();
        let got = alice_task.await.unwrap();
        assert_eq!(got, QevMessage::Pong);
    }

    #[test]
    fn encode_decode_round_trip_without_channel() {
        let msg = QevMessage::VaultTransfer {
            filename: "x.vault.json".into(),
            vault_bytes: sample_vault(200),
            note: Some("hi".into()),
            timestamp: 42,
        };
        let bytes = msg.encode().unwrap();
        let back = QevMessage::decode(&bytes).unwrap();
        assert_eq!(msg, back);
    }

    #[test]
    fn oversize_message_rejected() {
        // A 2 MiB vault blows past MAX_MESSAGE_BYTES and should
        // be rejected at encode time.
        let msg = QevMessage::VaultTransfer {
            filename: "huge.vault.json".into(),
            vault_bytes: vec![0u8; 2 * 1024 * 1024],
            note: None,
            timestamp: 0,
        };
        let err = msg.encode().unwrap_err();
        assert!(matches!(err, Error::TransportTooLarge { .. }));
    }

    #[test]
    fn ping_and_pong_encode_differently() {
        let p = QevMessage::Ping.encode().unwrap();
        let q = QevMessage::Pong.encode().unwrap();
        assert_ne!(p, q);
    }
}
