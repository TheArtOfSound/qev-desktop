//! RelayMessage — the CBOR RPC enum exchanged between client and
//! relay server inside the Noise XK channel.
//!
//! Every client→server interaction is one Request variant followed
//! by exactly one server→client Response variant of the matching
//! type, after which the session closes. There is no
//! server-push in phase 3.0.

use crate::error::{Error, Result};
use crate::{ENVELOPE_ID_BYTES, MAX_ENVELOPE_BYTES, MAX_LINK_PAYLOAD_BYTES, PROTOCOL_VERSION};
use serde::{Deserialize, Serialize};

/// Envelope as it appears on the wire inside a `FetchResult`
/// response. Distinct from [`crate::store::Envelope`] so the store
/// can use owned fixed-size arrays internally while the wire
/// format uses byte strings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireEnvelope {
    /// 16-byte opaque envelope ID assigned by the server at
    /// delivery time.
    #[serde(with = "serde_bytes")]
    pub id: Vec<u8>,
    /// Sender's 32-byte static public key.
    #[serde(with = "serde_bytes")]
    pub from: Vec<u8>,
    /// Opaque envelope bytes (already Noise-wrapped for the
    /// final recipient by the original sender; the relay never
    /// unwraps this).
    #[serde(with = "serde_bytes")]
    pub envelope: Vec<u8>,
    /// Unix milliseconds when the server received the envelope.
    pub created_at: u64,
}

/// Top-level RPC message exchanged inside the Noise channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RelayMessage {
    /// Client → server: store an envelope addressed to a specific
    /// recipient's static public key.
    #[serde(rename = "deliver-v1")]
    Deliver {
        /// 32-byte X25519 public key of the final recipient.
        /// This is the routing key used to index the envelope in
        /// the store.
        #[serde(with = "serde_bytes")]
        to: Vec<u8>,
        /// Opaque envelope bytes. Typically a Noise-wrapped
        /// vault delivered via the pairing crate's transport
        /// layer, but the relay does not look inside.
        #[serde(with = "serde_bytes")]
        envelope: Vec<u8>,
    },

    /// Server → client: successful deliver ack.
    #[serde(rename = "deliver-result-v1")]
    DeliverResult {
        /// 16-byte envelope ID the server assigned.
        #[serde(with = "serde_bytes")]
        id: Vec<u8>,
    },

    /// Client → server: fetch all pending envelopes addressed to
    /// the caller's static public key. The caller's identity is
    /// established by the Noise handshake — no `to` field is
    /// needed.
    #[serde(rename = "fetch-v1")]
    Fetch {
        /// Maximum number of envelopes to return in one response.
        /// 0 means "server default."
        limit: u32,
    },

    /// Server → client: fetch result.
    #[serde(rename = "fetch-result-v1")]
    FetchResult {
        /// Pending envelopes, oldest first.
        envelopes: Vec<WireEnvelope>,
        /// True if more envelopes are queued beyond this batch.
        /// Client should issue another Fetch to drain them.
        has_more: bool,
    },

    /// Client → server: delete envelopes by id (after successful
    /// pickup + decrypt on the client side).
    #[serde(rename = "ack-v1")]
    Ack {
        /// List of envelope IDs to delete. The server only deletes
        /// envelopes addressed to the caller's pk, even if the
        /// list happens to include IDs of envelopes belonging to
        /// someone else.
        ids: Vec<Vec<u8>>,
    },

    /// Server → client: ack result.
    #[serde(rename = "ack-result-v1")]
    AckResult {
        /// Number of envelopes actually deleted.
        deleted: u32,
    },

    /// Server → client: error response for a well-formed request.
    /// The client should surface this to the UI; it is NOT a
    /// reason to close the connection.
    #[serde(rename = "error-v1")]
    Error {
        /// Machine-readable code: "rate_limited", "too_large",
        /// "invalid_to", "internal", "unsupported_version".
        code: String,
        /// Human-readable message.
        msg: String,
    },

    /// Server → client: a one-time informational hello sent at
    /// the start of every session. Contains the protocol
    /// version so the client can bail out early on mismatch.
    /// Not required — the server may skip this and go straight
    /// to handling requests.
    #[serde(rename = "hello-v1")]
    Hello {
        /// Protocol version string (currently "QEV-RELAY-V1").
        version: String,
        /// Maximum envelope bytes the server will accept.
        max_envelope_bytes: u32,
    },

    // ---- Qira Link live-relay extensions (v1) ----
    //
    // These variants support the Qira Link VPN product: a live
    // bidirectional packet-forwarding mode layered on the same
    // Noise XK channel. Orthogonal to the existing store-and-
    // forward Deliver/Fetch variants — a single session is
    // EITHER in one-shot mode (Deliver/Fetch/Ack) OR in live
    // mode (LinkAttach → LinkTunnel ↔ LinkInbound), never both.
    //
    // The server distinguishes modes by the first message:
    //   - LinkAttach → live mode, connection stays open
    //   - anything else → one-shot mode (legacy QEV behaviour)

    /// Client → server: enter live mode. The server registers
    /// this session as the live delivery endpoint for the
    /// client's pk (learned from the Noise handshake), and
    /// starts accepting subsequent `LinkTunnel` messages.
    /// At most one live session per pk — if the pk is already
    /// attached, the server returns an `Error { code: "already_attached" }`
    /// and keeps the existing attachment.
    #[serde(rename = "link-attach-v1")]
    LinkAttach {},

    /// Server → client: live mode confirmed.
    /// Sent exactly once, immediately after a successful
    /// `LinkAttach`. After this the client may begin sending
    /// `LinkTunnel` messages.
    #[serde(rename = "link-attach-ack-v1")]
    LinkAttachAck {
        /// Protocol version the server is speaking.
        version: String,
        /// Max bytes per LinkTunnel payload. Much smaller than
        /// MAX_ENVELOPE_BYTES because these are wire-speed
        /// UDP-sized packets, not large envelopes.
        max_payload_bytes: u32,
    },

    /// Client → server (live mode only): forward a Qira Link
    /// UDP payload to the recipient pk. The payload is opaque
    /// to the relay — in practice it's a
    /// `qira_link_core::MessageTransport`-encoded WG-shaped
    /// ciphertext packet, but the relay never looks inside.
    ///
    /// Ephemeral: the relay does NOT persist these. If the
    /// recipient is not currently attached the server returns
    /// `LinkUnreachable { to }` (not Error) so a briefly
    /// disconnected peer just drops one packet, not the whole
    /// session.
    #[serde(rename = "link-tunnel-v1")]
    LinkTunnel {
        /// 32-byte recipient pk.
        #[serde(with = "serde_bytes")]
        to: Vec<u8>,
        /// Opaque packet bytes.
        #[serde(with = "serde_bytes")]
        payload: Vec<u8>,
    },

    /// Server → client (live mode only): a `LinkTunnel` payload
    /// forwarded from another attached peer.
    #[serde(rename = "link-inbound-v1")]
    LinkInbound {
        /// 32-byte sender pk (the peer that sent the payload).
        #[serde(with = "serde_bytes")]
        from: Vec<u8>,
        /// Opaque packet bytes, as received.
        #[serde(with = "serde_bytes")]
        payload: Vec<u8>,
    },

    /// Server → client (live mode only): the peer named in a
    /// previous `LinkTunnel { to }` is not currently attached.
    /// Soft failure — the session stays open; the client may
    /// back off and retry later.
    #[serde(rename = "link-unreachable-v1")]
    LinkUnreachable {
        /// 32-byte pk of the peer we tried to reach.
        #[serde(with = "serde_bytes")]
        to: Vec<u8>,
    },
}

impl RelayMessage {
    /// CBOR-encode the message to bytes. Enforces the
    /// `MAX_ENVELOPE_BYTES` cap on Deliver payloads and the
    /// `MAX_LINK_PAYLOAD_BYTES` cap on LinkTunnel payloads
    /// before encoding.
    pub fn encode(&self) -> Result<Vec<u8>> {
        // Pre-flight size checks so the client catches oversize
        // payloads before they hit the wire.
        match self {
            RelayMessage::Deliver { envelope, .. } => {
                if envelope.len() > MAX_ENVELOPE_BYTES {
                    return Err(Error::TooLarge {
                        size: envelope.len(),
                        max: MAX_ENVELOPE_BYTES,
                    });
                }
            }
            RelayMessage::LinkTunnel { payload, .. } => {
                if payload.len() > MAX_LINK_PAYLOAD_BYTES {
                    return Err(Error::TooLarge {
                        size: payload.len(),
                        max: MAX_LINK_PAYLOAD_BYTES,
                    });
                }
            }
            _ => {}
        }
        let mut buf = Vec::with_capacity(256);
        ciborium::ser::into_writer(self, &mut buf)?;
        Ok(buf)
    }

    /// CBOR-decode a message from bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Ok(ciborium::de::from_reader(bytes)?)
    }

    /// Build a well-formed hello message for a server to send
    /// at session start.
    pub fn hello() -> Self {
        Self::Hello {
            version: PROTOCOL_VERSION.to_string(),
            max_envelope_bytes: MAX_ENVELOPE_BYTES as u32,
        }
    }

    /// Convenience: build an Error variant with a specific code.
    pub fn error(code: impl Into<String>, msg: impl Into<String>) -> Self {
        Self::Error {
            code: code.into(),
            msg: msg.into(),
        }
    }
}

/// Validate a 32-byte public key field from the wire.
pub(crate) fn check_pk_bytes(field: &str, bytes: &[u8]) -> Result<[u8; 32]> {
    if bytes.len() != 32 {
        return Err(Error::Internal(format!(
            "{field} must be 32 bytes (got {})",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

/// Validate a 16-byte envelope ID field from the wire.
pub(crate) fn check_id_bytes(field: &str, bytes: &[u8]) -> Result<[u8; ENVELOPE_ID_BYTES]> {
    if bytes.len() != ENVELOPE_ID_BYTES {
        return Err(Error::Internal(format!(
            "{field} must be {ENVELOPE_ID_BYTES} bytes (got {})",
            bytes.len()
        )));
    }
    let mut out = [0u8; ENVELOPE_ID_BYTES];
    out.copy_from_slice(bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deliver_round_trip() {
        let m = RelayMessage::Deliver {
            to: vec![0x11u8; 32],
            envelope: b"opaque noise bytes".to_vec(),
        };
        let bytes = m.encode().unwrap();
        let back = RelayMessage::decode(&bytes).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn deliver_rejects_oversize_envelope() {
        let m = RelayMessage::Deliver {
            to: vec![0x11u8; 32],
            envelope: vec![0u8; MAX_ENVELOPE_BYTES + 1],
        };
        let err = m.encode().unwrap_err();
        assert!(matches!(err, Error::TooLarge { .. }));
    }

    #[test]
    fn fetch_round_trip() {
        let m = RelayMessage::Fetch { limit: 50 };
        let bytes = m.encode().unwrap();
        assert_eq!(RelayMessage::decode(&bytes).unwrap(), m);
    }

    #[test]
    fn fetch_result_with_envelopes() {
        let env = WireEnvelope {
            id: vec![0x99; 16],
            from: vec![0x11; 32],
            envelope: b"ciphertext".to_vec(),
            created_at: 1717171717000,
        };
        let m = RelayMessage::FetchResult {
            envelopes: vec![env],
            has_more: false,
        };
        let bytes = m.encode().unwrap();
        assert_eq!(RelayMessage::decode(&bytes).unwrap(), m);
    }

    #[test]
    fn hello_contains_current_version() {
        let h = RelayMessage::hello();
        match h {
            RelayMessage::Hello {
                version,
                max_envelope_bytes,
            } => {
                assert_eq!(version, PROTOCOL_VERSION);
                assert_eq!(max_envelope_bytes as usize, MAX_ENVELOPE_BYTES);
            }
            _ => panic!("hello() must return a Hello variant"),
        }
    }

    #[test]
    fn error_variant_round_trips() {
        let m = RelayMessage::error("rate_limited", "slow down");
        let bytes = m.encode().unwrap();
        match RelayMessage::decode(&bytes).unwrap() {
            RelayMessage::Error { code, msg } => {
                assert_eq!(code, "rate_limited");
                assert_eq!(msg, "slow down");
            }
            _ => panic!("expected Error variant"),
        }
    }

    #[test]
    fn ack_with_ids() {
        let m = RelayMessage::Ack {
            ids: vec![vec![0x01; 16], vec![0x02; 16]],
        };
        let bytes = m.encode().unwrap();
        assert_eq!(RelayMessage::decode(&bytes).unwrap(), m);
    }

    #[test]
    fn check_pk_bytes_enforces_32() {
        assert!(check_pk_bytes("to", &[0u8; 32]).is_ok());
        assert!(check_pk_bytes("to", &[0u8; 31]).is_err());
        assert!(check_pk_bytes("to", &[0u8; 33]).is_err());
    }

    #[test]
    fn check_id_bytes_enforces_16() {
        assert!(check_id_bytes("id", &[0u8; 16]).is_ok());
        assert!(check_id_bytes("id", &[0u8; 15]).is_err());
        assert!(check_id_bytes("id", &[0u8; 17]).is_err());
    }

    // ---- Qira Link live-mode variants ----

    #[test]
    fn link_attach_round_trip() {
        let m = RelayMessage::LinkAttach {};
        let bytes = m.encode().unwrap();
        assert_eq!(RelayMessage::decode(&bytes).unwrap(), m);
    }

    #[test]
    fn link_attach_ack_round_trip() {
        let m = RelayMessage::LinkAttachAck {
            version: PROTOCOL_VERSION.to_string(),
            max_payload_bytes: MAX_LINK_PAYLOAD_BYTES as u32,
        };
        let bytes = m.encode().unwrap();
        assert_eq!(RelayMessage::decode(&bytes).unwrap(), m);
    }

    #[test]
    fn link_tunnel_round_trip() {
        let m = RelayMessage::LinkTunnel {
            to: vec![0xABu8; 32],
            payload: b"ciphertext goes here".to_vec(),
        };
        let bytes = m.encode().unwrap();
        assert_eq!(RelayMessage::decode(&bytes).unwrap(), m);
    }

    #[test]
    fn link_tunnel_rejects_oversize_payload() {
        let m = RelayMessage::LinkTunnel {
            to: vec![0xABu8; 32],
            payload: vec![0u8; MAX_LINK_PAYLOAD_BYTES + 1],
        };
        let err = m.encode().unwrap_err();
        assert!(matches!(err, Error::TooLarge { .. }));
    }

    #[test]
    fn link_inbound_round_trip() {
        let m = RelayMessage::LinkInbound {
            from: vec![0x42u8; 32],
            payload: b"forwarded".to_vec(),
        };
        let bytes = m.encode().unwrap();
        assert_eq!(RelayMessage::decode(&bytes).unwrap(), m);
    }

    #[test]
    fn link_unreachable_round_trip() {
        let m = RelayMessage::LinkUnreachable {
            to: vec![0x77u8; 32],
        };
        let bytes = m.encode().unwrap();
        assert_eq!(RelayMessage::decode(&bytes).unwrap(), m);
    }

    #[test]
    fn link_tunnel_tag_is_stable() {
        // Wire-format guard: CBOR-encoding of the type tag must
        // be exactly "link-tunnel-v1" so future forks can't drift.
        let m = RelayMessage::LinkTunnel {
            to: vec![0u8; 32],
            payload: b"x".to_vec(),
        };
        let bytes = m.encode().unwrap();
        let hay = String::from_utf8_lossy(&bytes);
        assert!(
            hay.contains("link-tunnel-v1"),
            "tag must be 'link-tunnel-v1' in CBOR-encoded form; got {hay:?}"
        );
    }
}
