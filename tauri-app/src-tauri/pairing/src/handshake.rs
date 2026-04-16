//! Noise XK handshake and transport wrapper.
//!
//! This module wraps the `snow` crate with a convenient async API
//! for both the initiator (the scanner, who learned the responder's
//! static key from the QR) and the responder (the inviter, who
//! displayed the QR and is waiting for a connection).
//!
//! ## Noise XK in QEV
//!
//! XK is a 1.5-round-trip (3-message) pattern. The responder's
//! static key is PRE-KNOWN to the initiator (via the scanned QR
//! code, represented in the spec as the pre-message `<- s`). The
//! actual handshake is:
//!
//! ```text
//!   -> e, es
//!   <- e, ee
//!   -> s, se
//! ```
//!
//! - Msg 1 (initiator → responder): ephemeral + ES token
//!   (ephemeral × known-responder-static).
//! - Msg 2 (responder → initiator): responder's ephemeral + EE
//!   token (ephemeral × ephemeral). No static transmitted here
//!   because the responder's static is already known to the
//!   initiator.
//! - Msg 3 (initiator → responder): initiator's static public key
//!   + SE token (static × ephemeral). This is where the responder
//!   learns who the initiator is.
//!
//! After msg 3 lands, both sides call `into_transport_mode()` and
//! the channel is ready. Forward secrecy on the transport is
//! guaranteed because the session keys are derived from the
//! ephemeral DH outputs, not from the long-lived static keys alone.
//!
//! ## API shape
//!
//! ```rust,ignore
//! let keypair = StaticKeypair::generate()?;
//! let invite = /* scanned from QR */;
//!
//! // Initiator side:
//! let mut handshake = Initiator::new(&keypair, invite.static_pk_array()?)?;
//! let (stream, _addr) = connect_one_of(invite.addrs_parsed()?).await?;
//! let channel = handshake.run(stream).await?;
//!
//! // Responder side:
//! let listener = TcpListener::bind("0.0.0.0:7891").await?;
//! let (stream, _addr) = listener.accept().await?;
//! let mut handshake = Responder::new(&keypair)?;
//! let channel = handshake.run(stream).await?;
//!
//! // Both sides now have a Channel and can exchange messages.
//! channel.send(&QevMessage::VaultTransfer { ... }).await?;
//! let incoming = channel.recv().await?;
//! ```
//!
//! The `run` method is where the 2-message dance happens. Before
//! returning, both sides compute the safety number from their own
//! and peer's static keys and attach it to the channel for
//! in-person verification.

use crate::error::{Error, Result};
use crate::identity::StaticKeypair;
use crate::safety::safety_number;
use crate::{MAX_TRANSPORT_MSG, NOISE_PATTERN, STATIC_KEY_BYTES};

use snow::{Builder, HandshakeState, TransportState};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Max size of a single Noise handshake message. Per Noise spec,
/// handshake messages are at most 65535 bytes.
const HANDSHAKE_MSG_LIMIT: usize = 65535;

/// Noise XK initiator.
///
/// Holds a prepared `HandshakeState` with the initiator role and the
/// responder's static public key already provided (learned from the
/// scanned QR code).
pub struct Initiator {
    state: HandshakeState,
    peer_pk: [u8; STATIC_KEY_BYTES],
    own_pk: [u8; STATIC_KEY_BYTES],
}

impl Initiator {
    /// Construct a new initiator with our own static keypair and
    /// the responder's static public key (from the QR invite).
    pub fn new(
        own: &StaticKeypair,
        peer_static_pk: [u8; STATIC_KEY_BYTES],
    ) -> Result<Self> {
        let params = NOISE_PATTERN.parse().map_err(|_| {
            Error::Internal("pattern parse failed (constant should be valid)".into())
        })?;
        let state = Builder::new(params)
            .local_private_key(&own.secret)
            .remote_public_key(&peer_static_pk)
            .build_initiator()?;
        Ok(Self {
            state,
            peer_pk: peer_static_pk,
            own_pk: own.public,
        })
    }

    /// Drive the handshake over an async IO stream. On success,
    /// returns a [`Channel`] ready for transport messages.
    ///
    /// XK is 3 messages:
    ///   1. initiator → responder: e, es
    ///   2. responder → initiator: e, ee
    ///   3. initiator → responder: s, se
    pub async fn run<S>(self, mut io: S) -> Result<Channel<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let Initiator {
            mut state,
            peer_pk,
            own_pk,
        } = self;

        // Msg 1: -> e, es
        let mut buf = vec![0u8; HANDSHAKE_MSG_LIMIT];
        let n = state.write_message(&[], &mut buf)?;
        write_frame(&mut io, &buf[..n]).await?;

        // Msg 2: <- e, ee
        let reply = read_frame(&mut io).await?;
        let mut payload = vec![0u8; HANDSHAKE_MSG_LIMIT];
        state.read_message(&reply, &mut payload)?;

        // Msg 3: -> s, se  (transmits our static, completes the
        // handshake on both sides)
        let mut buf3 = vec![0u8; HANDSHAKE_MSG_LIMIT];
        let n3 = state.write_message(&[], &mut buf3)?;
        write_frame(&mut io, &buf3[..n3]).await?;

        // We already know the responder's static (from the QR); snow's
        // get_remote_static() will return it now that the handshake
        // has processed the ES token. Double-check it matches the
        // pre-shared value as a belt-and-suspenders MITM guard.
        if let Some(got) = state.get_remote_static() {
            if got != peer_pk {
                return Err(Error::Handshake(
                    "responder static mismatch — possible MITM".into(),
                ));
            }
        }

        let transport = state.into_transport_mode()?;
        Ok(Channel::new(io, transport, own_pk, peer_pk))
    }
}

/// Noise XK responder.
///
/// Holds a prepared `HandshakeState` with the responder role. The
/// responder does NOT need to know the initiator's static key in
/// advance — the initiator transmits its ephemeral as msg 1 and
/// nothing else about its identity leaks.
pub struct Responder {
    state: HandshakeState,
    own_pk: [u8; STATIC_KEY_BYTES],
}

impl Responder {
    /// Construct a new responder with our static keypair.
    pub fn new(own: &StaticKeypair) -> Result<Self> {
        let params = NOISE_PATTERN.parse().map_err(|_| {
            Error::Internal("pattern parse failed (constant should be valid)".into())
        })?;
        let state = Builder::new(params)
            .local_private_key(&own.secret)
            .build_responder()?;
        Ok(Self {
            state,
            own_pk: own.public,
        })
    }

    /// Drive the handshake over an async IO stream. On success,
    /// returns a [`Channel`] ready for transport messages.
    ///
    /// XK is 3 messages:
    ///   1. initiator → responder: e, es
    ///   2. responder → initiator: e, ee
    ///   3. initiator → responder: s, se
    ///
    /// After msg 3 we know the initiator's static pk (it was
    /// transmitted in that message), so we can compute a symmetric
    /// safety number from both keys.
    pub async fn run<S>(self, mut io: S) -> Result<Channel<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let Responder { mut state, own_pk } = self;

        // Msg 1: <- e, es
        let first = read_frame(&mut io).await?;
        let mut payload = vec![0u8; HANDSHAKE_MSG_LIMIT];
        state.read_message(&first, &mut payload)?;

        // Msg 2: -> e, ee
        let mut buf2 = vec![0u8; HANDSHAKE_MSG_LIMIT];
        let n2 = state.write_message(&[], &mut buf2)?;
        write_frame(&mut io, &buf2[..n2]).await?;

        // Msg 3: <- s, se  (initiator transmits static, completes)
        let third = read_frame(&mut io).await?;
        let mut payload3 = vec![0u8; HANDSHAKE_MSG_LIMIT];
        state.read_message(&third, &mut payload3)?;

        // Now we know the initiator's static key. Extract it for
        // the safety number calculation.
        let peer_pk_bytes = state.get_remote_static().ok_or_else(|| {
            Error::Handshake("initiator did not transmit static key in msg 3".into())
        })?;
        if peer_pk_bytes.len() != STATIC_KEY_BYTES {
            return Err(Error::Handshake(format!(
                "initiator static wrong length: {}",
                peer_pk_bytes.len()
            )));
        }
        let mut peer_pk = [0u8; STATIC_KEY_BYTES];
        peer_pk.copy_from_slice(peer_pk_bytes);

        let transport = state.into_transport_mode()?;
        Ok(Channel::new(io, transport, own_pk, peer_pk))
    }
}

/// A post-handshake Noise channel. Both sides can send and receive
/// length-prefixed encrypted messages.
pub struct Channel<S> {
    io: S,
    transport: TransportState,
    own_pk: [u8; STATIC_KEY_BYTES],
    peer_pk: [u8; STATIC_KEY_BYTES],
}

impl<S> Channel<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn new(
        io: S,
        transport: TransportState,
        own_pk: [u8; STATIC_KEY_BYTES],
        peer_pk: [u8; STATIC_KEY_BYTES],
    ) -> Self {
        Self {
            io,
            transport,
            own_pk,
            peer_pk,
        }
    }

    /// Return the 30-digit safety number for this channel's peer
    /// pair. Both sides produce the same number; the UI displays
    /// it and asks the user to verify.
    pub fn safety_number(&self) -> String {
        safety_number(&self.own_pk, &self.peer_pk)
    }

    /// The peer's static public key, as learned during the
    /// handshake. May be all-zeros if we're the responder in XK
    /// (see the `Responder::run` comment).
    pub fn peer_static_pk(&self) -> [u8; STATIC_KEY_BYTES] {
        self.peer_pk
    }

    /// Encrypt and write a message to the transport.
    pub async fn send(&mut self, plaintext: &[u8]) -> Result<()> {
        if plaintext.len() > MAX_TRANSPORT_MSG {
            return Err(Error::TransportTooLarge {
                size: plaintext.len(),
                max: MAX_TRANSPORT_MSG,
            });
        }
        let mut ciphertext = vec![0u8; plaintext.len() + 16];
        let n = self
            .transport
            .write_message(plaintext, &mut ciphertext)
            .map_err(Error::from)?;
        write_frame(&mut self.io, &ciphertext[..n]).await?;
        Ok(())
    }

    /// Receive the next encrypted message and decrypt it.
    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        let ciphertext = read_frame(&mut self.io).await?;
        if ciphertext.len() > MAX_TRANSPORT_MSG + 16 {
            return Err(Error::TransportTooLarge {
                size: ciphertext.len(),
                max: MAX_TRANSPORT_MSG + 16,
            });
        }
        let mut plaintext = vec![0u8; ciphertext.len()];
        let n = self
            .transport
            .read_message(&ciphertext, &mut plaintext)
            .map_err(|e| Error::TransportDecrypt(e.to_string()))?;
        plaintext.truncate(n);
        Ok(plaintext)
    }
}

// -------- Framing --------
//
// Noise handshake and transport messages are length-prefixed with a
// 2-byte big-endian length. The maximum per-Noise-message is 65535
// bytes; larger payloads are fragmented at a higher layer.

async fn write_frame<S: AsyncWrite + Unpin>(io: &mut S, msg: &[u8]) -> Result<()> {
    if msg.len() > 65535 {
        return Err(Error::TransportTooLarge {
            size: msg.len(),
            max: 65535,
        });
    }
    let len = (msg.len() as u16).to_be_bytes();
    io.write_all(&len).await?;
    io.write_all(msg).await?;
    io.flush().await?;
    Ok(())
}

async fn read_frame<S: AsyncRead + Unpin>(io: &mut S) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    io.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    io.read_exact(&mut buf).await?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn handshake_completes_over_duplex() {
        // Two in-process StaticKeypairs. The initiator knows the
        // responder's public key; the responder will learn the
        // initiator's during the handshake (or not, in XK — see
        // Responder::run comments).
        let alice = StaticKeypair::generate().unwrap();
        let bob = StaticKeypair::generate().unwrap();

        // Duplex pair: one side = alice→bob, other = bob→alice.
        let (a_side, b_side) = duplex(64 * 1024);

        let bob_static = bob.public;

        let alice_task = tokio::spawn(async move {
            let initiator = Initiator::new(&alice, bob_static).unwrap();
            let mut channel = initiator.run(a_side).await.unwrap();
            channel.send(b"hello from alice").await.unwrap();
            let reply = channel.recv().await.unwrap();
            (channel.safety_number(), reply)
        });

        let bob_task = tokio::spawn(async move {
            let responder = Responder::new(&bob).unwrap();
            let mut channel = responder.run(b_side).await.unwrap();
            let msg = channel.recv().await.unwrap();
            channel.send(b"hello from bob").await.unwrap();
            (channel.safety_number(), msg)
        });

        let (alice_sn, alice_got) = alice_task.await.unwrap();
        let (bob_sn, bob_got) = bob_task.await.unwrap();

        assert_eq!(alice_got, b"hello from bob");
        assert_eq!(bob_got, b"hello from alice");

        // XK msg 3 transmits the initiator's static to the responder,
        // so both sides know each other's static key by the time the
        // channel is created. Safety numbers must therefore be
        // SYMMETRIC (sort-then-hash means both sides produce the
        // same 30-digit number).
        assert_eq!(alice_sn, bob_sn);
        assert_eq!(alice_sn.len(), 35);
    }

    #[tokio::test]
    async fn multiple_messages_per_channel() {
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
            for i in 0..5u8 {
                ch.send(&[i; 100]).await.unwrap();
            }
            for i in 0..5u8 {
                let got = ch.recv().await.unwrap();
                assert_eq!(got, vec![i; 200]);
            }
        });

        let bob_task = tokio::spawn(async move {
            let mut ch = Responder::new(&bob).unwrap().run(b_side).await.unwrap();
            for i in 0..5u8 {
                let got = ch.recv().await.unwrap();
                assert_eq!(got, vec![i; 100]);
            }
            for i in 0..5u8 {
                ch.send(&[i; 200]).await.unwrap();
            }
        });

        alice_task.await.unwrap();
        bob_task.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_initiator_with_wrong_peer_key() {
        // If the initiator is handed a static_pk that doesn't
        // match the responder's real key, the handshake should
        // fail at read_message time (the ES token wouldn't
        // decrypt), not silently succeed.
        let alice = StaticKeypair::generate().unwrap();
        let bob = StaticKeypair::generate().unwrap();
        let impostor = StaticKeypair::generate().unwrap();
        let (a_side, b_side) = duplex(64 * 1024);

        let alice_task = tokio::spawn(async move {
            // Use impostor's pk as if it were bob's — alice will
            // talk to bob thinking bob's key is different.
            let initiator = Initiator::new(&alice, impostor.public).unwrap();
            initiator.run(a_side).await
        });

        let bob_task = tokio::spawn(async move {
            let responder = Responder::new(&bob).unwrap();
            responder.run(b_side).await
        });

        let alice_result = alice_task.await.unwrap();
        let _ = bob_task.await.unwrap();

        // Alice's handshake should fail — she was told to trust
        // `impostor.public` but bob sent his real public key.
        assert!(
            alice_result.is_err(),
            "initiator should reject mismatched responder key"
        );
    }
}
