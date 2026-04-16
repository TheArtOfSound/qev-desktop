//! EnvelopeStore trait + InMemoryStore implementation.
//!
//! The store is the server's only stateful component. It's a
//! key-value structure indexed by the recipient's 32-byte public
//! key, storing ordered envelopes with a 16-byte ID per envelope.
//!
//! ## Trait vs. concrete
//!
//! The trait lets us swap in a SQLite-backed implementation later
//! without changing the service loop. For phase 3.0 we ship the
//! `InMemoryStore` — its contents are lost on server restart,
//! which is acceptable for a beta. Phase 3.x replaces it.
//!
//! ## Concurrency model
//!
//! The trait methods take `&self` and the in-memory impl uses a
//! parking-lot-equivalent `tokio::sync::RwLock<HashMap<...>>`.
//! Reads (get_pending, count_pending) can proceed concurrently;
//! writes (put, delete) briefly take an exclusive lock. The
//! overall throughput ceiling is fine for a beta — the relay
//! is bottlenecked by Noise handshake cost, not storage.
//!
//! ## Eviction
//!
//! `InMemoryStore` enforces two caps at put time:
//!
//! 1. Per-recipient maximum (default 100 envelopes): when
//!    exceeded, the oldest envelope for that recipient is
//!    dropped.
//! 2. Max envelope age (default 30 days): a background task in
//!    `RelayService` periodically calls `evict_older_than` to
//!    drop stale envelopes across all recipients.

use crate::error::Result;
use crate::ENVELOPE_ID_BYTES;
use std::collections::{HashMap, VecDeque};
use tokio::sync::RwLock;

/// One stored envelope.
#[derive(Debug, Clone)]
pub struct Envelope {
    /// 16-byte random id assigned at put() time.
    pub id: [u8; ENVELOPE_ID_BYTES],
    /// 32-byte static public key of the recipient.
    pub to: [u8; 32],
    /// 32-byte static public key of the sender.
    pub from: [u8; 32],
    /// Opaque envelope bytes.
    pub bytes: Vec<u8>,
    /// Unix milliseconds when the server received the envelope.
    pub created_at: u64,
}

/// Envelope store trait. Implement this to plug in SQLite or any
/// other backend.
///
/// All methods return explicit `impl Future + Send` rather than
/// `async fn` to ensure the returned futures can cross thread
/// boundaries inside the multi-threaded tokio runtime used by
/// the relay service's `tokio::spawn` call sites.
pub trait EnvelopeStore: Send + Sync {
    /// Deposit an envelope. The store assigns a fresh 16-byte id
    /// and returns it.
    fn put(
        &self,
        env: Envelope,
    ) -> impl std::future::Future<Output = Result<[u8; ENVELOPE_ID_BYTES]>> + Send;

    /// Return up to `limit` oldest pending envelopes for a recipient.
    fn get_pending(
        &self,
        to: &[u8; 32],
        limit: usize,
    ) -> impl std::future::Future<Output = Result<(Vec<Envelope>, bool)>> + Send;

    /// Delete envelopes by id. Only deletes envelopes addressed
    /// to `requester_pk` (so one peer can't delete another's).
    /// Returns the number actually deleted.
    fn delete(
        &self,
        requester_pk: &[u8; 32],
        ids: &[[u8; ENVELOPE_ID_BYTES]],
    ) -> impl std::future::Future<Output = Result<usize>> + Send;

    /// Count envelopes pending for a recipient (for rate limiting).
    fn count_pending(
        &self,
        to: &[u8; 32],
    ) -> impl std::future::Future<Output = Result<usize>> + Send;

    /// Evict envelopes older than `max_age_ms` milliseconds.
    /// Returns the number evicted.
    fn evict_older_than(
        &self,
        now_ms: u64,
        max_age_ms: u64,
    ) -> impl std::future::Future<Output = Result<usize>> + Send;
}

/// In-memory implementation of `EnvelopeStore` used by phase 3.0.
///
/// Lost on server restart. Acceptable for a beta; replace with
/// SQLite in a later phase.
pub struct InMemoryStore {
    /// key: recipient pk  →  FIFO deque of envelopes.
    inner: RwLock<HashMap<[u8; 32], VecDeque<Envelope>>>,
    /// Per-recipient cap. Default 100.
    pub max_per_recipient: usize,
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new(100)
    }
}

impl InMemoryStore {
    /// Construct an empty store.
    pub fn new(max_per_recipient: usize) -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            max_per_recipient,
        }
    }
}

impl EnvelopeStore for InMemoryStore {
    fn put(
        &self,
        mut env: Envelope,
    ) -> impl std::future::Future<Output = Result<[u8; ENVELOPE_ID_BYTES]>> + Send {
        let max = self.max_per_recipient;
        async move {
            // Assign a fresh random id if the caller didn't.
            if env.id == [0u8; ENVELOPE_ID_BYTES] {
                let mut id = [0u8; ENVELOPE_ID_BYTES];
                random_bytes(&mut id)?;
                env.id = id;
            }

            let mut w = self.inner.write().await;
            let queue = w.entry(env.to).or_insert_with(VecDeque::new);
            queue.push_back(env.clone());
            // Evict oldest if over cap.
            while queue.len() > max {
                queue.pop_front();
            }
            Ok(env.id)
        }
    }

    fn get_pending(
        &self,
        to: &[u8; 32],
        limit: usize,
    ) -> impl std::future::Future<Output = Result<(Vec<Envelope>, bool)>> + Send {
        let to = *to;
        async move {
            let r = self.inner.read().await;
            let Some(queue) = r.get(&to) else {
                return Ok((Vec::new(), false));
            };
            let total = queue.len();
            let take = limit.min(total);
            let batch: Vec<Envelope> = queue.iter().take(take).cloned().collect();
            let has_more = total > take;
            Ok((batch, has_more))
        }
    }

    fn delete(
        &self,
        requester_pk: &[u8; 32],
        ids: &[[u8; ENVELOPE_ID_BYTES]],
    ) -> impl std::future::Future<Output = Result<usize>> + Send {
        let requester = *requester_pk;
        let ids_owned: Vec<[u8; ENVELOPE_ID_BYTES]> = ids.to_vec();
        async move {
            let mut w = self.inner.write().await;
            let Some(queue) = w.get_mut(&requester) else {
                return Ok(0);
            };
            let before = queue.len();
            queue.retain(|env| !ids_owned.contains(&env.id));
            Ok(before - queue.len())
        }
    }

    fn count_pending(
        &self,
        to: &[u8; 32],
    ) -> impl std::future::Future<Output = Result<usize>> + Send {
        let to = *to;
        async move {
            let r = self.inner.read().await;
            Ok(r.get(&to).map(|q| q.len()).unwrap_or(0))
        }
    }

    fn evict_older_than(
        &self,
        now_ms: u64,
        max_age_ms: u64,
    ) -> impl std::future::Future<Output = Result<usize>> + Send {
        async move {
            let cutoff = now_ms.saturating_sub(max_age_ms);
            let mut total = 0;
            let mut w = self.inner.write().await;
            for queue in w.values_mut() {
                let before = queue.len();
                queue.retain(|env| env.created_at >= cutoff);
                total += before - queue.len();
            }
            w.retain(|_, q| !q.is_empty());
            Ok(total)
        }
    }
}

// ---- Helpers ----

fn random_bytes(out: &mut [u8]) -> Result<()> {
    // getrandom-backed OsRng via rand_core. The qev-pairing +
    // snow stack already pulls in getrandom transitively, so
    // this is ~0 additional binary size on a build that
    // already includes the pairing crate.
    use rand_core::{OsRng, RngCore};
    OsRng.fill_bytes(out);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_env(to_seed: u8, from_seed: u8, created_at: u64) -> Envelope {
        let mut to = [0u8; 32];
        let mut from = [0u8; 32];
        for i in 0..32 {
            to[i] = to_seed.wrapping_add(i as u8);
            from[i] = from_seed.wrapping_add(i as u8);
        }
        Envelope {
            id: [0u8; 16], // store will assign
            to,
            from,
            bytes: b"opaque".to_vec(),
            created_at,
        }
    }

    #[tokio::test]
    async fn put_and_get_round_trip() {
        let s = InMemoryStore::default();
        let env = sample_env(1, 2, 100);
        let id = s.put(env.clone()).await.unwrap();
        assert_ne!(id, [0u8; 16]);

        let (batch, has_more) = s.get_pending(&env.to, 10).await.unwrap();
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].from, env.from);
        assert_eq!(batch[0].bytes, b"opaque");
        assert!(!has_more);
    }

    #[tokio::test]
    async fn per_recipient_cap_evicts_oldest() {
        let s = InMemoryStore::new(3); // cap = 3
        let mut env = sample_env(1, 2, 0);
        env.created_at = 100;
        s.put(env.clone()).await.unwrap();
        env.created_at = 200;
        s.put(env.clone()).await.unwrap();
        env.created_at = 300;
        s.put(env.clone()).await.unwrap();
        env.created_at = 400;
        s.put(env.clone()).await.unwrap();

        let (batch, _) = s.get_pending(&env.to, 10).await.unwrap();
        assert_eq!(batch.len(), 3);
        // Oldest (created_at=100) should be gone.
        assert_eq!(batch[0].created_at, 200);
        assert_eq!(batch[2].created_at, 400);
    }

    #[tokio::test]
    async fn delete_only_affects_requester_queue() {
        let s = InMemoryStore::default();
        let alice = sample_env(1, 2, 100);
        let alice_id = s.put(alice.clone()).await.unwrap();
        let bob = sample_env(3, 4, 200);
        let _bob_id = s.put(bob.clone()).await.unwrap();

        // Bob tries to delete Alice's envelope by id. Should
        // not find it in Bob's queue and thus delete 0.
        let deleted = s.delete(&bob.to, &[alice_id]).await.unwrap();
        assert_eq!(deleted, 0);
        assert_eq!(s.count_pending(&alice.to).await.unwrap(), 1);

        // Alice deletes her own envelope.
        let deleted = s.delete(&alice.to, &[alice_id]).await.unwrap();
        assert_eq!(deleted, 1);
        assert_eq!(s.count_pending(&alice.to).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn evict_older_than() {
        let s = InMemoryStore::default();
        let env = sample_env(1, 2, 100);
        s.put(env.clone()).await.unwrap();
        let env2 = sample_env(1, 2, 200);
        s.put(env2.clone()).await.unwrap();
        let env3 = sample_env(1, 2, 300);
        s.put(env3.clone()).await.unwrap();

        // "now" is 350, max age is 100 → cutoff is 250 →
        // anything with created_at < 250 is evicted.
        let n = s.evict_older_than(350, 100).await.unwrap();
        assert_eq!(n, 2);
        assert_eq!(s.count_pending(&env.to).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn get_pending_returns_has_more_when_truncated() {
        let s = InMemoryStore::default();
        for i in 0..10 {
            s.put(sample_env(1, 2, i as u64 * 100)).await.unwrap();
        }
        // Wrong-seed query: all-zero pk should have nothing queued.
        let (batch, _has_more) = s.get_pending(&[0u8; 32], 5).await.unwrap();
        assert_eq!(batch.len(), 0);

        let correct_to = {
            let mut t = [0u8; 32];
            for i in 0..32 {
                t[i] = 1u8.wrapping_add(i as u8);
            }
            t
        };
        let (batch, has_more) = s.get_pending(&correct_to, 5).await.unwrap();
        assert_eq!(batch.len(), 5);
        assert!(has_more);
    }

    #[tokio::test]
    async fn count_pending_zero_for_unknown_key() {
        let s = InMemoryStore::default();
        assert_eq!(s.count_pending(&[0u8; 32]).await.unwrap(), 0);
    }
}
