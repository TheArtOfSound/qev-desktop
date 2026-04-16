//! SQLite-backed envelope store for the relay server.
//!
//! Replaces the `InMemoryStore` for production use so envelopes
//! survive server restarts. Uses `rusqlite` for a single-file
//! database at `/var/lib/qev-relay/envelopes.db`.
//!
//! Schema:
//! ```sql
//! CREATE TABLE IF NOT EXISTS envelopes (
//!     id          BLOB PRIMARY KEY,    -- 16 bytes
//!     to_pk       BLOB NOT NULL,       -- 32 bytes (recipient)
//!     from_pk     BLOB NOT NULL,       -- 32 bytes (sender)
//!     bytes       BLOB NOT NULL,       -- opaque envelope
//!     created_at  INTEGER NOT NULL     -- unix ms
//! );
//! CREATE INDEX IF NOT EXISTS idx_to ON envelopes(to_pk, created_at);
//! ```
//!
//! Thread safety: `rusqlite::Connection` is not `Send`, so we
//! wrap it in a `tokio::sync::Mutex` and run all DB ops inside
//! `spawn_blocking` closures. This is the standard pattern for
//! rusqlite + tokio; the blocking thread pool handles the
//! synchronous SQLite calls without stalling the async runtime.

use crate::error::{Error, Result};
use crate::store::{Envelope, EnvelopeStore};
use crate::ENVELOPE_ID_BYTES;

use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;

/// SQLite-backed envelope store.
pub struct SqliteStore {
    conn: Arc<Mutex<rusqlite::Connection>>,
    max_per_recipient: usize,
}

impl SqliteStore {
    /// Open (or create) the database at `path`.
    pub fn open(path: &Path, max_per_recipient: usize) -> Result<Self> {
        let conn = rusqlite::Connection::open(path)
            .map_err(|e| Error::Internal(format!("sqlite open: {e}")))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS envelopes (
                id          BLOB PRIMARY KEY,
                to_pk       BLOB NOT NULL,
                from_pk     BLOB NOT NULL,
                bytes       BLOB NOT NULL,
                created_at  INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_to ON envelopes(to_pk, created_at);",
        )
        .map_err(|e| Error::Internal(format!("sqlite schema: {e}")))?;
        // WAL mode for concurrent readers + single writer.
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| Error::Internal(format!("sqlite WAL: {e}")))?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            max_per_recipient,
        })
    }
}

impl EnvelopeStore for SqliteStore {
    fn put(
        &self,
        mut env: Envelope,
    ) -> impl std::future::Future<Output = Result<[u8; ENVELOPE_ID_BYTES]>> + Send {
        let conn = Arc::clone(&self.conn);
        let max = self.max_per_recipient;
        async move {
            if env.id == [0u8; ENVELOPE_ID_BYTES] {
                use rand_core::{OsRng, RngCore};
                OsRng.fill_bytes(&mut env.id);
            }
            let id = env.id;
            let to = env.to;
            let from = env.from;
            let bytes = env.bytes;
            let created_at = env.created_at as i64;

            tokio::task::spawn_blocking(move || {
                let guard = conn.lock().map_err(|e| Error::Internal(format!("mutex: {e}")))?;
                guard
                    .execute(
                        "INSERT OR REPLACE INTO envelopes (id, to_pk, from_pk, bytes, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                        rusqlite::params![id.as_slice(), to.as_slice(), from.as_slice(), bytes, created_at],
                    )
                    .map_err(|e| Error::Internal(format!("sqlite insert: {e}")))?;

                // Enforce per-recipient cap: count, then delete oldest if over.
                let count: i64 = guard
                    .query_row(
                        "SELECT COUNT(*) FROM envelopes WHERE to_pk = ?1",
                        [to.as_slice()],
                        |row| row.get(0),
                    )
                    .map_err(|e| Error::Internal(format!("sqlite count: {e}")))?;
                if count as usize > max {
                    let excess = count as usize - max;
                    guard
                        .execute(
                            "DELETE FROM envelopes WHERE id IN (
                                SELECT id FROM envelopes WHERE to_pk = ?1
                                ORDER BY created_at ASC LIMIT ?2
                            )",
                            rusqlite::params![to.as_slice(), excess as i64],
                        )
                        .map_err(|e| Error::Internal(format!("sqlite evict: {e}")))?;
                }
                Ok(id)
            })
            .await
            .map_err(|e| Error::Internal(format!("spawn_blocking: {e}")))?
        }
    }

    fn get_pending(
        &self,
        to: &[u8; 32],
        limit: usize,
    ) -> impl std::future::Future<Output = Result<(Vec<Envelope>, bool)>> + Send {
        let conn = Arc::clone(&self.conn);
        let to = *to;
        async move {
            let lim = limit as i64;
            tokio::task::spawn_blocking(move || {
                let guard = conn.lock().map_err(|e| Error::Internal(format!("mutex: {e}")))?;
                let mut stmt = guard
                    .prepare(
                        "SELECT id, to_pk, from_pk, bytes, created_at FROM envelopes
                         WHERE to_pk = ?1 ORDER BY created_at ASC LIMIT ?2",
                    )
                    .map_err(|e| Error::Internal(format!("sqlite prepare: {e}")))?;
                let rows = stmt
                    .query_map(rusqlite::params![to.as_slice(), lim + 1], |row| {
                        let id_vec: Vec<u8> = row.get(0)?;
                        let to_vec: Vec<u8> = row.get(1)?;
                        let from_vec: Vec<u8> = row.get(2)?;
                        let bytes: Vec<u8> = row.get(3)?;
                        let created_at: i64 = row.get(4)?;
                        Ok((id_vec, to_vec, from_vec, bytes, created_at))
                    })
                    .map_err(|e| Error::Internal(format!("sqlite query: {e}")))?;
                let mut envs = Vec::new();
                for row in rows {
                    let (id_vec, to_vec, from_vec, bytes, created_at) =
                        row.map_err(|e| Error::Internal(format!("sqlite row: {e}")))?;
                    if id_vec.len() != ENVELOPE_ID_BYTES || to_vec.len() != 32 || from_vec.len() != 32 {
                        continue; // skip corrupt rows
                    }
                    let mut id = [0u8; ENVELOPE_ID_BYTES];
                    let mut to_arr = [0u8; 32];
                    let mut from_arr = [0u8; 32];
                    id.copy_from_slice(&id_vec);
                    to_arr.copy_from_slice(&to_vec);
                    from_arr.copy_from_slice(&from_vec);
                    envs.push(Envelope {
                        id,
                        to: to_arr,
                        from: from_arr,
                        bytes,
                        created_at: created_at as u64,
                    });
                }
                let has_more = envs.len() > limit;
                if has_more {
                    envs.truncate(limit);
                }
                Ok((envs, has_more))
            })
            .await
            .map_err(|e| Error::Internal(format!("spawn_blocking: {e}")))?
        }
    }

    fn delete(
        &self,
        requester_pk: &[u8; 32],
        ids: &[[u8; ENVELOPE_ID_BYTES]],
    ) -> impl std::future::Future<Output = Result<usize>> + Send {
        let conn = Arc::clone(&self.conn);
        let requester = *requester_pk;
        let ids_owned: Vec<[u8; ENVELOPE_ID_BYTES]> = ids.to_vec();
        async move {
            tokio::task::spawn_blocking(move || {
                let guard = conn.lock().map_err(|e| Error::Internal(format!("mutex: {e}")))?;
                let mut deleted = 0usize;
                for id in &ids_owned {
                    let n = guard
                        .execute(
                            "DELETE FROM envelopes WHERE id = ?1 AND to_pk = ?2",
                            rusqlite::params![id.as_slice(), requester.as_slice()],
                        )
                        .map_err(|e| Error::Internal(format!("sqlite delete: {e}")))?;
                    deleted += n;
                }
                Ok(deleted)
            })
            .await
            .map_err(|e| Error::Internal(format!("spawn_blocking: {e}")))?
        }
    }

    fn count_pending(
        &self,
        to: &[u8; 32],
    ) -> impl std::future::Future<Output = Result<usize>> + Send {
        let conn = Arc::clone(&self.conn);
        let to = *to;
        async move {
            tokio::task::spawn_blocking(move || {
                let guard = conn.lock().map_err(|e| Error::Internal(format!("mutex: {e}")))?;
                let count: i64 = guard
                    .query_row(
                        "SELECT COUNT(*) FROM envelopes WHERE to_pk = ?1",
                        [to.as_slice()],
                        |row| row.get(0),
                    )
                    .map_err(|e| Error::Internal(format!("sqlite count: {e}")))?;
                Ok(count as usize)
            })
            .await
            .map_err(|e| Error::Internal(format!("spawn_blocking: {e}")))?
        }
    }

    fn evict_older_than(
        &self,
        now_ms: u64,
        max_age_ms: u64,
    ) -> impl std::future::Future<Output = Result<usize>> + Send {
        let conn = Arc::clone(&self.conn);
        async move {
            let cutoff = (now_ms.saturating_sub(max_age_ms)) as i64;
            tokio::task::spawn_blocking(move || {
                let guard = conn.lock().map_err(|e| Error::Internal(format!("mutex: {e}")))?;
                let n = guard
                    .execute(
                        "DELETE FROM envelopes WHERE created_at < ?1",
                        [cutoff],
                    )
                    .map_err(|e| Error::Internal(format!("sqlite evict: {e}")))?;
                Ok(n)
            })
            .await
            .map_err(|e| Error::Internal(format!("spawn_blocking: {e}")))?
        }
    }
}
