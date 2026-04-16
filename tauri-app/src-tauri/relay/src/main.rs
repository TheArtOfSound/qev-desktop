//! qev-relay-server binary entry point.
//!
//! Loads a TOML config, loads-or-generates the server identity,
//! constructs an `InMemoryStore`, starts the accept loop, and
//! waits for a SIGTERM / Ctrl-C to trigger a clean shutdown.
//!
//! Usage:
//!   qev-relay-server [CONFIG_PATH]
//!
//! If CONFIG_PATH is omitted, the server uses built-in defaults
//! (listen on 0.0.0.0:7892, identity at /var/lib/qev-relay/server-static.json,
//! in-memory store, 100 envelopes per recipient, 30-day retention).
//!
//! Env var overrides:
//!   QEV_RELAY_LISTEN   — override server.listen
//!   QEV_RELAY_IDENTITY — override server.identity_path
//!
//! Logs:
//!   RUST_LOG=info    standard runtime info
//!   RUST_LOG=debug   handshake + request detail

use qev_relay::{
    config::{Config, ServerIdentityFile},
    EnvelopeStore, InMemoryStore, RelayService,
};
use std::path::PathBuf;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ---- Logging ----
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    // ---- Config ----
    let mut cfg = if let Some(arg) = std::env::args().nth(1) {
        Config::load(&PathBuf::from(&arg))?
    } else {
        eprintln!("qev-relay-server: no config path provided, using built-in defaults");
        Config::default()
    };
    cfg.apply_env_overrides();

    // ---- Identity ----
    let kp = ServerIdentityFile::load_or_generate(&cfg.server.identity_path)?;
    let public_hex = kp
        .public
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            s.push_str(&format!("{b:02x}"));
            s
        });
    tracing::info!(
        public_key = %public_hex,
        identity_path = %cfg.server.identity_path.display(),
        "loaded server identity"
    );

    // ---- Store ----
    let store = Arc::new(InMemoryStore::new(cfg.store.max_per_recipient));

    // ---- Eviction task ----
    // A background task that periodically drops envelopes older
    // than the configured retention window. Runs every hour; on a
    // beta-scale server this has no observable cost.
    {
        let store = Arc::clone(&store);
        let retention_ms = (cfg.store.retention_hours as u64) * 60 * 60 * 1000;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
            interval.tick().await; // skip the immediate first tick
            loop {
                interval.tick().await;
                let now = now_ms();
                match store.evict_older_than(now, retention_ms).await {
                    Ok(0) => {}
                    Ok(n) => tracing::info!(evicted = n, "eviction sweep"),
                    Err(e) => tracing::warn!(?e, "eviction sweep failed"),
                }
            }
        });
    }

    // ---- Service ----
    let service = Arc::new(RelayService::new(kp, store));

    // ---- Shutdown channel ----
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    // Wire Ctrl-C → shutdown.
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            tracing::info!("Ctrl-C received, initiating shutdown");
            let _ = shutdown_tx.send(());
        }
    });

    // ---- Accept loop ----
    let listen = cfg.server.listen;
    tracing::info!(%listen, "starting accept loop");
    service.serve(listen, shutdown_rx).await?;
    tracing::info!("qev-relay-server exiting cleanly");
    Ok(())
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
