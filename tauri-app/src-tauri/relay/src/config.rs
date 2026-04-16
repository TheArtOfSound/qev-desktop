//! Relay server configuration.
//!
//! Loaded from a TOML file at startup. See
//! docs/qev/phase-3-relay.md for the shape. Env vars override
//! the file on a per-field basis.

use crate::error::{Error, Result};
use crate::DEFAULT_PORT;
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// Top-level server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Server-level knobs.
    #[serde(default)]
    pub server: ServerConfig,
    /// Envelope-store knobs.
    #[serde(default)]
    pub store: StoreConfig,
    /// Rate-limit knobs.
    #[serde(default)]
    pub limits: LimitsConfig,
}

/// Server-level knobs (listen address, identity path).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Address:port to bind the TCP listener on.
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// Path to the long-term server static keypair file. If the
    /// file doesn't exist at startup, a fresh keypair is
    /// generated and written here with 0600 permissions.
    #[serde(default = "default_identity_path")]
    pub identity_path: PathBuf,
}

/// Envelope-store knobs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreConfig {
    /// Store backend. For phase 3.0 only "in-memory" is supported.
    #[serde(default = "default_store_type")]
    pub r#type: String,
    /// Maximum envelopes to hold per recipient.
    #[serde(default = "default_max_per_recipient")]
    pub max_per_recipient: usize,
    /// Maximum envelope age in hours. Envelopes older than
    /// this are dropped by a periodic eviction task.
    #[serde(default = "default_retention_hours")]
    pub retention_hours: u64,
}

/// Rate-limit knobs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitsConfig {
    /// Maximum delivery requests per sender pk per minute.
    #[serde(default = "default_deliver_per_minute")]
    pub deliver_per_minute: u32,
    /// Maximum fetch requests per recipient pk per minute.
    #[serde(default = "default_fetch_per_minute")]
    pub fetch_per_minute: u32,
    /// Maximum envelope size in bytes.
    #[serde(default = "default_max_envelope_bytes")]
    pub max_envelope_bytes: usize,
}

// ---- Defaults ----

fn default_listen() -> SocketAddr {
    format!("0.0.0.0:{DEFAULT_PORT}")
        .parse()
        .expect("default_listen: unreachable")
}

fn default_identity_path() -> PathBuf {
    PathBuf::from("/var/lib/qev-relay/server-static.json")
}

fn default_store_type() -> String {
    "sqlite".to_string()
}

fn default_max_per_recipient() -> usize {
    100
}

fn default_retention_hours() -> u64 {
    24 * 30
}

fn default_deliver_per_minute() -> u32 {
    30
}

fn default_fetch_per_minute() -> u32 {
    60
}

fn default_max_envelope_bytes() -> usize {
    crate::MAX_ENVELOPE_BYTES
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            store: StoreConfig::default(),
            limits: LimitsConfig::default(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            identity_path: default_identity_path(),
        }
    }
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            r#type: default_store_type(),
            max_per_recipient: default_max_per_recipient(),
            retention_hours: default_retention_hours(),
        }
    }
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            deliver_per_minute: default_deliver_per_minute(),
            fetch_per_minute: default_fetch_per_minute(),
            max_envelope_bytes: default_max_envelope_bytes(),
        }
    }
}

impl Config {
    /// Load a TOML config file.
    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .map_err(|e| Error::Internal(format!("read config {path:?}: {e}")))?;
        toml::from_str(&text)
            .map_err(|e| Error::Internal(format!("parse config {path:?}: {e}")))
    }

    /// Apply environment variable overrides to the config.
    /// Currently supports:
    ///   QEV_RELAY_LISTEN       — override server.listen
    ///   QEV_RELAY_IDENTITY     — override server.identity_path
    pub fn apply_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("QEV_RELAY_LISTEN") {
            if let Ok(sa) = v.parse() {
                self.server.listen = sa;
            }
        }
        if let Ok(v) = std::env::var("QEV_RELAY_IDENTITY") {
            self.server.identity_path = PathBuf::from(v);
        }
    }
}

/// On-disk format for the server's long-term static keypair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerIdentityFile {
    /// Schema tag. Must be "QEV-RELAY-IDENTITY-V1".
    pub schema: String,
    /// 32-byte X25519 public key, base64url encoded.
    pub public: String,
    /// 32-byte X25519 private scalar, base64url encoded.
    pub secret: String,
    /// ISO 8601 timestamp when the file was first written.
    pub created_at: String,
}

impl ServerIdentityFile {
    /// Load the identity file from disk, or generate one if it
    /// doesn't exist. Returns the parsed static keypair.
    pub fn load_or_generate(path: &Path) -> Result<qev_pairing::StaticKeypair> {
        match fs::read(path) {
            Ok(bytes) => {
                let parsed: ServerIdentityFile = serde_json::from_slice(&bytes)
                    .map_err(|e| Error::Internal(format!("identity file decode: {e}")))?;
                if parsed.schema != "QEV-RELAY-IDENTITY-V1" {
                    return Err(Error::Internal(format!(
                        "unsupported identity schema: {}",
                        parsed.schema
                    )));
                }
                use base64::engine::general_purpose::URL_SAFE_NO_PAD;
                use base64::Engine;
                let pub_bytes = URL_SAFE_NO_PAD
                    .decode(parsed.public.as_bytes())
                    .map_err(|e| Error::Internal(format!("identity public b64: {e}")))?;
                let sec_bytes = URL_SAFE_NO_PAD
                    .decode(parsed.secret.as_bytes())
                    .map_err(|e| Error::Internal(format!("identity secret b64: {e}")))?;
                if pub_bytes.len() != 32 || sec_bytes.len() != 32 {
                    return Err(Error::Internal("identity key wrong length".into()));
                }
                let mut public = [0u8; 32];
                let mut secret = [0u8; 32];
                public.copy_from_slice(&pub_bytes);
                secret.copy_from_slice(&sec_bytes);
                Ok(qev_pairing::StaticKeypair { public, secret })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let kp = qev_pairing::StaticKeypair::generate()?;
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent).map_err(|e| Error::Io(e))?;
                }
                use base64::engine::general_purpose::URL_SAFE_NO_PAD;
                use base64::Engine;
                let file = ServerIdentityFile {
                    schema: "QEV-RELAY-IDENTITY-V1".to_string(),
                    public: URL_SAFE_NO_PAD.encode(kp.public),
                    secret: URL_SAFE_NO_PAD.encode(kp.secret),
                    created_at: iso_now(),
                };
                let json = serde_json::to_vec_pretty(&file)
                    .map_err(|e| Error::Internal(format!("identity encode: {e}")))?;
                fs::write(path, &json).map_err(|e| Error::Io(e))?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let perms = fs::Permissions::from_mode(0o600);
                    fs::set_permissions(path, perms).map_err(|e| Error::Io(e))?;
                }
                Ok(kp)
            }
            Err(e) => Err(Error::Io(e)),
        }
    }
}

fn iso_now() -> String {
    use time::format_description::well_known::Iso8601;
    use time::OffsetDateTime;
    let odt: OffsetDateTime = std::time::SystemTime::now().into();
    odt.format(&Iso8601::DEFAULT)
        .unwrap_or_else(|_| "1970-01-01T00:00:00.000000000Z".to_string())
}

// base64 is pulled in transitively via qev-pairing.
// We don't need to add it as a direct dep — the `use` statements
// above work as long as base64 appears anywhere in the graph.
// (If rustc complains, add `base64 = "0.22"` to Cargo.toml.)

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_sane_values() {
        let c = Config::default();
        assert_eq!(c.server.listen.port(), DEFAULT_PORT);
        assert_eq!(c.store.r#type, "in-memory");
        assert_eq!(c.store.max_per_recipient, 100);
        assert_eq!(c.store.retention_hours, 24 * 30);
        assert_eq!(c.limits.deliver_per_minute, 30);
    }

    #[test]
    fn toml_round_trip() {
        let c = Config::default();
        let s = toml::to_string(&c).unwrap();
        let back: Config = toml::from_str(&s).unwrap();
        assert_eq!(back.server.listen.port(), c.server.listen.port());
        assert_eq!(back.store.max_per_recipient, c.store.max_per_recipient);
    }

    #[test]
    fn partial_toml_fills_defaults() {
        let s = r#"
            [server]
            listen = "127.0.0.1:9999"
        "#;
        let c: Config = toml::from_str(s).unwrap();
        assert_eq!(c.server.listen.port(), 9999);
        // Store defaults preserved.
        assert_eq!(c.store.r#type, "in-memory");
    }

    #[test]
    fn env_override_listen() {
        // Only set the env var within this test to avoid leaking
        // to other tests.
        std::env::set_var("QEV_RELAY_LISTEN", "10.0.0.1:12345");
        let mut c = Config::default();
        c.apply_env_overrides();
        assert_eq!(c.server.listen.port(), 12345);
        std::env::remove_var("QEV_RELAY_LISTEN");
    }
}
