//! OS keystore wrapping for the device's static private key.
//!
//! On supported platforms, the 32-byte X25519 secret is encrypted
//! at rest using the OS credential manager:
//!
//!   - **macOS**: Keychain Services via `security-framework`
//!   - **Windows**: DPAPI via `windows-sys` (future)
//!   - **Android**: EncryptedSharedPreferences via JNI (future)
//!   - **Linux/other**: plaintext fallback (same as before)
//!
//! The keystore module exposes two functions:
//!
//!   `store_secret(service, account, secret)` — store 32 bytes
//!   `load_secret(service, account)` → Option<[u8; 32]>
//!
//! If the platform doesn't support a keystore, both functions
//! return errors and the caller falls back to plaintext JSON.
//! The peer_store module checks for keystore support at runtime
//! and uses it when available.
//!
//! ## macOS implementation
//!
//! Uses `SecKeychainAddGenericPassword` / `SecKeychainFindGenericPassword`
//! via the `security-framework` crate. The item is stored with:
//!   service = "com.imagineqira.qev"
//!   account = "static-private-key"
//!   password = the raw 32 bytes of the X25519 secret
//!
//! The macOS Keychain encrypts the item at rest using the user's
//! login keychain password. Access is granted per-app via the
//! code-signing identity; unsigned binaries get a one-time
//! "allow" dialog on first access.

/// Service name used in the keychain entry.
pub const KEYCHAIN_SERVICE: &str = "com.imagineqira.qev";
/// Account name for the static private key.
pub const KEYCHAIN_ACCOUNT: &str = "static-private-key";

/// Store a 32-byte secret in the OS keystore.
///
/// Returns `Ok(())` on success, or `Err` if the platform doesn't
/// support a keystore or the operation failed.
#[cfg(target_os = "macos")]
pub fn store_secret(service: &str, account: &str, secret: &[u8; 32]) -> Result<(), String> {
    use security_framework::passwords::{set_generic_password, delete_generic_password};
    // Delete any existing item first (idempotent upsert).
    let _ = delete_generic_password(service, account);
    set_generic_password(service, account, secret)
        .map_err(|e| format!("keychain store: {e}"))
}

/// Load a 32-byte secret from the OS keystore.
///
/// Returns `Ok(Some([u8; 32]))` if found, `Ok(None)` if not found,
/// or `Err` if the keystore is unavailable or the operation failed.
#[cfg(target_os = "macos")]
pub fn load_secret(service: &str, account: &str) -> Result<Option<[u8; 32]>, String> {
    use security_framework::passwords::get_generic_password;
    match get_generic_password(service, account) {
        Ok(bytes) => {
            if bytes.len() != 32 {
                return Err(format!(
                    "keychain: secret wrong length {} (expected 32)",
                    bytes.len()
                ));
            }
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            Ok(Some(out))
        }
        Err(e) => {
            let msg = format!("{e}");
            if msg.contains("not found") || msg.contains("could not be found") || msg.contains("-25300") {
                Ok(None)
            } else {
                Err(format!("keychain load: {e}"))
            }
        }
    }
}

/// Delete the secret from the OS keystore (used on unpair-all /
/// identity reset).
#[cfg(target_os = "macos")]
pub fn delete_secret(service: &str, account: &str) -> Result<(), String> {
    use security_framework::passwords::delete_generic_password;
    delete_generic_password(service, account)
        .map_err(|e| format!("keychain delete: {e}"))
}

// ---- Non-macOS stubs (plaintext fallback) ----

#[cfg(not(target_os = "macos"))]
pub fn store_secret(_service: &str, _account: &str, _secret: &[u8; 32]) -> Result<(), String> {
    Err("OS keystore not available on this platform".into())
}

#[cfg(not(target_os = "macos"))]
pub fn load_secret(_service: &str, _account: &str) -> Result<Option<[u8; 32]>, String> {
    Err("OS keystore not available on this platform".into())
}

#[cfg(not(target_os = "macos"))]
pub fn delete_secret(_service: &str, _account: &str) -> Result<(), String> {
    Err("OS keystore not available on this platform".into())
}

/// Returns true if the current platform has a supported OS keystore.
pub fn is_available() -> bool {
    cfg!(target_os = "macos")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_available_reflects_platform() {
        // On macOS CI this should be true; on Linux CI it should
        // be false. The test is platform-aware.
        if cfg!(target_os = "macos") {
            assert!(is_available());
        } else {
            assert!(!is_available());
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn store_load_delete_round_trip() {
        let secret = [0x42u8; 32];
        let svc = "com.imagineqira.qev.test";
        let acct = "test-key";

        // Store
        store_secret(svc, acct, &secret).expect("store ok");

        // Load
        let loaded = load_secret(svc, acct).expect("load ok");
        assert_eq!(loaded, Some(secret));

        // Delete
        delete_secret(svc, acct).expect("delete ok");

        // Load after delete → None
        let gone = load_secret(svc, acct).expect("load after delete ok");
        assert_eq!(gone, None);
    }
}
