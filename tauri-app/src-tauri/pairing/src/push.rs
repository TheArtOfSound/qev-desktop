//! Push notifications for relay envelope arrival.
//!
//! When a relay envelope arrives for this device's static pk, the
//! server can trigger a push notification to wake the device and
//! prompt the user to fetch their inbox.
//!
//! ## Implementation plan (not yet implemented)
//!
//! ### Android (FCM)
//!
//! 1. App registers with Firebase Cloud Messaging at launch and
//!    receives a registration token.
//! 2. App sends the FCM token to the relay alongside its static pk
//!    via a new `RelayMessage::RegisterPush { fcm_token }`.
//! 3. When the relay receives a `Deliver` for that pk, it sends a
//!    data-only FCM message to the registered token.
//! 4. The Android app's FCM receiver triggers a local notification:
//!    "New encrypted vault waiting. Tap to fetch."
//! 5. User taps → app calls `relay_fetch_inbox`.
//!
//! ### Desktop (macOS / Windows)
//!
//! Desktop push is deferred. The relay can't push to a Mac or
//! Windows app without a platform-specific push service (APNS for
//! Mac, WNS for Windows). An alternative: the app polls the relay
//! on a timer (e.g. every 5 minutes) and shows a system
//! notification when new envelopes are found. This avoids the
//! push infra entirely.
//!
//! ## Status
//!
//! Module is a stub. Real implementation requires:
//! - FCM project setup in the Firebase console
//! - google-services.json in the Android build
//! - FCM registration in MainActivity.kt
//! - RelayMessage::RegisterPush variant
//! - Server-side FCM HTTP API call on delivery
//! - Local notification display in the Android app

/// Register a push token with the relay for this device's pk.
/// Stub: returns an error until FCM is set up.
pub async fn register_push_token(
    _relay_addr: std::net::SocketAddr,
    _server_pk: [u8; 32],
    _own_pk: [u8; 32],
    _fcm_token: &str,
) -> Result<(), String> {
    Err("Push notifications not yet implemented".into())
}
