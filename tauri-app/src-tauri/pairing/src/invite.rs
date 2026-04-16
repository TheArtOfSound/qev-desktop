//! Pairing invite — the payload embedded in a QR code.
//!
//! A `PairingInvite` represents everything the other device needs
//! to start a Noise XK handshake with us: our static public key,
//! a display name and device label, the network addresses we're
//! listening on, and a short-lived expiry.
//!
//! ## Wire format
//!
//! The invite is serialized to CBOR (for size) then base64url
//! (for QR friendliness). The CBOR structure is:
//!
//! ```cbor
//! {
//!   "schema":     "QEV-PAIRING-V1",
//!   "version":    "0.29.0",
//!   "static_pk":  bytes(32),
//!   "name":       "alice",
//!   "device":     "alice-phone",
//!   "addrs":      ["192.168.1.42:7891", ...],
//!   "created_at": "2026-05-01T12:00:00Z",
//!   "expires_at": "2026-05-01T12:10:00Z"
//! }
//! ```
//!
//! The base64url encoding uses the URL-safe alphabet with no
//! padding, matching the vault format's binary-field encoding.
//!
//! ## Size budget
//!
//! Typical payload:
//!   - schema: 14 bytes
//!   - version: 6 bytes
//!   - static_pk: 32 bytes
//!   - name: up to 32 bytes
//!   - device: up to 32 bytes
//!   - addrs: typically 1-2 addresses at ~20 bytes each
//!   - created_at: 20 bytes (ISO 8601)
//!   - expires_at: 20 bytes
//!
//! Total CBOR: ~180-220 bytes
//! Base64url:  ~240-290 characters
//!
//! This fits comfortably in a QR version 11 code at error
//! correction level M (61×61 modules), scannable from 30 cm away
//! on any modern phone camera.

use crate::error::{Error, Result};
use crate::{INVITE_SCHEMA, QEV_VERSION, STATIC_KEY_BYTES};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};
use time::format_description::well_known::Iso8601;
use time::OffsetDateTime;

/// Default invite expiry — 10 minutes from creation.
///
/// The static key in the invite is long-lived, but the network
/// addresses and the pairing session itself have a short window.
/// An invite that's been lying around for hours is probably not
/// a legitimate pairing request.
pub const DEFAULT_EXPIRY: Duration = Duration::from_secs(10 * 60);

/// Maximum length of the display `name` field (user-chosen label).
pub const NAME_MAX_LEN: usize = 32;

/// Maximum length of the `device` field (device label, e.g. "alice-phone").
pub const DEVICE_MAX_LEN: usize = 32;

/// Maximum number of advertised network addresses per invite.
///
/// A device with many interfaces (Wi-Fi + Ethernet + IPv6 link-local)
/// can list several. We cap at 8 to keep QR size bounded.
pub const ADDRS_MAX: usize = 8;

/// Pairing invite payload. Serializes to CBOR + base64url for QR
/// encoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingInvite {
    /// Schema identifier. Always "QEV-PAIRING-V1" for now.
    pub schema: String,
    /// Originating QEV version. Cosmetic, used for display only.
    pub version: String,
    /// 32-byte X25519 static public key of the inviter.
    #[serde(with = "serde_bytes")]
    pub static_pk: Vec<u8>,
    /// User-chosen display name, 1..NAME_MAX_LEN chars.
    pub name: String,
    /// Device label (e.g. "alice-phone"), 1..DEVICE_MAX_LEN chars.
    pub device: String,
    /// One or more network addresses the responder is listening on.
    /// Strings rather than SocketAddr structs so CBOR stays simple
    /// and human-inspectable; the parser below validates them.
    pub addrs: Vec<String>,
    /// RFC 3339 / ISO 8601 timestamp when the invite was created.
    pub created_at: String,
    /// RFC 3339 / ISO 8601 timestamp after which the invite is
    /// no longer valid.
    pub expires_at: String,
}

impl PairingInvite {
    /// Construct a new pairing invite.
    ///
    /// Takes ownership of the caller's strings and addrs list.
    /// Validates the invariants: static_pk must be 32 bytes, name
    /// and device must be within length limits, addrs must contain
    /// at least one valid SocketAddr, and expiry must be in the
    /// future (at call time).
    pub fn new(
        static_pk: [u8; STATIC_KEY_BYTES],
        name: String,
        device: String,
        addrs: Vec<SocketAddr>,
    ) -> Result<Self> {
        Self::new_with_expiry(static_pk, name, device, addrs, DEFAULT_EXPIRY)
    }

    /// Like [`new`], but with a custom expiry duration.
    pub fn new_with_expiry(
        static_pk: [u8; STATIC_KEY_BYTES],
        name: String,
        device: String,
        addrs: Vec<SocketAddr>,
        expires_in: Duration,
    ) -> Result<Self> {
        Self::validate_name(&name, "name")?;
        Self::validate_name(&device, "device")?;
        if addrs.is_empty() {
            return Err(Error::Invite("addrs must be non-empty".into()));
        }
        if addrs.len() > ADDRS_MAX {
            return Err(Error::Invite(format!("too many addrs (max {ADDRS_MAX})")));
        }

        let now_system = SystemTime::now();
        let expires = now_system + expires_in;

        let created_at = iso8601(now_system)?;
        let expires_at = iso8601(expires)?;

        let addrs_str = addrs.into_iter().map(|a| a.to_string()).collect();

        Ok(Self {
            schema: INVITE_SCHEMA.to_string(),
            version: QEV_VERSION.to_string(),
            static_pk: static_pk.to_vec(),
            name,
            device,
            addrs: addrs_str,
            created_at,
            expires_at,
        })
    }

    /// Validate the invite's shape: required fields, length limits,
    /// schema version, static_pk size, parseable addresses, valid
    /// ISO 8601 timestamps.
    ///
    /// Does NOT check expiry — use [`check_expiry`] separately
    /// because a just-stored but expired invite is a distinct
    /// error state from a malformed one.
    pub fn validate(&self) -> Result<()> {
        if self.schema != INVITE_SCHEMA {
            return Err(Error::Invite(format!(
                "unsupported invite schema: {:?} (expected {})",
                self.schema, INVITE_SCHEMA
            )));
        }
        if self.version.is_empty() {
            return Err(Error::Invite("version must be non-empty".into()));
        }
        if self.static_pk.len() != STATIC_KEY_BYTES {
            return Err(Error::Invite(format!(
                "static_pk must be {STATIC_KEY_BYTES} bytes (got {})",
                self.static_pk.len()
            )));
        }
        Self::validate_name(&self.name, "name")?;
        Self::validate_name(&self.device, "device")?;
        if self.addrs.is_empty() {
            return Err(Error::Invite("addrs must be non-empty".into()));
        }
        if self.addrs.len() > ADDRS_MAX {
            return Err(Error::Invite(format!(
                "too many addrs: {} (max {ADDRS_MAX})",
                self.addrs.len()
            )));
        }
        for a in &self.addrs {
            a.parse::<SocketAddr>()
                .map_err(|_| Error::Invite(format!("invalid addr: {a:?}")))?;
        }
        parse_iso8601(&self.created_at).map_err(|_| {
            Error::Invite(format!("bad created_at: {:?}", self.created_at))
        })?;
        parse_iso8601(&self.expires_at).map_err(|_| {
            Error::Invite(format!("bad expires_at: {:?}", self.expires_at))
        })?;
        Ok(())
    }

    /// Return Ok if the invite's `expires_at` is strictly in the
    /// future relative to the passed `now`. Returns
    /// [`Error::InviteExpired`] otherwise.
    ///
    /// Taking `now` as a parameter rather than calling
    /// `SystemTime::now` internally makes the function testable
    /// and keeps the expiry check deterministic.
    pub fn check_expiry(&self, now: SystemTime) -> Result<()> {
        let expires = parse_iso8601(&self.expires_at).map_err(|_| {
            Error::Invite(format!("bad expires_at: {:?}", self.expires_at))
        })?;
        if now >= expires {
            return Err(Error::InviteExpired(self.expires_at.clone()));
        }
        Ok(())
    }

    /// Parse the static_pk Vec<u8> back into a fixed-size
    /// `[u8; 32]` for use with the Noise handshake API.
    pub fn static_pk_array(&self) -> Result<[u8; STATIC_KEY_BYTES]> {
        if self.static_pk.len() != STATIC_KEY_BYTES {
            return Err(Error::Invite(format!(
                "static_pk wrong length: {}",
                self.static_pk.len()
            )));
        }
        let mut out = [0u8; STATIC_KEY_BYTES];
        out.copy_from_slice(&self.static_pk);
        Ok(out)
    }

    /// Parse the addrs string list into validated SocketAddr values.
    pub fn addrs_parsed(&self) -> Result<Vec<SocketAddr>> {
        self.addrs
            .iter()
            .map(|s| {
                s.parse::<SocketAddr>()
                    .map_err(|_| Error::Invite(format!("invalid addr: {s:?}")))
            })
            .collect()
    }

    /// Serialize to CBOR bytes. Used by [`encode_qr`] and the
    /// integration tests.
    pub fn encode_cbor(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut buf = Vec::with_capacity(256);
        ciborium::ser::into_writer(self, &mut buf)?;
        Ok(buf)
    }

    /// Decode from raw CBOR bytes. Runs `validate()` but NOT
    /// `check_expiry` — callers that care about freshness should
    /// call `check_expiry` explicitly.
    pub fn decode_cbor(bytes: &[u8]) -> Result<Self> {
        let invite: Self = ciborium::de::from_reader(bytes)?;
        invite.validate()?;
        Ok(invite)
    }

    /// Encode the invite as a base64url string (the QR payload).
    pub fn encode_qr(&self) -> Result<String> {
        let cbor = self.encode_cbor()?;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        Ok(URL_SAFE_NO_PAD.encode(&cbor))
    }

    /// Decode from a base64url string (the scanned QR payload).
    /// Runs `validate()` on the decoded invite.
    pub fn decode_qr(qr_text: &str) -> Result<Self> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let cbor = URL_SAFE_NO_PAD
            .decode(qr_text.trim())
            .map_err(|e| Error::Invite(format!("base64url decode: {e}")))?;
        Self::decode_cbor(&cbor)
    }

    /// Render the invite as an ASCII QR code, suitable for
    /// displaying in a terminal or debug log. Uses qrcodegen's
    /// default error correction level M.
    pub fn render_qr_ascii(&self) -> Result<String> {
        use qrcodegen::{QrCode, QrCodeEcc};
        let text = self.encode_qr()?;
        let qr = QrCode::encode_text(&text, QrCodeEcc::Medium)
            .map_err(|e| Error::Internal(format!("qrcodegen: {e:?}")))?;
        Ok(qr_to_ascii(&qr))
    }

    /// Render the invite as an SVG QR code, suitable for embedding
    /// in the UI or printing. The SVG has `border` modules of
    /// quiet zone on each side (QR spec recommends >=4).
    pub fn render_qr_svg(&self) -> Result<String> {
        use qrcodegen::{QrCode, QrCodeEcc};
        let text = self.encode_qr()?;
        let qr = QrCode::encode_text(&text, QrCodeEcc::Medium)
            .map_err(|e| Error::Internal(format!("qrcodegen: {e:?}")))?;
        Ok(qr_to_svg_string(&qr, 4))
    }

    // -------- helpers --------

    fn validate_name(s: &str, field: &str) -> Result<()> {
        if s.is_empty() {
            return Err(Error::Invite(format!("{field} must be non-empty")));
        }
        let max = if field == "name" {
            NAME_MAX_LEN
        } else {
            DEVICE_MAX_LEN
        };
        if s.len() > max {
            return Err(Error::Invite(format!(
                "{field} too long: {} bytes (max {max})",
                s.len()
            )));
        }
        // Reject control characters and NUL to avoid terminal
        // escape injection via a malicious QR display.
        if s.chars().any(|c| c.is_control()) {
            return Err(Error::Invite(format!(
                "{field} contains control characters"
            )));
        }
        Ok(())
    }
}

fn iso8601(t: SystemTime) -> Result<String> {
    let odt: OffsetDateTime = t.into();
    odt.format(&Iso8601::DEFAULT)
        .map_err(|e| Error::Internal(format!("iso8601 format: {e}")))
}

fn parse_iso8601(s: &str) -> Result<SystemTime> {
    let odt = OffsetDateTime::parse(s, &Iso8601::DEFAULT)
        .map_err(|e| Error::Invite(format!("iso8601 parse: {e}")))?;
    Ok(odt.into())
}

fn qr_to_svg_string(qr: &qrcodegen::QrCode, border: i32) -> String {
    // Minimal SVG renderer — black-on-white, module=1 unit, no
    // embedded CSS or JavaScript. Safe to inline in an HTML page
    // under a strict CSP.
    let size = qr.size();
    let dim = size + border * 2;
    let mut out = String::with_capacity(4096);
    out.push_str(&format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {dim} {dim}\" stroke=\"none\">\n"
    ));
    out.push_str(&format!(
        "  <rect width=\"100%\" height=\"100%\" fill=\"#ffffff\"/>\n"
    ));
    out.push_str("  <path fill=\"#000000\" d=\"");
    for y in 0..size {
        for x in 0..size {
            if qr.get_module(x, y) {
                out.push_str(&format!("M{},{}h1v1h-1z", x + border, y + border));
            }
        }
    }
    out.push_str("\"/>\n</svg>\n");
    out
}

fn qr_to_ascii(qr: &qrcodegen::QrCode) -> String {
    // Two modules per char (▀ = top, ▄ = bottom) halves the
    // vertical size, which matters for terminal rendering.
    let size = qr.size();
    let mut s = String::with_capacity((size as usize + 1) * (size as usize / 2 + 1));
    let mut y = 0i32;
    while y < size {
        for x in 0..size {
            let top = qr.get_module(x, y);
            let bot = if y + 1 < size {
                qr.get_module(x, y + 1)
            } else {
                false
            };
            s.push(match (top, bot) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        s.push('\n');
        y += 2;
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_addrs() -> Vec<SocketAddr> {
        vec!["192.168.1.42:7891".parse().unwrap()]
    }

    fn sample_pk() -> [u8; STATIC_KEY_BYTES] {
        let mut pk = [0u8; STATIC_KEY_BYTES];
        for (i, b) in pk.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7);
        }
        pk
    }

    #[test]
    fn new_valid() {
        let inv = PairingInvite::new(
            sample_pk(),
            "alice".into(),
            "alice-phone".into(),
            sample_addrs(),
        )
        .expect("invite builds");
        assert_eq!(inv.schema, INVITE_SCHEMA);
        assert_eq!(inv.version, QEV_VERSION);
        assert_eq!(inv.static_pk.len(), STATIC_KEY_BYTES);
        assert_eq!(inv.name, "alice");
        assert_eq!(inv.device, "alice-phone");
        assert_eq!(inv.addrs.len(), 1);
    }

    #[test]
    fn rejects_empty_name() {
        let err = PairingInvite::new(
            sample_pk(),
            String::new(),
            "device".into(),
            sample_addrs(),
        )
        .unwrap_err();
        assert!(format!("{err}").contains("name must be non-empty"));
    }

    #[test]
    fn rejects_control_chars_in_name() {
        let err = PairingInvite::new(
            sample_pk(),
            "alice\u{001b}[31m".into(),
            "device".into(),
            sample_addrs(),
        )
        .unwrap_err();
        assert!(format!("{err}").contains("control"));
    }

    #[test]
    fn rejects_too_many_addrs() {
        let addrs = (0..20)
            .map(|i| format!("10.0.0.{i}:7891").parse().unwrap())
            .collect();
        let err = PairingInvite::new(sample_pk(), "a".into(), "d".into(), addrs).unwrap_err();
        assert!(format!("{err}").contains("too many"));
    }

    #[test]
    fn rejects_empty_addrs() {
        let err = PairingInvite::new(sample_pk(), "a".into(), "d".into(), vec![]).unwrap_err();
        assert!(format!("{err}").contains("non-empty"));
    }

    #[test]
    fn cbor_round_trip() {
        let inv = PairingInvite::new(
            sample_pk(),
            "alice".into(),
            "alice-phone".into(),
            sample_addrs(),
        )
        .unwrap();
        let bytes = inv.encode_cbor().unwrap();
        let decoded = PairingInvite::decode_cbor(&bytes).unwrap();
        assert_eq!(inv, decoded);
    }

    #[test]
    fn qr_round_trip() {
        let inv = PairingInvite::new(
            sample_pk(),
            "alice".into(),
            "alice-phone".into(),
            sample_addrs(),
        )
        .unwrap();
        let qr_text = inv.encode_qr().unwrap();
        let decoded = PairingInvite::decode_qr(&qr_text).unwrap();
        assert_eq!(inv, decoded);
    }

    #[test]
    fn qr_payload_size_is_bounded() {
        let inv = PairingInvite::new(
            sample_pk(),
            "alice".into(),
            "alice-phone".into(),
            sample_addrs(),
        )
        .unwrap();
        let qr = inv.encode_qr().unwrap();
        // Should be under ~300 chars for a single-address invite.
        // If this ever grows past 350 we've broken the size budget
        // and the QR will need a higher version/ECC level.
        assert!(qr.len() < 350, "QR payload too large: {} bytes", qr.len());
    }

    #[test]
    fn qr_ascii_renders_and_starts_with_border_row() {
        let inv = PairingInvite::new(
            sample_pk(),
            "a".into(),
            "d".into(),
            sample_addrs(),
        )
        .unwrap();
        let ascii = inv.render_qr_ascii().unwrap();
        assert!(!ascii.is_empty());
        assert!(ascii.contains('█') || ascii.contains('▀') || ascii.contains('▄'));
    }

    #[test]
    fn decode_rejects_wrong_schema() {
        let mut inv = PairingInvite::new(
            sample_pk(),
            "alice".into(),
            "alice-phone".into(),
            sample_addrs(),
        )
        .unwrap();
        inv.schema = "WRONG".into();
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&inv, &mut buf).unwrap();
        let err = PairingInvite::decode_cbor(&buf).unwrap_err();
        assert!(format!("{err}").contains("schema"));
    }

    #[test]
    fn decode_rejects_short_static_pk() {
        // Hand-build a bad invite with a 16-byte key to confirm
        // the validator catches it.
        let inv = PairingInvite {
            schema: INVITE_SCHEMA.into(),
            version: QEV_VERSION.into(),
            static_pk: vec![0u8; 16],
            name: "a".into(),
            device: "d".into(),
            addrs: vec!["192.168.1.1:7891".into()],
            created_at: iso8601(SystemTime::now()).unwrap(),
            expires_at: iso8601(SystemTime::now() + Duration::from_secs(600)).unwrap(),
        };
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&inv, &mut buf).unwrap();
        let err = PairingInvite::decode_cbor(&buf).unwrap_err();
        assert!(format!("{err}").contains("static_pk must be 32"));
    }

    #[test]
    fn check_expiry_fresh_ok() {
        let inv = PairingInvite::new(
            sample_pk(),
            "alice".into(),
            "alice-phone".into(),
            sample_addrs(),
        )
        .unwrap();
        inv.check_expiry(SystemTime::now()).unwrap();
    }

    #[test]
    fn check_expiry_stale_rejected() {
        let inv = PairingInvite::new_with_expiry(
            sample_pk(),
            "alice".into(),
            "alice-phone".into(),
            sample_addrs(),
            Duration::from_secs(1),
        )
        .unwrap();
        // Ask "is this invite still valid 1 hour from now?"
        let future = SystemTime::now() + Duration::from_secs(3600);
        let err = inv.check_expiry(future).unwrap_err();
        assert!(matches!(err, Error::InviteExpired(_)));
    }

    #[test]
    fn multi_address_invite() {
        let addrs = vec![
            "192.168.1.42:7891".parse().unwrap(),
            "10.0.0.5:7891".parse().unwrap(),
        ];
        let inv = PairingInvite::new(sample_pk(), "a".into(), "d".into(), addrs).unwrap();
        let parsed = inv.addrs_parsed().unwrap();
        assert_eq!(parsed.len(), 2);
    }
}
