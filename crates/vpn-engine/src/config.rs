//! Resolved runtime configuration for the engine.
//!
//! The former CLI/TOML front-end (clap + toml + rpassword) was removed when the
//! engine became a library driven by the elevated helper: the helper builds
//! [`Config`] directly from the IPC wire form. Only the resolved struct, the
//! protocol enum, and the cert-fingerprint parser remain.
use serde::Deserialize;

use crate::error::VpnError;

/// Which VPN protocol the client speaks (CP-INT-01). Default preserves v0.1
/// behavior (Cisco AnyConnect / CSTP).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// Cisco AnyConnect / OpenConnect CSTP (v0.1).
    #[default]
    AnyConnect,
    /// Check Point SNX (CCC + SLIM) (v0.2).
    Checkpoint,
}

/// Fully-resolved, validated configuration used by the rest of the client.
#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
    pub verbose: bool,
    /// Pinned server-cert SHA-256 fingerprint (32 bytes), if configured.
    pub cert_sha256: Option<[u8; 32]>,
    /// DANGER: skip all certificate verification.
    pub insecure: bool,
    /// Selected VPN protocol (CP-INT-01); default AnyConnect.
    pub protocol: Protocol,
}

/// Parse a SHA-256 fingerprint string into 32 raw bytes. Accepts an optional
/// `sha256:` prefix and optional `:` separators; case-insensitive hex.
/// Example: `sha256:4C:B6:...` or `4cb652...` (64 hex chars).
pub fn parse_sha256_fingerprint(input: &str) -> Result<[u8; 32], VpnError> {
    let cleaned: String = input
        .trim()
        .trim_start_matches("sha256:")
        .trim_start_matches("SHA256:")
        .chars()
        .filter(|c| *c != ':' && !c.is_whitespace())
        .collect();
    if cleaned.len() != 64 || !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(VpnError::Config(format!(
            "invalid SHA-256 fingerprint '{input}': expected 64 hex characters (32 bytes)"
        )));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&cleaned[i * 2..i * 2 + 2], 16)
            .map_err(|e| VpnError::Config(format!("invalid fingerprint hex: {e}")))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_defaults_to_anyconnect() {
        assert_eq!(Protocol::default(), Protocol::AnyConnect);
    }

    #[test]
    fn parse_fingerprint_accepts_colons_and_prefix() {
        let expected = [
            0x4c, 0xb6, 0x52, 0x94, 0x82, 0xe0, 0x85, 0xe0, 0x1c, 0x79, 0x4c, 0x2d, 0x83, 0x20,
            0xcf, 0xf8, 0xbd, 0xcd, 0xc2, 0xb8, 0xea, 0xee, 0x1e, 0xc7, 0x27, 0x39, 0x89, 0x9c,
            0xae, 0x1a, 0x74, 0xa7,
        ];
        let colons = "4C:B6:52:94:82:E0:85:E0:1C:79:4C:2D:83:20:CF:F8:BD:CD:C2:B8:EA:EE:1E:C7:27:39:89:9C:AE:1A:74:A7";
        assert_eq!(parse_sha256_fingerprint(colons).unwrap(), expected);
        let prefixed = format!("sha256:{colons}");
        assert_eq!(parse_sha256_fingerprint(&prefixed).unwrap(), expected);
        let bare = "4cb6529482e085e01c794c2d8320cff8bdcdc2b8eaee1ec72739899cae1a74a7";
        assert_eq!(parse_sha256_fingerprint(bare).unwrap(), expected);
    }

    #[test]
    fn parse_fingerprint_rejects_bad_length() {
        assert!(parse_sha256_fingerprint("abcd").is_err());
        assert!(parse_sha256_fingerprint("xy".repeat(32).as_str()).is_err()); // non-hex
    }
}
