//! SNX password obfuscation — a positional XOR stream cipher over a fixed
//! 77-byte keystream, with 0x00<->0xFF swapping and a full reversal.
//! translate() is involutive per position (for typical text bytes); encode
//! reverses, decode un-reverses. NEVER log the plaintext, raw bytes, or hex.
#![allow(dead_code)]

use crate::error::VpnError;

/// 77-byte SNX obfuscation keystream. Byte-exact per ancwrd1/snx-rs
/// (crates/snxcore/src/util.rs `XOR_TABLE`), cross-checked against rgwohlbold's
/// reverse-engineering write-up — both agree byte-for-byte. Note the two escapes:
/// `\x10` = literal byte 0x10 (position 63, 0-indexed) and `\"` = a double-quote.
const KEY_TABLE: &[u8] =
    b"-ODIFIED&W0ROPERTY3HEET7ITH/+4HE3HEET)$3?,$!0?!5?02/0%24)%3.5,,\x10&7?70?/\"*%#43";

/// Per-position transform. Involutive for typical text bytes:
/// `translate(i, translate(i, c)) == c`.
fn translate(i: usize, c: u8) -> u8 {
    // 0xFF maps to 0 on the way in (equivalent to snx-rs `c % 255`).
    let mut c = if c == 0xFF { 0 } else { c };
    c ^= KEY_TABLE[i % KEY_TABLE.len()];
    if c == 0 { 0xFF } else { c }
}

/// Obfuscate raw bytes: translate each byte at its position, then reverse.
fn obfuscate(bytes: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = bytes
        .iter()
        .enumerate()
        .map(|(i, &c)| translate(i, c))
        .collect();
    out.reverse();
    out
}

/// Inverse of `obfuscate`: reverse first, then translate each byte at its position.
fn deobfuscate(bytes: &[u8]) -> Vec<u8> {
    let mut rev = bytes.to_vec();
    rev.reverse();
    rev.iter()
        .enumerate()
        .map(|(i, &c)| translate(i, c))
        .collect()
}

/// Wire form: lowercase hex of the obfuscated password bytes.
pub fn encode(password: &str) -> String {
    to_hex_lower(&obfuscate(password.as_bytes()))
}

/// Reverse of `encode`: hex-decode then deobfuscate. Malformed hex -> Protocol.
pub fn decode(hex: &str) -> Result<Vec<u8>, VpnError> {
    Ok(deobfuscate(&from_hex(hex)?))
}

/// Lowercase hex encoding (no `hex` crate — deps are locked).
fn to_hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    s
}

/// Decode lowercase/uppercase hex. Odd length or non-hex -> Protocol, no panic.
fn from_hex(s: &str) -> Result<Vec<u8>, VpnError> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(VpnError::Protocol("hex string has odd length".into()));
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = hex_val(pair[0])?;
        let lo = hex_val(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_val(c: u8) -> Result<u8, VpnError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(VpnError::Protocol("invalid hex digit".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::VpnError;

    #[test]
    fn key_table_is_77_bytes() {
        assert_eq!(KEY_TABLE.len(), 77);
    }

    #[test]
    fn round_trip_several_inputs() {
        let long: String = "x".repeat(500);
        for p in ["", "password", "P@ssw0rd!", "café", long.as_str()] {
            let hex = encode(p);
            let back = decode(&hex).expect("decode succeeds");
            assert_eq!(back, p.as_bytes(), "round-trip failed for {p:?}");
        }
    }

    #[test]
    fn encode_is_lowercase_hex() {
        let hex = encode("password");
        assert_eq!(hex.len() % 2, 0, "hex must be even length");
        assert!(
            hex.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "hex must be lowercase 0-9a-f"
        );
    }

    #[test]
    fn decode_rejects_bad_hex() {
        for bad in ["zz", "abc"] {
            match decode(bad) {
                Err(VpnError::Protocol(_)) => {}
                other => panic!("expected Protocol error for {bad:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn translate_is_involutive() {
        for &(i, b) in &[(0usize, b'a'), (5, b'Z'), (10, b'0')] {
            assert_eq!(translate(i, translate(i, b)), b);
        }
    }

    #[test]
    fn matches_snx_rs_vector() {
        // Authoritative vector from ancwrd1/snx-rs util.rs test_obfuscation:
        // snx_obfuscate("testuser") == "36203a333d372a59".
        assert_eq!(encode("testuser"), "36203a333d372a59");
    }
}
