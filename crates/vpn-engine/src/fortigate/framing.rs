//! FortiGate SSL VPN data-tunnel frame codec (FG-TUN-01). Every frame is a 6-byte
//! big-endian header followed by the payload:
//!
//! ```text
//! offset 0  u16  total length  = 6 + payload_len   (big-endian)
//! offset 2  u16  magic         = 0x5050 ("PP")      (big-endian)
//! offset 4  u16  payload_len                        (big-endian)
//! offset 6  ..   payload
//! ```
//!
//! This is the outer framing shared by both FortiGate wire protocols. For the v2
//! (non-PPP) protocol targeted here the payload is a raw IPv4 packet, written
//! straight to the TUN device. Source: openfortivpn `src/io.c` (RESEARCH §5).
//!
//! Server frames are untrusted: decoding is bounded (max payload) and never
//! panics; malformed input maps to `VpnError::Protocol`. The decoder is buffered
//! and cancel-safe (mirrors `tunnel::try_decode_cstp` / `checkpoint::framing`).
#![allow(dead_code)]

use bytes::{Buf, BytesMut};

use crate::error::VpnError;

/// Fixed FortiGate frame header length (BE u16 total + BE u16 magic + BE u16 len).
pub const FORTI_HEADER_LEN: usize = 6;

/// Frame magic — the ASCII bytes "PP" (0x50 0x50), big-endian u16.
pub const FORTI_MAGIC: u16 = 0x5050;

/// Largest payload we will buffer (64 KiB). Guards against a hostile `length`
/// header causing unbounded buffering (DoS); far above any real IP MTU.
const MAX_FORTI_PAYLOAD: usize = 64 * 1024;

/// Encode a data frame: 6-byte header + raw IP payload.
pub fn encode_data(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(FORTI_HEADER_LEN + payload.len());
    encode_data_append(payload, &mut frame);
    frame
}

/// Append a data frame to a caller-owned buffer, so the hot forwarding path can
/// reuse one allocation across packets AND coalesce several packets into one
/// buffer (frames are length-prefixed, so back-to-back frames decode cleanly).
/// Same wire layout as [`encode_data`]; does NOT clear `out`.
pub fn encode_data_append(payload: &[u8], out: &mut Vec<u8>) {
    let total = (FORTI_HEADER_LEN + payload.len()) as u16;
    out.reserve(FORTI_HEADER_LEN + payload.len());
    out.extend_from_slice(&total.to_be_bytes());
    out.extend_from_slice(&FORTI_MAGIC.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
}

/// Try to decode one frame from the front of `buf`, consuming its bytes on
/// success. `Ok(None)` when more bytes are still needed — the caller keeps the
/// buffer across reads, which makes the inbound read path cancellation-safe (a
/// partial frame is never lost when a sibling `select!` arm wins). `Ok(Some)`
/// consumes exactly one full frame; `Err` on a bad magic, a length disagreement,
/// or an over-large payload. Pure — no I/O.
pub fn try_decode_forti(buf: &mut BytesMut) -> Result<Option<Vec<u8>>, VpnError> {
    if buf.len() < FORTI_HEADER_LEN {
        return Ok(None); // header not fully arrived yet
    }
    let total = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    let magic = u16::from_be_bytes([buf[2], buf[3]]);
    let payload_len = u16::from_be_bytes([buf[4], buf[5]]) as usize;

    if magic != FORTI_MAGIC {
        return Err(VpnError::Protocol(format!(
            "bad FortiGate frame magic: 0x{magic:04x}"
        )));
    }
    // total MUST equal header + payload; reject a self-inconsistent header before
    // trusting either length to size a read.
    if total != FORTI_HEADER_LEN + payload_len {
        return Err(VpnError::Protocol(format!(
            "FortiGate length mismatch: total {total}, payload {payload_len}"
        )));
    }
    if payload_len > MAX_FORTI_PAYLOAD {
        return Err(VpnError::Protocol(format!(
            "FortiGate frame payload {payload_len} exceeds cap"
        )));
    }
    if buf.len() < FORTI_HEADER_LEN + payload_len {
        return Ok(None); // payload not fully arrived yet — wait for more bytes
    }
    buf.advance(FORTI_HEADER_LEN); // drop the header
    let payload = buf.split_to(payload_len).to_vec(); // consume exactly the payload
    Ok(Some(payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_header_is_big_endian() {
        let frame = encode_data(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(&frame[0..2], &[0x00, 0x0A]); // total = 6 + 4 = 10 BE
        assert_eq!(&frame[2..4], &[0x50, 0x50]); // magic BE
        assert_eq!(&frame[4..6], &[0x00, 0x04]); // payload_len = 4 BE
        assert_eq!(&frame[6..], &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn data_round_trips() {
        let payload = vec![0x45, 0x00, 0x00, 0x14, 0x01, 0x02]; // fake IPv4 header start
        let frame = encode_data(&payload);
        let mut buf = BytesMut::from(&frame[..]);
        let out = try_decode_forti(&mut buf).unwrap().unwrap();
        assert_eq!(out, payload);
        assert!(buf.is_empty());
    }

    #[test]
    fn decode_waits_for_full_header_then_payload() {
        let mut buf = BytesMut::new();
        // Partial header -> None, nothing consumed.
        buf.extend_from_slice(&[0x00, 0x0A, 0x50]);
        assert!(try_decode_forti(&mut buf).unwrap().is_none());
        assert_eq!(buf.len(), 3);
        // Full header declaring 4-byte payload, payload absent -> None.
        buf.clear();
        buf.extend_from_slice(&[0x00, 0x0A, 0x50, 0x50, 0x00, 0x04]);
        assert!(try_decode_forti(&mut buf).unwrap().is_none());
        assert_eq!(buf.len(), FORTI_HEADER_LEN);
        // Payload arrives -> full frame decoded and consumed.
        buf.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        let out = try_decode_forti(&mut buf).unwrap().unwrap();
        assert_eq!(out, vec![0x01, 0x02, 0x03, 0x04]);
        assert!(buf.is_empty());
    }

    #[test]
    fn decode_drains_two_coalesced_frames_and_keeps_partial() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&encode_data(&[0xAA]));
        buf.extend_from_slice(&encode_data(&[0xBB, 0xCC]));
        buf.extend_from_slice(&[0x00]); // partial third frame
        let p1 = try_decode_forti(&mut buf).unwrap().unwrap();
        assert_eq!(p1, vec![0xAA]);
        let p2 = try_decode_forti(&mut buf).unwrap().unwrap();
        assert_eq!(p2, vec![0xBB, 0xCC]);
        // Partial third frame preserved (cancel-safety).
        assert!(try_decode_forti(&mut buf).unwrap().is_none());
        assert_eq!(buf.len(), 1);
    }

    #[test]
    fn bad_magic_is_rejected() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0x00, 0x06, 0xDE, 0xAD, 0x00, 0x00]);
        assert!(matches!(
            try_decode_forti(&mut buf),
            Err(VpnError::Protocol(_))
        ));
    }

    #[test]
    fn length_mismatch_is_rejected() {
        let mut buf = BytesMut::new();
        // total says 10, payload says 8 — inconsistent.
        buf.extend_from_slice(&[0x00, 0x0A, 0x50, 0x50, 0x00, 0x08]);
        assert!(matches!(
            try_decode_forti(&mut buf),
            Err(VpnError::Protocol(_))
        ));
    }
}
