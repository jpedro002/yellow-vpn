//! SLIM data-tunnel frame codec (CP-TUN-01/02). Every SLIM frame is an 8-byte
//! big-endian header — `u32 length` (payload only, excludes the header) + `u32
//! packet_type` (1 = CONTROL, 2 = DATA) — followed by `length` payload bytes.
//! CONTROL payloads are CCC S-expression text with a trailing NUL (counted in
//! `length`); DATA payloads are raw IPv4 packets. Source: snx-rs
//! `crates/snxcore/src/tunnel/ssl/codec.rs` (RESEARCH §3).
//!
//! Server frames are untrusted: decoding is bounded (max frame length) and never
//! panics; malformed input maps to `VpnError::Protocol`. The decoder is buffered
//! and cancel-safe (mirrors `tunnel::try_decode_cstp`).
#![allow(dead_code)]

use bytes::{Buf, BytesMut};

use crate::checkpoint::ccc::{self, CccValue};
use crate::error::VpnError;

/// Fixed SLIM header length (BE u32 length + BE u32 packet_type).
pub const SLIM_HEADER_LEN: usize = 8;

/// CONTROL frame: S-expression payload (+ trailing NUL).
pub const PKT_CONTROL: u32 = 1;
/// DATA frame: raw IPv4 packet payload.
pub const PKT_DATA: u32 = 2;

/// Largest SLIM payload we will buffer (1 MiB). Guards against a hostile
/// `length` header causing unbounded buffering (T-05 DoS). Matches the CCC codec
/// input cap; far above any real IP MTU or control message.
const MAX_SLIM_PAYLOAD: usize = 1_048_576;

/// A decoded SLIM frame.
#[derive(Debug, Clone, PartialEq)]
pub enum SlimPacket {
    /// `packet_type 1` — a parsed CCC control S-expression (client_hello,
    /// hello_reply, keepalive, disconnect, …). The trailing NUL is tolerated.
    Control(CccValue),
    /// `packet_type 2` — a raw IPv4 packet, written straight to the TUN device.
    Data(Vec<u8>),
}

/// Encode a DATA frame: 8-byte header (`length`, `PKT_DATA`) + raw IP payload.
pub fn encode_data(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(SLIM_HEADER_LEN + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&PKT_DATA.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Encode a CONTROL frame from CCC wire text: append the trailing NUL (counted in
/// `length`, per snx-rs), then the 8-byte header (`length`, `PKT_CONTROL`).
pub fn encode_control(sexpr_wire: &str) -> Vec<u8> {
    let mut payload = sexpr_wire.as_bytes().to_vec();
    payload.push(0x00); // trailing NUL — server expects it, counted in length
    let mut frame = Vec::with_capacity(SLIM_HEADER_LEN + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&PKT_CONTROL.to_be_bytes());
    frame.extend_from_slice(&payload);
    frame
}

/// Build the SLIM keepalive CONTROL frame `(keepalive :id (0))` (RESEARCH §4).
pub fn encode_keepalive() -> Vec<u8> {
    let sexpr = CccValue::Node {
        name: Some("keepalive".into()),
        fields: vec![("id".into(), CccValue::Atom("0".into()))],
    };
    encode_control(&sexpr.to_wire())
}

/// Try to decode one SLIM frame from a running byte buffer, consuming its bytes on
/// success. `Ok(None)` when more bytes are still needed — the caller keeps the
/// buffer across reads, which makes the inbound read path cancellation-safe
/// (a partial frame is never lost when a sibling `select!` arm wins). `Ok(Some)`
/// consumes exactly one full frame from the front of `buf`; `Err` on a malformed
/// header/payload or an over-large `length`. Pure — no I/O.
pub fn try_decode_slim(buf: &mut BytesMut) -> Result<Option<SlimPacket>, VpnError> {
    if buf.len() < SLIM_HEADER_LEN {
        return Ok(None); // header not fully arrived yet
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len > MAX_SLIM_PAYLOAD {
        return Err(VpnError::Protocol(format!(
            "SLIM frame length {len} exceeds cap"
        )));
    }
    let packet_type = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if buf.len() < SLIM_HEADER_LEN + len {
        return Ok(None); // payload not fully arrived yet — wait for more bytes
    }
    buf.advance(SLIM_HEADER_LEN); // drop the header
    let payload = buf.split_to(len); // consume exactly the declared payload
    match packet_type {
        PKT_CONTROL => {
            // Strip a single trailing NUL (the S-expr grammar also tolerates it).
            let text = match payload.last() {
                Some(0x00) => &payload[..payload.len() - 1],
                _ => &payload[..],
            };
            let s = String::from_utf8_lossy(text);
            let tree = ccc::parse(&s)?; // malformed control -> VpnError::Protocol
            Ok(Some(SlimPacket::Control(tree)))
        }
        PKT_DATA => Ok(Some(SlimPacket::Data(payload.to_vec()))),
        other => Err(VpnError::Protocol(format!(
            "unknown SLIM packet type: {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_data_header_is_big_endian() {
        let frame = encode_data(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(&frame[0..4], &[0x00, 0x00, 0x00, 0x04]); // length = 4 BE
        assert_eq!(&frame[4..8], &[0x00, 0x00, 0x00, 0x02]); // type = DATA BE
        assert_eq!(&frame[8..], &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn data_round_trips() {
        let payload = vec![0x45, 0x00, 0x00, 0x14, 0x01, 0x02]; // fake IPv4 header start
        let frame = encode_data(&payload);
        let mut buf = BytesMut::from(&frame[..]);
        let pkt = try_decode_slim(&mut buf).unwrap().unwrap();
        assert_eq!(pkt, SlimPacket::Data(payload));
        assert!(buf.is_empty());
    }

    #[test]
    fn control_round_trips_and_strips_nul() {
        let frame = encode_control("(keepalive :id (0))");
        // Trailing NUL is present and counted in length.
        assert_eq!(*frame.last().unwrap(), 0x00);
        let mut buf = BytesMut::from(&frame[..]);
        let pkt = try_decode_slim(&mut buf).unwrap().unwrap();
        match pkt {
            SlimPacket::Control(tree) => assert_eq!(tree.name(), Some("keepalive")),
            other => panic!("expected Control, got {other:?}"),
        }
    }

    #[test]
    fn keepalive_frame_matches_research_bytes() {
        // RESEARCH §4: len=21, type=1, "(keepalive\n\t:id (0))" + NUL.
        let frame = encode_keepalive();
        let mut buf = BytesMut::from(&frame[..]);
        let pkt = try_decode_slim(&mut buf).unwrap().unwrap();
        match pkt {
            SlimPacket::Control(tree) => {
                assert_eq!(tree.name(), Some("keepalive"));
                assert_eq!(tree.get("id").and_then(|v| v.as_atom()), Some("0"));
            }
            other => panic!("expected keepalive Control, got {other:?}"),
        }
    }

    #[test]
    fn decode_waits_for_full_header_then_payload() {
        let mut buf = BytesMut::new();
        // Partial header -> None, nothing consumed.
        buf.extend_from_slice(&[0x00, 0x00, 0x00]);
        assert!(try_decode_slim(&mut buf).unwrap().is_none());
        assert_eq!(buf.len(), 3);
        // Full header declaring 4-byte payload, payload absent -> None.
        buf.clear();
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x02]);
        assert!(try_decode_slim(&mut buf).unwrap().is_none());
        assert_eq!(buf.len(), SLIM_HEADER_LEN);
        // Payload arrives -> full frame decoded and consumed.
        buf.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        let pkt = try_decode_slim(&mut buf).unwrap().unwrap();
        assert_eq!(pkt, SlimPacket::Data(vec![0x01, 0x02, 0x03, 0x04]));
        assert!(buf.is_empty());
    }

    #[test]
    fn decode_drains_two_coalesced_frames_and_keeps_partial() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&encode_data(&[0xAA]));
        buf.extend_from_slice(&encode_keepalive());
        buf.extend_from_slice(&[0x00]); // partial third frame
        let p1 = try_decode_slim(&mut buf).unwrap().unwrap();
        assert_eq!(p1, SlimPacket::Data(vec![0xAA]));
        let p2 = try_decode_slim(&mut buf).unwrap().unwrap();
        assert!(matches!(p2, SlimPacket::Control(_)));
        // Partial third frame preserved (cancel-safety).
        assert!(try_decode_slim(&mut buf).unwrap().is_none());
        assert_eq!(buf.len(), 1);
    }

    #[test]
    fn oversize_length_is_rejected() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&(u32::MAX).to_be_bytes()); // absurd length
        buf.extend_from_slice(&PKT_DATA.to_be_bytes());
        assert!(matches!(
            try_decode_slim(&mut buf),
            Err(VpnError::Protocol(_))
        ));
    }

    #[test]
    fn unknown_packet_type_is_rejected() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&0u32.to_be_bytes()); // length 0
        buf.extend_from_slice(&9u32.to_be_bytes()); // type 9 (unknown)
        assert!(matches!(
            try_decode_slim(&mut buf),
            Err(VpnError::Protocol(_))
        ));
    }

    #[test]
    fn malformed_control_is_protocol_error() {
        // A control frame whose payload is not a valid S-expression.
        let mut payload = b"not an sexpr".to_vec();
        payload.push(0x00);
        let mut frame = Vec::new();
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&PKT_CONTROL.to_be_bytes());
        frame.extend_from_slice(&payload);
        let mut buf = BytesMut::from(&frame[..]);
        assert!(matches!(
            try_decode_slim(&mut buf),
            Err(VpnError::Protocol(_))
        ));
    }
}
