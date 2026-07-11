//! Protocol-agnostic tunnel framing (CP-TUN-01). The forwarding loop
//! (`forward::run_forwarding`) drives bytes over TLS without knowing whether the
//! wire protocol is Cisco CSTP (v0.1) or Check Point SLIM (v0.2). Both implement
//! [`TunnelFramer`]: `encode_data`, `encode_keepalive`, and a buffered,
//! cancel-safe `try_decode` that yields a classified [`FrameEvent`].
//!
//! Phase 6 swaps `run_forwarding` onto `Box<dyn TunnelFramer>`; this phase
//! delivers and unit-tests the trait plus both implementations.
#![allow(dead_code)]

use bytes::BytesMut;

use crate::checkpoint::framing::{self, SlimPacket};
use crate::error::VpnError;
use crate::tunnel::{self, CstpType};

/// The protocol-agnostic result of decoding one inbound frame — what the forward
/// loop should do next. Any protocol-specific reply is already encoded into
/// `Reply` bytes, so the loop never branches on protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameEvent {
    /// A data (IP) payload — write it to the TUN device.
    Data(Vec<u8>),
    /// The peer requires a control reply — write these ready-made bytes back over
    /// TLS (e.g. a CSTP `DpdResp` answering a `DpdOut`). SLIM never uses this.
    Reply(Vec<u8>),
    /// A liveness/keepalive frame — no action beyond noting the peer is alive.
    Ignore,
    /// The peer asked to tear down — end the forwarding loop.
    Disconnect,
}

/// Encode + decode tunnel frames for one wire protocol. Decoding is buffered and
/// cancel-safe: `try_decode` returns `Ok(None)` until a whole frame is present and
/// leaves any partial frame in `buf` for the next read.
pub trait TunnelFramer: Send {
    /// Frame a data (IP) payload for transmission.
    fn encode_data(&self, payload: &[u8]) -> Vec<u8>;
    /// Build a client-initiated keepalive/liveness frame.
    fn encode_keepalive(&self) -> Vec<u8>;
    /// Optional in-tunnel frame to send on a polite client shutdown. CSTP sends a
    /// `Disconnect`; SLIM sends nothing in-tunnel (teardown is a CCC `Signout` on
    /// the auth channel — RESEARCH §5). `None` = send nothing.
    fn encode_shutdown(&self) -> Option<Vec<u8>> {
        None
    }
    /// Try to decode one frame from the front of `buf`, classifying it into a
    /// [`FrameEvent`]. `Ok(None)` = need more bytes. `Err` = malformed frame.
    fn try_decode(&mut self, buf: &mut BytesMut) -> Result<Option<FrameEvent>, VpnError>;
}

// ---------------------------------------------------------------------------
// Cisco CSTP (v0.1)
// ---------------------------------------------------------------------------

/// CSTP framer — wraps the v0.1 `tunnel` codec behind [`TunnelFramer`].
#[derive(Debug, Default, Clone, Copy)]
pub struct CstpTunnelFramer;

impl TunnelFramer for CstpTunnelFramer {
    fn encode_data(&self, payload: &[u8]) -> Vec<u8> {
        tunnel::CstpFramer::encode_data(payload)
    }

    fn encode_keepalive(&self) -> Vec<u8> {
        // Client liveness tick = a CSTP DpdOut control frame (no payload).
        tunnel::write_header(CstpType::DpdOut, 0).to_vec()
    }

    fn encode_shutdown(&self) -> Option<Vec<u8>> {
        // Polite CSTP teardown: an empty Disconnect frame.
        Some(tunnel::write_header(CstpType::Disconnect, 0).to_vec())
    }

    fn try_decode(&mut self, buf: &mut BytesMut) -> Result<Option<FrameEvent>, VpnError> {
        let Some(packet) = tunnel::try_decode_cstp(buf)? else {
            return Ok(None);
        };
        let event = match packet.packet_type {
            CstpType::Data => FrameEvent::Data(packet.payload),
            // Server DPD request -> answer with an empty DpdResp frame.
            CstpType::DpdOut => {
                FrameEvent::Reply(tunnel::write_header(CstpType::DpdResp, 0).to_vec())
            }
            CstpType::DpdResp | CstpType::Keepalive | CstpType::Compressed => FrameEvent::Ignore,
            CstpType::Disconnect | CstpType::TermServer => FrameEvent::Disconnect,
        };
        Ok(Some(event))
    }
}

// ---------------------------------------------------------------------------
// Check Point SLIM (v0.2)
// ---------------------------------------------------------------------------

/// SLIM framer — wraps the `checkpoint::framing` codec behind [`TunnelFramer`].
#[derive(Debug, Default, Clone, Copy)]
pub struct SlimTunnelFramer;

impl TunnelFramer for SlimTunnelFramer {
    fn encode_data(&self, payload: &[u8]) -> Vec<u8> {
        framing::encode_data(payload)
    }

    fn encode_keepalive(&self) -> Vec<u8> {
        framing::encode_keepalive()
    }

    fn try_decode(&mut self, buf: &mut BytesMut) -> Result<Option<FrameEvent>, VpnError> {
        let Some(packet) = framing::try_decode_slim(buf)? else {
            return Ok(None);
        };
        let event = match packet {
            SlimPacket::Data(payload) => FrameEvent::Data(payload),
            // Control frames dispatch on the S-expression object name.
            SlimPacket::Control(tree) => match tree.name() {
                Some("disconnect") => FrameEvent::Disconnect,
                // keepalive (and any other control) -> liveness only. SLIM does
                // not echo server keepalives (RESEARCH §4).
                _ => FrameEvent::Ignore,
            },
        };
        Ok(Some(event))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- CSTP ---

    #[test]
    fn cstp_data_round_trips_through_framer() {
        let mut f = CstpTunnelFramer;
        let frame = f.encode_data(&[0x11, 0x22, 0x33]);
        let mut buf = BytesMut::from(&frame[..]);
        assert_eq!(
            f.try_decode(&mut buf).unwrap(),
            Some(FrameEvent::Data(vec![0x11, 0x22, 0x33]))
        );
    }

    #[test]
    fn cstp_server_dpd_out_yields_reply() {
        let mut f = CstpTunnelFramer;
        let dpd_out = tunnel::write_header(CstpType::DpdOut, 0);
        let mut buf = BytesMut::from(&dpd_out[..]);
        match f.try_decode(&mut buf).unwrap() {
            Some(FrameEvent::Reply(bytes)) => {
                // The reply is a valid DpdResp frame.
                let (t, len) = tunnel::parse_header(bytes.as_slice().try_into().unwrap()).unwrap();
                assert_eq!(t, CstpType::DpdResp);
                assert_eq!(len, 0);
            }
            other => panic!("expected Reply, got {other:?}"),
        }
    }

    #[test]
    fn cstp_disconnect_yields_disconnect() {
        let mut f = CstpTunnelFramer;
        let frame = tunnel::write_header(CstpType::Disconnect, 0);
        let mut buf = BytesMut::from(&frame[..]);
        assert_eq!(
            f.try_decode(&mut buf).unwrap(),
            Some(FrameEvent::Disconnect)
        );
    }

    #[test]
    fn cstp_keepalive_encodes_dpd_out() {
        let f = CstpTunnelFramer;
        let frame = f.encode_keepalive();
        let (t, len) = tunnel::parse_header(frame.as_slice().try_into().unwrap()).unwrap();
        assert_eq!(t, CstpType::DpdOut);
        assert_eq!(len, 0);
    }

    #[test]
    fn cstp_partial_frame_needs_more() {
        let mut f = CstpTunnelFramer;
        let mut buf = BytesMut::from(&[0x53, 0x54, 0x46][..]); // partial header
        assert_eq!(f.try_decode(&mut buf).unwrap(), None);
    }

    // --- SLIM ---

    #[test]
    fn slim_data_round_trips_through_framer() {
        let mut f = SlimTunnelFramer;
        let frame = f.encode_data(&[0xAB, 0xCD]);
        let mut buf = BytesMut::from(&frame[..]);
        assert_eq!(
            f.try_decode(&mut buf).unwrap(),
            Some(FrameEvent::Data(vec![0xAB, 0xCD]))
        );
    }

    #[test]
    fn slim_keepalive_is_ignored_on_decode() {
        let mut f = SlimTunnelFramer;
        let frame = f.encode_keepalive();
        let mut buf = BytesMut::from(&frame[..]);
        assert_eq!(f.try_decode(&mut buf).unwrap(), Some(FrameEvent::Ignore));
    }

    #[test]
    fn slim_disconnect_yields_disconnect() {
        let mut f = SlimTunnelFramer;
        let frame = framing::encode_control("(disconnect :code (0))");
        let mut buf = BytesMut::from(&frame[..]);
        assert_eq!(
            f.try_decode(&mut buf).unwrap(),
            Some(FrameEvent::Disconnect)
        );
    }

    #[test]
    fn slim_unknown_control_is_ignored() {
        let mut f = SlimTunnelFramer;
        let frame = framing::encode_control("(hello_reply :OM ( :ipaddr (10.0.0.10)))");
        let mut buf = BytesMut::from(&frame[..]);
        assert_eq!(f.try_decode(&mut buf).unwrap(), Some(FrameEvent::Ignore));
    }

    #[test]
    fn cstp_shutdown_is_disconnect_slim_is_none() {
        let cstp = CstpTunnelFramer.encode_shutdown().expect("CSTP sends disconnect");
        let (t, len) = tunnel::parse_header(cstp.as_slice().try_into().unwrap()).unwrap();
        assert_eq!(t, CstpType::Disconnect);
        assert_eq!(len, 0);
        assert_eq!(SlimTunnelFramer.encode_shutdown(), None);
    }

    #[test]
    fn slim_partial_frame_needs_more() {
        let mut f = SlimTunnelFramer;
        let mut buf = BytesMut::from(&[0x00, 0x00][..]); // partial header
        assert_eq!(f.try_decode(&mut buf).unwrap(), None);
    }

    #[test]
    fn framers_are_trait_objects() {
        // Prove both are usable behind the dyn trait Phase 6 will hold.
        let framers: Vec<Box<dyn TunnelFramer>> =
            vec![Box::new(CstpTunnelFramer), Box::new(SlimTunnelFramer)];
        for f in framers {
            let data = f.encode_data(&[0x01]);
            assert!(!data.is_empty());
            let ka = f.encode_keepalive();
            assert!(!ka.is_empty());
        }
    }
}
