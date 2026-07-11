//! TLS transport + CSTP framing for the AnyConnect tunnel.
//!
//! Implements the real Cisco AnyConnect / OpenConnect CSTP 8-byte packet header
//! (D-09): magic `S` `T` `F`, version, big-endian u16 payload length, packet
//! type, reserved byte. The `[0xDE,0xAD]` magic in research/ARCHITECTURE.md is
//! WRONG — do not use it.
#![allow(dead_code)]

use std::net::Ipv4Addr;
use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::error::VpnError;

/// Length of the fixed CSTP packet header, in bytes.
pub const CSTP_HEADER_LEN: usize = 8;

const CSTP_MAGIC: [u8; 3] = [0x53, 0x54, 0x46]; // "STF"
const CSTP_VERSION: u8 = 0x01;

/// CSTP packet type (OpenConnect AC_PKT_* constants, D-10).
///
/// NOTE: ROADMAP Phase 6 loosely calls keepalive "type 0x03" and disconnect
/// "type 0x05". In the real protocol 0x03 is `DpdOut` (dead-peer-detection
/// request) and 0x07 is `Keepalive`. All variants are modelled so Phase 6 can
/// dispatch against the correct constants.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CstpType {
    Data = 0x00,
    DpdOut = 0x03,
    DpdResp = 0x04,
    Disconnect = 0x05,
    Keepalive = 0x07,
    Compressed = 0x08,
    TermServer = 0x09,
}

impl CstpType {
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(b: u8) -> Result<Self, VpnError> {
        Ok(match b {
            0x00 => CstpType::Data,
            0x03 => CstpType::DpdOut,
            0x04 => CstpType::DpdResp,
            0x05 => CstpType::Disconnect,
            0x07 => CstpType::Keepalive,
            0x08 => CstpType::Compressed,
            0x09 => CstpType::TermServer,
            other => {
                return Err(VpnError::Protocol(format!(
                    "unknown CSTP packet type: 0x{other:02x}"
                )));
            }
        })
    }
}

/// A decoded CSTP packet: its type and the payload that followed the header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CstpPacket {
    pub packet_type: CstpType,
    pub payload: Vec<u8>,
}

/// Build the 8-byte CSTP header. The payload length occupies bytes 4-5 as a
/// BIG-ENDIAN u16 (pitfall m4 — never native-endian).
pub fn write_header(packet_type: CstpType, payload_len: usize) -> [u8; 8] {
    let len = payload_len as u16; // payloads are <= MTU 1400, fits u16
    let len_be = len.to_be_bytes();
    [
        CSTP_MAGIC[0],
        CSTP_MAGIC[1],
        CSTP_MAGIC[2],
        CSTP_VERSION,
        len_be[0],
        len_be[1],
        packet_type.to_u8(),
        0x00,
    ]
}

/// Parse an 8-byte CSTP header, returning `(type, payload_len)`.
///
/// The bytes originate from the untrusted remote server: a non-"STF" magic or
/// an unknown type byte is rejected with `VpnError::Protocol` (never a panic).
pub fn parse_header(header: &[u8; 8]) -> Result<(CstpType, usize), VpnError> {
    if header[0..3] != CSTP_MAGIC {
        return Err(VpnError::Protocol(format!(
            "bad CSTP magic: {:02x?}",
            &header[0..3]
        )));
    }
    // version (header[3]) is accepted as-is; reserved byte 7 is ignored.
    let len = u16::from_be_bytes([header[4], header[5]]) as usize;
    let packet_type = CstpType::from_u8(header[6])?;
    Ok((packet_type, len))
}

/// Stateless encoder/decoder for CSTP frames (D-11 surface).
pub struct CstpFramer;

impl CstpFramer {
    /// Prepend an 8-byte DATA header to `payload`, returning the full frame.
    pub fn encode_data(payload: &[u8]) -> Vec<u8> {
        let header = write_header(CstpType::Data, payload.len());
        let mut frame = Vec::with_capacity(CSTP_HEADER_LEN + payload.len());
        frame.extend_from_slice(&header);
        frame.extend_from_slice(payload);
        frame
    }

    /// Decode a full frame (8-byte header + body). The header's declared length
    /// must match the number of remaining bytes.
    pub fn decode(frame: &[u8]) -> Result<CstpPacket, VpnError> {
        if frame.len() < CSTP_HEADER_LEN {
            return Err(VpnError::Protocol(format!(
                "CSTP frame too short: {} bytes",
                frame.len()
            )));
        }
        // Length-checked to exactly 8 above, so try_into cannot fail.
        let header: &[u8; 8] = frame[0..CSTP_HEADER_LEN].try_into().unwrap();
        let (packet_type, len) = parse_header(header)?;
        let body = &frame[CSTP_HEADER_LEN..];
        if body.len() != len {
            return Err(VpnError::Protocol(format!(
                "CSTP length mismatch: header says {len}, body is {}",
                body.len()
            )));
        }
        Ok(CstpPacket {
            packet_type,
            payload: body.to_vec(),
        })
    }
}

/// Try to decode one CSTP frame from a running byte buffer, consuming its bytes on
/// success. Returns `Ok(None)` when more bytes are still needed — the caller keeps the
/// buffer across reads, which is what makes the inbound read path cancellation-safe
/// (`read_buf` into a persistent buffer never loses a partially-received frame when a
/// sibling `select!` arm wins). `Ok(Some(packet))` consumes exactly one full frame from
/// the front of `buf`; `Err` on a malformed header. Pure — no I/O.
pub fn try_decode_cstp(buf: &mut bytes::BytesMut) -> Result<Option<CstpPacket>, VpnError> {
    use bytes::Buf;
    if buf.len() < CSTP_HEADER_LEN {
        return Ok(None); // header not fully arrived yet
    }
    let header: &[u8; 8] = buf[0..CSTP_HEADER_LEN].try_into().unwrap();
    let (packet_type, len) = parse_header(header)?; // bad magic/type -> VpnError::Protocol
    if buf.len() < CSTP_HEADER_LEN + len {
        return Ok(None); // payload not fully arrived yet — wait for more bytes
    }
    buf.advance(CSTP_HEADER_LEN); // drop the header
    let payload = buf.split_to(len).to_vec(); // consume exactly the declared payload
    Ok(Some(CstpPacket {
        packet_type,
        payload,
    }))
}

// ---------------------------------------------------------------------------
// TLS transport (CONN-01) — rustls ring provider + webpki-roots verification.
// ---------------------------------------------------------------------------

/// How the server certificate is trusted.
#[derive(Debug, Clone)]
pub enum CertTrust {
    /// Default: verify against the Mozilla root store (webpki-roots).
    Webpki,
    /// Pin the end-entity certificate by its SHA-256 fingerprint (self-signed /
    /// private-CA VPN servers). Rejects any other cert; ignores name mismatch.
    Pinned([u8; 32]),
    /// DANGER: accept any certificate without verification (MITM-vulnerable).
    Insecure,
}

/// Build the rustls client config for the chosen trust mode. Resumption is
/// always disabled for the long-lived single tunnel (PITFALL C4).
///
/// `Webpki` verifies against Mozilla roots (default). `Pinned`/`Insecure` install
/// a custom `ServerCertVerifier` via the `dangerous()` builder for VPN servers
/// whose cert is not chained to a public CA — the handshake signature is still
/// verified by the crypto provider in `Pinned` mode; only `Insecure` skips it.
pub fn build_tls_config(trust: &CertTrust) -> Arc<ClientConfig> {
    let mut config = match trust {
        CertTrust::Webpki => {
            let mut root_store = RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        }
        CertTrust::Pinned(pin) => {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(PinnedVerifier {
                    pin: *pin,
                    provider,
                }))
                .with_no_client_auth()
        }
        CertTrust::Insecure => ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureVerifier {
                provider: Arc::new(rustls::crypto::ring::default_provider()),
            }))
            .with_no_client_auth(),
    };
    // PITFALL C4 — disable resumption for the long-lived tunnel.
    config.resumption = rustls::client::Resumption::disabled();
    Arc::new(config)
}

/// Open a TCP connection to `host:port` and complete the TLS handshake with the
/// chosen `trust` mode. Returns the owned TLS stream (split happens in Phase 6).
///
/// The `ServerName` is used for SNI (and, in `Webpki` mode, name verification).
/// When `host` is an IP address it becomes an `IpAddress` server name, which is
/// why pinning/insecure mode is required for IP-only VPN endpoints. TLS/IO
/// failures map to transient `VpnError` variants (D-03) so Phase 8 can retry.
pub async fn connect_tls(
    host: &str,
    port: u16,
    trust: &CertTrust,
) -> Result<TlsStream<TcpStream>, VpnError> {
    let connector = TlsConnector::from(build_tls_config(trust));
    let server_name = ServerName::try_from(host.to_owned())
        .map_err(|e| VpnError::Tls(format!("invalid server name '{host}': {e}")))?;
    let tcp = TcpStream::connect((host, port)).await?; // Io -> transient
    let tls = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| VpnError::Tls(format!("TLS handshake failed: {e}")))?;
    tracing::info!(host = %host, port, "TLS connection established");
    Ok(tls)
}

// ---------------------------------------------------------------------------
// Custom certificate verifiers for pinning / insecure trust modes.
// ---------------------------------------------------------------------------

/// Lowercase-hex encode bytes (for fingerprint mismatch messages).
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Accepts ONLY the end-entity certificate whose DER SHA-256 matches `pin`.
/// Handshake signatures are still verified by the crypto provider, so a matching
/// cert also proves the peer holds the corresponding private key.
#[derive(Debug)]
struct PinnedVerifier {
    pin: [u8; 32],
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        use sha2::{Digest, Sha256};
        let got = Sha256::digest(end_entity.as_ref());
        if got.as_slice() == self.pin {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "server certificate fingerprint mismatch: pinned {}, presented {}",
                hex_encode(&self.pin),
                hex_encode(got.as_slice())
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// DANGER: accepts any certificate and any handshake signature. MITM-vulnerable.
#[derive(Debug)]
struct InsecureVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ---------------------------------------------------------------------------
// CSTP tunnel upgrade (CONN-02 / CONN-03) — CONNECT request + response parse.
// ---------------------------------------------------------------------------

/// Maximum bytes read while waiting for the CONNECT response headers. Guards
/// against a hostile/hung server that never sends the `\r\n\r\n` terminator
/// (threat T-03-09).
const CONNECT_RESPONSE_MAX: usize = 64 * 1024;

/// Build the AnyConnect `CONNECT /CSCOSSLC/tunnel` request (D-07), CRLF
/// terminated with a trailing blank line. Carries the `webvpn` session cookie
/// and the `X-CSTP-*` client headers.
pub fn build_connect_request(host: &str, cookie: &str) -> String {
    format!(
        "CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: AnyConnect Windows 4.10.05085\r\n\
         Cookie: webvpn={cookie}\r\n\
         X-CSTP-Version: 1\r\n\
         X-CSTP-Hostname: vpn-client\r\n\
         X-CSTP-Address-Type: IPv4\r\n\
         X-CSTP-MTU: 1400\r\n\
         X-CSTP-Base-MTU: 1400\r\n\
         X-CSTP-Full-IPv6-Capability: false\r\n\
         \r\n"
    )
}

/// Server-assigned session parameters parsed from the `X-CSTP-*` response
/// headers (D-08). These feed Phases 4/5/6 (TUN IP, MTU, DNS, keepalive/DPD).
#[derive(Debug, Clone)]
pub struct SessionParams {
    /// X-CSTP-Address — assigned tunnel IPv4 (required).
    pub address: Ipv4Addr,
    /// X-CSTP-Netmask.
    pub netmask: Option<Ipv4Addr>,
    /// X-CSTP-DNS — zero or more resolver addresses.
    pub dns: Vec<Ipv4Addr>,
    /// X-CSTP-MTU — defaults to 1400 when absent.
    pub mtu: u16,
    /// X-CSTP-Keepalive interval, in seconds.
    pub keepalive: Option<u32>,
    /// X-CSTP-DPD (dead-peer-detection) interval, in seconds.
    pub dpd: Option<u32>,
    /// X-CSTP-Disconnected-Timeout, in seconds.
    pub disconnected_timeout: Option<u32>,
}

/// Default tunnel MTU when the server omits `X-CSTP-MTU` (D-08).
const DEFAULT_MTU: u16 = 1400;

/// Parse the `HTTP/1.1 200 CONNECTED` response into `SessionParams` (D-08).
///
/// The header bytes are untrusted server input (threat T-03-08): a non-200
/// status or a missing `X-CSTP-Address` is rejected with `VpnError::Tls`.
/// Header names are matched case-insensitively; unparseable optional values are
/// dropped rather than fatal.
pub fn parse_connect_response(raw: &str) -> Result<SessionParams, VpnError> {
    let mut lines = raw.lines();
    let status = lines.next().unwrap_or("");
    if !status.contains("200") {
        return Err(VpnError::Tls(format!(
            "unexpected CONNECT response: {status}"
        )));
    }

    let mut address: Option<Ipv4Addr> = None;
    let mut netmask: Option<Ipv4Addr> = None;
    let mut dns: Vec<Ipv4Addr> = Vec::new();
    let mut mtu: u16 = DEFAULT_MTU;
    let mut keepalive: Option<u32> = None;
    let mut dpd: Option<u32> = None;
    let mut disconnected_timeout: Option<u32> = None;

    for line in lines {
        if line.is_empty() {
            break; // end of headers
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "x-cstp-address" => address = value.parse().ok(),
            "x-cstp-netmask" => netmask = value.parse().ok(),
            "x-cstp-dns" => {
                if let Ok(ip) = value.parse() {
                    dns.push(ip);
                }
            }
            "x-cstp-mtu" => {
                if let Ok(m) = value.parse() {
                    mtu = m;
                }
            }
            "x-cstp-keepalive" => keepalive = value.parse().ok(),
            "x-cstp-dpd" => dpd = value.parse().ok(),
            "x-cstp-disconnected-timeout" => disconnected_timeout = value.parse().ok(),
            _ => {}
        }
    }

    let address = address.ok_or_else(|| {
        VpnError::Tls("server did not assign an address (missing X-CSTP-Address)".into())
    })?;

    Ok(SessionParams {
        address,
        netmask,
        dns,
        mtu,
        keepalive,
        dpd,
        disconnected_timeout,
    })
}

/// Perform the CSTP tunnel upgrade over an established TLS stream: write the
/// CONNECT request, read the response headers, and parse `SessionParams`
/// (CONN-02/CONN-03).
///
/// The response read is bounded (threat T-03-09) — it stops at the `\r\n\r\n`
/// header terminator or the [`CONNECT_RESPONSE_MAX`] guard, never trusting the
/// server to close. The webvpn cookie is never logged (threat T-03-10).
pub async fn cstp_connect<S>(
    stream: &mut S,
    host: &str,
    cookie: &str,
) -> Result<SessionParams, VpnError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let request = build_connect_request(host, cookie);
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(VpnError::Tls(
                "connection closed before CONNECT response completed".into(),
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break; // header terminator reached
        }
        if buf.len() > CONNECT_RESPONSE_MAX {
            return Err(VpnError::Tls(
                "CONNECT response exceeded size guard before headers ended".into(),
            ));
        }
    }

    let raw = String::from_utf8_lossy(&buf);
    let params = parse_connect_response(&raw)?;
    tracing::info!(
        address = %params.address,
        mtu = params.mtu,
        dns_count = params.dns.len(),
        "CSTP session established"
    );
    Ok(params)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_header_is_big_endian() {
        let h = write_header(CstpType::Data, 4);
        assert_eq!(&h[0..3], &[0x53, 0x54, 0x46]); // STF
        assert_eq!(h[3], 0x01); // version
        assert_eq!(&h[4..6], &[0x00, 0x04]); // length big-endian
        assert_eq!(h[6], 0x00); // type = DATA
        assert_eq!(h[7], 0x00); // reserved
        // 258 = 0x0102 -> [0x01, 0x02]
        let h2 = write_header(CstpType::Data, 258);
        assert_eq!(&h2[4..6], &[0x01, 0x02]);
    }

    #[test]
    fn decode_captured_frame() {
        // 53 54 46 01 00 04 00 00 DE AD BE EF  ->  DATA, payload DE AD BE EF
        let frame = [
            0x53, 0x54, 0x46, 0x01, 0x00, 0x04, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF,
        ];
        let pkt = CstpFramer::decode(&frame).unwrap();
        assert_eq!(pkt.packet_type, CstpType::Data);
        assert_eq!(pkt.payload, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn encode_decode_round_trip() {
        let payload = b"hello world";
        let frame = CstpFramer::encode_data(payload);
        assert_eq!(frame.len(), CSTP_HEADER_LEN + payload.len());
        let pkt = CstpFramer::decode(&frame).unwrap();
        assert_eq!(pkt.packet_type, CstpType::Data);
        assert_eq!(pkt.payload, payload);
    }

    #[test]
    fn parse_header_rejects_bad_magic() {
        let bad = [0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00];
        assert!(matches!(parse_header(&bad), Err(VpnError::Protocol(_))));
    }

    #[test]
    fn try_decode_waits_for_full_header_then_payload() {
        use bytes::BytesMut;
        let mut buf = BytesMut::new();
        // Partial header -> None, buffer untouched.
        buf.extend_from_slice(&[0x53, 0x54, 0x46]);
        assert!(try_decode_cstp(&mut buf).unwrap().is_none());
        assert_eq!(buf.len(), 3);
        // Full header declaring 4-byte payload, but payload not yet present -> None.
        buf.clear();
        buf.extend_from_slice(&[0x53, 0x54, 0x46, 0x01, 0x00, 0x04, 0x00, 0x00]);
        assert!(try_decode_cstp(&mut buf).unwrap().is_none());
        assert_eq!(buf.len(), CSTP_HEADER_LEN); // still buffered, nothing consumed
        // Payload arrives -> full frame decoded and consumed.
        buf.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let pkt = try_decode_cstp(&mut buf).unwrap().unwrap();
        assert_eq!(pkt.packet_type, CstpType::Data);
        assert_eq!(pkt.payload, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(buf.is_empty());
    }

    #[test]
    fn try_decode_drains_two_coalesced_frames_and_keeps_partial() {
        use bytes::BytesMut;
        let mut buf = BytesMut::new();
        // Frame 1: DpdOut (0x03), empty payload. Frame 2: Data, 2-byte payload. Then 1 stray byte.
        buf.extend_from_slice(&[0x53, 0x54, 0x46, 0x01, 0x00, 0x00, 0x03, 0x00]); // DpdOut, len 0
        buf.extend_from_slice(&[0x53, 0x54, 0x46, 0x01, 0x00, 0x02, 0x00, 0x00, 0xAA, 0xBB]); // Data, len 2
        buf.extend_from_slice(&[0x53]); // start of a third frame — partial
        let p1 = try_decode_cstp(&mut buf).unwrap().unwrap();
        assert_eq!(p1.packet_type, CstpType::DpdOut);
        assert!(p1.payload.is_empty());
        let p2 = try_decode_cstp(&mut buf).unwrap().unwrap();
        assert_eq!(p2.packet_type, CstpType::Data);
        assert_eq!(p2.payload, vec![0xAA, 0xBB]);
        // The partial third frame is preserved, not lost (cancel-safety guarantee).
        assert!(try_decode_cstp(&mut buf).unwrap().is_none());
        assert_eq!(buf.len(), 1);
    }

    #[test]
    fn try_decode_rejects_bad_magic() {
        use bytes::BytesMut;
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
        assert!(matches!(try_decode_cstp(&mut buf), Err(VpnError::Protocol(_))));
    }

    #[test]
    fn parse_header_rejects_unknown_type() {
        let bad = [0x53, 0x54, 0x46, 0x01, 0x00, 0x00, 0x42, 0x00]; // type 0x42
        assert!(matches!(parse_header(&bad), Err(VpnError::Protocol(_))));
    }

    #[test]
    fn cstp_type_round_trips() {
        for t in [
            CstpType::Data,
            CstpType::DpdOut,
            CstpType::DpdResp,
            CstpType::Disconnect,
            CstpType::Keepalive,
            CstpType::Compressed,
            CstpType::TermServer,
        ] {
            assert_eq!(CstpType::from_u8(t.to_u8()).unwrap(), t);
        }
    }

    #[test]
    fn tls_config_builds() {
        // Proves ring provider auto-selects and each trust mode builds without panic.
        assert!(Arc::strong_count(&build_tls_config(&CertTrust::Webpki)) >= 1);
        assert!(Arc::strong_count(&build_tls_config(&CertTrust::Pinned([0u8; 32]))) >= 1);
        assert!(Arc::strong_count(&build_tls_config(&CertTrust::Insecure)) >= 1);
    }

    #[test]
    fn connect_request_has_cstp_headers() {
        let r = build_connect_request("vpn.example.com", "COOKIEVAL");
        assert!(r.starts_with("CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n"));
        assert!(r.contains("Cookie: webvpn=COOKIEVAL"));
        assert!(r.contains("X-CSTP-Version: 1"));
        assert!(r.contains("X-CSTP-MTU: 1400"));
        assert!(r.ends_with("\r\n\r\n"));
    }

    #[test]
    fn parse_connect_response_full() {
        let raw = "HTTP/1.1 200 CONNECTED\r\n\
                   X-CSTP-Address: 10.0.0.5\r\n\
                   X-CSTP-Netmask: 255.255.255.0\r\n\
                   X-CSTP-DNS: 8.8.8.8\r\n\
                   X-CSTP-DNS: 8.8.4.4\r\n\
                   X-CSTP-MTU: 1400\r\n\
                   X-CSTP-Keepalive: 20\r\n\
                   X-CSTP-DPD: 30\r\n\
                   \r\n";
        let p = parse_connect_response(raw).unwrap();
        assert_eq!(p.address, "10.0.0.5".parse::<std::net::Ipv4Addr>().unwrap());
        assert_eq!(
            p.dns,
            vec![
                "8.8.8.8".parse::<Ipv4Addr>().unwrap(),
                "8.8.4.4".parse::<Ipv4Addr>().unwrap()
            ]
        );
        assert_eq!(p.mtu, 1400);
        assert_eq!(p.keepalive, Some(20));
        assert_eq!(p.dpd, Some(30));
    }

    #[test]
    fn parse_connect_response_defaults_mtu() {
        let raw = "HTTP/1.1 200 CONNECTED\r\nX-CSTP-Address: 10.1.2.3\r\n\r\n";
        let p = parse_connect_response(raw).unwrap();
        assert_eq!(p.mtu, 1400); // default when X-CSTP-MTU absent
    }

    #[test]
    fn parse_connect_response_rejects_non_200() {
        let raw = "HTTP/1.1 403 Forbidden\r\n\r\n";
        assert!(matches!(parse_connect_response(raw), Err(VpnError::Tls(_))));
    }
}
