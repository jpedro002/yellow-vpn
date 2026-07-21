//! FortiGate tunnel upgrade (FG-SESS-01).
//!
//! `GET /remote/sslvpn-tunnel` over a fresh TLS connection, carrying the
//! `SVPNCOOKIE`. After the request the socket stops being HTTP and starts
//! carrying `0x5050`-framed packets (see `framing.rs`). Some gateways answer with
//! an `HTTP/1.1 200` header block first and then switch; others begin framed data
//! immediately. Both are handled, and any tunnel bytes that arrive glued to the
//! response are preserved as a "prime" buffer so the forwarding loop never drops
//! them. Source: openfortivpn `src/tunnel.c` (RESEARCH §4).
#![allow(dead_code)]

use std::time::Duration;

use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use crate::error::VpnError;
use crate::tunnel::{connect_tls, CertTrust};

/// User-Agent — see `auth.rs` (must not contain `SV1`).
const USER_AGENT: &str = "Mozilla/5.0";

/// Upper bound on bytes buffered while probing the tunnel-upgrade response.
const UPGRADE_PROBE_MAX: usize = 64 * 1024;

/// How long to wait for an HTTP upgrade response before assuming the server is
/// waiting for the client to speak first (data-driven v2 gateways). Kept short so
/// a silent gateway does not stall the connect.
const UPGRADE_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Build the `GET /remote/sslvpn-tunnel` upgrade request.
pub fn build_tunnel_request(host: &str, cookie: &str) -> String {
    format!(
        "GET /remote/sslvpn-tunnel HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: {USER_AGENT}\r\n\
         Cookie: SVPNCOOKIE={cookie}\r\n\
         \r\n"
    )
}

/// Position just past the first `\r\n\r\n` header terminator, if present.
fn header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// Open the packet tunnel over a fresh TLS connection (FG-SESS-01). Returns the
/// live stream plus any already-received tunnel bytes ("prime") that the
/// forwarding loop must decode before its first read. The cookie is never logged.
pub async fn open_tunnel(
    host: &str,
    port: u16,
    trust: &CertTrust,
    cookie: &str,
) -> Result<(TlsStream<TcpStream>, BytesMut), VpnError> {
    let mut stream = connect_tls(host, port, trust).await?;
    stream
        .write_all(build_tunnel_request(host, cookie).as_bytes())
        .await?;
    stream.flush().await?;

    let mut buf = BytesMut::with_capacity(4096);
    let mut chunk = [0u8; 2048];

    loop {
        match tokio::time::timeout(UPGRADE_PROBE_TIMEOUT, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => {
                return Err(VpnError::Tls(
                    "connection closed during FortiGate tunnel upgrade".into(),
                ));
            }
            Ok(Ok(n)) => {
                buf.extend_from_slice(&chunk[..n]);

                // If the first bytes are NOT an HTTP status line, the gateway went
                // straight to framed data — everything buffered is tunnel data.
                if buf.len() >= 5 && !buf.starts_with(b"HTTP/") {
                    return Ok((stream, buf));
                }
                // HTTP response: once the header block is complete, verify the
                // status and hand back whatever tunnel bytes followed the headers.
                if let Some(end) = header_end(&buf) {
                    let status = String::from_utf8_lossy(&buf[..end]);
                    let first = status.lines().next().unwrap_or("");
                    if !first.contains("200") {
                        return Err(VpnError::Tls(format!(
                            "unexpected tunnel-upgrade response: {first}"
                        )));
                    }
                    let prime = buf.split_off(end); // bytes after the header block
                    return Ok((stream, prime));
                }
                if buf.len() > UPGRADE_PROBE_MAX {
                    return Err(VpnError::Tls(
                        "FortiGate tunnel-upgrade response exceeded size guard".into(),
                    ));
                }
            }
            Ok(Err(e)) => return Err(e.into()),
            // No bytes yet: the gateway is waiting for the client to send first.
            // Proceed with whatever (likely nothing) we have buffered as prime.
            Err(_timeout) => return Ok((stream, buf)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnel_request_carries_cookie() {
        let r = build_tunnel_request("vpn.example.com", "C00K1E");
        assert!(r.starts_with("GET /remote/sslvpn-tunnel HTTP/1.1\r\n"));
        assert!(r.contains("Cookie: SVPNCOOKIE=C00K1E"));
        assert!(!r.contains("SV1"));
        assert!(r.ends_with("\r\n\r\n"));
    }

    #[test]
    fn header_end_finds_terminator() {
        assert_eq!(header_end(b"HTTP/1.1 200 OK\r\n\r\nDATA"), Some(19));
        assert_eq!(header_end(b"HTTP/1.1 200 OK\r\n"), None);
    }
}
