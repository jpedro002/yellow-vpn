//! FortiGate tunnel configuration retrieval (FG-CFG-01).
//!
//! After auth, `GET /remote/fortisslvpn_xml` returns the tunnel parameters as
//! XML: the assigned IPv4 address, DNS servers, an optional search domain, and an
//! optional split-tunnel route list. openfortivpn also pings `/remote/index` and
//! `/remote/fortisslvpn` first to trigger the session allocation, so we do too
//! (best-effort). Source: openfortivpn `src/http.c` (RESEARCH §3).
//!
//! The XML is untrusted server input: parsing is a bounded, panic-free
//! attribute scan (no XML crate — deps are LOCKED). A missing assigned address is
//! a hard `VpnError::Protocol`; everything else is optional.
#![allow(dead_code)]

use std::net::Ipv4Addr;

use crate::error::VpnError;
use crate::tunnel::{connect_tls, CertTrust, SessionParams};

/// Default tunnel MTU when the server does not carry one (the XML endpoint does
/// not expose MTU; 1400 is the safe FortiGate SSL VPN default — RESEARCH §3).
const DEFAULT_MTU: u16 = 1400;

/// User-Agent — see `auth.rs` (must not contain `SV1`).
const USER_AGENT: &str = "Mozilla/5.0";

/// Largest config reply we will buffer (256 KiB).
const CONFIG_RESPONSE_MAX: usize = 256 * 1024;

/// Parsed FortiGate tunnel configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FortiConfig {
    /// Assigned tunnel IPv4 address (`<assigned-addr ipv4="...">`).
    pub address: Ipv4Addr,
    /// DNS resolvers (`<dns ip="...">`), zero or more.
    pub dns: Vec<Ipv4Addr>,
    /// DNS search domain (`<dns domain="...">`), if present.
    pub dns_suffix: Option<String>,
    /// Split-tunnel routes (`<split-tunnel-info><addr ip mask>`). Empty means the
    /// server pushed no split list — a FULL tunnel (RESEARCH §3); the caller
    /// decides how to route that.
    pub routes: Vec<(Ipv4Addr, u8)>,
    /// Tunnel MTU (defaulted — the XML does not carry one).
    pub mtu: u16,
}

impl FortiConfig {
    /// Map into the protocol-agnostic [`SessionParams`] the shared pipeline wants.
    pub fn to_session_params(&self) -> SessionParams {
        SessionParams {
            address: self.address,
            netmask: None, // assigned as a /32 host address
            dns: self.dns.clone(),
            mtu: self.mtu,
            keepalive: None, // no in-tunnel keepalive frame (RESEARCH §6)
            dpd: None,
            disconnected_timeout: None,
        }
    }
}

/// Convert a dotted netmask (`255.255.255.0`) to a prefix length (`24`).
fn mask_to_prefix(mask: Ipv4Addr) -> u8 {
    u32::from(mask).count_ones() as u8
}

/// Extract the value of `attr="..."` from an element fragment, if present.
fn attr_after(fragment: &str, attr: &str) -> Option<String> {
    let key = format!("{attr}=\"");
    let start = fragment.find(&key)? + key.len();
    let end = fragment[start..].find('"')? + start;
    Some(fragment[start..end].to_string())
}

/// Parse the `fortisslvpn_xml` body (FG-CFG-02). Scans element fragments rather
/// than building a DOM — the schema is flat and the input is untrusted, so a
/// bounded string scan is simpler and panic-free. A missing assigned address is a
/// protocol error (the tunnel is unusable without it).
pub fn parse_config_xml(body: &str) -> Result<FortiConfig, VpnError> {
    let mut address: Option<Ipv4Addr> = None;
    let mut dns: Vec<Ipv4Addr> = Vec::new();
    let mut dns_suffix: Option<String> = None;
    let mut routes: Vec<(Ipv4Addr, u8)> = Vec::new();

    // Split on '<' so each fragment is one element's "name attr=... " text.
    for frag in body.split('<') {
        let frag = frag.trim_start();
        if let Some(rest) = frag.strip_prefix("assigned-addr") {
            if let Some(ip) = attr_after(rest, "ipv4") {
                address = ip.parse().ok();
            }
        } else if let Some(rest) = frag.strip_prefix("dns") {
            if let Some(ip) = attr_after(rest, "ip") {
                if let Ok(a) = ip.parse::<Ipv4Addr>() {
                    dns.push(a);
                }
            }
            if let Some(d) = attr_after(rest, "domain") {
                if !d.is_empty() {
                    dns_suffix = Some(d);
                }
            }
        } else if let Some(rest) = frag.strip_prefix("addr") {
            // A split-tunnel-info entry: <addr ip="..." mask="...">.
            if let (Some(ip), Some(mask)) = (attr_after(rest, "ip"), attr_after(rest, "mask")) {
                if let (Ok(ip), Ok(mask)) = (ip.parse::<Ipv4Addr>(), mask.parse::<Ipv4Addr>()) {
                    routes.push((ip, mask_to_prefix(mask)));
                }
            }
        }
    }

    let address = address.ok_or_else(|| {
        VpnError::Protocol("FortiGate config missing assigned-addr ipv4".into())
    })?;

    Ok(FortiConfig {
        address,
        dns,
        dns_suffix,
        routes,
        mtu: DEFAULT_MTU,
    })
}

/// Build a `GET <path>` request carrying the session cookie.
fn build_get_request(host: &str, path: &str, cookie: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: {USER_AGENT}\r\n\
         Cookie: SVPNCOOKIE={cookie}\r\n\
         Connection: close\r\n\
         \r\n"
    )
}

/// Read a full HTTP response and return just the body (text after the first
/// `\r\n\r\n`). Bounded; tolerates a close without TLS `close_notify`.
async fn read_http_body<S>(stream: &mut S) -> Result<String, VpnError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = [0u8; 2048];
    loop {
        let n = match stream.read(&mut chunk).await {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        };
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > CONFIG_RESPONSE_MAX {
            break;
        }
    }
    let raw = String::from_utf8_lossy(&buf).into_owned();
    let body = match raw.find("\r\n\r\n") {
        Some(idx) => raw[idx + 4..].to_string(),
        None => raw,
    };
    Ok(body)
}

/// Issue one `GET` over a fresh short-lived TLS connection and return its body.
async fn http_get(
    host: &str,
    port: u16,
    trust: &CertTrust,
    path: &str,
    cookie: &str,
) -> Result<String, VpnError> {
    use tokio::io::AsyncWriteExt;

    let mut tls = connect_tls(host, port, trust).await?;
    tls.write_all(build_get_request(host, path, cookie).as_bytes())
        .await?;
    tls.flush().await?;
    read_http_body(&mut tls).await
}

/// Fetch and parse the tunnel configuration (FG-CFG-01). Pings the allocation
/// endpoints first (best-effort — a failure there is not fatal), then fetches and
/// parses `fortisslvpn_xml`. The cookie is never logged.
pub async fn fetch_config(
    host: &str,
    port: u16,
    trust: &CertTrust,
    cookie: &str,
) -> Result<FortiConfig, VpnError> {
    // Allocation warm-up (openfortivpn ordering). Bodies are HTML we ignore; a
    // transient failure here should not block the config fetch that follows.
    let _ = http_get(host, port, trust, "/remote/index", cookie).await;
    let _ = http_get(host, port, trust, "/remote/fortisslvpn", cookie).await;

    let body = http_get(host, port, trust, "/remote/fortisslvpn_xml", cookie).await?;
    let cfg = parse_config_xml(&body)?;
    tracing::info!(
        address = %cfg.address,
        dns_count = cfg.dns.len(),
        route_count = cfg.routes.len(),
        "FortiGate tunnel config retrieved"
    );
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_to_prefix_common_values() {
        assert_eq!(mask_to_prefix("255.255.255.0".parse().unwrap()), 24);
        assert_eq!(mask_to_prefix("255.255.0.0".parse().unwrap()), 16);
        assert_eq!(mask_to_prefix("255.0.0.0".parse().unwrap()), 8);
        assert_eq!(mask_to_prefix("0.0.0.0".parse().unwrap()), 0);
        assert_eq!(mask_to_prefix("255.255.255.255".parse().unwrap()), 32);
    }

    #[test]
    fn parse_split_tunnel_config() {
        let xml = r#"<?xml version="1.0"?>
            <sslvpn-tunnel>
              <assigned-addr ipv4="10.212.134.100"/>
              <dns ip="8.8.8.8"/>
              <dns ip="8.8.4.4"/>
              <dns domain="corp.local"/>
              <split-tunnel-info>
                <addr ip="10.0.0.0" mask="255.0.0.0"/>
                <addr ip="192.168.1.0" mask="255.255.255.0"/>
              </split-tunnel-info>
            </sslvpn-tunnel>"#;
        let c = parse_config_xml(xml).unwrap();
        assert_eq!(c.address, "10.212.134.100".parse::<Ipv4Addr>().unwrap());
        assert_eq!(
            c.dns,
            vec![
                "8.8.8.8".parse::<Ipv4Addr>().unwrap(),
                "8.8.4.4".parse::<Ipv4Addr>().unwrap()
            ]
        );
        assert_eq!(c.dns_suffix.as_deref(), Some("corp.local"));
        assert_eq!(
            c.routes,
            vec![
                ("10.0.0.0".parse::<Ipv4Addr>().unwrap(), 8),
                ("192.168.1.0".parse::<Ipv4Addr>().unwrap(), 24),
            ]
        );
        assert_eq!(c.mtu, DEFAULT_MTU);
    }

    #[test]
    fn parse_full_tunnel_has_no_routes() {
        let xml = r#"<sslvpn-tunnel><assigned-addr ipv4="10.1.2.3"/><dns ip="1.1.1.1"/></sslvpn-tunnel>"#;
        let c = parse_config_xml(xml).unwrap();
        assert_eq!(c.address, "10.1.2.3".parse::<Ipv4Addr>().unwrap());
        assert!(c.routes.is_empty(), "no split-tunnel-info => full tunnel");
        assert_eq!(c.dns_suffix, None);
    }

    #[test]
    fn parse_missing_address_is_protocol_error() {
        let xml = r#"<sslvpn-tunnel><dns ip="1.1.1.1"/></sslvpn-tunnel>"#;
        assert!(matches!(parse_config_xml(xml), Err(VpnError::Protocol(_))));
    }

    #[test]
    fn to_session_params_maps_fields() {
        let c = FortiConfig {
            address: "10.0.0.9".parse().unwrap(),
            dns: vec!["8.8.8.8".parse().unwrap()],
            dns_suffix: None,
            routes: vec![],
            mtu: 1400,
        };
        let p = c.to_session_params();
        assert_eq!(p.address, "10.0.0.9".parse::<Ipv4Addr>().unwrap());
        assert_eq!(p.mtu, 1400);
        assert_eq!(p.dns, vec!["8.8.8.8".parse::<Ipv4Addr>().unwrap()]);
        assert_eq!(p.keepalive, None);
    }

    #[test]
    fn get_request_carries_cookie() {
        let r = build_get_request("vpn.example.com", "/remote/fortisslvpn_xml", "C00K1E");
        assert!(r.starts_with("GET /remote/fortisslvpn_xml HTTP/1.1\r\n"));
        assert!(r.contains("Cookie: SVPNCOOKIE=C00K1E"));
    }
}
