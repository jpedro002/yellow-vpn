//! SLIM session layer (CP-SESS-01): the `client_hello` control-message builder
//! and the `hello_reply` parser that yields a typed [`CheckpointSession`]
//! (assigned Office Mode IP, prefix, DNS, search domains, routed subnets, and
//! keepalive/auth timeouts). Pure request-build + response-parse over the
//! Phase-1 `checkpoint::ccc` codec — no socket, no framing (Phase 5/6).
//!
//! Server input (`hello_reply`) is untrusted: parsing never unwraps on server
//! values and never panics; malformed/unusable input maps to `VpnError::Protocol`.
//! The `cookie` (deobfuscated active_key) is credential-equivalent — never logged.
#![allow(dead_code)]

use std::net::Ipv4Addr;

use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::checkpoint::ccc::CccValue;
use crate::checkpoint::framing::{self, SlimPacket};
use crate::error::VpnError;

/// Default tunnel MTU for SLIM — `hello_reply` does not provide one (RESEARCH §5);
/// reuse the v0.1 default.
pub const DEFAULT_SLIM_MTU: u16 = 1400;

/// Upper bound on bytes read while awaiting `hello_reply` — guards a hostile/hung
/// server that never completes the first control frame.
const HELLO_REPLY_MAX_BYTES: usize = 64 * 1024;

/// Typed SLIM session derived from `hello_reply` (D-04). Separate from the v0.1
/// `tunnel::SessionParams` (CSTP-shaped); Phase 6 maps this onto the TUN device
/// and routing table. Debug carries only network config — no secret.
#[derive(Debug, Clone, PartialEq)]
pub struct CheckpointSession {
    /// Assigned Office Mode IP (`OM.ipaddr`).
    pub address: Ipv4Addr,
    /// Netmask prefix length (`optional.subnet` → count_ones; absent → 32).
    pub prefix: u8,
    /// DNS servers (`OM.dns_servers` array elements).
    pub dns: Vec<Ipv4Addr>,
    /// Search domains (`OM.dns_suffix`, split on `,` or `;`).
    pub search_domains: Vec<String>,
    /// Routed subnets (`range[]` → CIDR; `0.0.0.1` sentinel skipped).
    pub routes: Vec<(Ipv4Addr, u8)>,
    /// Keepalive interval (`timeouts.keepalive`; default 20).
    pub keepalive_secs: u64,
    /// Reauth window (`timeouts.authentication - 60`, saturating; default 0).
    pub auth_timeout_secs: u64,
}

impl CheckpointSession {
    /// Map the Check Point session onto the v0.1 `tunnel::SessionParams` the TUN
    /// device + forwarding loop already consume (D-04). MTU is the SLIM default
    /// (not server-provided); keepalive carries the server cadence. Routes and
    /// search domains are Check-Point-only and applied separately (Phase 7).
    pub fn to_session_params(&self) -> crate::tunnel::SessionParams {
        crate::tunnel::SessionParams {
            address: self.address,
            netmask: Some(prefix_to_netmask(self.prefix)),
            dns: self.dns.clone(),
            mtu: DEFAULT_SLIM_MTU,
            keepalive: Some(self.keepalive_secs.min(u32::MAX as u64) as u32),
            dpd: None,
            disconnected_timeout: None,
        }
    }
}

/// Convert a prefix length (0..=32) into an IPv4 netmask. Values > 32 saturate to `/32`.
fn prefix_to_netmask(prefix: u8) -> Ipv4Addr {
    let p = prefix.min(32);
    let mask: u32 = if p == 0 { 0 } else { u32::MAX << (32 - p) };
    Ipv4Addr::from(mask)
}

/// Version/client_type parameters for `client_hello` (D-02). Defaults match the
/// snx-rs non-mobile client verified live: `client_version 2`, `protocol_version 2`,
/// `protocol_minor_version` OMITTED (`None`), `client_type "4"`. The mobile/blog
/// variant is `1/1` + `Some(1)` + `"TRAC"` — switchable here without code surgery.
pub struct HelloOpts<'a> {
    pub client_version: u32,
    pub protocol_version: u32,
    /// Emitted only when `Some` (snx-rs omits it for non-mobile).
    pub protocol_minor_version: Option<u32>,
    pub client_type: &'a str,
}

impl Default for HelloOpts<'_> {
    fn default() -> Self {
        HelloOpts {
            client_version: 2,
            protocol_version: 2,
            protocol_minor_version: None,
            client_type: "4",
        }
    }
}

/// Build the SLIM `client_hello` control S-expression (D-01). `cookie` is the
/// DEOBFUSCATED active_key, placed PLAINTEXT (RESEARCH §5, risk R3) — do NOT
/// re-obfuscate. `om_ip` is the Office Mode IP request (default "0.0.0.0").
/// Returns re-parseable wire text. NEVER log `cookie`.
pub fn build_client_hello(cookie: &str, om_ip: &str, opts: HelloOpts) -> String {
    let om = CccValue::Node {
        name: None,
        fields: vec![
            ("ipaddr".into(), CccValue::Atom(om_ip.to_string())),
            ("keep_address".into(), CccValue::Atom("false".into())),
        ],
    };
    let optional = CccValue::Node {
        name: None,
        fields: vec![(
            "client_type".into(),
            CccValue::Atom(opts.client_type.to_string()),
        )],
    };
    let mut fields = vec![
        (
            "client_version".into(),
            CccValue::Atom(opts.client_version.to_string()),
        ),
        (
            "protocol_version".into(),
            CccValue::Atom(opts.protocol_version.to_string()),
        ),
    ];
    // snx-rs omits protocol_minor_version for non-mobile — only emit when set.
    if let Some(minor) = opts.protocol_minor_version {
        fields.push((
            "protocol_minor_version".into(),
            CccValue::Atom(minor.to_string()),
        ));
    }
    fields.push(("OM".into(), om));
    fields.push(("optional".into(), optional));
    fields.push(("cookie".into(), CccValue::Atom(cookie.to_string())));
    let hello = CccValue::Node {
        name: Some("client_hello".into()),
        fields,
    };
    hello.to_wire()
}

/// Split an inclusive IPv4 range into aligned CIDR blocks (mirrors snx-rs
/// `ranges_to_subnets`). Pure. `from > to` → empty. Uses u64 arithmetic to avoid
/// overflow when `to == 255.255.255.255`. Terminates: each iteration advances
/// `start` by `>= 1`.
pub fn range_to_subnets(from: Ipv4Addr, to: Ipv4Addr) -> Vec<(Ipv4Addr, u8)> {
    let mut start = u32::from(from) as u64;
    let end = u32::from(to) as u64; // inclusive
    let mut out = Vec::new();
    if start > end {
        return out;
    }
    while start <= end {
        // Largest block the alignment of `start` allows (start==0 → whole space).
        let align_bits = if start == 0 {
            32
        } else {
            (start as u32).trailing_zeros()
        };
        // Largest power-of-two block that fits in the remaining count.
        let remaining = end - start + 1; // >= 1
        let size_bits = 63 - remaining.leading_zeros(); // floor(log2(remaining))
        let bits = align_bits.min(size_bits); // host bits for this block
        let prefix = (32 - bits) as u8;
        out.push((Ipv4Addr::from(start as u32), prefix));
        start += 1u64 << bits; // advance past this block
    }
    out
}

/// Parse a SLIM `hello_reply` S-expression into a typed [`CheckpointSession`]
/// (D-03). `tree` is the already-parsed CCC document. A `disconnect` object →
/// `Err(ServerDisconnect)`. Untrusted server input: no unwrap on server data, no
/// panics; unusable/malformed → `VpnError::Protocol`. Never log field contents.
pub fn parse_hello_reply(tree: &CccValue) -> Result<CheckpointSession, VpnError> {
    match tree.name() {
        Some("disconnect") => return Err(VpnError::ServerDisconnect),
        Some("hello_reply") => {}
        _ => {
            return Err(VpnError::Protocol(
                "unexpected hello reply object".into(),
            ))
        }
    }

    // address (REQUIRED)
    let address = tree
        .get("OM")
        .and_then(|om| om.get("ipaddr"))
        .and_then(|v| v.as_atom())
        .and_then(|s| s.parse::<Ipv4Addr>().ok())
        .ok_or_else(|| VpnError::Protocol("missing OM.ipaddr".into()))?;

    // prefix (optional.subnet netmask → count_ones; default /32)
    let prefix = tree
        .get("optional")
        .and_then(|o| o.get("subnet"))
        .and_then(|v| v.as_atom())
        .and_then(|s| s.parse::<Ipv4Addr>().ok())
        .map(|mask| u32::from(mask).count_ones() as u8)
        .unwrap_or(32);

    // dns (OM.dns_servers array)
    let dns = tree
        .get("OM")
        .and_then(|om| om.get("dns_servers"))
        .map(|node| {
            node.elements()
                .into_iter()
                .filter_map(|v| v.as_atom())
                .filter_map(|s| s.parse::<Ipv4Addr>().ok())
                .collect()
        })
        .unwrap_or_default();

    // search_domains (OM.dns_suffix, quoted, comma/semicolon-separated)
    let search_domains = tree
        .get("OM")
        .and_then(|om| om.get("dns_suffix"))
        .and_then(|v| v.as_atom())
        .map(|s| {
            let trimmed = s.trim_matches('"');
            trimmed
                .split([',', ';'])
                .map(|d| d.trim())
                .filter(|d| !d.is_empty())
                .map(|d| d.to_string())
                .collect()
        })
        .unwrap_or_default();

    // routes (range[] → range_to_subnets; skip the 0.0.0.1 default-route sentinel)
    let sentinel = Ipv4Addr::new(0, 0, 0, 1);
    let mut routes = Vec::new();
    if let Some(range) = tree.get("range") {
        for elem in range.elements() {
            let from = elem
                .get("from")
                .and_then(|v| v.as_atom())
                .and_then(|s| s.parse::<Ipv4Addr>().ok());
            let to = elem
                .get("to")
                .and_then(|v| v.as_atom())
                .and_then(|s| s.parse::<Ipv4Addr>().ok());
            match (from, to) {
                (Some(f), Some(t)) if f != sentinel => routes.extend(range_to_subnets(f, t)),
                _ => {} // unparseable or sentinel → skip
            }
        }
    }

    // timeouts
    let timeouts = tree.get("timeouts");
    let keepalive_secs = timeouts
        .and_then(|t| t.get("keepalive"))
        .and_then(|v| v.as_atom())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(20);
    let auth_timeout_secs = timeouts
        .and_then(|t| t.get("authentication"))
        .and_then(|v| v.as_atom())
        .and_then(|s| s.parse::<u64>().ok())
        .map(|a| a.saturating_sub(60))
        .unwrap_or(0);

    Ok(CheckpointSession {
        address,
        prefix,
        dns,
        search_domains,
        routes,
        keepalive_secs,
        auth_timeout_secs,
    })
}

/// Run the SLIM session handshake over an established data-tunnel TLS stream: send
/// `client_hello` as the first frame, then read frames until the server's
/// `hello_reply` control frame arrives, and parse it into a [`CheckpointSession`]
/// (RESEARCH §1/§2). `cookie` is the DEOBFUSCATED active_key (plaintext).
///
/// The read is bounded ([`HELLO_REPLY_MAX_BYTES`]) and never trusts the server to
/// close. A `disconnect` reply surfaces as `VpnError::ServerDisconnect`
/// (`parse_hello_reply`). The live exchange is exercised in Phase 7.
pub async fn establish_session<S>(
    stream: &mut S,
    cookie: &str,
    opts: HelloOpts<'_>,
) -> Result<CheckpointSession, VpnError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let hello = build_client_hello(cookie, "0.0.0.0", opts);
    let frame = framing::encode_control(&hello);
    // Log the client_hello wire with the cookie value REDACTED (credential-equivalent).
    tracing::debug!(
        frame_len = frame.len(),
        client_hello = %redact_cookie(&hello),
        "SLIM: sending client_hello"
    );
    stream.write_all(&frame).await?;
    stream.flush().await?;

    let mut buf = BytesMut::with_capacity(4096);
    loop {
        // Drain any complete frame already buffered before reading more.
        match framing::try_decode_slim(&mut buf)? {
            Some(SlimPacket::Control(tree)) => {
                tracing::debug!(object = ?tree.name(), "SLIM: received control frame");
                return parse_hello_reply(&tree);
            }
            Some(SlimPacket::Data(_)) => continue, // ignore stray data before hello_reply
            None => {}
        }
        if buf.len() > HELLO_REPLY_MAX_BYTES {
            return Err(VpnError::Protocol(
                "hello_reply exceeded size guard".into(),
            ));
        }
        // Bounded wait: a silent gateway must surface as an error, not a hang.
        let n = match tokio::time::timeout(
            std::time::Duration::from_secs(HELLO_REPLY_TIMEOUT_SECS),
            stream.read_buf(&mut buf),
        )
        .await
        {
            Ok(res) => res?,
            Err(_) => {
                return Err(VpnError::Protocol(format!(
                    "no hello_reply within {HELLO_REPLY_TIMEOUT_SECS}s ({} bytes buffered)",
                    buf.len()
                )))
            }
        };
        if n == 0 {
            return Err(VpnError::Protocol(
                "connection closed before hello_reply".into(),
            ));
        }
        tracing::debug!(
            n,
            total = buf.len(),
            head = %hex_head(&buf, 64),
            "SLIM: read bytes awaiting hello_reply"
        );
    }
}

/// Seconds to wait for `hello_reply` before declaring the gateway silent.
const HELLO_REPLY_TIMEOUT_SECS: u64 = 20;

/// Redact the `:cookie (...)` value in client_hello wire text for safe logging.
fn redact_cookie(wire: &str) -> String {
    match wire.find(":cookie (") {
        Some(start) => {
            let after = start + ":cookie (".len();
            match wire[after..].find(')') {
                Some(rel) => format!("{}<redacted>{}", &wire[..after], &wire[after + rel..]),
                None => wire.to_string(),
            }
        }
        None => wire.to_string(),
    }
}

/// Lowercase-hex the first `max` bytes of a buffer (diagnostics only).
fn hex_head(buf: &[u8], max: usize) -> String {
    use std::fmt::Write;
    let n = buf.len().min(max);
    let mut s = String::with_capacity(n * 2);
    for b in &buf[..n] {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::ccc;

    // Byte-exact snx-rs committed fixture (RESEARCH §2b).
    const HELLO_REPLY_FIXTURE: &str = "(hello_reply
    :version (1)
    :protocol_version (1)
    :OM (
        :ipaddr (10.0.0.10)
        :dns_servers (
            : (10.0.0.1)
            : (10.0.0.2))
        :dns_suffix (\"domain1.com,domain2.com\"))
    :range (
        : (:from (10.0.0.0) :to (10.255.255.255))
        : (:from (172.16.0.0) :to (172.16.255.255)))
    :timeouts (
        :authentication (259193)
        :keepalive (20))
    :optional (
        :subnet (255.255.255.0)))";

    // --- build_client_hello ---

    #[test]
    fn client_hello_defaults() {
        // Defaults now match snx-rs non-mobile: 2/2, no minor, client_type "4".
        let wire = build_client_hello("SECRETCOOKIE", "0.0.0.0", HelloOpts::default());
        let doc = ccc::parse(&wire).expect("re-parses");
        assert_eq!(doc.name(), Some("client_hello"));
        assert_eq!(
            doc.get("client_version").and_then(|v| v.as_atom()),
            Some("2")
        );
        assert_eq!(
            doc.get("protocol_version").and_then(|v| v.as_atom()),
            Some("2")
        );
        // protocol_minor_version is OMITTED for the non-mobile default.
        assert!(doc.get("protocol_minor_version").is_none());
        let om = doc.get("OM").expect("OM present");
        assert_eq!(om.get("ipaddr").and_then(|v| v.as_atom()), Some("0.0.0.0"));
        assert_eq!(
            om.get("keep_address").and_then(|v| v.as_atom()),
            Some("false")
        );
        let optional = doc.get("optional").expect("optional present");
        assert_eq!(
            optional.get("client_type").and_then(|v| v.as_atom()),
            Some("4")
        );
        // cookie is plaintext, verbatim.
        assert_eq!(
            doc.get("cookie").and_then(|v| v.as_atom()),
            Some("SECRETCOOKIE")
        );
    }

    #[test]
    fn client_hello_parameterized_mobile_variant() {
        // The mobile/blog variant: 1/1 + Some(1) + "TRAC".
        let opts = HelloOpts {
            client_version: 1,
            protocol_version: 1,
            protocol_minor_version: Some(1),
            client_type: "TRAC",
        };
        let wire = build_client_hello("C", "0.0.0.0", opts);
        let doc = ccc::parse(&wire).expect("re-parses");
        assert_eq!(
            doc.get("client_version").and_then(|v| v.as_atom()),
            Some("1")
        );
        assert_eq!(
            doc.get("protocol_minor_version").and_then(|v| v.as_atom()),
            Some("1")
        );
        assert_eq!(
            doc.get("optional")
                .and_then(|o| o.get("client_type"))
                .and_then(|v| v.as_atom()),
            Some("TRAC")
        );
    }

    // --- range_to_subnets ---

    #[test]
    fn range_fixture_class_a() {
        assert_eq!(
            range_to_subnets(
                Ipv4Addr::new(10, 0, 0, 0),
                Ipv4Addr::new(10, 255, 255, 255)
            ),
            vec![(Ipv4Addr::new(10, 0, 0, 0), 8)]
        );
    }

    #[test]
    fn range_fixture_class_b() {
        assert_eq!(
            range_to_subnets(
                Ipv4Addr::new(172, 16, 0, 0),
                Ipv4Addr::new(172, 16, 255, 255)
            ),
            vec![(Ipv4Addr::new(172, 16, 0, 0), 16)]
        );
    }

    #[test]
    fn range_single_host() {
        assert_eq!(
            range_to_subnets(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 0)),
            vec![(Ipv4Addr::new(10, 0, 0, 0), 32)]
        );
    }

    #[test]
    fn range_from_greater_than_to_is_empty() {
        assert!(range_to_subnets(Ipv4Addr::new(10, 0, 0, 5), Ipv4Addr::new(10, 0, 0, 1)).is_empty());
    }

    #[test]
    fn range_unaligned_two_hosts() {
        assert_eq!(
            range_to_subnets(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)),
            vec![
                (Ipv4Addr::new(10, 0, 0, 1), 32),
                (Ipv4Addr::new(10, 0, 0, 2), 32)
            ]
        );
    }

    #[test]
    fn range_top_of_space_no_overflow() {
        // 255.255.255.254..=255.255.255.255 → two /32s (or a /31 if aligned).
        let out = range_to_subnets(
            Ipv4Addr::new(255, 255, 255, 254),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        assert_eq!(out, vec![(Ipv4Addr::new(255, 255, 255, 254), 31)]);
    }

    // --- parse_hello_reply ---

    #[test]
    fn parse_full_fixture() {
        let tree = ccc::parse(HELLO_REPLY_FIXTURE).expect("fixture parses");
        let s = parse_hello_reply(&tree).expect("hello_reply parses");
        assert_eq!(s.address, Ipv4Addr::new(10, 0, 0, 10));
        assert_eq!(s.prefix, 24);
        assert_eq!(
            s.dns,
            vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)]
        );
        assert_eq!(
            s.search_domains,
            vec!["domain1.com".to_string(), "domain2.com".to_string()]
        );
        assert_eq!(
            s.routes,
            vec![
                (Ipv4Addr::new(10, 0, 0, 0), 8),
                (Ipv4Addr::new(172, 16, 0, 0), 16)
            ]
        );
        assert_eq!(s.keepalive_secs, 20);
        assert_eq!(s.auth_timeout_secs, 259133);
    }

    #[test]
    fn disconnect_is_server_disconnect() {
        let tree = ccc::parse("(disconnect :message (\"bye\"))").expect("parses");
        match parse_hello_reply(&tree) {
            Err(VpnError::ServerDisconnect) => {}
            other => panic!("expected ServerDisconnect, got {other:?}"),
        }
    }

    #[test]
    fn missing_ipaddr_is_protocol_error() {
        let tree = ccc::parse("(hello_reply :OM ( :dns_suffix (\"x.com\")))").expect("parses");
        match parse_hello_reply(&tree) {
            Err(VpnError::Protocol(_)) => {}
            other => panic!("expected Protocol, got {other:?}"),
        }
    }

    #[test]
    fn unexpected_object_is_protocol_error() {
        let tree = ccc::parse("(something_else :OM ( :ipaddr (10.0.0.10)))").expect("parses");
        match parse_hello_reply(&tree) {
            Err(VpnError::Protocol(_)) => {}
            other => panic!("expected Protocol, got {other:?}"),
        }
    }

    #[test]
    fn absent_subnet_defaults_to_slash_32() {
        let tree = ccc::parse("(hello_reply :OM ( :ipaddr (10.0.0.10)))").expect("parses");
        let s = parse_hello_reply(&tree).expect("parses");
        assert_eq!(s.prefix, 32);
    }

    #[test]
    fn sentinel_route_is_skipped() {
        let tree = ccc::parse(
            "(hello_reply :OM ( :ipaddr (10.0.0.10)) :range ( : (:from (0.0.0.1) :to (0.0.0.1)) : (:from (10.0.0.0) :to (10.255.255.255))))",
        )
        .expect("parses");
        let s = parse_hello_reply(&tree).expect("parses");
        // Only the real range contributes; the 0.0.0.1 sentinel is skipped.
        assert_eq!(s.routes, vec![(Ipv4Addr::new(10, 0, 0, 0), 8)]);
    }

    #[test]
    fn prefix_to_netmask_conversions() {
        assert_eq!(prefix_to_netmask(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(prefix_to_netmask(8), Ipv4Addr::new(255, 0, 0, 0));
        assert_eq!(prefix_to_netmask(32), Ipv4Addr::new(255, 255, 255, 255));
        assert_eq!(prefix_to_netmask(0), Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(prefix_to_netmask(40), Ipv4Addr::new(255, 255, 255, 255)); // saturates
    }

    #[test]
    fn to_session_params_maps_fields() {
        let tree = ccc::parse(HELLO_REPLY_FIXTURE).expect("parses");
        let s = parse_hello_reply(&tree).expect("parses");
        let p = s.to_session_params();
        assert_eq!(p.address, Ipv4Addr::new(10, 0, 0, 10));
        assert_eq!(p.netmask, Some(Ipv4Addr::new(255, 255, 255, 0)));
        assert_eq!(p.dns, vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)]);
        assert_eq!(p.mtu, DEFAULT_SLIM_MTU);
        assert_eq!(p.keepalive, Some(20));
    }

    #[test]
    fn missing_timeouts_use_defaults() {
        let tree = ccc::parse("(hello_reply :OM ( :ipaddr (10.0.0.10)))").expect("parses");
        let s = parse_hello_reply(&tree).expect("parses");
        assert_eq!(s.keepalive_secs, 20);
        assert_eq!(s.auth_timeout_secs, 0);
    }
}
