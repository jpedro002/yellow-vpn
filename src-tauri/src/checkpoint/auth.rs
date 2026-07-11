//! CCC UserPass authentication — POST /clients/. Pure request builder +
//! response parser are unit-tested offline; the live round-trip is Phase 7.
//! Credentials and active_key are NEVER logged.
#![allow(dead_code)]

use crate::checkpoint::ccc::CccValue;
use crate::checkpoint::{ccc, cipher};
use crate::error::VpnError;
use crate::tunnel::{connect_tls, CertTrust};

/// Live-probed `connectivity_info.tcpt_port` default. The authoritative value
/// comes from a Phase-4 CCC ClientHello, so the UserPass response usually omits
/// a `connectivity_info` block — fall back to this (the live server used 443).
pub const DEFAULT_TCPT_PORT: u16 = 443;

/// A successful CCC authentication session (D-03/D-04).
///
/// `active_key` is stored OBFUSCATED (hex) exactly as received; it is
/// credential-equivalent and is redacted from `Debug`. Use
/// [`CccSession::active_key_deobfuscated`] to get the plaintext cookie Phase 4
/// places in `client_hello.cookie`.
pub struct CccSession {
    pub session_id: String,
    active_key: String, // OBFUSCATED (hex) as received; never logged
    pub tcpt_port: u16,
}

impl CccSession {
    /// Deobfuscated active_key — the plaintext value Phase 4 puts in
    /// client_hello.cookie (RESEARCH risk R3). Do NOT re-obfuscate it downstream.
    pub fn active_key_deobfuscated(&self) -> Result<String, VpnError> {
        Ok(String::from_utf8_lossy(&cipher::decode(&self.active_key)?).into_owned())
    }

    /// Constructor used by parse_ccc_response (kept crate-visible for tests).
    pub(crate) fn new(session_id: String, active_key: String, tcpt_port: u16) -> Self {
        Self {
            session_id,
            active_key,
            tcpt_port,
        }
    }
}

impl std::fmt::Debug for CccSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CccSession")
            .field("session_id", &self.session_id)
            .field("active_key", &"<redacted>")
            .field("tcpt_port", &self.tcpt_port)
            .finish()
    }
}

/// Build the CCC `(CCCclientRequest ...)` UserPass login body (CP-AUTH-01).
///
/// Both `username` and `password` are hex-obfuscated via [`cipher::encode`]
/// (VERIFIED against snx-rs: the username IS obfuscated, not plaintext).
/// `protocol_version` and `endpoint_os` are intentionally omitted (matches
/// snx-rs; keeps the request minimal). Neither credential is ever logged.
pub fn build_userpass_request(username: &str, password: &str, id: u32) -> String {
    let header = CccValue::Node {
        name: None,
        fields: vec![
            ("id".into(), CccValue::Atom(id.to_string())),
            ("type".into(), CccValue::Atom("UserPass".into())),
            ("session_id".into(), CccValue::Empty),
        ],
    };
    let data = CccValue::Node {
        name: None,
        fields: vec![
            ("client_type".into(), CccValue::Atom("TRAC".into())),
            ("username".into(), CccValue::Atom(cipher::encode(username))),
            ("password".into(), CccValue::Atom(cipher::encode(password))),
        ],
    };
    CccValue::Node {
        name: Some("CCCclientRequest".into()),
        fields: vec![
            ("RequestHeader".into(), header),
            ("RequestData".into(), data),
        ],
    }
    .to_wire()
}

/// Parse a CCC `(CCCserverResponse ...)` body into a [`CccSession`] (CP-AUTH-02).
///
/// Mapping (D-05):
/// - `return_code == 600` + a present `active_key` -> `Ok(CccSession)`.
/// - `return_code == 600` but no `active_key` -> `VpnError::Protocol` (unusable).
/// - any well-formed non-600 -> PERMANENT `VpnError::AuthFailed` (credential/
///   authorization rejection; reconnecting cannot fix it).
/// - unparseable body / missing / non-numeric `return_code` -> transient
///   `VpnError::Protocol`.
///
/// The body, `active_key`, and `session_id` are never logged.
pub fn parse_ccc_response(body: &str) -> Result<CccSession, VpnError> {
    // Untrusted server body: ccc::parse is bounded + panic-free; any failure
    // bubbles up as VpnError::Protocol.
    let doc = ccc::parse(body)?;
    if doc.name() != Some("CCCserverResponse") {
        return Err(VpnError::Protocol("not a CCCserverResponse".into()));
    }

    let header = doc.get("ResponseHeader");
    let rdata = doc.get("ResponseData");

    // Missing / non-numeric return_code -> Protocol (transient).
    let rc: u32 = header
        .and_then(|h| h.get("return_code"))
        .and_then(|v| v.as_atom())
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| VpnError::Protocol("missing/invalid return_code".into()))?;

    // D-05: any well-formed non-600 response is a credential/authorization
    // rejection -> PERMANENT AuthFailed (reconnecting cannot fix it). Never put
    // credentials or the body in the message.
    if rc != 600 {
        return Err(VpnError::AuthFailed(format!(
            "server rejected authentication (return_code {rc})"
        )));
    }

    // session_id: prefer the header, fall back to ResponseData. Empty/absent is
    // acceptable ("" ) — active_key is the real secret, not session_id.
    let session_id = header
        .and_then(|h| h.get("session_id"))
        .and_then(|v| v.as_atom())
        .or_else(|| rdata.and_then(|d| d.get("session_id")).and_then(|v| v.as_atom()))
        .unwrap_or("")
        .to_string();

    // active_key: required for a usable 600. Kept as the raw OBFUSCATED hex;
    // deobfuscate lazily via CccSession::active_key_deobfuscated.
    let active_key = rdata
        .and_then(|d| d.get("active_key"))
        .and_then(|v| v.as_atom())
        .ok_or_else(|| VpnError::Protocol("600 response missing active_key".into()))?
        .to_string();

    // tcpt_port: connectivity_info is authoritative from a Phase-4 ClientHello,
    // so the UserPass response usually omits it — default to 443.
    let tcpt_port = rdata
        .and_then(|d| d.get("connectivity_info"))
        .and_then(|c| c.get("tcpt_port"))
        .and_then(|v| v.as_atom())
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(DEFAULT_TCPT_PORT);

    Ok(CccSession::new(session_id, active_key, tcpt_port))
}

/// Largest CCC auth reply we will buffer (256 KiB). A real reply is tiny; this
/// guards a hostile/hung server that never closes (threat T-03-02).
const AUTH_RESPONSE_MAX: usize = 256 * 1024;

/// Build the `POST /clients/` HTTP/1.1 request carrying the raw CCC S-expr body.
///
/// `Content-Length` uses the byte length of `body`; `Connection: close` makes the
/// HTTP/1.0-style Check Point server close after the body so the reader below
/// terminates on EOF.
fn http_post_clients(host: &str, body: &str) -> String {
    format!(
        "POST /clients/ HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: TRAC/E\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    )
}

/// Read the full HTTP response (headers AND body) over an async stream, then
/// return just the CCC body. Bounded: stops at EOF or [`AUTH_RESPONSE_MAX`]
/// (threat T-03-02) — never trust the server to close. The body is the text
/// after the first `\r\n\r\n`; if that terminator is absent (some CP servers use
/// bare LF), fall back to the first `(`. Trailing NULs/whitespace are trimmed.
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
            // Check Point closes the TCP after the body WITHOUT a TLS close_notify,
            // which rustls surfaces as UnexpectedEof. The body already buffered is
            // complete — treat this as a graceful end-of-stream, not a failure.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()), // other Io -> transient
        };
        if n == 0 {
            break; // clean EOF — server closed after the body
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > AUTH_RESPONSE_MAX {
            break; // guard against unbounded server data
        }
    }

    let raw = String::from_utf8_lossy(&buf).into_owned();
    let body = if let Some(idx) = raw.find("\r\n\r\n") {
        &raw[idx + 4..]
    } else if let Some(idx) = raw.find('(') {
        &raw[idx..]
    } else {
        raw.as_str()
    };
    Ok(body.trim_matches(|c: char| c == '\0' || c.is_whitespace()).to_string())
}

/// Authenticate to the Check Point gateway (CP-AUTH-01): connect over the reused
/// v0.1 TLS layer, POST the UserPass body to `/clients/`, read the bounded
/// response, and parse it into a [`CccSession`].
///
/// I/O over a live server — NOT unit-tested; the live round-trip is a Phase-7
/// human/live check. Its behavior is covered by [`build_userpass_request`] +
/// [`parse_ccc_response`]. Credentials, the request, the raw response, the CCC
/// body, `active_key`, and `session_id` are NEVER logged (D-05 / threat T-03-03);
/// the success log states the host only.
pub async fn authenticate_checkpoint(
    host: &str,
    port: u16,
    trust: &CertTrust,
    username: &str,
    password: &str,
) -> Result<CccSession, VpnError> {
    use tokio::io::AsyncWriteExt;

    let mut tls = connect_tls(host, port, trust).await?; // reused v0.1 TLS + CertTrust
    let request = http_post_clients(host, &build_userpass_request(username, password, 1));
    tls.write_all(request.as_bytes()).await?;
    tls.flush().await?;

    let body = read_http_body(&mut tls).await?;
    let session = parse_ccc_response(&body)?;
    tracing::info!(host = %host, "Check Point CCC authentication succeeded");
    Ok(session)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_has_userpass_and_trac() {
        let req = build_userpass_request("alice", "s3cret", 2);
        assert!(req.contains("(CCCclientRequest"), "req: {req}");
        assert!(req.contains(":type (UserPass)"), "req: {req}");
        assert!(req.contains(":client_type (TRAC)"), "req: {req}");
        assert!(req.contains(":id (2)"), "req: {req}");
        assert!(req.contains(":session_id ()"), "req: {req}");
    }

    #[test]
    fn builder_obfuscates_both_credentials() {
        let req = build_userpass_request("alice", "s3cret", 2);
        assert!(req.contains(&cipher::encode("alice")));
        assert!(req.contains(&cipher::encode("s3cret")));
        assert!(!req.contains("alice"), "plaintext username leaked");
        assert!(!req.contains("s3cret"), "plaintext password leaked");
    }

    #[test]
    fn builder_omits_protocol_version_and_endpoint_os() {
        let req = build_userpass_request("u", "p", 1);
        assert!(!req.contains("protocol_version"));
        assert!(!req.contains("endpoint_os"));
    }

    #[test]
    fn builder_output_reparses() {
        let doc = ccc::parse(&build_userpass_request("u", "p", 1)).expect("re-parses");
        assert_eq!(doc.name(), Some("CCCclientRequest"));
    }

    #[test]
    fn active_key_deobfuscates() {
        let s = CccSession::new("s".into(), "36203a333d372a59".into(), 443);
        assert_eq!(s.active_key_deobfuscated().unwrap(), "testuser");
    }

    #[test]
    fn debug_redacts_active_key() {
        let s = CccSession::new("SESS".into(), "36203a333d372a59".into(), 443);
        let dbg = format!("{s:?}");
        assert!(dbg.contains("<redacted>"), "dbg: {dbg}");
        assert!(!dbg.contains("36203a333d372a59"), "active_key leaked: {dbg}");
    }

    const SUCCESS: &str = "(CCCserverResponse :ResponseHeader ( :id (2) :type (UserPass) :session_id (SESS123) :return_code (600) ) :ResponseData ( :active_key (36203a333d372a59) :session_id (SESS123) ) )";
    const SUCCESS_WITH_PORT: &str = "(CCCserverResponse :ResponseHeader ( :return_code (600) :session_id (SESS123) ) :ResponseData ( :active_key (36203a333d372a59) :connectivity_info ( :tcpt_port (8443) ) ) )";
    const MISSING_KEY: &str = "(CCCserverResponse :ResponseHeader ( :return_code (600) ) :ResponseData () )";
    const AUTH_FAIL: &str = "(CCCserverResponse :ResponseHeader ( :return_code (101) ) :ResponseData () )";
    const NO_RETURN_CODE: &str = "(CCCserverResponse :ResponseHeader ( :type (UserPass) ) :ResponseData () )";

    #[test]
    fn parse_success_yields_session() {
        let s = parse_ccc_response(SUCCESS).expect("600 parses");
        assert_eq!(s.session_id, "SESS123");
        assert_eq!(s.active_key_deobfuscated().unwrap(), "testuser");
        assert_eq!(s.tcpt_port, 443);
    }

    #[test]
    fn parse_success_reads_connectivity_port() {
        let s = parse_ccc_response(SUCCESS_WITH_PORT).expect("600 parses");
        assert_eq!(s.tcpt_port, 8443);
    }

    #[test]
    fn parse_600_without_key_is_protocol() {
        assert!(matches!(
            parse_ccc_response(MISSING_KEY),
            Err(VpnError::Protocol(_))
        ));
    }

    #[test]
    fn parse_non_600_is_permanent_auth_failed() {
        let err = parse_ccc_response(AUTH_FAIL).unwrap_err();
        assert!(matches!(err, VpnError::AuthFailed(_)));
        assert!(err.is_permanent());
    }

    #[test]
    fn parse_missing_return_code_is_protocol() {
        assert!(matches!(
            parse_ccc_response(NO_RETURN_CODE),
            Err(VpnError::Protocol(_))
        ));
    }

    #[test]
    fn parse_malformed_is_protocol() {
        for bad in ["(CCCserverResponse", "garbage", ""] {
            assert!(
                matches!(parse_ccc_response(bad), Err(VpnError::Protocol(_))),
                "expected Protocol for {bad:?}"
            );
        }
    }
}
