//! FortiGate SSL VPN username/password authentication (FG-AUTH-01).
//!
//! POSTs an `x-www-form-urlencoded` login to `/remote/logincheck` over TLS and
//! extracts the `SVPNCOOKIE` session cookie from the response `Set-Cookie`
//! header. The cookie is the session credential fed to the config fetch and the
//! tunnel upgrade. Source: openfortivpn `src/http.c` (RESEARCH §2).
//!
//! Security: credentials travel only over the established TLS channel and are
//! NEVER logged; form values are percent-encoded so a crafted credential cannot
//! alter the request. The `SVPNCOOKIE` is credential-equivalent and never logged.
//!
//! Scope: the single-round username/password path. If the server accepts the
//! credentials but withholds a cookie (a 2FA/OTP challenge), that is surfaced as
//! a clear `AuthFailed` — the interactive OTP round is a documented follow-up.
#![allow(dead_code)]

use crate::error::VpnError;
use crate::tunnel::{connect_tls, CertTrust};

/// Client User-Agent. MUST NOT contain the substring `SV1` — some FortiOS
/// versions answer HTTP 405 to that (openfortivpn issue #409, RESEARCH §1).
const USER_AGENT: &str = "Mozilla/5.0";

/// Largest login reply we will buffer (256 KiB). A real reply is tiny; this
/// guards a hostile/hung server that never closes.
const AUTH_RESPONSE_MAX: usize = 256 * 1024;

/// Percent-encode a form value: everything outside the unreserved set
/// (`A-Z a-z 0-9 - _ . ~`, RFC 3986) is escaped as `%XX`.
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Build the `POST /remote/logincheck` request carrying the credentials
/// (FG-AUTH-01). `Connection: close` makes the server close after the body so the
/// reader terminates on EOF. Credentials are percent-encoded; never logged.
pub fn build_login_request(host: &str, username: &str, password: &str) -> String {
    let body = format!(
        "username={}&credential={}&realm=&ajax=1",
        url_encode(username),
        url_encode(password)
    );
    format!(
        "POST /remote/logincheck HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: {USER_AGENT}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    )
}

/// Parse the login response, extracting the `SVPNCOOKIE` value on success
/// (FG-AUTH-02). The bytes are untrusted server input; checks run in order:
/// 1. A `4xx`/`5xx` status line → PERMANENT [`VpnError::AuthFailed`].
/// 2. A `Set-Cookie: SVPNCOOKIE=<value>` with a non-empty, non-sentinel value →
///    success.
/// 3. Otherwise → `AuthFailed` (a 200 without a cookie means the server wants a
///    second factor, or rejected the login — either way this single-round flow
///    cannot proceed). The cookie value is never logged.
pub fn parse_login_response(raw: &str) -> Result<String, VpnError> {
    // 1. Status line — reject any non-2xx.
    let status = raw.lines().next().unwrap_or("");
    if let Some(code) = status.split_whitespace().nth(1) {
        if code.starts_with('4') || code.starts_with('5') {
            return Err(VpnError::AuthFailed(format!(
                "server rejected credentials (HTTP {code})"
            )));
        }
    }

    // 2. Extract SVPNCOOKIE from a Set-Cookie header (case-insensitive name);
    //    take everything after `SVPNCOOKIE=` up to `;`, CR, or LF.
    for line in raw.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("set-cookie") {
            continue;
        }
        if let Some(start) = value.find("SVPNCOOKIE=") {
            let rest = &value[start + "SVPNCOOKIE=".len()..];
            let end = rest.find([';', '\r', '\n']).unwrap_or(rest.len());
            let cookie = rest[..end].trim();
            // FortiGate clears the cookie to an empty/`0` sentinel on a failed
            // login while still returning 200 — treat that as a rejection.
            if !cookie.is_empty() && cookie != "0" {
                return Ok(cookie.to_string());
            }
        }
    }

    // 3. No usable cookie: rejected credentials or a 2FA challenge.
    Err(VpnError::AuthFailed(
        "no SVPNCOOKIE in login response (wrong credentials or two-factor required)".into(),
    ))
}

/// Read one HTTP response into a String over an async stream, bounded by
/// [`AUTH_RESPONSE_MAX`]. Tolerates the server closing without a TLS
/// `close_notify` (surfaced by rustls as `UnexpectedEof`) — the buffered bytes
/// are complete.
async fn read_http_response<S>(stream: &mut S) -> Result<String, VpnError>
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
            break; // clean EOF — server closed after the body
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > AUTH_RESPONSE_MAX {
            break; // guard against unbounded server data
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Authenticate to the FortiGate gateway (FG-AUTH-01): connect over the reused
/// TLS layer, POST the login form to `/remote/logincheck`, read the bounded
/// response, and return the `SVPNCOOKIE`. I/O over a live server — its behavior
/// is covered by [`build_login_request`] + [`parse_login_response`]. Credentials
/// and the cookie are NEVER logged; the success log states the host only.
pub async fn authenticate_fortigate(
    host: &str,
    port: u16,
    trust: &CertTrust,
    username: &str,
    password: &str,
) -> Result<String, VpnError> {
    use tokio::io::AsyncWriteExt;

    let mut tls = connect_tls(host, port, trust).await?;
    let request = build_login_request(host, username, password);
    tls.write_all(request.as_bytes()).await?;
    tls.flush().await?;

    let raw = read_http_response(&mut tls).await?;
    let cookie = parse_login_response(&raw)?;
    tracing::info!(host = %host, "FortiGate authentication succeeded");
    Ok(cookie)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_request_has_form_fields() {
        let r = build_login_request("vpn.example.com", "alice", "s3cret");
        assert!(r.starts_with("POST /remote/logincheck HTTP/1.1\r\n"));
        assert!(r.contains("Host: vpn.example.com"));
        assert!(r.contains("username=alice&credential=s3cret&realm=&ajax=1"));
        assert!(r.ends_with("ajax=1"));
    }

    #[test]
    fn user_agent_never_contains_sv1() {
        let r = build_login_request("h", "u", "p");
        assert!(!r.contains("SV1"), "User-Agent must not contain SV1 (HTTP 405)");
    }

    #[test]
    fn credentials_are_percent_encoded() {
        let r = build_login_request("h", "a b", "p&w=x");
        assert!(r.contains("username=a%20b&credential=p%26w%3Dx"));
        assert!(!r.contains("p&w=x"));
    }

    #[test]
    fn parse_success_extracts_cookie() {
        let raw = "HTTP/1.1 200 OK\r\n\
                   Set-Cookie: SVPNCOOKIE=abc123def; path=/; secure; httponly\r\n\
                   Content-Type: text/html\r\n\
                   \r\n\
                   <html>ok</html>";
        assert_eq!(parse_login_response(raw).unwrap(), "abc123def");
    }

    #[test]
    fn parse_http_403_is_auth_failed() {
        let raw = "HTTP/1.1 403 Forbidden\r\n\r\n";
        assert!(matches!(
            parse_login_response(raw),
            Err(VpnError::AuthFailed(_))
        ));
    }

    #[test]
    fn parse_200_without_cookie_is_auth_failed() {
        // A 2FA challenge or a rejected login: 200 but no usable cookie.
        let raw = "HTTP/1.1 200 OK\r\n\r\nret=1,tokeninfo=,grp=";
        assert!(matches!(
            parse_login_response(raw),
            Err(VpnError::AuthFailed(_))
        ));
    }

    #[test]
    fn parse_empty_cookie_sentinel_is_auth_failed() {
        let raw = "HTTP/1.1 200 OK\r\nSet-Cookie: SVPNCOOKIE=0; path=/\r\n\r\n";
        assert!(matches!(
            parse_login_response(raw),
            Err(VpnError::AuthFailed(_))
        ));
    }
}
