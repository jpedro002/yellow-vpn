//! AnyConnect XML username/password authentication.
//!
//! Implements the two-step AnyConnect aggregate-auth flow (D-04): a
//! `type="init"` POST to fetch the auth form followed by a `type="auth-reply"`
//! POST carrying the credentials. On success the server returns a `webvpn`
//! session cookie (AUTH-02) that the CSTP CONNECT upgrade (Plan 03) consumes.
//!
//! Only the single-form user/password path is in scope; multi-step challenge /
//! 2FA / client-cert auth are deferred (D-04, Deferred Ideas).
//!
//! Security (D-06): credentials travel only over the established TLS channel and
//! are NEVER logged; user-supplied credentials are XML-escaped before embedding
//! so a crafted password cannot alter the document structure (threat T-03-04).
#![allow(dead_code)]

/// AnyConnect client User-Agent — a real string improves server compatibility.
const USER_AGENT: &str = "AnyConnect Windows 4.10.05085";

/// `type="init"` request body: fetch the auth form (D-04).
const INIT_BODY: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
    <config-auth client=\"vpn\" type=\"init\" aggregate-auth-version=\"2\">\n\
    <version who=\"vpn\">4.10.05085</version>\n\
    <device-id>win</device-id>\n\
    </config-auth>";

/// Escape the five XML metacharacters so a credential containing `&` or `<`
/// cannot break the document or inject markup (D-06, threat T-03-04).
///
/// `&` MUST be replaced first so the ampersands introduced by later replacements
/// are not themselves double-escaped.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Wrap an XML `body` in the AnyConnect HTTP POST envelope with the correct
/// `Content-Length` (byte length, not char count) and the `X-Aggregate-Auth: 1`
/// marker the server keys off (D-04).
fn http_post(host: &str, body: &str) -> String {
    format!(
        "POST / HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: {USER_AGENT}\r\n\
         X-Aggregate-Auth: 1\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {}\r\n\
         Connection: keep-alive\r\n\
         \r\n\
         {body}",
        body.len()
    )
}

/// Build the `type="init"` POST that fetches the auth form (D-04).
pub fn build_init_request(host: &str) -> String {
    http_post(host, INIT_BODY)
}

/// Build the `type="auth-reply"` POST carrying the credentials (D-04). Both
/// `username` and `password` are XML-escaped before embedding (D-06); neither is
/// ever logged.
pub fn build_auth_reply_request(host: &str, username: &str, password: &str) -> String {
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <config-auth client=\"vpn\" type=\"auth-reply\" aggregate-auth-version=\"2\">\n\
         <version who=\"vpn\">4.10.05085</version>\n\
         <device-id>win</device-id>\n\
         <auth>\n\
         <username>{}</username>\n\
         <password>{}</password>\n\
         </auth>\n\
         </config-auth>",
        xml_escape(username),
        xml_escape(password)
    );
    http_post(host, &body)
}

use crate::error::VpnError;

/// Successful auth result: the opaque `webvpn` session cookie value (AUTH-02).
#[derive(Debug, Clone)]
pub struct AuthOutcome {
    /// The `webvpn=<value>` cookie value fed to the CSTP CONNECT upgrade.
    pub session_cookie: String,
}

/// Maximum bytes read while waiting for an HTTP auth response. Guards against a
/// hostile/hung server that never closes and never terminates its headers
/// (threat T-03-05) — do not trust the server to bound the read.
const AUTH_RESPONSE_MAX: usize = 64 * 1024;

/// Return the index just past the first `\r\n\r\n` header terminator, if present.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// Parse an AnyConnect auth response (pure), extracting the `webvpn` cookie on
/// success or mapping rejection to a PERMANENT [`VpnError::AuthFailed`] (D-06).
///
/// The bytes are untrusted server input. Checks run in order:
/// 1. A `4xx` status line (e.g. HTTP 401) → `AuthFailed`.
/// 2. A `<auth id="failure">` marker in the body → `AuthFailed`.
/// 3. A `Set-Cookie:` header carrying a non-empty `webvpn=` value → success.
/// 4. Otherwise `AuthFailed` (no session cookie means no proof of success —
///    threat T-03-06: require an explicit success signal before returning Ok).
///
/// The cookie value is never logged (D-06).
pub fn parse_auth_response(raw: &str) -> Result<AuthOutcome, VpnError> {
    // 1. Status line — reject any 4xx (client error / credential rejection).
    let status = raw.lines().next().unwrap_or("");
    if let Some(code) = status.split_whitespace().nth(1)
        && code.starts_with('4')
    {
        return Err(VpnError::AuthFailed(format!(
            "server rejected credentials (HTTP {code})"
        )));
    }

    // 2. Explicit failure marker in the body.
    if raw.contains("<auth id=\"failure\"") {
        return Err(VpnError::AuthFailed(
            "authentication rejected by server".into(),
        ));
    }

    // 3. Extract the webvpn cookie from a Set-Cookie header (case-insensitive
    //    header name); take everything after `webvpn=` up to `;`, CR, or LF.
    for line in raw.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("set-cookie") {
            continue;
        }
        if let Some(start) = value.find("webvpn=") {
            let rest = &value[start + "webvpn=".len()..];
            let end = rest
                .find([';', '\r', '\n'])
                .unwrap_or(rest.len());
            let cookie = rest[..end].trim();
            if !cookie.is_empty() {
                return Ok(AuthOutcome {
                    session_cookie: cookie.to_string(),
                });
            }
        }
    }

    // 4. No success signal.
    Err(VpnError::AuthFailed(
        "no webvpn session cookie in auth response".into(),
    ))
}

/// Read one HTTP response into a String over an async stream. The read is
/// bounded: it stops once the `\r\n\r\n` header terminator is seen or the
/// [`AUTH_RESPONSE_MAX`] guard trips (threat T-03-05) — the short AnyConnect
/// auth responses fit comfortably and we never depend on the server to close.
async fn read_http_response<S>(stream: &mut S) -> Result<String, VpnError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = [0u8; 2048];
    loop {
        let n = stream.read(&mut chunk).await?; // Io -> transient
        if n == 0 {
            break; // connection closed by peer
        }
        buf.extend_from_slice(&chunk[..n]);
        if find_header_end(&buf).is_some() {
            // Headers complete — the auth responses carry their marker/cookie in
            // headers + a short body; stop here rather than block on more data.
            break;
        }
        if buf.len() > AUTH_RESPONSE_MAX {
            break; // guard against unbounded server data
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Run the AnyConnect username/password exchange over an established TLS stream
/// (AUTH-01), returning the extracted `webvpn` session cookie (AUTH-02).
///
/// Generic over the stream (`S: AsyncRead + AsyncWrite + Unpin`) so Plan 03's
/// `TlsStream<TcpStream>` composes without a concrete dependency here and the
/// flow stays unit-testable. Credentials and cookie are never logged (D-06);
/// wrong credentials surface as a PERMANENT [`VpnError::AuthFailed`].
pub async fn authenticate<S>(
    stream: &mut S,
    host: &str,
    username: &str,
    password: &str,
) -> Result<String, VpnError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    // Step 1: init — fetch the auth form and establish the keep-alive session.
    // Parsing the form detail is out of scope (single-form path, D-04).
    stream
        .write_all(build_init_request(host).as_bytes())
        .await?;
    stream.flush().await?;
    let _init_raw = read_http_response(stream).await?;

    // Step 2: auth-reply — submit the credentials.
    stream
        .write_all(build_auth_reply_request(host, username, password).as_bytes())
        .await?;
    stream.flush().await?;
    let reply_raw = read_http_response(stream).await?;

    let outcome = parse_auth_response(&reply_raw)?;
    tracing::info!("authenticated with VPN server");
    Ok(outcome.session_cookie)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_request_has_required_headers() {
        let r = build_init_request("vpn.example.com");
        assert!(r.starts_with("POST / HTTP/1.1\r\n"));
        assert!(r.contains("Host: vpn.example.com"));
        assert!(r.contains("X-Aggregate-Auth: 1"));
        assert!(r.contains("type=\"init\""));
    }

    #[test]
    fn auth_reply_carries_credentials() {
        let r = build_auth_reply_request("h", "alice", "s3cret");
        assert!(r.contains("type=\"auth-reply\""));
        assert!(r.contains("<username>alice</username>"));
        assert!(r.contains("<password>s3cret</password>"));
        assert!(r.contains("<auth>"));
    }

    #[test]
    fn credentials_are_xml_escaped() {
        let r = build_auth_reply_request("h", "a&b", "p<w>\"x'");
        assert!(r.contains("<username>a&amp;b</username>"));
        assert!(r.contains("p&lt;w&gt;&quot;x&apos;"));
        assert!(!r.contains("<username>a&b</username>"));
    }

    #[test]
    fn parse_success_extracts_cookie() {
        let raw = "HTTP/1.1 200 OK\r\n\
                   Set-Cookie: webvpn=ABC123DEF; path=/; secure\r\n\
                   Content-Type: text/xml\r\n\
                   \r\n\
                   <?xml version=\"1.0\"?><config-auth><auth id=\"success\"></auth></config-auth>";
        let out = parse_auth_response(raw).unwrap();
        assert_eq!(out.session_cookie, "ABC123DEF");
    }

    #[test]
    fn parse_http_401_is_auth_failed() {
        let raw = "HTTP/1.1 401 Unauthorized\r\n\r\n";
        assert!(matches!(parse_auth_response(raw), Err(VpnError::AuthFailed(_))));
    }

    #[test]
    fn parse_failure_body_is_auth_failed() {
        let raw = "HTTP/1.1 200 OK\r\n\r\n<config-auth><auth id=\"failure\"/></config-auth>";
        assert!(matches!(parse_auth_response(raw), Err(VpnError::AuthFailed(_))));
    }
}
