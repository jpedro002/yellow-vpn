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

/// Build the `MultiChallange` request that answers a gateway challenge — the
/// expired-password flow's "Enter new password" / "Retype password" rounds.
///
/// The type string is Check Point's own misspelling (no second "e"); the
/// correctly-spelled `MultiChallenge` is rejected with `return_code 502`.
/// `user_input` is obfuscated like every other secret. `session_id` is the one
/// the gateway handed back with the challenge, not a secret.
pub fn build_multichallange_request(session_id: &str, user_input: &str, id: u32) -> String {
    let header = CccValue::Node {
        name: None,
        fields: vec![
            ("id".into(), CccValue::Atom(id.to_string())),
            ("type".into(), CccValue::Atom("MultiChallange".into())),
            ("session_id".into(), CccValue::Atom(session_id.to_string())),
        ],
    };
    let data = CccValue::Node {
        name: None,
        fields: vec![
            ("client_type".into(), CccValue::Atom("TRAC".into())),
            ("auth_session_id".into(), CccValue::Atom(session_id.to_string())),
            ("user_input".into(), CccValue::Atom(cipher::encode(user_input))),
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

/// What a well-formed `return_code 600` reply actually is: a finished login, or
/// the gateway asking one more question (`auth_state (new_challenge)`).
#[derive(Debug)]
pub enum CccAuthReply {
    Session(CccSession),
    Challenge {
        session_id: String,
        /// Human-readable prompt, deobfuscated (e.g. "Enter new password").
        prompt: String,
        /// Machine id, deobfuscated (e.g. `CPSC_INTERNAL_PASSWORD_UPDATE`).
        prompt_id: String,
    },
}

/// Deobfuscate a challenge field. Falls back to the raw text so a gateway that
/// sends the prompt in the clear still yields something readable.
fn decode_challenge_text(raw: &str) -> String {
    cipher::decode(raw)
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_else(|_| raw.to_string())
}

/// True when the challenge is one of the password-change rounds (as opposed to,
/// say, an OTP prompt this client cannot answer).
fn is_password_challenge(prompt_id: &str, prompt: &str) -> bool {
    if prompt_id.is_empty() {
        return prompt.to_ascii_lowercase().contains("password");
    }
    prompt_id.to_ascii_uppercase().contains("PASSWORD")
}

/// Parse a CCC `(CCCserverResponse ...)` body into a [`CccSession`] (CP-AUTH-02).
///
/// Mapping (D-05):
/// - `return_code == 600` + a present `active_key` -> `Ok(CccSession)`.
/// - `return_code == 600` + `auth_state (new_challenge)` -> `VpnError::PasswordExpired`
///   for a password-change prompt, `AuthFailed` for any other challenge. Use
///   [`parse_auth_reply`] to answer it instead.
/// - `return_code == 600` but no `active_key` -> `VpnError::Protocol` (unusable).
/// - any well-formed non-600 -> PERMANENT `VpnError::AuthFailed` (credential/
///   authorization rejection; reconnecting cannot fix it).
/// - unparseable body / missing / non-numeric `return_code` -> transient
///   `VpnError::Protocol`.
///
/// The body, `active_key`, and `session_id` are never logged.
pub fn parse_ccc_response(body: &str) -> Result<CccSession, VpnError> {
    match parse_auth_reply(body)? {
        CccAuthReply::Session(s) => Ok(s),
        CccAuthReply::Challenge { prompt, prompt_id, .. } => {
            Err(challenge_error(&prompt_id, prompt))
        }
    }
}

fn challenge_error(prompt_id: &str, prompt: String) -> VpnError {
    if is_password_challenge(prompt_id, &prompt) {
        VpnError::PasswordExpired { prompt }
    } else {
        VpnError::AuthFailed("server requested an unsupported authentication challenge".into())
    }
}

/// Like [`parse_ccc_response`], but a `new_challenge` reply is returned to the
/// caller as [`CccAuthReply::Challenge`] so it can be answered.
pub fn parse_auth_reply(body: &str) -> Result<CccAuthReply, VpnError> {
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

    // A 600 that is not a login but a follow-up question. Challenge fields are
    // looked up in ResponseData first, then the header, because the gateway is
    // not consistent about where it puts them.
    let challenge_field = |name: &str| {
        rdata
            .and_then(|d| d.get(name))
            .or_else(|| header.and_then(|h| h.get(name)))
            .and_then(|v| v.as_atom())
    };
    if challenge_field("auth_state") == Some("new_challenge") {
        let prompt = challenge_field("prompt").map(decode_challenge_text).unwrap_or_default();
        let prompt_id =
            challenge_field("prompt_id").map(decode_challenge_text).unwrap_or_default();
        return Ok(CccAuthReply::Challenge { session_id, prompt, prompt_id });
    }

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

    Ok(CccAuthReply::Session(CccSession::new(session_id, active_key, tcpt_port)))
}

/// Build the CCC `Signout` request that releases a session server-side.
///
/// Without it the gateway holds the session — and the Office Mode address it
/// allocated — until `active_key_timeout` expires (32400 s / 9 h on the reference
/// gateway). A reconnect loop therefore leaks one session and one address per
/// attempt, which drains the Office Mode pool and makes the gateway start
/// evicting live clients. `session_id` is not a secret; `active_key` is, and is
/// deliberately NOT sent here.
pub fn build_signout_request(session_id: &str, id: u32) -> String {
    let header = CccValue::Node {
        name: None,
        fields: vec![
            ("id".into(), CccValue::Atom(id.to_string())),
            ("type".into(), CccValue::Atom("Signout".into())),
            ("session_id".into(), CccValue::Atom(session_id.to_string())),
        ],
    };
    CccValue::Node {
        name: Some("CCCclientRequest".into()),
        fields: vec![
            ("RequestHeader".into(), header),
            ("RequestData".into(), CccValue::Empty),
        ],
    }
    .to_wire()
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
    authenticate_checkpoint_with_change(host, port, trust, username, password, None)
        .await
        .map(|(session, _changed)| session)
}

/// Most `MultiChallange` rounds we will answer. The expired-password flow has
/// two (new password, retype); the cap only stops a misbehaving gateway from
/// looping us forever.
const MAX_CHALLENGE_ROUNDS: u32 = 4;

/// One HTTPS round trip to `/clients/`. Every CCC round gets its own connection
/// (`Connection: close`); state is carried by `session_id`, not the socket.
async fn ccc_exchange(
    host: &str,
    port: u16,
    trust: &CertTrust,
    body: &str,
) -> Result<String, VpnError> {
    use tokio::io::AsyncWriteExt;

    let mut tls = connect_tls(host, port, trust).await?; // reused v0.1 TLS + CertTrust
    tls.write_all(http_post_clients(host, body).as_bytes()).await?;
    tls.flush().await?;
    read_http_body(&mut tls).await
}

/// What to do with one parsed reply — split out of the I/O loop so the decision
/// table is unit-testable.
enum Step {
    Done(CccSession),
    /// Answer the challenge on this session with the new password.
    Answer { session_id: String },
}

fn plan_step(
    reply: CccAuthReply,
    has_new_password: bool,
    rounds_done: u32,
) -> Result<Step, VpnError> {
    match reply {
        CccAuthReply::Session(s) => Ok(Step::Done(s)),
        CccAuthReply::Challenge { session_id, prompt, prompt_id } => {
            if !is_password_challenge(&prompt_id, &prompt) {
                return Err(challenge_error(&prompt_id, prompt));
            }
            if !has_new_password {
                return Err(VpnError::PasswordExpired { prompt });
            }
            if rounds_done >= MAX_CHALLENGE_ROUNDS {
                return Err(VpnError::Protocol("too many password-change rounds".into()));
            }
            Ok(Step::Answer { session_id })
        }
    }
}

/// [`authenticate_checkpoint`] that can also rotate an expired password.
///
/// If the gateway answers the login with a password-change challenge and
/// `new_password` is `Some`, it is submitted for each round (new password, then
/// retype) until the gateway issues the `active_key`. With `None` the challenge
/// surfaces as [`VpnError::PasswordExpired`] so the caller can ask the user.
///
/// Returns the session and whether the password was actually changed — the
/// caller must use `new_password` for every later login when it was.
/// Neither password is ever logged.
pub async fn authenticate_checkpoint_with_change(
    host: &str,
    port: u16,
    trust: &CertTrust,
    username: &str,
    password: &str,
    new_password: Option<&str>,
) -> Result<(CccSession, bool), VpnError> {
    let body = ccc_exchange(host, port, trust, &build_userpass_request(username, password, 1))
        .await?;
    let mut reply = parse_auth_reply(&body)?;
    let mut rounds: u32 = 0;

    loop {
        let pending_session = match &reply {
            CccAuthReply::Challenge { session_id, .. } if !session_id.is_empty() => {
                Some(session_id.clone())
            }
            _ => None,
        };
        let step = match plan_step(reply, new_password.is_some(), rounds) {
            Ok(step) => step,
            Err(e) => {
                // The challenge opened a half-authenticated session on the gateway;
                // release it rather than leave it to time out. Best-effort.
                if let Some(sid) = pending_session {
                    if let Err(se) = signout_checkpoint(host, port, trust, &sid).await {
                        tracing::debug!(error = %se, "signout of pending challenge session failed");
                    }
                }
                return Err(e);
            }
        };
        match step {
            Step::Done(session) => {
                tracing::info!(host = %host, changed = rounds > 0, "Check Point CCC authentication succeeded");
                return Ok((session, rounds > 0));
            }
            Step::Answer { session_id } => {
                rounds += 1;
                let request = build_multichallange_request(
                    &session_id,
                    new_password.unwrap_or_default(),
                    rounds + 1,
                );
                let body = ccc_exchange(host, port, trust, &request).await?;
                reply = parse_auth_reply(&body).map_err(|e| match e {
                    VpnError::AuthFailed(m) => {
                        VpnError::AuthFailed(format!("password change rejected: {m}"))
                    }
                    other => other,
                })?;
            }
        }
    }
}

/// Release the CCC session on the gateway (best-effort counterpart to
/// [`authenticate_checkpoint`]).
///
/// Opens its own short-lived HTTPS connection — the auth socket is long gone by
/// the time a tunnel ends. The gateway answers `Signout` with `return_code 699`,
/// NOT the 600 that [`parse_ccc_response`] expects, so the reply is only checked
/// for well-formedness and logged; the caller treats any failure as non-fatal
/// because the session expires on its own eventually.
pub async fn signout_checkpoint(
    host: &str,
    port: u16,
    trust: &CertTrust,
    session_id: &str,
) -> Result<(), VpnError> {
    use tokio::io::AsyncWriteExt;

    let mut tls = connect_tls(host, port, trust).await?;
    let request = http_post_clients(host, &build_signout_request(session_id, 2));
    tls.write_all(request.as_bytes()).await?;
    tls.flush().await?;

    let body = read_http_body(&mut tls).await?;
    let doc = ccc::parse(&body)?;
    if doc.name() != Some("CCCserverResponse") {
        return Err(VpnError::Protocol("signout: not a CCCserverResponse".into()));
    }
    let rc = doc
        .get("ResponseHeader")
        .and_then(|h| h.get("return_code"))
        .and_then(|v| v.as_atom())
        .unwrap_or("?");
    tracing::info!(host = %host, return_code = %rc, "Check Point CCC session signed out");
    Ok(())
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
    fn signout_request_carries_session_id_and_no_credentials() {
        let req = build_signout_request("SESS123", 2);
        assert!(req.contains(":type (Signout)"), "req: {req}");
        assert!(req.contains(":session_id (SESS123)"), "req: {req}");
        assert!(req.contains(":id (2)"), "req: {req}");
        // active_key / password must never appear in a signout.
        assert!(!req.contains("active_key"), "req: {req}");
        assert!(!req.contains("password"), "req: {req}");
        let doc = ccc::parse(&req).expect("re-parses");
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

    fn challenge_body(prompt: &str, prompt_id: &str) -> String {
        format!(
            "(CCCserverResponse :ResponseHeader ( :id (1) :type (UserPass) :session_id (NEWSESS) \
             :return_code (600) ) :ResponseData ( :authn_status (continue) :auth_state (new_challenge) \
             :prompt ({}) :prompt_id ({}) ) )",
            cipher::encode(prompt),
            cipher::encode(prompt_id)
        )
    }

    #[test]
    fn multichallange_request_uses_the_misspelled_type() {
        let req = build_multichallange_request("NEWSESS", "n3wpass", 2);
        assert!(req.contains(":type (MultiChallange)"), "req: {req}");
        assert!(!req.contains("MultiChallenge"), "correct spelling is rejected by the gateway");
        assert!(req.contains(":auth_session_id (NEWSESS)"), "req: {req}");
        assert!(req.contains(":client_type (TRAC)"), "req: {req}");
        assert!(req.contains(&format!(":user_input ({})", cipher::encode("n3wpass"))));
        assert!(!req.contains("n3wpass"), "plaintext new password leaked");
        assert_eq!(ccc::parse(&req).unwrap().name(), Some("CCCclientRequest"));
    }

    #[test]
    fn parse_auth_reply_returns_the_challenge() {
        let body = challenge_body("Enter new password", "CPSC_INTERNAL_PASSWORD_UPDATE");
        match parse_auth_reply(&body).unwrap() {
            CccAuthReply::Challenge { session_id, prompt, prompt_id } => {
                assert_eq!(session_id, "NEWSESS");
                assert_eq!(prompt, "Enter new password");
                assert_eq!(prompt_id, "CPSC_INTERNAL_PASSWORD_UPDATE");
            }
            other => panic!("expected a challenge, got {other:?}"),
        }
    }

    #[test]
    fn parse_auth_reply_still_returns_a_session() {
        assert!(matches!(parse_auth_reply(SUCCESS).unwrap(), CccAuthReply::Session(_)));
    }

    #[test]
    fn parse_ccc_response_maps_password_challenge_to_expired() {
        let body = challenge_body("Enter new password", "CPSC_INTERNAL_PASSWORD_UPDATE");
        match parse_ccc_response(&body).unwrap_err() {
            VpnError::PasswordExpired { prompt } => assert_eq!(prompt, "Enter new password"),
            other => panic!("expected PasswordExpired, got {other:?}"),
        }
    }

    #[test]
    fn parse_ccc_response_rejects_non_password_challenge() {
        let body = challenge_body("Enter the code", "CPSC_INTERNAL_OTP");
        assert!(matches!(parse_ccc_response(&body), Err(VpnError::AuthFailed(_))));
    }

    fn challenge(prompt_id: &str) -> CccAuthReply {
        CccAuthReply::Challenge {
            session_id: "S".into(),
            prompt: "Enter new password".into(),
            prompt_id: prompt_id.into(),
        }
    }

    #[test]
    fn plan_without_new_password_reports_expiry() {
        let r = plan_step(challenge("CPSC_INTERNAL_PASSWORD_UPDATE"), false, 0);
        assert!(matches!(r, Err(VpnError::PasswordExpired { .. })));
    }

    #[test]
    fn plan_answers_both_password_rounds() {
        for id in ["CPSC_INTERNAL_PASSWORD_UPDATE", "CPSC_INTERNAL_RETYPE_PASSWORD"] {
            assert!(matches!(
                plan_step(challenge(id), true, 0),
                Ok(Step::Answer { .. })
            ));
        }
    }

    #[test]
    fn plan_stops_after_max_rounds() {
        let r = plan_step(challenge("CPSC_INTERNAL_PASSWORD_UPDATE"), true, MAX_CHALLENGE_ROUNDS);
        assert!(matches!(r, Err(VpnError::Protocol(_))));
    }

    #[test]
    fn plan_never_answers_an_unknown_challenge_with_the_password() {
        let r = plan_step(challenge("CPSC_INTERNAL_OTP"), true, 0);
        assert!(matches!(r, Err(VpnError::AuthFailed(_))));
    }

    #[test]
    fn plan_session_is_done() {
        let s = CccAuthReply::Session(CccSession::new("s".into(), "36203a333d372a59".into(), 443));
        assert!(matches!(plan_step(s, false, 2), Ok(Step::Done(_))));
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
