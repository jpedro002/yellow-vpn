//! Top-level client lifecycle (LIFE-03): the automatic exponential-backoff reconnect loop.
//!
//! `run_client` wraps the single-connection `connect()` so a transient failure triggers a
//! jittered backoff sleep then a fresh full connect, a permanent error exits immediately, and a
//! user shutdown (Ctrl+C / SIGTERM) is terminal. The backoff math is factored into the pure,
//! unit-testable helpers below (base 1s, x2, cap 60s, +/-25% jitter — D-04/D-05); jitter derives
//! from wall-clock sub-nanos so no `rand` crate is needed (deps are LOCKED).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::BytesMut;

use crate::checkpoint::{auth as cp_auth, session as cp_session};
use crate::config::{Config, Protocol};
use crate::error::VpnError;
use crate::fortigate::{
    auth as fg_auth, config as fg_config, http as fg_http, session as fg_session,
};
use crate::framer::{CstpTunnelFramer, FortinetPppFramer, SlimTunnelFramer, TunnelFramer};
use crate::{auth, forward, routing, signal, tun_device, tunnel};

// Android only: a factory the engine calls AFTER the handshake (once the
// server-assigned address/DNS are known in `SessionParams`) to build the
// VpnService tunnel on the Kotlin side and return its fd. This ordering matches
// desktop (`open_tun` runs post-handshake with the assigned address) — creating
// the tun earlier with a guessed address breaks return routing.
#[cfg(target_os = "android")]
pub type AndroidTunFactory =
    Box<dyn Fn(&tunnel::SessionParams) -> Result<std::os::fd::RawFd, VpnError> + Send>;

#[cfg(target_os = "android")]
tokio::task_local! {
    static ANDROID_TUN_FACTORY: AndroidTunFactory;
}

/// State transitions surfaced to an out-of-process supervisor (the GUI helper).
#[derive(Debug, Clone)]
pub enum ClientEvent {
    Connecting,
    Established,
    Reconnecting { delay_secs: f64 },
    Disconnected,
    PermanentError(String),
    /// The gateway wants a new password before it will log the user in. Terminal
    /// like `PermanentError`, but the UI can answer it and reconnect.
    PasswordExpired(String),
    /// The gateway accepted the replacement password. Emitted as soon as the
    /// rotation succeeds — before the tunnel is up — so the UI can persist it even
    /// if a later step fails.
    PasswordChanged,
}

const BASE_DELAY_MS: u64 = 1_000; // base 1s (D-04)
const MAX_DELAY_MS: u64 = 60_000; // cap 60s (D-04)

/// How long a session must survive to count as SUSTAINED, i.e. worth resetting the
/// backoff schedule for.
///
/// "Reached the forwarding loop" is not the same as "worked". A gateway that
/// accepts the handshake and then tears the tunnel down a second later would,
/// without this floor, reset `attempt` to 0 on every cycle — an endless ~1s
/// retry loop that hammers the gateway and never backs off. A session shorter
/// than this keeps the escalating schedule.
const MIN_SUSTAINED_SESSION: Duration = Duration::from_secs(30);

/// Deterministic (un-jittered) backoff: BASE * 2^attempt, capped at MAX. Saturating so an
/// unbounded reconnect loop never overflows/panics (D-04, unlimited attempts).
fn backoff_base_ms(attempt: u32) -> u64 {
    let factor = 2u64.saturating_pow(attempt);
    BASE_DELAY_MS.saturating_mul(factor).min(MAX_DELAY_MS)
}

/// A cheap pseudo-random fraction in [0.75, 1.25] for +/-25% jitter, WITHOUT a `rand` crate
/// (D-05). Entropy source: the sub-nanosecond field of the wall clock. Exactness is NOT
/// security-critical — jitter only spreads reconnect timing to avoid a thundering herd.
fn jitter_fraction() -> f64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let unit = nanos as f64 / 1_000_000_000.0; // [0.0, 1.0)
    0.75 + unit * 0.5 // [0.75, 1.25)
}

/// Exponential backoff delay for a given transient-failure attempt (0-based): the capped
/// doubling base with +/-25% jitter applied. PURE-ish (jitter reads the clock) — the runnable
/// proof of ROADMAP criterion 4 (bounds asserted in tests, not exact values).
fn backoff_delay(attempt: u32) -> Duration {
    let base = backoff_base_ms(attempt) as f64;
    Duration::from_millis((base * jitter_fraction()) as u64)
}

/// Determine certificate trust: pinning (--servercert) > --insecure > Mozilla roots.
fn cert_trust(config: &Config) -> tunnel::CertTrust {
    if let Some(pin) = config.cert_sha256 {
        tunnel::CertTrust::Pinned(pin)
    } else if config.insecure {
        tracing::warn!(
            "TLS certificate verification DISABLED (--insecure) — connection is vulnerable to MITM"
        );
        tunnel::CertTrust::Insecure
    } else {
        tunnel::CertTrust::Webpki
    }
}

/// One full connection attempt, dispatched by protocol (CP-INT-01). Both paths converge on
/// the shared TUN/routing/forwarding pipeline; only the protocol layer (auth + session +
/// framer) differs. `established` is set to true the instant the tunnel reaches the forwarding
/// loop, so run_client can reset the backoff counter when a long-lived session later drops.
///
/// `password` and `new_password` are `&mut` because a Check Point password rotation changes
/// which password later reconnects must use: once the gateway accepted `new_password`, the old
/// one is dead and `password` is overwritten with it.
async fn connect(
    config: &Config,
    password: &mut String,
    new_password: &mut Option<String>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    established: &mut bool,
    events: &tokio::sync::mpsc::Sender<ClientEvent>,
) -> Result<(), VpnError> {
    match config.protocol {
        Protocol::AnyConnect => {
            connect_anyconnect(config, password, shutdown_rx, established, events).await
        }
        Protocol::Checkpoint => {
            connect_checkpoint(config, password, new_password, shutdown_rx, established, events)
                .await
        }
        Protocol::FortiGate => {
            connect_fortigate(config, password, shutdown_rx, established, events).await
        }
    }
}

/// Bring the TUN device up, install routes, and enter the protocol-agnostic forwarding loop.
/// Shared by both protocol paths — `stream` is the live data-tunnel TLS stream, `params` the
/// session config, `framer` the wire codec. Sets `*established = true` before forwarding.
async fn run_pipeline(
    stream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    params: &tunnel::SessionParams,
    routes: &[(std::net::Ipv4Addr, u8)],
    framer: Box<dyn TunnelFramer>,
    prime: BytesMut,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    established: &mut bool,
    events: &tokio::sync::mpsc::Sender<ClientEvent>,
) -> Result<(), VpnError> {
    #[cfg(not(target_os = "android"))]
    let (tun, routing) = {
        let tun = tun_device::open_tun(params).await?;
        tracing::info!(interface = %tun.name(), "TUN interface ready");

        let ifindex = tun.if_index()?;
        let routing = routing::RoutingGuard::install_routes(ifindex, routes).await?;
        tracing::info!(ifindex, route_count = routes.len(), "VPN routes installed");
        (tun, routing)
    };
    // Android: the TUN fd is opened by the system VpnService and injected via a
    // task-local; routes/DNS/MTU are set by VpnService.Builder, so the engine
    // wraps the fd and installs no OS routes (RoutingGuard is a no-op here).
    #[cfg(target_os = "android")]
    let (tun, routing) = {
        // Now that the session address is known, ask Kotlin to establish the
        // VpnService tunnel with it and hand back the fd.
        let fd = ANDROID_TUN_FACTORY.with(|f| f(params))?;
        let tun = tun_device::open_tun_from_fd(fd, params)?;
        tracing::info!(address = %params.address, "android: VpnService TUN established");
        let routing = routing::RoutingGuard::install_routes(0, routes).await?;
        (tun, routing)
    };

    let keepalive_secs = params.keepalive.unwrap_or(30) as u64;
    tracing::info!(
        address = %params.address,
        mtu = params.mtu,
        dns_count = params.dns.len(),
        "tunnel session established — entering packet forwarding loop"
    );

    // We reached forwarding: a live tunnel exists. If it drops after this point, run_client
    // treats it as a sustained connection and resets the backoff schedule (D-04).
    *established = true;
    let _ = events.send(ClientEvent::Established).await;

    // run_forwarding OWNS stream+tun+routing and runs the LOCKED routes-before-TUN teardown on
    // EVERY exit (D-07). The injected shutdown_rx is MOVED in; its shutdown arm returns Ok(()).
    forward::run_forwarding(
        stream,
        tun,
        routing,
        framer,
        params.mtu,
        keepalive_secs,
        prime,
        shutdown_rx,
    )
    .await
}

/// v0.1 path: TLS -> AnyConnect auth -> CSTP CONNECT -> shared pipeline (CSTP framer).
async fn connect_anyconnect(
    config: &Config,
    password: &str,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    established: &mut bool,
    events: &tokio::sync::mpsc::Sender<ClientEvent>,
) -> Result<(), VpnError> {
    tracing::info!(host = %config.host, port = config.port, "connecting (AnyConnect)");
    let trust = cert_trust(config);
    let mut stream = tunnel::connect_tls(&config.host, config.port, &trust).await?;
    let cookie = auth::authenticate(&mut stream, &config.host, &config.username, password).await?;
    let params = tunnel::cstp_connect(&mut stream, &config.host, &cookie).await?;
    run_pipeline(
        stream,
        &params,
        &routing::vpn_routes(), // v0.1 hardcoded split-tunnel ranges
        Box::new(CstpTunnelFramer),
        BytesMut::new(),
        shutdown_rx,
        established,
        events,
    )
    .await
}

/// v0.2 path: CCC UserPass auth -> separate SLIM data socket -> client_hello/hello_reply ->
/// shared pipeline (SLIM framer). The auth and data-tunnel sockets are independent, linked only
/// by the deobfuscated active_key carried as the client_hello cookie (RESEARCH §1).
async fn connect_checkpoint(
    config: &Config,
    password: &mut String,
    new_password: &mut Option<String>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    established: &mut bool,
    events: &tokio::sync::mpsc::Sender<ClientEvent>,
) -> Result<(), VpnError> {
    tracing::info!(host = %config.host, port = config.port, "connecting (Check Point SNX)");
    let trust = cert_trust(config);

    // 1. CCC UserPass auth over its own HTTPS socket -> session (session_id, active_key, tcpt_port).
    //    If the password is expired and a replacement was supplied, this also rotates it.
    let (ccc, changed) = cp_auth::authenticate_checkpoint_with_change(
        &config.host,
        config.port,
        &trust,
        &config.username,
        password,
        new_password.as_deref(),
    )
    .await?;
    if changed {
        // The old password no longer works; every reconnect must use the new one.
        if let Some(np) = new_password.take() {
            *password = np;
        }
        tracing::info!("Check Point password rotated");
        let _ = events.send(ClientEvent::PasswordChanged).await;
    }
    let cookie = ccc.active_key_deobfuscated()?;
    let session_id = ccc.session_id.clone();

    // Everything past a successful auth runs inside this block so its result can be
    // captured and the CCC session released on EVERY exit path — see the signout below.
    let result = connect_checkpoint_tunnel(
        config, &trust, &cookie, ccc.tcpt_port, shutdown_rx, established, events,
    )
    .await;

    // Release the session server-side. The gateway otherwise holds it, AND the Office
    // Mode address it allocated, until active_key_timeout (9 h on the reference gateway):
    // a reconnect loop would leak one address per attempt and drain the pool. Best-effort
    // and deliberately not `?` — failing to sign out must not mask the real error, and the
    // session does expire on its own.
    if session_id.is_empty() {
        tracing::warn!("no CCC session_id — cannot sign out; the gateway will hold this session");
    } else if let Err(e) =
        cp_auth::signout_checkpoint(&config.host, config.port, &trust, &session_id).await
    {
        tracing::warn!(
            error = %e,
            "CCC signout failed — the gateway will hold this session until active_key_timeout"
        );
    }
    result
}

/// The post-auth half of the Check Point path, split out so `connect_checkpoint` can
/// sign the CCC session out on every exit path (including the error ones).
#[allow(clippy::too_many_arguments)]
async fn connect_checkpoint_tunnel(
    config: &Config,
    trust: &tunnel::CertTrust,
    cookie: &str,
    tcpt_port: u16,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    established: &mut bool,
    events: &tokio::sync::mpsc::Sender<ClientEvent>,
) -> Result<(), VpnError> {
    // 2. Open the SEPARATE data-tunnel TLS socket to tcpt_port and run the SLIM session.
    let mut stream = tunnel::connect_tls(&config.host, tcpt_port, trust).await?;
    let session =
        cp_session::establish_session(&mut stream, cookie, cp_session::HelloOpts::default())
            .await?;
    tracing::info!(
        address = %session.address,
        prefix = session.prefix,
        dns_count = session.dns.len(),
        route_count = session.routes.len(),
        "Check Point SLIM session established"
    );

    // 3. Shared pipeline with the SLIM framer. Routes come from the authenticated hello_reply
    //    Office-Mode range (split-tunnel; full-tunnel sentinel already stripped). If the gateway
    //    sent no range, fall back to the v0.1 private ranges so the tunnel is still useful.
    let params = session.to_session_params();
    let routes = if session.routes.is_empty() {
        tracing::warn!("hello_reply carried no routes — falling back to default private ranges");
        routing::vpn_routes()
    } else {
        session.routes.clone()
    };
    run_pipeline(
        stream,
        &params,
        &routes,
        Box::new(SlimTunnelFramer),
        BytesMut::new(),
        shutdown_rx,
        established,
        events,
    )
    .await
}

/// v0.3 path: FortiGate SSL VPN. HTTPS login (with the host-check round) ->
/// `SVPNCOOKIE` -> config XML -> a SEPARATE TLS socket for
/// `GET /remote/sslvpn-tunnel` -> LCP/IPCP -> shared pipeline (PPP-in-`0x5050`
/// framer). The HTTP steps share one keep-alive connection; the tunnel needs its
/// own socket because the upgrade hijacks it.
async fn connect_fortigate(
    config: &Config,
    password: &str,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    established: &mut bool,
    events: &tokio::sync::mpsc::Sender<ClientEvent>,
) -> Result<(), VpnError> {
    tracing::info!(host = %config.host, port = config.port, "connecting (FortiGate SSL VPN)");
    let trust = cert_trust(config);

    // 1+2. Login and config fetch share one HTTP session: five requests over one
    //      TLS connection instead of five handshakes.
    let mut http = fg_http::HttpSession::new(&config.host, config.port, &trust);
    let cookie =
        fg_auth::authenticate_on(&mut http, &config.username, password, &config.realm).await?;
    let cfg = fg_config::fetch_config_on(&mut http, &cookie).await?;
    drop(http);

    // 3. Open the packet tunnel on a fresh socket and bring PPP up. `ppp` carries
    //    the IPCP-assigned address, the DNS servers, the agreed MRU, and the LCP
    //    magic number the framer needs for Echo frames.
    let (stream, ppp, prime) =
        fg_session::open_tunnel(&config.host, config.port, &trust, &cookie).await?;

    // 4. Shared pipeline. An empty split-tunnel list means the gateway wants a
    //    full tunnel; we have no default-route support yet, so fall back to the
    //    default private ranges (same policy as Check Point) and say so loudly.
    let params = cfg.to_session_params(Some(&ppp));
    let routes = if cfg.routes.is_empty() {
        tracing::warn!(
            "FortiGate pushed no split routes (full tunnel requested) — falling back to the \
             default private ranges; traffic outside them will NOT use the VPN"
        );
        routing::vpn_routes()
    } else {
        cfg.routes.clone()
    };
    if !cfg.exclude_routes.is_empty() {
        // Parsed and reported rather than silently folded into `routes`, which
        // would hijack traffic the gateway explicitly wants kept off the tunnel.
        tracing::warn!(
            count = cfg.exclude_routes.len(),
            "gateway pushed split-tunnel EXCLUDE routes; exclusion is not implemented yet"
        );
    }
    run_pipeline(
        stream,
        &params,
        &routes,
        Box::new(FortinetPppFramer::new(ppp.magic)),
        prime,
        shutdown_rx,
        established,
        events,
    )
    .await
}

/// The v0.1 top-level client lifecycle (LIFE-03): repeatedly attempt a full connection,
/// auto-reconnecting with exponential backoff after any TRANSIENT failure. Owns the shutdown
/// watch channel + the OS-signal task (hoisted out of connect, D-01). Terminal on user shutdown
/// (Ok) and on any permanent error (D-03).
pub async fn run_client(config: &Config, password: &str) -> Result<(), VpnError> {
    // Hoisted from connect(): one watch channel + one signal task for the whole process life.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        signal::wait_for_shutdown().await;
        tracing::info!("Shutdown signal received");
        let _ = shutdown_tx.send(true); // receivers may be gone — ignore send error
    });

    // CLI path discards events.
    let (etx, mut erx) = tokio::sync::mpsc::channel::<ClientEvent>(16);
    tokio::spawn(async move { while erx.recv().await.is_some() {} });
    run_client_supervised(config, password, shutdown_rx, etx).await
}

/// Reconnect loop driven by an EXTERNAL shutdown channel, emitting state events.
/// Same control flow as the old run_client body minus the internal signal task.
pub async fn run_client_supervised(
    config: &Config,
    password: &str,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    events: tokio::sync::mpsc::Sender<ClientEvent>,
) -> Result<(), VpnError> {
    let mut attempt: u32 = 0;
    // Owned copies: a Check Point password rotation replaces them mid-run so a later
    // reconnect logs in with the password that is actually valid now.
    let mut password = password.to_owned();
    let mut new_password = config.new_password.clone();
    loop {
        // Honor an already-set shutdown before doing any network work.
        if *shutdown_rx.borrow() {
            let _ = events.send(ClientEvent::Disconnected).await;
            return Ok(());
        }
        let mut established = false;
        let _ = events.send(ClientEvent::Connecting).await;
        let started = std::time::Instant::now();
        match connect(
            config,
            &mut password,
            &mut new_password,
            shutdown_rx.clone(),
            &mut established,
            &events,
        )
        .await
        {
            // Clean user shutdown -> terminal, do NOT reconnect (Phase 7 contract, criterion 1).
            Ok(()) => {
                let _ = events.send(ClientEvent::Disconnected).await;
                return Ok(());
            }

            // Permanent error (auth/config/privilege/tun-unavailable) -> terminal, exit non-zero
            // (criterion 3). No backoff, no retry.
            Err(e) if e.is_permanent() => {
                tracing::error!(error = %e, "permanent error — not reconnecting");
                let event = match &e {
                    VpnError::PasswordExpired { prompt } => {
                        ClientEvent::PasswordExpired(prompt.clone())
                    }
                    _ => ClientEvent::PermanentError(e.to_string()),
                };
                let _ = events.send(event).await;
                return Err(e);
            }

            // Transient failure -> teardown already ran inside run_forwarding / RAII (D-07);
            // log, then backoff (unless shutdown fired), then retry (criterion 1, 4).
            Err(e) => {
                // A SUSTAINED session that dropped resets the schedule so the first retry is
                // fast (D-04). A session that died almost immediately does not: see
                // MIN_SUSTAINED_SESSION.
                let lasted = started.elapsed();
                if established && lasted >= MIN_SUSTAINED_SESSION {
                    attempt = 0;
                } else if established {
                    tracing::warn!(
                        lasted_secs = lasted.as_secs_f64(),
                        "tunnel came up but dropped almost immediately — keeping the backoff \
                         schedule instead of retrying tightly"
                    );
                }
                tracing::warn!(error = %e, "connection dropped — will reconnect");
                tracing::debug!("previous attempt torn down (routes removed before TUN) — TUN-03");

                // If shutdown already fired (e.g. concurrently with the drop), exit now (D-06).
                if *shutdown_rx.borrow() {
                    let _ = events.send(ClientEvent::Disconnected).await;
                    return Ok(());
                }

                let delay = backoff_delay(attempt);
                tracing::info!(
                    attempt = attempt + 1,
                    delay_secs = delay.as_secs_f64(),
                    "reconnecting after backoff"
                );
                let _ = events
                    .send(ClientEvent::Reconnecting { delay_secs: delay.as_secs_f64() })
                    .await;

                // Shutdown-interruptible backoff (D-06): sleep OR shutdown, whichever first.
                // Shadow with a scoped clone so the literal `shutdown_rx.changed()` drives the arm.
                let mut shutdown_rx = shutdown_rx.clone();
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    _ = shutdown_rx.changed() => {
                        tracing::info!("shutdown during backoff — aborting reconnect");
                        let _ = events.send(ClientEvent::Disconnected).await;
                        return Ok(());
                    }
                }

                attempt = attempt.saturating_add(1);
            }
        }
    }
}

/// Android entry: same reconnect/supervision loop as [`run_client_supervised`],
/// but the TUN fd (opened by the system `VpnService`) is injected via a
/// task-local that `run_pipeline` reads instead of opening `/dev/net/tun`.
#[cfg(target_os = "android")]
pub async fn run_client_supervised_android(
    config: &Config,
    password: &str,
    tun_factory: AndroidTunFactory,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    events: tokio::sync::mpsc::Sender<ClientEvent>,
) -> Result<(), VpnError> {
    ANDROID_TUN_FACTORY
        .scope(
            tun_factory,
            run_client_supervised(config, password, shutdown_rx, events),
        )
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_doubles_and_caps() {
        assert_eq!(backoff_base_ms(0), 1_000);
        assert_eq!(backoff_base_ms(1), 2_000);
        assert_eq!(backoff_base_ms(2), 4_000);
        assert_eq!(backoff_base_ms(3), 8_000);
        assert_eq!(backoff_base_ms(20), 60_000); // capped
        assert_eq!(backoff_base_ms(u32::MAX), 60_000); // no overflow panic
    }

    #[test]
    fn jitter_fraction_stays_in_range() {
        for _ in 0..1000 {
            let f = jitter_fraction();
            assert!((0.75..=1.25).contains(&f), "jitter {f} out of range");
        }
    }

    #[test]
    fn attempt_zero_within_quarter_of_one_second() {
        for _ in 0..1000 {
            let d = backoff_delay(0).as_millis();
            assert!((750..=1250).contains(&d), "delay {d}ms out of [750,1250]");
        }
    }

    #[test]
    fn capped_tail_stays_within_jitter_of_max() {
        for _ in 0..1000 {
            let d = backoff_delay(30).as_millis();
            assert!(
                (45_000..=75_000).contains(&d),
                "capped delay {d}ms out of [45000,75000]"
            );
        }
    }

    #[tokio::test]
    async fn supervised_honors_preset_shutdown() {
        use crate::config::{Config, Protocol};
        let cfg = Config {
            host: "127.0.0.1".into(),
            port: 1, // nothing listening
            username: "u".into(),
            password: Some("p".into()),
            verbose: false,
            cert_sha256: None,
            insecure: true,
            protocol: Protocol::AnyConnect,
            realm: String::new(),
            new_password: None,
        };
        let (tx, rx) = tokio::sync::watch::channel(true); // already shutting down
        let _ = tx;
        let (etx, mut erx) = tokio::sync::mpsc::channel(8);
        let res = run_client_supervised(&cfg, "p", rx, etx).await;
        assert!(res.is_ok(), "preset shutdown must return Ok, got {res:?}");
        // Drain events: last must be Disconnected.
        let mut last = None;
        while let Ok(ev) = erx.try_recv() {
            last = Some(ev);
        }
        assert!(matches!(last, Some(ClientEvent::Disconnected)));
    }
}
