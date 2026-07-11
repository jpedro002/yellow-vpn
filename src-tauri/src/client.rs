//! Top-level client lifecycle (LIFE-03): the automatic exponential-backoff reconnect loop.
//!
//! `run_client` wraps the single-connection `connect()` so a transient failure triggers a
//! jittered backoff sleep then a fresh full connect, a permanent error exits immediately, and a
//! user shutdown (Ctrl+C / SIGTERM) is terminal. The backoff math is factored into the pure,
//! unit-testable helpers below (base 1s, x2, cap 60s, +/-25% jitter — D-04/D-05); jitter derives
//! from wall-clock sub-nanos so no `rand` crate is needed (deps are LOCKED).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::checkpoint::{auth as cp_auth, session as cp_session};
use crate::config::{Config, Protocol};
use crate::error::VpnError;
use crate::framer::{CstpTunnelFramer, SlimTunnelFramer, TunnelFramer};
use crate::{auth, forward, routing, signal, tun_device, tunnel};

const BASE_DELAY_MS: u64 = 1_000; // base 1s (D-04)
const MAX_DELAY_MS: u64 = 60_000; // cap 60s (D-04)

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
async fn connect(
    config: &Config,
    password: &str,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    established: &mut bool,
) -> Result<(), VpnError> {
    match config.protocol {
        Protocol::AnyConnect => connect_anyconnect(config, password, shutdown_rx, established).await,
        Protocol::Checkpoint => connect_checkpoint(config, password, shutdown_rx, established).await,
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
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    established: &mut bool,
) -> Result<(), VpnError> {
    let tun = tun_device::open_tun(params).await?;
    tracing::info!(interface = %tun.name(), "TUN interface ready");

    let ifindex = tun.if_index()?;
    let routing = routing::RoutingGuard::install_routes(ifindex, routes).await?;
    tracing::info!(ifindex, route_count = routes.len(), "VPN routes installed");

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

    // run_forwarding OWNS stream+tun+routing and runs the LOCKED routes-before-TUN teardown on
    // EVERY exit (D-07). The injected shutdown_rx is MOVED in; its shutdown arm returns Ok(()).
    forward::run_forwarding(stream, tun, routing, framer, params.mtu, keepalive_secs, shutdown_rx)
        .await
}

/// v0.1 path: TLS -> AnyConnect auth -> CSTP CONNECT -> shared pipeline (CSTP framer).
async fn connect_anyconnect(
    config: &Config,
    password: &str,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    established: &mut bool,
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
        shutdown_rx,
        established,
    )
    .await
}

/// v0.2 path: CCC UserPass auth -> separate SLIM data socket -> client_hello/hello_reply ->
/// shared pipeline (SLIM framer). The auth and data-tunnel sockets are independent, linked only
/// by the deobfuscated active_key carried as the client_hello cookie (RESEARCH §1).
async fn connect_checkpoint(
    config: &Config,
    password: &str,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    established: &mut bool,
) -> Result<(), VpnError> {
    tracing::info!(host = %config.host, port = config.port, "connecting (Check Point SNX)");
    let trust = cert_trust(config);

    // 1. CCC UserPass auth over its own HTTPS socket -> session (session_id, active_key, tcpt_port).
    let ccc = cp_auth::authenticate_checkpoint(
        &config.host,
        config.port,
        &trust,
        &config.username,
        password,
    )
    .await?;
    let cookie = ccc.active_key_deobfuscated()?;

    // 2. Open the SEPARATE data-tunnel TLS socket to tcpt_port and run the SLIM session.
    let mut stream = tunnel::connect_tls(&config.host, ccc.tcpt_port, &trust).await?;
    let session =
        cp_session::establish_session(&mut stream, &cookie, cp_session::HelloOpts::default())
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
        shutdown_rx,
        established,
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

    let mut attempt: u32 = 0;
    loop {
        let mut established = false;
        match connect(config, password, shutdown_rx.clone(), &mut established).await {
            // Clean user shutdown -> terminal, do NOT reconnect (Phase 7 contract, criterion 1).
            Ok(()) => return Ok(()),

            // Permanent error (auth/config/privilege/tun-unavailable) -> terminal, exit non-zero
            // (criterion 3). No backoff, no retry.
            Err(e) if e.is_permanent() => {
                tracing::error!(error = %e, "permanent error — not reconnecting");
                return Err(e);
            }

            // Transient failure -> teardown already ran inside run_forwarding / RAII (D-07);
            // log, then backoff (unless shutdown fired), then retry (criterion 1, 4).
            Err(e) => {
                // A sustained session that dropped resets the schedule so the first retry is fast (D-04).
                if established {
                    attempt = 0;
                }
                tracing::warn!(error = %e, "connection dropped — will reconnect");
                tracing::debug!("previous attempt torn down (routes removed before TUN) — TUN-03");

                // If shutdown already fired (e.g. concurrently with the drop), exit now (D-06).
                if *shutdown_rx.borrow() {
                    return Ok(());
                }

                let delay = backoff_delay(attempt);
                tracing::info!(
                    attempt = attempt + 1,
                    delay_secs = delay.as_secs_f64(),
                    "reconnecting after backoff"
                );

                // Shutdown-interruptible backoff (D-06): sleep OR shutdown, whichever first.
                // Shadow with a scoped clone so the literal `shutdown_rx.changed()` drives the arm.
                let mut shutdown_rx = shutdown_rx.clone();
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    _ = shutdown_rx.changed() => {
                        tracing::info!("shutdown during backoff — aborting reconnect");
                        return Ok(());
                    }
                }

                attempt = attempt.saturating_add(1);
            }
        }
    }
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
}
