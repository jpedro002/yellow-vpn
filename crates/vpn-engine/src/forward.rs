//! Bidirectional, protocol-agnostic packet-forwarding loop (FWD-01/02/03, CP-INT-01).
//!
//! ONE tokio task drives both directions + a keepalive timer + a shutdown signal via a
//! SINGLE `tokio::select!` (never two spawned tasks over the TLS stream — TLS read/write are
//! coupled, so splitting into separate tasks risks deadlock; STATE.md / ARCHITECTURE.md
//! Anti-Pattern 1, criterion 4). The wire protocol (Cisco CSTP or Check Point SLIM) is
//! injected as a `Box<dyn TunnelFramer>`, so this loop contains no protocol-specific bytes:
//! it only sees classified [`FrameEvent`]s and opaque encoded frames.
#![allow(dead_code)]

use std::time::Duration;

use futures_util::future::FutureExt; // now_or_never for the non-blocking TUN drain
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use crate::error::VpnError;
use crate::framer::{FrameEvent, TunnelFramer};
use crate::routing::RoutingGuard;
use crate::tun_device::TunDevice;
use bytes::BytesMut;

/// Header slack for the inbound accumulator (largest fixed header across protocols).
const HEADER_SLACK: usize = 8;

/// Max packets drained from the TUN and coalesced into a single TLS write per
/// wake. The tunnel is TLS-over-TCP (a byte stream, not UDP), so the applicable
/// batching is concatenating length-prefixed frames into one buffer — one
/// `write_all` + one `flush` for the batch instead of per packet. Bounded so a
/// saturated TUN can't starve the inbound / keepalive / shutdown arms.
const MAX_TX_BATCH: usize = 32;

/// Consecutive keepalives sent with NO inbound frame before the peer is declared
/// dead and the loop exits for reconnect (CP-TUN-02, RESEARCH §4). Any inbound
/// frame — data or control — resets the counter to 0.
const MAX_MISSED_KEEPALIVES: u32 = 3;

/// The bidirectional forwarding loop (FWD-01/02/03). Owns the TLS stream, the TUN device,
/// and the routing guard for the connection's life (D-07). Drives BOTH directions + a
/// keepalive timer + the shutdown signal in a SINGLE `tokio::select!` in this one task —
/// never spawning a second task over the TLS halves (criterion 4). On ANY exit it runs the
/// LOCKED teardown: `routing.remove_all().await` BEFORE the TUN halves drop (routes-before-TUN,
/// D-07).
///
/// `framer` selects the wire protocol; `mtu` sizes the TUN read buffer; `keepalive_secs` sets
/// the liveness timer cadence (server-dictated; a floor of 1s prevents a busy loop).
pub async fn run_forwarding(
    stream: TlsStream<TcpStream>,
    tun: TunDevice,
    mut routing: RoutingGuard,
    mut framer: Box<dyn TunnelFramer>,
    mtu: u16,
    keepalive_secs: u64,
    prime: BytesMut,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), VpnError> {
    // Split TLS with tokio::io::split (NOT into_split — tokio-rustls has no into_split; STATE.md).
    let (mut tls_read, mut tls_write) = tokio::io::split(stream);
    // Split TUN with the Phase 4 helper (consumes `tun`).
    let (mut tun_read, mut tun_write) = tun.split();

    // TUN read buffer: MTU + 4-byte PI/headroom (D-08 / ARCHITECTURE buffer table).
    let mut tun_buf = vec![0u8; mtu as usize + 4];

    // Reusable outbound batch buffer. The TUN->TLS path appends every packet's
    // frame into THIS buffer (see `encode_data_append`) instead of allocating a
    // fresh Vec per packet, and coalesces up to MAX_TX_BATCH packets per wake so
    // a burst costs one write + one flush. Sized for a full batch; it only grows.
    let mut out_frame = Vec::with_capacity(MAX_TX_BATCH * (HEADER_SLACK + mtu as usize));

    // Inbound TLS accumulator. `read_buf` into this persistent buffer is CANCELLATION-SAFE:
    // if a sibling select! arm wins while bytes are only partially received, nothing is lost —
    // the partial frame stays buffered here and the framer decodes it once complete (TD-1 fix).
    // Seed it with any bytes the protocol layer already read past the handshake (FortiGate's
    // tunnel-upgrade response can carry the first frames glued to it); empty for CSTP/SLIM.
    let mut inbound = BytesMut::with_capacity(HEADER_SLACK + mtu as usize + 16);
    inbound.extend_from_slice(&prime);

    // Keepalive interval: server-dictated, floored at 1s so it never busy-loops.
    let interval_secs = keepalive_secs.max(1);
    let mut ka_timer = tokio::time::interval(Duration::from_secs(interval_secs));
    // interval() fires immediately on first tick; consume it so we don't keepalive on connect.
    ka_timer.tick().await;

    // Liveness: incremented per keepalive sent, reset on any inbound frame (CP-TUN-02).
    let mut missed: u32 = 0;

    tracing::info!(keepalive_secs = interval_secs, "packet forwarding loop started");

    // The loop returns its exit status via `break 'forward <Result>` so ALL exits reach the
    // teardown below (bare `?` would skip route removal).
    let result: Result<(), VpnError> = 'forward: loop {
        tokio::select! {
            biased; // deterministic ordering: shutdown first (D-01)

            // Shutdown signal. Best-effort polite in-tunnel notification (protocol-dependent),
            // then exit Ok.
            _ = shutdown.changed() => {
                if let Some(frame) = framer.encode_shutdown() {
                    let _ = tls_write.write_all(&frame).await; // best-effort — leaving anyway
                    let _ = tls_write.flush().await;
                }
                tracing::info!("shutdown signalled — leaving forwarding loop");
                break 'forward Ok(());
            }

            // Client-initiated keepalive/liveness tick. A framer with no keepalive
            // frame (empty buffer, e.g. FortiGate) opts out of active DPD: send
            // nothing and do not count missed intervals — liveness then rests on
            // TLS EOF detection in the inbound arm.
            _ = ka_timer.tick() => {
                let frame = framer.encode_keepalive();
                if !frame.is_empty() {
                    if let Err(e) = tls_write.write_all(&frame).await { break 'forward Err(VpnError::from(e)); }
                    if let Err(e) = tls_write.flush().await { break 'forward Err(VpnError::from(e)); }
                    missed += 1;
                    if missed >= MAX_MISSED_KEEPALIVES {
                        // Peer unresponsive across several intervals — transient, reconnect.
                        break 'forward Err(VpnError::Protocol(
                            "peer unresponsive (missed keepalives)".into(),
                        ));
                    }
                }
            }

            // Outbound: TUN -> TLS (FWD-01, criterion 1). Drain a bounded batch of
            // ready packets, frame them back-to-back into one buffer, then send the
            // whole batch with a SINGLE write + flush. `read` (the select arm) is
            // cancel-safe; the follow-on `now_or_never` reads only grab packets that
            // are ALREADY ready (dropping a Pending read loses nothing — cancel-safe),
            // so an idle TUN still yields promptly with a batch of one.
            res = tun_read.read(&mut tun_buf) => {
                let n = match res { Ok(n) => n, Err(e) => break 'forward Err(VpnError::from(e)) };
                if n == 0 {
                    // TUN closed -> local link is gone. Transient so run_client re-opens on reconnect.
                    break 'forward Err(VpnError::Io(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof, "TUN device closed (read returned 0)",
                    )));
                }
                out_frame.clear();
                framer.encode_data_append(&tun_buf[..n], &mut out_frame);
                // Opportunistically coalesce further already-ready packets.
                let mut eof = false;
                let mut read_err: Option<std::io::Error> = None;
                for _ in 1..MAX_TX_BATCH {
                    match tun_read.read(&mut tun_buf).now_or_never() {
                        Some(Ok(0)) => { eof = true; break }
                        Some(Ok(m)) => framer.encode_data_append(&tun_buf[..m], &mut out_frame),
                        Some(Err(e)) => { read_err = Some(e); break }
                        None => break, // nothing more ready right now
                    }
                }
                // Flush once for the whole batch: keeps latency low (a lone packet
                // still flushes immediately) while amortizing the syscall over a
                // burst. tokio-rustls may otherwise hold the encrypted record until
                // the next write, so the flush is required for prompt delivery.
                if let Err(e) = tls_write.write_all(&out_frame).await { break 'forward Err(VpnError::from(e)); }
                if let Err(e) = tls_write.flush().await { break 'forward Err(VpnError::from(e)); }
                if let Some(e) = read_err { break 'forward Err(VpnError::from(e)); }
                if eof {
                    break 'forward Err(VpnError::Io(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof, "TUN device closed (read returned 0)",
                    )));
                }
            }

            // Inbound: TLS -> buffer (cancel-safe) -> drain complete frames -> act.
            // read_buf into the persistent `inbound` accumulator is cancellation-safe, so a
            // partially-received frame is never lost if a sibling arm wins first (TD-1 fix).
            res = tls_read.read_buf(&mut inbound) => {
                let n = match res { Ok(n) => n, Err(e) => break 'forward Err(VpnError::from(e)) };
                if n == 0 {
                    // Peer closed the TLS stream. Transient so run_client reconnects.
                    break 'forward Err(VpnError::Io(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof, "TLS stream closed by peer (read returned 0)",
                    )));
                }
                // Drain every complete frame now buffered; leave any partial frame for the next read.
                loop {
                    let event = match framer.try_decode(&mut inbound) {
                        Ok(Some(e)) => e,
                        Ok(None) => break,                       // need more bytes
                        Err(e) => break 'forward Err(e),         // malformed frame
                    };
                    // Any inbound frame proves the peer is alive (CP-TUN-02).
                    missed = 0;
                    match event {
                        FrameEvent::Data(payload) => {
                            if let Err(e) = tun_write.write_all(&payload).await { break 'forward Err(VpnError::from(e)); }
                        }
                        FrameEvent::Reply(bytes) => {
                            if let Err(e) = tls_write.write_all(&bytes).await { break 'forward Err(VpnError::from(e)); }
                            if let Err(e) = tls_write.flush().await { break 'forward Err(VpnError::from(e)); }
                        }
                        FrameEvent::Ignore => {}
                        FrameEvent::Disconnect => break 'forward Err(VpnError::ServerDisconnect),
                    }
                }
            }
        }
    };

    // LOCKED teardown ordering (D-07 / ARCHITECTURE Anti-Pattern 2): remove routes BEFORE the
    // TUN halves drop, so no zombie routes point at a dead interface. remove_all() must run on
    // EVERY exit path — hence the break-based loop above (bare `?` would skip this).
    routing.remove_all().await;
    drop(tun_write);
    drop(tun_read); // TUN fd closes AFTER routes are gone
    result
}
