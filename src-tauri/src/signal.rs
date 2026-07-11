//! OS-signal → shutdown bridge (LIFE-04).
//!
//! `wait_for_shutdown()` resolves when the user asks the process to stop:
//! Ctrl+C on every platform (SIGINT on Unix, CTRL_C_EVENT on Windows) and, on
//! Unix only, SIGTERM (systemd / `kill` / `docker stop`). The caller flips the
//! Phase 6 `watch<bool>` shutdown channel so the forwarding loop drains politely
//! (CSTP Disconnect + routes-before-TUN teardown). No secrets are involved and
//! no `std::process::exit` is ever called — teardown runs via RAII unwind (D-04).

/// Resolve when an OS shutdown signal arrives. Cross-platform per STACK.md Q6.
pub async fn wait_for_shutdown() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        // Also catch SIGTERM (systemd / kill / docker stop). tokio::signal::unix
        // is cfg(unix)-only and must be gated — it does not compile on Windows.
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm =
            signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {}
            _ = sigterm.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        // Windows: only Ctrl+C is meaningful; SIGTERM does not exist.
        ctrl_c.await.expect("failed to listen for Ctrl+C");
    }
}

#[cfg(test)]
mod tests {
    /// The Phase 6 shutdown primitive: a `watch<bool>` set to true must reach a
    /// receiver's `changed()`. Proves the signal-task → forwarding-loop bridge
    /// mechanic without needing a real OS signal (the live signal path is
    /// human_verification only — this host has no live tunnel).
    #[tokio::test]
    async fn watch_channel_propagates_shutdown() {
        let (tx, mut rx) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            let _ = tx.send(true);
        });
        rx.changed().await.expect("sender dropped before send");
        assert!(*rx.borrow());
    }
}
