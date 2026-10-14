//! Typed error enum for the VPN client. A single flat enum is used so the
//! reconnect loop (Phase 8) can classify failures with one `match`.
#![allow(dead_code)]

/// All fatal and recoverable errors surfaced by the client.
#[derive(Debug, thiserror::Error)]
pub enum VpnError {
    /// Configuration / CLI / TOML problem — permanent, do not retry.
    #[error("configuration error: {0}")]
    Config(String),

    /// Missing privileges (CAP_NET_ADMIN / root / Administrator) — permanent.
    #[error("privilege error: {0}")]
    Privilege(String),

    /// TUN device creation or configuration failure.
    #[error("TUN error: {0}")]
    Tun(String),

    /// TUN subsystem absent at startup (/dev/net/tun missing, wintun.dll absent) — permanent.
    #[error("TUN unavailable: {0}")]
    TunUnavailable(String),

    /// Routing table operation failure.
    #[error("routing error: {0}")]
    Routing(String),

    /// TLS handshake or transport error — transient, reconnect.
    #[error("TLS error: {0}")]
    Tls(String),

    /// Malformed CSTP frame or protocol violation — transient, reconnect.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Authentication rejected by server — permanent, do not retry.
    #[error("authentication failed: {0}")]
    AuthFailed(String),

    /// The gateway demands a new password before it will log the user in —
    /// permanent: retrying with the same credentials cannot succeed. Carries the
    /// gateway's own prompt text so the UI can show it.
    #[error("password expired: {prompt}")]
    PasswordExpired { prompt: String },

    /// The peer asked to tear the tunnel down — transient, reconnect.
    ///
    /// Carries the reason the peer gave, so a policy rejection is diagnosable
    /// instead of surfacing as a bare "server disconnected" in a reconnect loop.
    /// Check Point sends a `(disconnect :code (N) :message ("..."))` control
    /// frame; CSTP has no reason field, so the string is a fixed description.
    #[error("server disconnected: {0}")]
    ServerDisconnect(String),

    /// Underlying I/O error — transient.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Functionality stubbed for a later phase.
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
}

impl VpnError {
    /// True for errors that must NOT trigger an auto-reconnect (Phase 8).
    pub fn is_permanent(&self) -> bool {
        matches!(
            self,
            VpnError::Config(_)
                | VpnError::Privilege(_)
                | VpnError::AuthFailed(_)
                | VpnError::PasswordExpired { .. }
                | VpnError::TunUnavailable(_)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permanent_classification() {
        assert!(VpnError::AuthFailed("bad".into()).is_permanent());
        assert!(VpnError::PasswordExpired { prompt: "p".into() }.is_permanent());
        assert!(VpnError::Config("x".into()).is_permanent());
        assert!(VpnError::TunUnavailable("no tun".into()).is_permanent());
        assert!(!VpnError::ServerDisconnect("bye".into()).is_permanent());
        assert!(!VpnError::Tls("x".into()).is_permanent());
    }

    #[test]
    fn io_error_converts() {
        let io = std::io::Error::other("boom");
        let e: VpnError = io.into();
        assert!(!e.is_permanent());
    }
}
