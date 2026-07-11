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

    /// Server sent a CSTP disconnect (type 0x05) — transient, reconnect.
    #[error("server disconnected")]
    ServerDisconnect,

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
        assert!(VpnError::Config("x".into()).is_permanent());
        assert!(VpnError::TunUnavailable("no tun".into()).is_permanent());
        assert!(!VpnError::ServerDisconnect.is_permanent());
        assert!(!VpnError::Tls("x".into()).is_permanent());
    }

    #[test]
    fn io_error_converts() {
        let io = std::io::Error::other("boom");
        let e: VpnError = io.into();
        assert!(!e.is_permanent());
    }
}
