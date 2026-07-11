//! Linux platform surface: root privilege check + `/dev/net/tun` presence probe.
#![allow(dead_code)]

use crate::error::VpnError;

/// Verify the process holds sufficient privileges (root implies CAP_NET_ADMIN, D-01).
pub fn check_privileges() -> Result<(), VpnError> {
    if nix::unistd::geteuid().is_root() {
        Ok(())
    } else {
        Err(VpnError::Privilege(
            "Root privileges required (CAP_NET_ADMIN). Run with: sudo vpn-client".into(),
        ))
    }
}

/// Verify the TUN subsystem is available by probing `/dev/net/tun` (D-05).
pub fn check_tun_availability() -> Result<(), VpnError> {
    if std::path::Path::new("/dev/net/tun").exists() {
        Ok(())
    } else {
        Err(VpnError::TunUnavailable(
            "/dev/net/tun is missing. Load the TUN kernel module: sudo modprobe tun".into(),
        ))
    }
}
