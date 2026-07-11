//! macOS platform surface: root privilege check; utun is always kernel-present.
#![allow(dead_code)]

use crate::error::VpnError;

/// Verify the process runs as root (D-02).
pub fn check_privileges() -> Result<(), VpnError> {
    if nix::unistd::geteuid().is_root() {
        Ok(())
    } else {
        Err(VpnError::Privilege(
            "Root privileges required on macOS. Run with: sudo vpn-client".into(),
        ))
    }
}

/// utun is always present in the macOS kernel; the real gate is privilege (D-07).
pub fn check_tun_availability() -> Result<(), VpnError> {
    Ok(())
}
