//! TUN device layer (TUN-01): open, configure, and bring up a kernel TUN
//! interface from the Phase 3 [`SessionParams`], wrapped in a [`TunDevice`] that
//! records the interface name (for Phase 5 routing) and exposes tokio async
//! read/write halves (for the Phase 6 forwarding loop).
//!
//! The `tun` crate handles IP assignment + bring-up internally on all platforms
//! (Linux ioctl, macOS utun, Windows Wintun) — this module does NOT hand-roll
//! ioctl/netlink (D-03). Teardown is RAII: dropping [`TunDevice`] closes the fd
//! and the kernel removes the interface (D-07 — no explicit destroy call).
//!
//! The split read/write handles are consumed only in Phase 6, so they are dead
//! until then — hence the crate-standard `#![allow(dead_code)]`.
#![allow(dead_code)]

use std::net::Ipv4Addr;

use tokio::io::{ReadHalf, WriteHalf};
use tun::{AbstractDevice, AsyncDevice};

use crate::error::VpnError;
use crate::tunnel::SessionParams;

/// Host netmask (/32): the server assigns a single tunnel address, so the TUN
/// interface owns exactly one host — no on-link subnet. Routes come in Phase 5.
pub const HOST_NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 255);

/// Encode a string as a NUL-terminated UTF-16 (wide) buffer suitable for passing
/// `.as_ptr()` as a Win32 `PCWSTR`. Pure — the returned Vec owns the buffer and must
/// outlive the FFI call. (D-01 step 1.)
fn encode_wide_nul(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// The `tun` Configuration builder takes the MTU as `u16`; SessionParams already
/// stores `u16`, so this is an identity pass-through kept explicit for testing and
/// to document that no lossy cast occurs.
pub fn config_mtu(params: &SessionParams) -> u16 {
    params.mtu
}

/// An open, configured, and up TUN interface. Owns the async device handle; when
/// dropped, the fd closes and the kernel removes the interface (RAII teardown,
/// D-07 — no explicit destroy call). Also records the kernel-assigned interface
/// name so Phase 5 can install routes that reference it.
pub struct TunDevice {
    device: AsyncDevice,
    name: String,
}

impl TunDevice {
    /// The kernel-assigned interface name (e.g. `utunN` on macOS, the Wintun
    /// adapter name on Windows, `tunN` on Linux). Needed by Phase 5 routing.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Resolve the kernel interface index for this TUN device from its name, for
    /// Phase 5 routing (`Route::with_ifindex`). Unix uses `nix::net::if_::if_nametoindex`
    /// (requires the nix `net` feature). Windows resolves the real Wintun adapter index
    /// via the IpHelper LUID FFI in the `#[cfg(windows)]` branch below (D-01).
    #[cfg(unix)]
    pub fn if_index(&self) -> Result<u32, VpnError> {
        nix::net::if_::if_nametoindex(self.name.as_str())
            .map(|idx| idx as u32)
            .map_err(|e| {
                VpnError::Routing(format!(
                    "failed to resolve interface index for '{}': {e}",
                    self.name
                ))
            })
    }

    /// Resolve the kernel interface index for this Windows Wintun adapter from its name
    /// (D-01): encode the alias as a wide string, `ConvertInterfaceAliasToLuid` -> `NET_LUID_LH`,
    /// then `ConvertInterfaceLuidToIndex` -> `u32`. Both return `WIN32_ERROR` (0 == NO_ERROR);
    /// non-zero maps to `VpnError::Routing` with the code. Fail-closed; nothing to free.
    #[cfg(windows)]
    pub fn if_index(&self) -> Result<u32, VpnError> {
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToIndex,
        };
        use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;

        let alias = encode_wide_nul(&self.name);
        // SAFETY: `alias` is a valid NUL-terminated UTF-16 buffer that outlives this call;
        // NET_LUID_LH is a union that the API fully populates, so zero-init is the documented
        // starting state. No allocations are made that require freeing.
        let mut luid: NET_LUID_LH = unsafe { std::mem::zeroed() };
        let err = unsafe { ConvertInterfaceAliasToLuid(alias.as_ptr(), &mut luid) };
        if err != 0 {
            return Err(VpnError::Routing(format!(
                "ConvertInterfaceAliasToLuid failed for adapter '{}' (code {})",
                self.name, err
            )));
        }
        let mut index: u32 = 0;
        let err = unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) };
        if err != 0 {
            return Err(VpnError::Routing(format!(
                "ConvertInterfaceLuidToIndex failed for adapter '{}' (code {})",
                self.name, err
            )));
        }
        Ok(index)
    }

    /// Consume the device into tokio async read/write halves for the Phase 6
    /// forwarding loop (D-05 — mirrors the TLS `tokio::io::split()` decision in
    /// STATE.md; NOT the native `dev.split()` which returns (writer, reader)).
    /// The interface name was captured at open time and is unavailable after this
    /// consumes `self` — capture `name()` before splitting if you need it.
    pub fn split(self) -> (ReadHalf<AsyncDevice>, WriteHalf<AsyncDevice>) {
        tokio::io::split(self.device)
    }
}

/// Open, configure, and bring up a TUN interface from the server-assigned
/// [`SessionParams`] (TUN-01). The `tun` crate handles IP assignment + bring-up
/// internally on all platforms (D-03 — do NOT hand-roll ioctl/netlink here;
/// net-route is only for Phase 5 routes).
///
/// Failure (permission denied, driver/wintun.dll missing) maps to
/// [`VpnError::Tun`] with a clear message and propagates cleanly — no panic, no
/// unwrap on the crate result (D-06). Classified transient by default so Phase 8
/// can retry; Phase 2 already gates privileges up front.
pub async fn open_tun(params: &SessionParams) -> Result<TunDevice, VpnError> {
    let mut config = tun::Configuration::default();
    config
        .address(params.address) // X-CSTP-Address, the assigned tunnel IPv4
        .netmask(HOST_NETMASK) // /32 (D-01)
        .mtu(config_mtu(params)) // u16, defaulted to 1400 in Phase 3 (D-02)
        .up(); // bring the interface up

    // Windows: set a deterministic, recognizable Wintun adapter name (D-03) so it
    // appears clearly in Network Connections AND so the alias->index lookup in
    // if_index() is stable (self.name readback matches the alias). No effect on unix.
    #[cfg(windows)]
    config.tun_name("VPN Client");

    let device = tun::create_as_async(&config)
        .map_err(|e| VpnError::Tun(format!("failed to create TUN device: {e}")))?;

    // Capture the interface name BEFORE any potential split (AbstractDevice via
    // Deref) for Phase 5 routing (D-04).
    let name = device
        .tun_name()
        .map_err(|e| VpnError::Tun(format!("failed to read TUN interface name: {e}")))?;

    tracing::info!(
        interface = %name,
        address = %params.address,
        mtu = params.mtu,
        "TUN device created and up"
    );

    Ok(TunDevice { device, name })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params_with_mtu(mtu: u16) -> SessionParams {
        SessionParams {
            address: "10.0.0.5".parse().unwrap(),
            netmask: None,
            dns: vec![],
            mtu,
            keepalive: None,
            dpd: None,
            disconnected_timeout: None,
        }
    }

    #[test]
    fn host_netmask_is_slash_32() {
        assert_eq!(HOST_NETMASK, Ipv4Addr::new(255, 255, 255, 255));
        assert!(HOST_NETMASK.is_broadcast());
    }

    #[test]
    fn config_mtu_passes_through() {
        assert_eq!(config_mtu(&params_with_mtu(1400)), 1400);
        assert_eq!(config_mtu(&params_with_mtu(1300)), 1300);
    }

    #[test]
    fn encode_wide_nul_terminates() {
        // "utun" -> UTF-16 code units + trailing NUL terminator.
        assert_eq!(encode_wide_nul("utun"), vec![0x75, 0x74, 0x75, 0x6e, 0x00]);
    }

    #[test]
    fn encode_wide_nul_empty() {
        // Empty string encodes to just the NUL terminator.
        assert_eq!(encode_wide_nul(""), vec![0x00]);
    }
}
