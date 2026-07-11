//! Windows platform surface: token-elevation privilege check + wintun.dll presence probe.
#![allow(dead_code)]

use crate::error::VpnError;

/// Query the current process token for elevation status (D-03).
///
/// Fail-closed: any FFI failure returns `false` (treated as not elevated). The
/// process token handle is always closed before returning to avoid a handle leak.
fn is_elevated() -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token: HANDLE = std::ptr::null_mut(); // HANDLE is *mut c_void in 0.61
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false; // fail-closed: treat as not elevated
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            size,
            &mut size,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

/// Verify the process token is elevated / Administrator (D-03).
pub fn check_privileges() -> Result<(), VpnError> {
    if is_elevated() {
        Ok(())
    } else {
        Err(VpnError::Privilege(
            "Administrator privileges required. Right-click the terminal and choose \
             'Run as administrator'."
                .into(),
        ))
    }
}

/// Verify `wintun.dll` is present on the loader search path (D-06).
pub fn check_tun_availability() -> Result<(), VpnError> {
    // wintun.dll is loaded at runtime by the `tun` crate (via wintun-bindings).
    // Mirror its search path: next to the executable, then System32.
    use std::path::PathBuf;
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        candidates.push(dir.join("wintun.dll"));
    }
    if let Ok(sysroot) = std::env::var("SystemRoot") {
        candidates.push(PathBuf::from(sysroot).join("System32").join("wintun.dll"));
    }
    if candidates.iter().any(|p| p.exists()) {
        Ok(())
    } else {
        Err(VpnError::TunUnavailable(
            "wintun.dll not found. Download it from https://www.wintun.net/ and place \
             wintun.dll next to vpn-client.exe (or in System32)."
                .into(),
        ))
    }
}
