//! Android platform surface. Unlike the desktop modules, Android does NOT open
//! `/dev/net/tun` or install OS routes: the system `VpnService` hands us a
//! pre-opened TUN fd and configures routes/DNS/MTU via `VpnService.Builder`.
//! This module therefore exposes the same *names* as the other platforms but the
//! route operations are no-ops (see `routing.rs` android branch and
//! `tun_device::open_tun_from_fd`).
#![allow(dead_code)]
