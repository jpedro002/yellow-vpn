//! Platform abstraction. Each per-OS module exports an identical public surface
//! so callers never contain `#[cfg]` blocks (ARCHITECTURE.md Q1).
//!
//! The per-OS surface is re-exported for use from Phase 2 onward; until callers
//! exist the re-export is unused, so silence that warning at the module level.
#![allow(unused_imports)]

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::*;

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
compile_error!("unsupported target platform: only linux, macos, and windows are supported");
