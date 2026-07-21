//! Yellow VPN engine: protocol clients, TUN/routing, reconnect lifecycle.
//! Library form of the former CLI binary; consumed by the elevated helper.

pub mod auth;
pub mod checkpoint;
pub mod client;
pub mod config;
pub mod error;
pub mod fortigate;
pub mod forward;
pub mod framer;
pub mod platform;
pub mod routing;
pub mod signal;
pub mod tun_device;
pub mod tunnel;

pub use client::{run_client, run_client_supervised, ClientEvent};
pub use config::{Config, Protocol};
pub use error::VpnError;

#[cfg(target_os = "android")]
pub mod jni_bridge;
#[cfg(target_os = "android")]
pub use client::run_client_supervised_android;
