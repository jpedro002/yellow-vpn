//! FortiGate SSL VPN protocol layer (FG). HTTPS auth -> SVPNCOOKIE -> config XML
//! -> `GET /remote/sslvpn-tunnel` upgrade -> `0x5050`-framed IP over TLS. Targets
//! the v2 (non-PPP, raw-IP) wire protocol; the legacy PPP path is a follow-up.
#![allow(dead_code)]

pub mod auth;
pub mod config;
pub mod framing;
pub mod session;
