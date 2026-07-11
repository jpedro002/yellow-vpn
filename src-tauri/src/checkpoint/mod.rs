//! Check Point (CCC + SLIM/SNX) protocol layer. Pure codec + cipher in Phase 1;
//! auth/session/framing modules arrive in later phases.
#![allow(dead_code)]

pub mod auth;
pub mod ccc;
pub mod cipher;
pub mod framing;
pub mod session;
