//! Routing layer (TUN-02): install the VPN's private-network routes through the
//! Phase 4 TUN interface using the `net-route` crate's async API, and remove them
//! cleanly on teardown.
//!
//! The route CIDRs are HARDCODED (`vpn_routes()`) — split-tunnel v0.1 — and are
//! deliberately NOT derived from any server header (`X-CSTP-Split-Include` is
//! deferred), so a malicious server cannot inject routes to hijack traffic
//! (threat_model T-05-01). Teardown ordering is LOCKED: routes are removed BEFORE
//! the TUN device drops (D-06) to avoid zombie routes pointing at a dead interface.
//!
//! [`RoutingGuard::remove_all`] is the primary teardown (Drop cannot be async and
//! `Handle` is not Clone); [`Drop`] is a best-effort safety net that logs a warning
//! if routes remain (D-05). Consumed by main.rs wiring (Task 3) and, from Phase 6,
//! held alive across the forwarding loop — hence the crate-standard allow.
#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr};

use net_route::{Handle, Route};

use crate::error::VpnError;

/// The private-network CIDRs routed through the TUN interface (v0.1 split-tunnel, D-02).
/// Hardcoded constants — NOT derived from server headers (X-CSTP-Split-Include is deferred,
/// threat_model T-05-01). Returns exactly [(10.0.0.0, 8), (172.16.0.0, 12)].
pub fn vpn_routes() -> Vec<(Ipv4Addr, u8)> {
    vec![
        (Ipv4Addr::new(10, 0, 0, 0), 8),
        (Ipv4Addr::new(172, 16, 0, 0), 12),
    ]
}

/// Owns the routing Handle and every Route it installed. Teardown is primarily via the
/// explicit async `remove_all()` (Drop cannot be async). `Drop` is a best-effort SAFETY
/// NET: if routes remain (remove_all was never called), it logs a warning so orphaned
/// routes are visible rather than silent (D-05).
pub struct RoutingGuard {
    handle: Handle,
    routes: Vec<Route>,
}

impl RoutingGuard {
    /// Install the VPN routes so they egress the interface `ifindex` (the TUN device's
    /// index from `TunDevice::if_index()`). Handle::new() is sync; add() is async. On any
    /// failure the routes added so far are best-effort removed before returning the error,
    /// so a partial install does not leave zombie routes (D-04).
    pub async fn install(ifindex: u32) -> Result<Self, VpnError> {
        Self::install_routes(ifindex, &vpn_routes()).await
    }

    /// Install an EXPLICIT set of routes through `ifindex`. Used by the Check Point path,
    /// whose routes come from the authenticated `hello_reply` Office-Mode range (split-tunnel;
    /// the `0.0.0.0/0` default-route sentinel is already stripped in `parse_hello_reply`, so a
    /// server cannot install a full-tunnel hijack). Same partial-install rollback as `install`.
    pub async fn install_routes(ifindex: u32, routes: &[(Ipv4Addr, u8)]) -> Result<Self, VpnError> {
        let handle = Handle::new()
            .map_err(|e| VpnError::Routing(format!("failed to open routing handle: {e}")))?;
        let mut added: Vec<Route> = Vec::new();
        for &(dest, prefix) in routes {
            let route = Route::new(IpAddr::V4(dest), prefix).with_ifindex(ifindex);
            if let Err(e) = handle.add(&route).await {
                // best-effort rollback of what we already added
                for r in &added {
                    let _ = handle.delete(r).await;
                }
                return Err(VpnError::Routing(format!(
                    "failed to add route {dest}/{prefix} via ifindex {ifindex}: {e}"
                )));
            }
            tracing::info!(destination = %dest, prefix, ifindex, "route installed");
            added.push(route);
        }
        Ok(RoutingGuard {
            handle,
            routes: added,
        })
    }

    /// Remove every installed route. Call this in the teardown path BEFORE dropping the
    /// TunDevice (D-06 locked ordering: routes before TUN). Idempotent — takes the route
    /// list so a later Drop sees nothing to warn about. Best-effort: logs (does not abort)
    /// on individual delete failures so teardown always completes.
    pub async fn remove_all(&mut self) {
        let routes = std::mem::take(&mut self.routes);
        for route in &routes {
            match self.handle.delete(route).await {
                Ok(()) => tracing::info!(
                    destination = %route.destination,
                    prefix = route.prefix,
                    "route removed"
                ),
                Err(e) => tracing::warn!(
                    destination = %route.destination,
                    prefix = route.prefix,
                    error = %e,
                    "failed to remove route (may need manual cleanup)"
                ),
            }
        }
    }
}

impl Drop for RoutingGuard {
    fn drop(&mut self) {
        if !self.routes.is_empty() {
            // Drop cannot be async and `Handle` is NOT Clone, so we cannot reliably delete
            // here. Warn loudly instead — the correct path is an explicit remove_all().await
            // during teardown (D-05/D-06). Phases 6/7/8 must call remove_all() before drop.
            tracing::warn!(
                remaining = self.routes.len(),
                "RoutingGuard dropped with routes still installed — remove_all() was not called; \
                 routes may remain in the table (manual `ip route del` / `route delete` may be needed)"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vpn_routes_are_the_two_private_ranges() {
        let routes = vpn_routes();
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0], (Ipv4Addr::new(10, 0, 0, 0), 8));
        assert_eq!(routes[1], (Ipv4Addr::new(172, 16, 0, 0), 12));
    }

    #[test]
    fn vpn_route_prefixes_are_8_and_12() {
        let prefixes: Vec<u8> = vpn_routes().into_iter().map(|(_, p)| p).collect();
        assert_eq!(prefixes, vec![8, 12]);
    }
}
