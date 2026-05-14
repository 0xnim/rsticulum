use crate::link::LinkManager;
use rsticulum_identity::RnsAddress;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Route entry in the routing table.
#[derive(Debug, Clone)]
pub struct RouteEntry {
    pub destination: RnsAddress,
    pub next_hop: RnsAddress,
    pub path_quality: f64,
    pub hop_count: u8,
    pub last_refresh: Instant,
}

/// Hybrid routing table: link-state announcements + path request/reply.
pub struct MeshRouter {
    routes: HashMap<RnsAddress, RouteEntry>,
    local_addr: RnsAddress,
    route_timeout: Duration,
}

impl MeshRouter {
    pub fn new(local_addr: RnsAddress) -> Self {
        Self {
            routes: HashMap::new(),
            local_addr,
            route_timeout: Duration::from_secs(300),
        }
    }

    /// This node's address.
    pub fn local_addr(&self) -> &RnsAddress {
        &self.local_addr
    }

    /// Update or add a route. Keeps the best path by quality (then hop count).
    pub fn update_route(
        &mut self,
        dest: RnsAddress,
        next_hop: RnsAddress,
        quality: f64,
        hop_count: u8,
    ) {
        let entry = self.routes.entry(dest).or_insert_with(|| RouteEntry {
            destination: dest,
            next_hop,
            path_quality: quality,
            hop_count,
            last_refresh: Instant::now(),
        });

        if quality > entry.path_quality
            || (quality == entry.path_quality && hop_count < entry.hop_count)
        {
            entry.next_hop = next_hop;
            entry.path_quality = quality;
            entry.hop_count = hop_count;
            entry.last_refresh = Instant::now();
        }
    }

    /// Get the next hop for a destination, if known.
    pub fn next_hop(&self, dest: &RnsAddress) -> Option<&RouteEntry> {
        self.routes.get(dest)
    }

    /// All known destinations.
    pub fn destinations(&self) -> Vec<RnsAddress> {
        self.routes.keys().cloned().collect()
    }

    /// Number of routes.
    pub fn route_count(&self) -> usize {
        self.routes.len()
    }

    /// Prune stale routes.
    pub fn prune_stale(&mut self) {
        self.routes
            .retain(|_, e| e.last_refresh.elapsed() < self.route_timeout);
    }

    /// Build announce from link manager state.
    pub fn build_announce(&self, link_mgr: &LinkManager) -> rsticulum_packet::Packet {
        let payload = bincode::serialize(&AnnouncePayload {
            origin: self.local_addr,
            peers: link_mgr
                .peers_above(0.0)
                .iter()
                .map(|p| (p.address, p.quality.score))
                .collect(),
        })
        .unwrap_or_default();
        // Announce to broadcast (all-zeros is broadcast in RNS)
        let broadcast = RnsAddress::from_bytes(&[0u8; 16]).unwrap();
        rsticulum_packet::Packet::new_announce(broadcast, payload)
    }

    /// Process incoming announce: update routes for origin and its peers.
    pub fn process_announce(
        &mut self,
        origin: RnsAddress,
        link_mgr: &LinkManager,
        announce: &AnnouncePayload,
    ) {
        // Direct route to origin
        if let Some(q) = link_mgr.quality_to(&origin) {
            self.update_route(origin, origin, q.score, 1);
        }
        // Origin's peers are reachable through origin (+1 hop)
        for &(ref peer_addr, peer_q) in &announce.peers {
            if let Some(direct_q) = link_mgr.quality_to(&origin) {
                let path_q = direct_q.score.min(peer_q);
                self.update_route(*peer_addr, origin, path_q, 2);
            }
        }
    }
}

/// Payload of an announce packet (RNS wire-compatible).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AnnouncePayload {
    /// The origin node broadcasting this announcement.
    pub origin: RnsAddress,
    /// Peers the origin can directly reach with their link quality scores.
    pub peers: Vec<(RnsAddress, f64)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_addr(b: u8) -> RnsAddress {
        RnsAddress::from_identity_key(&[b; 32])
    }

    #[test]
    fn route_update_basic() {
        let local = test_addr(0);
        let mut router = MeshRouter::new(local);
        let dest = test_addr(1);
        let hop = test_addr(2);
        router.update_route(dest, hop, 0.9, 1);
        assert_eq!(router.next_hop(&dest).unwrap().next_hop, hop);
    }

    #[test]
    fn best_path_wins() {
        let local = test_addr(0);
        let mut router = MeshRouter::new(local);
        let dest = test_addr(1);
        router.update_route(dest, test_addr(2), 0.3, 1);
        router.update_route(dest, test_addr(3), 0.9, 2);
        assert_eq!(router.next_hop(&dest).unwrap().next_hop, test_addr(3));
    }
}
