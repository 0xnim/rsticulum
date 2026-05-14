//! Path request and path reply — on-demand route discovery.
//!
//! When a node needs to reach a destination it doesn't have a route for,
//! it floods a PathRequest. Any node that knows the destination (or is the
//! destination) responds with a PathReply containing the route.
//!
//! Matches Python RNS `PathRequest` and `PathResponse` semantics.

use serde::{Deserialize, Serialize};
use rsticulum_identity::RnsAddress;

/// A path request — "Who can reach this destination?"
///
/// Flooded through the mesh. Each forwarder decrements TTL and adds
/// itself to the path so the reply can trace back.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathRequest {
    /// The destination we're looking for.
    pub destination_hash: [u8; 16],
    /// Maximum hops this request should travel.
    pub max_hops: u8,
    /// Request ID (unique per origin, for deduplication).
    pub request_id: [u8; 16],
    /// Accumulated path (addresses that have forwarded this request).
    /// Used to route the reply back to the origin.
    pub path: Vec<RnsAddress>,
}

impl PathRequest {
    /// Create a new path request.
    pub fn new(destination: RnsAddress, max_hops: u8) -> Self {
        Self {
            destination_hash: *destination.as_bytes(),
            max_hops,
            request_id: rand::random(),
            path: Vec::new(),
        }
    }

    /// Returns the destination we're looking for.
    pub fn destination(&self) -> Result<RnsAddress, crate::MeshError> {
        RnsAddress::from_bytes(&self.destination_hash)
            .map_err(|_| crate::MeshError::InvalidPacket("invalid destination in path request"))
    }

    /// Check if this request has expired (path length >= max_hops).
    pub fn is_expired(&self) -> bool {
        self.path.len() >= self.max_hops as usize
    }

    /// Add a hop to the accumulated path.
    pub fn add_hop(&mut self, addr: RnsAddress) {
        // Don't add duplicate hops (loop prevention)
        if !self.path.contains(&addr) {
            self.path.push(addr);
        }
    }
}

/// A path reply — "I found the destination, here's the route."
///
/// Travels back along the reversed path from the responder to the requester.
/// Each node along the way updates its routing table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathReply {
    /// The request ID this is responding to.
    pub request_id: [u8; 16],
    /// The destination that was found.
    pub destination_hash: [u8; 16],
    /// The route back to the destination (from closest to farthest).
    pub route: Vec<RnsAddress>,
    /// Quality score of the discovered path.
    pub quality: f64,
    /// Hop count to the destination.
    pub hop_count: u8,
}

impl PathReply {
    /// Create a path reply.
    pub fn new(
        request_id: [u8; 16],
        destination: RnsAddress,
        route: Vec<RnsAddress>,
        quality: f64,
        hop_count: u8,
    ) -> Self {
        Self {
            request_id,
            destination_hash: *destination.as_bytes(),
            route,
            quality,
            hop_count,
        }
    }

    /// Returns the destination that was found.
    pub fn destination(&self) -> Result<RnsAddress, crate::MeshError> {
        RnsAddress::from_bytes(&self.destination_hash)
            .map_err(|_| crate::MeshError::InvalidPacket("invalid destination in path reply"))
    }
}

/// Process an incoming path request.
///
/// Returns:
/// - `Some(PathReply)` if this node knows a route to the destination
/// - `None` if the request should be forwarded
pub fn handle_path_request(
    request: &PathRequest,
    router: &crate::routing::MeshRouter,
    local_addr: RnsAddress,
) -> Option<PathReply> {
    let dest = request.destination().ok()?;

    // Check if we ARE the destination
    if dest == local_addr {
        let mut route = request.path.clone();
        route.push(local_addr);
        route.reverse();
        return Some(PathReply::new(
            request.request_id,
            dest,
            route,
            1.0, // direct = perfect quality
            0,   // 0 hops to self
        ));
    }

    // Check if we have a route to the destination
    if let Some(entry) = router.next_hop(&dest) {
        let mut route = request.path.clone();
        route.push(local_addr);
        route.reverse();
        return Some(PathReply::new(
            request.request_id,
            dest,
            route,
            entry.path_quality,
            entry.hop_count,
        ));
    }

    None
}

/// Process an incoming path reply.
///
/// Updates the routing table with the discovered route.
/// Returns the next hop to forward the reply to, if any.
pub fn handle_path_reply(
    reply: &PathReply,
    router: &mut crate::routing::MeshRouter,
    local_addr: RnsAddress,
) -> Option<RnsAddress> {
    let dest = reply.destination().ok()?;

    // Find our position in the route and extract the next hop toward the destination
    if let Some(pos) = reply.route.iter().position(|a| *a == local_addr) {
        // The next hop toward the destination (closer to dest, earlier in the reply route)
        if pos > 0 {
            let next_hop = reply.route[pos - 1];
            let remaining_hops = pos as u8;
            router.update_route(
                dest,
                next_hop,
                reply.quality,
                reply.hop_count + remaining_hops,
            );
        }

        // The next hop toward the origin (farther from dest, later in the reply route)
        if pos + 1 < reply.route.len() {
            return Some(reply.route[pos + 1]);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_addr(b: u8) -> RnsAddress {
        RnsAddress::from_identity_key(&[b; 32])
    }

    #[test]
    fn path_request_deduplicates_hops() {
        let dest = test_addr(99);
        let mut req = PathRequest::new(dest, 10);

        req.add_hop(test_addr(1));
        req.add_hop(test_addr(2));
        req.add_hop(test_addr(1)); // duplicate — should be ignored

        assert_eq!(req.path.len(), 2);
    }

    #[test]
    fn path_request_ttl_expiry() {
        let mut req = PathRequest::new(test_addr(99), 2);
        req.add_hop(test_addr(1));
        assert!(!req.is_expired());
        req.add_hop(test_addr(2));
        assert!(req.is_expired());
    }

    #[test]
    fn path_reply_roundtrip() {
        let dest = test_addr(42);
        let route = vec![test_addr(1), test_addr(2), test_addr(3)];
        let reply = PathReply::new([0xAA; 16], dest, route.clone(), 0.8, 3);

        assert_eq!(reply.destination().unwrap(), dest);
        assert_eq!(reply.quality, 0.8);
        assert_eq!(reply.hop_count, 3);
        assert_eq!(reply.route, route);
    }
}
