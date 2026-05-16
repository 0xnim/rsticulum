//! RNS Transport layer — Link, Packet, Resource, proof handshake.

use std::time::Duration;

mod error;
mod link;
mod packet_transport;
mod proof;
mod resource;
mod suspendable;

pub use error::TransportError;
pub use link::{Link, LinkConfig, LinkState};
pub use packet_transport::{recv_packet, send_packet, PacketTransport};
pub use proof::{generate_proof, verify_proof, verify_proof_with_public_key, Proof};
pub use resource::{Resource, ResourceConfig, ResourceState, Segment, SegmentTracker};
pub use suspendable::{SuspendableLink, SuspendableState, SuspendedSession};

/// Interval at which KEEPALIVE packets are sent on idle links.
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
/// If no inbound traffic for this duration, a probe is sent.
pub const TRAFFIC_TIMEOUT: Duration = Duration::from_secs(300);
/// If no response for this duration, the link is closed as stale.
pub const STALE_TIME: Duration = Duration::from_secs(600);
