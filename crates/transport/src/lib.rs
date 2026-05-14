//! RNS Transport layer — Link, Packet, Resource, proof handshake.

mod error;
mod link;
mod packet_transport;
mod proof;
mod resource;
mod suspendable;

pub use error::TransportError;
pub use link::{Link, LinkConfig, LinkState};
pub use packet_transport::{recv_packet, send_packet, PacketTransport};
pub use proof::{generate_proof, verify_proof, Proof};
pub use resource::{Resource, ResourceConfig, ResourceState, SegmentTracker};
pub use suspendable::{SuspendableLink, SuspendableState, SuspendedSession};
