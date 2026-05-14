//! Reticulum mesh routing in Rust.
//!
//! Wire-compatible with Python RNS. Nodes peer over any Medium (UDP, serial, radio).
//! Hybrid routing: proactive link-state announcements + reactive path discovery.
//!
//! # Architecture
//! ```text
//! ┌──────────────────┐
//! │    MeshRouter    │  ← routing table, path selection
//! ├──────────────────┤
//! │   LinkManager    │  ← peer discovery, link quality
//! ├──────────────────┤
//! │  Medium │ Medium │  ← UDP, serial, radio (pluggable)
//! └──────────────────┘
//! ```

mod error;
mod link;
mod medium;
mod routing;
mod udp;

pub use error::MeshError;
pub use link::{LinkConfig, LinkManager, LinkQuality, PeerInfo};
pub use medium::Medium;
pub use routing::MeshRouter;
pub use udp::UdpMedium;

// Re-export path_request for convenience (it's mesh-level logic)
pub mod path_request;

/// Maximum hops a packet can traverse before being dropped.
pub const MAX_HOPS: u8 = 64;
