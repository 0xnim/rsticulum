//! rsticulum-icn — Information-Centric Networking application layer.
//!
//! Content-addressed named data on rsticulum mesh. Self-certifying names
//! encode producer identity. Manifests are the discovery mechanism:
//! know a producer → fetch manifest → discover content names → fetch content.
//!
//! ## Architecture
//!
//! ```text
//! Forwarder (FIB/PIT/CS/Strategy)
//! ├── Name           — /<producer-hash>/<path>[?blake3=<hash>]
//! ├── Interest       — "I want this named data"
//! ├── Data           — signed content + metadata
//! ├── Manifest       — producer's content index (JSON, signed)
//! ├── ContentStore   — LRU cache of Data packets
//! ├── Fib            — prefix → faces, longest-prefix-match
//! ├── Pit            — Interest aggregation, reverse-path for Data
//! ├── Face (trait)   — communication endpoint (LinkFace, TestFace)
//! └── Strategy       — pluggable forwarding decisions
//! ```

pub mod cs;
pub mod data;
pub mod face;
pub mod fib;
pub mod forwarder;
pub mod interest;
pub mod link_face;
pub mod manifest;
pub mod name;
pub mod pit;
pub mod strategy;

// Re-export core types
pub use cs::ContentStore;
pub use data::{Data, DataError, DataMetadata, Freshness};
pub use face::{test_face_pair, Face, FaceCapabilities, FaceId, TestFace};
pub use fib::{Fib, FibEntry};
pub use interest::{Interest, InterestError, InterestSelector};
pub use link_face::LinkFace;
pub use manifest::{ChunkRef, ContentManifest, EntryKind, Manifest, ManifestEntry, ManifestError};
pub use name::{Name, NameError, MAX_COMPONENTS};
pub use pit::{Pit, PitEntry, PitOp};
pub use strategy::{BestRoute, Strategy, StrategyDecision};

// Re-export for convenience
pub use rsticulum_transport::Proof;
