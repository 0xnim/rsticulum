//! Data packet types — re-exported from the interest module.
//!
//! The Interest/Data types live together in `interest.rs` since they share
//! the wire format encoding primitives. This module re-exports for clean API.

pub use crate::interest::{Data, DataError, DataMetadata, Freshness};
