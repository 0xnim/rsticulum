//! RNS wire-compatible packet format — pure protocol definition.
//!
//! Zero network dependencies. Converts between structs and the byte-level
//! header format used by Python RNS. Suitable for any RNS-compatible tooling.
//!
//! ## Header Format
//! ```text
//! HEADER_1: [flags:1][hops:1][dest_hash:16][context:1][ciphertext:...]
//! HEADER_2: [flags:1][hops:1][transport_id:16][dest_hash:16][context:1][ciphertext:...]
//! ```

mod packet;

pub use packet::*;
