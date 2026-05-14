//! RNS Destination abstraction.
//!
//! A Destination is a cryptographic endpoint identified by a hash derived
//! from an identity key and application name. Destinations are the fundamental
//! addressing unit for Links, Packets, and Resources.

mod destination;

pub use destination::*;
