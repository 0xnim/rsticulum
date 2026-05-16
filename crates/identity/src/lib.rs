//! Cryptographic identity: Ed25519/X25519 keys, 16-byte RNS-compatible addresses.
//!
//! Provides two address types:
//! - `Address` (32-byte BLAKE3) — our internal addressing for rsticulum-net
//! - `RnsAddress` (16-byte SHA-256 truncated) — wire-compatible with Python RNS
//!
//! # Example
//! ```rust
//! use rsticulum_identity::Keys;
//! let keys = Keys::generate();
//! let rns_addr = keys.rns_address();
//! println!("RNS address: {rns_addr}");  // 32-char hex
//! ```

mod address;
mod crypto;
mod error;
mod identity_announce;
mod keys;
mod rns_address;

pub use address::Address;
pub use crypto::{
    decrypt_packet, encrypt_packet, CryptoError, DerivedKey, Fernet, DERIVED_KEY_LEN,
    FERNET_OVERHEAD,
};
pub use error::IdentityError;
pub use identity_announce::IdentityAnnounce;
pub use keys::Keys;
pub use rns_address::RnsAddress;

/// Re-export for downstream crates that verify signatures.
pub use ed25519_dalek::Signature;

pub const ADDRESS_LEN: usize = 32;
pub const RNS_ADDRESS_LEN: usize = 16;
pub const IDENTITY_KEY_LEN: usize = 32;
pub const ENCRYPTION_KEY_LEN: usize = 32;
/// Full public key (X25519 || Ed25519) — 64 bytes, matches Python RNS.
pub const FULL_PUBLIC_KEY_LEN: usize = 64;
pub const SIGNATURE_LEN: usize = 64;
