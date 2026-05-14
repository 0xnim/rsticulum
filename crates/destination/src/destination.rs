//! RNS Destination: cryptographic identity + application addressing.
//!
//! A Destination is a cryptographic endpoint identified by a hash derived from
//! an identity key and application name. Destinations manage encryption, signing,
//! and are the fundamental addressing unit for Links, Packets, and Resources.
//!
//! ## Destination hash derivation (matches Python RNS)
//!
//! ```text
//! name_hash = SHA-256(app_name + aspects)[:NAME_HASH_LENGTH/8]
//! dest_hash = SHA-256(name_hash + identity_hash)[:TRUNCATED_HASHLENGTH/8]
//! ```

use rsticulum_identity::{Keys, RnsAddress};
use rsticulum_packet::HASH_LENGTH;
use sha2::{Digest, Sha256};

/// Length of the name hash portion (RNS: NAME_HASH_LENGTH = 80 bits = 10 bytes).
pub const NAME_HASH_LENGTH: usize = 10;

/// Destination type constants.
pub const DEST_SINGLE: u8 = 0x00;
pub const DEST_GROUP: u8 = 0x01;
pub const DEST_PLAIN: u8 = 0x02;
pub const DEST_LINK: u8 = 0x03;

/// An RNS Destination — a cryptographic endpoint.
#[derive(Debug)]
pub struct Destination {
    /// The owning identity keypair.
    keys: Keys,
    /// RNS destination hash (16 bytes).
    hash: RnsAddress,
    /// Destination type.
    dest_type: u8,
    /// Application name.
    app_name: String,
    /// Aspects (sub-addressing within the app).
    aspects: Vec<String>,
    /// Full expanded name.
    name: String,
    /// Maximum Transmission Unit.
    mtu: u16,
}

impl Destination {
    /// Create a new destination with a given identity and application name.
    ///
    /// The destination hash is computed from the identity and app aspects,
    /// matching Python RNS `Destination.__init__()`.
    pub fn new(
        keys: Keys,
        app_name: impl Into<String>,
        aspects: Vec<String>,
        dest_type: u8,
    ) -> Self {
        let app_name = app_name.into();
        let expanded = Self::expand_name(&app_name, &aspects);
        let hash = Self::compute_hash(&keys, &app_name, &aspects);
        let name = format!("{}.{}", expanded, hex::encode(hash.as_bytes()));

        Self {
            keys,
            hash,
            dest_type,
            app_name,
            aspects,
            name,
            mtu: 500, // default, negotiable via link
        }
    }

    /// Create a singleton destination (single recipient).
    pub fn singleton(keys: Keys, app_name: impl Into<String>, aspects: Vec<String>) -> Self {
        Self::new(keys, app_name, aspects, DEST_SINGLE)
    }

    /// The destination hash (16-byte RNS-compatible address).
    pub fn hash(&self) -> &RnsAddress {
        &self.hash
    }

    /// The identity keys for this destination.
    pub fn keys(&self) -> &Keys {
        &self.keys
    }

    /// The identity public key bytes.
    pub fn identity_key_bytes(&self) -> [u8; 32] {
        self.keys.identity_key_bytes()
    }

    /// The destination type.
    pub fn dest_type(&self) -> u8 {
        self.dest_type
    }

    /// The expanded human-readable name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The application name for this destination.
    pub fn app_name(&self) -> &str {
        &self.app_name
    }

    /// The aspects (sub-addressing) for this destination.
    pub fn aspects(&self) -> &[String] {
        &self.aspects
    }

    /// The MTU for this destination.
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Set the MTU.
    pub fn set_mtu(&mut self, mtu: u16) {
        self.mtu = mtu;
    }

    // ── Public helpers ──

    /// Expand an app name and aspects into a dot-separated string.
    /// Matches Python RNS `Destination.expand_name()`.
    pub fn expand_name(app_name: &str, aspects: &[String]) -> String {
        if aspects.is_empty() {
            app_name.to_string()
        } else {
            format!("{}.{}", app_name, aspects.join("."))
        }
    }

    // ── Private helpers ──

    /// Compute the destination hash, matching Python RNS `Destination.hash()`.
    fn compute_hash(keys: &Keys, app_name: &str, aspects: &[String]) -> RnsAddress {
        let full_name = Self::expand_name(app_name, aspects);

        // name_hash = SHA-256(full_name)[:NAME_HASH_LENGTH]
        let mut hasher = Sha256::new();
        hasher.update(full_name.as_bytes());
        let name_hash = &hasher.finalize()[..NAME_HASH_LENGTH];

        // dest_hash = SHA-256(name_hash + identity_hash)[:HASH_LENGTH]
        let rns_addr = keys.rns_address();
        let mut hasher2 = Sha256::new();
        hasher2.update(name_hash);
        hasher2.update(rns_addr.as_bytes());
        let result = hasher2.finalize();

        let mut addr_bytes = [0u8; HASH_LENGTH];
        addr_bytes.copy_from_slice(&result[..HASH_LENGTH]);
        RnsAddress::from_bytes(&addr_bytes).expect("16-byte hash")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destination_hash_is_16_bytes() {
        let keys = Keys::generate();
        let d = Destination::singleton(keys, "test", vec![]);
        assert_eq!(d.hash().as_bytes().len(), 16);
    }

    #[test]
    fn expanded_name_with_aspects() {
        let name = Destination::expand_name("matrix", &["room_42".into(), "user_alice".into()]);
        assert_eq!(name, "matrix.room_42.user_alice");
    }

    #[test]
    fn expanded_name_no_aspects() {
        let name = Destination::expand_name("lxmf", &[]);
        assert_eq!(name, "lxmf");
    }
}
