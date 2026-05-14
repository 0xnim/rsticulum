use crate::{IdentityError, RNS_ADDRESS_LEN};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// A 16-byte Reticulum-compatible address (truncated SHA-256 of Ed25519 pubkey).
///
/// Wire-compatible with Python RNS destination hashes (TRUNCATED_HASHLENGTH = 128 bits).
/// This is a locator — identity verification uses the full 32-byte public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(into = "String", try_from = "&str")]
pub struct RnsAddress([u8; RNS_ADDRESS_LEN]);

impl RnsAddress {
    /// Derive an RNS address from an Ed25519 public key.
    /// RNS uses: SHA-256(pubkey)[:16]
    pub fn from_identity_key(key: &[u8; crate::IDENTITY_KEY_LEN]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(key);
        let result = hasher.finalize();
        let mut bytes = [0u8; RNS_ADDRESS_LEN];
        bytes.copy_from_slice(&result[..RNS_ADDRESS_LEN]);
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; RNS_ADDRESS_LEN] {
        &self.0
    }
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        let arr: [u8; RNS_ADDRESS_LEN] =
            bytes.try_into().map_err(|_| IdentityError::InvalidLength {
                name: "RnsAddress",
                expected: RNS_ADDRESS_LEN,
                got: bytes.len(),
            })?;
        Ok(Self(arr))
    }
}

impl fmt::Display for RnsAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for RnsAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RnsAddr({})", hex::encode(self.0))
    }
}

impl From<RnsAddress> for String {
    fn from(a: RnsAddress) -> Self {
        a.to_string()
    }
}

impl TryFrom<&str> for RnsAddress {
    type Error = IdentityError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let bytes = hex::decode(s).map_err(|e| IdentityError::Serde(e.to_string()))?;
        Self::from_bytes(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn matches_rns_derivation() {
        let mut csprng = OsRng;
        let signing = SigningKey::generate(&mut csprng);
        let pk = signing.verifying_key().to_bytes();

        // Our derivation
        let ours = RnsAddress::from_identity_key(&pk);

        // Python RNS does: SHA-256(pk)[:16]
        let mut hasher = Sha256::new();
        hasher.update(pk);
        let expected = &hasher.finalize()[..16];

        assert_eq!(ours.as_bytes(), expected);
        assert_eq!(ours.as_bytes().len(), 16);
    }

    #[test]
    fn deterministic() {
        let key = [0xAB; crate::IDENTITY_KEY_LEN];
        assert_eq!(
            RnsAddress::from_identity_key(&key),
            RnsAddress::from_identity_key(&key)
        );
    }

    #[test]
    fn hex_roundtrip() {
        let key = [0x42; crate::IDENTITY_KEY_LEN];
        let a = RnsAddress::from_identity_key(&key);
        let s = a.to_string();
        assert_eq!(s.len(), 32);
        let a2: RnsAddress = s.as_str().try_into().unwrap();
        assert_eq!(a, a2);
    }
}
