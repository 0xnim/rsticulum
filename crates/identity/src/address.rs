use crate::{IdentityError, ADDRESS_LEN};
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(into = "String", try_from = "&str")]
pub struct Address([u8; ADDRESS_LEN]);

impl Address {
    pub fn from_identity_key(key: &[u8; crate::IDENTITY_KEY_LEN]) -> Self {
        let hash = blake3::hash(key);
        let mut bytes = [0u8; ADDRESS_LEN];
        bytes.copy_from_slice(hash.as_bytes());
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; ADDRESS_LEN] {
        &self.0
    }
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        let arr: [u8; ADDRESS_LEN] =
            bytes.try_into().map_err(|_| IdentityError::InvalidLength {
                name: "Address",
                expected: ADDRESS_LEN,
                got: bytes.len(),
            })?;
        Ok(Self(arr))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({})", hex::encode(self.0))
    }
}

impl From<Address> for String {
    fn from(a: Address) -> Self {
        a.to_string()
    }
}

impl TryFrom<&str> for Address {
    type Error = IdentityError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let bytes = hex::decode(s).map_err(|e| IdentityError::Serde(e.to_string()))?;
        Self::from_bytes(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let key = [0xAB; crate::IDENTITY_KEY_LEN];
        assert_eq!(
            Address::from_identity_key(&key),
            Address::from_identity_key(&key)
        );
    }

    #[test]
    fn hex_roundtrip() {
        let key = [0x42; crate::IDENTITY_KEY_LEN];
        let a = Address::from_identity_key(&key);
        let a2: Address = a.to_string().as_str().try_into().unwrap();
        assert_eq!(a, a2);
    }
}
