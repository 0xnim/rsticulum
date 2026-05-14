use crate::{IdentityError, Keys, ENCRYPTION_KEY_LEN, IDENTITY_KEY_LEN, SIGNATURE_LEN};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_CLOCK_DRIFT: Duration = Duration::from_secs(300);

/// Signed identity announcement for key exchange on the network.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityAnnounce {
    #[serde(with = "serde_bytes")]
    identity_key: [u8; IDENTITY_KEY_LEN],
    #[serde(with = "serde_bytes")]
    encryption_key: [u8; ENCRYPTION_KEY_LEN],
    created_at: u64,
    #[serde(with = "serde_bytes")]
    signature: [u8; SIGNATURE_LEN],
}

impl IdentityAnnounce {
    pub fn sign(keys: &Keys) -> Self {
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let payload = Self::payload(
            &keys.identity_key_bytes(),
            &keys.encryption_key(),
            created_at,
        );
        let sig = keys.signing_key().sign(&payload);
        Self {
            identity_key: keys.identity_key_bytes(),
            encryption_key: keys.encryption_key(),
            created_at,
            signature: sig.to_bytes(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("IdentityAnnounce serialization")
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, IdentityError> {
        bincode::deserialize(data).map_err(|e| IdentityError::Serde(e.to_string()))
    }

    pub fn verify(&self) -> Result<(), IdentityError> {
        let vk = VerifyingKey::from_bytes(&self.identity_key)
            .map_err(|_| IdentityError::SignatureMismatch)?;
        let sig = Signature::from_bytes(&self.signature);
        let payload = Self::payload(&self.identity_key, &self.encryption_key, self.created_at);
        vk.verify(&payload, &sig)
            .map_err(|_| IdentityError::SignatureMismatch)?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let delta = (self.created_at as i64) - (now as i64);
        if delta.unsigned_abs() > MAX_CLOCK_DRIFT.as_secs() {
            return Err(IdentityError::ClockDrift {
                delta_secs: delta,
                threshold_secs: MAX_CLOCK_DRIFT.as_secs(),
            });
        }
        Ok(())
    }

    pub fn identity_key(&self) -> &[u8; IDENTITY_KEY_LEN] {
        &self.identity_key
    }
    pub fn encryption_key(&self) -> &[u8; ENCRYPTION_KEY_LEN] {
        &self.encryption_key
    }
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    fn payload(ik: &[u8; IDENTITY_KEY_LEN], ek: &[u8; ENCRYPTION_KEY_LEN], ts: u64) -> Vec<u8> {
        let mut buf = Vec::with_capacity(IDENTITY_KEY_LEN + ENCRYPTION_KEY_LEN + 8);
        buf.extend_from_slice(ik);
        buf.extend_from_slice(ek);
        buf.extend_from_slice(&ts.to_le_bytes());
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let k = Keys::generate();
        let ann = IdentityAnnounce::sign(&k);
        assert!(ann.verify().is_ok());
    }

    #[test]
    fn tampered_fails() {
        let k = Keys::generate();
        let mut ann = IdentityAnnounce::sign(&k);
        ann.encryption_key[0] ^= 1;
        assert!(ann.verify().is_err());
    }
}
