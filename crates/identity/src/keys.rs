use crate::address::Address;
use crate::rns_address::RnsAddress;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;

/// A keypair bundle: Ed25519 (signing/identity) + X25519 (encryption).
pub struct Keys {
    signing: SigningKey,
    encryption: x25519_dalek::StaticSecret,
}

impl Keys {
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut OsRng),
            encryption: x25519_dalek::StaticSecret::random_from_rng(OsRng),
        }
    }

    pub fn identity_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }
    pub fn identity_key_bytes(&self) -> [u8; crate::IDENTITY_KEY_LEN] {
        self.identity_key().to_bytes()
    }
    pub fn encryption_key(&self) -> [u8; crate::ENCRYPTION_KEY_LEN] {
        x25519_dalek::PublicKey::from(&self.encryption).to_bytes()
    }

    /// Sign a message with the Ed25519 signing key.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing.sign(message)
    }

    /// Verify an Ed25519 signature against this identity's public key.
    pub fn verify(
        &self,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), ed25519_dalek::SignatureError> {
        self.signing.verify(message, signature)
    }

    /// 32-byte BLAKE3 address (our internal addressing).
    pub fn address(&self) -> Address {
        Address::from_identity_key(&self.identity_key_bytes())
    }

    /// 16-byte RNS-compatible address (wire protocol).
    pub fn rns_address(&self) -> RnsAddress {
        RnsAddress::from_identity_key(&self.identity_key_bytes())
    }

    pub(crate) fn signing_key(&self) -> &SigningKey {
        &self.signing
    }
    #[allow(dead_code)] // used by Phase 3 transport
    pub fn encryption_secret(&self) -> &x25519_dalek::StaticSecret {
        &self.encryption
    }
}

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keys")
            .field("rns", &hex::encode(self.rns_address().as_bytes()))
            .finish_non_exhaustive()
    }
}
