//! Proof generation and verification — RNS wire-compatible.
//!
//! Proofs are used during link establishment handshakes. The wire format
//! matches Python RNS `Identity.prove()` explicit mode:
//!
//! ```text
//! [packet_hash: 32 bytes SHA-256] [Ed25519 signature: 64 bytes]
//! ```
//!
//! Total: 96 bytes.
//!
//! Python RNS implicit mode (signature only, 64 bytes) is NOT supported
//! because it is deprecated in newer RNS versions.

use rsticulum_identity::{Keys, Signature};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Total proof size on the wire (explicit mode): 32 + 64 = 96 bytes.
pub const PROOF_LEN: usize = 96;

/// Hash portion: SHA-256 output.
pub const PROOF_HASH_LEN: usize = 32;

/// Signature portion: Ed25519 signature.
pub const PROOF_SIG_LEN: usize = 64;

// ── Error type ──

#[derive(Debug, Error)]
pub enum ProofError {
    #[error("invalid proof format: {0}")]
    InvalidFormat(String),
    #[error("proof serialization failed: {0}")]
    Serialization(String),
    #[error("signature mismatch")]
    SignatureMismatch,
    #[error("packet hash mismatch")]
    HashMismatch,
}

// ── Proof wire format ──

/// An RNS wire-compatible proof: packet_hash + Ed25519 signature.
///
/// Wire format: `[packet_hash(32)] [signature(64)]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    /// SHA-256 hash of the packet being proved (hashable part).
    pub packet_hash: [u8; PROOF_HASH_LEN],
    /// Ed25519 signature over the packet_hash.
    pub signature: [u8; PROOF_SIG_LEN],
}

impl Proof {
    /// Serialize to RNS wire format: 96 bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(PROOF_LEN);
        buf.extend_from_slice(&self.packet_hash);
        buf.extend_from_slice(&self.signature);
        buf
    }

    /// Deserialize from RNS wire format.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProofError> {
        if bytes.len() != PROOF_LEN {
            return Err(ProofError::InvalidFormat(format!(
                "expected {PROOF_LEN} bytes, got {}",
                bytes.len()
            )));
        }
        let mut packet_hash = [0u8; PROOF_HASH_LEN];
        let mut signature = [0u8; PROOF_SIG_LEN];
        packet_hash.copy_from_slice(&bytes[..PROOF_HASH_LEN]);
        signature.copy_from_slice(&bytes[PROOF_HASH_LEN..]);
        Ok(Self {
            packet_hash,
            signature,
        })
    }
}

// ── Generation and verification ──

/// Generate a proof for a message that will be used as packet_hash.
///
/// The `message` is hashed with SHA-256 to produce `packet_hash`,
/// then signed with Ed25519.
pub fn generate_proof(keys: &Keys, message: &[u8]) -> Proof {
    let packet_hash: [u8; 32] = Sha256::digest(message).into();
    let sig = keys.sign(message);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&sig.to_bytes());
    Proof {
        packet_hash,
        signature,
    }
}

/// Verify a proof against a known public key.
///
/// Recomputes `packet_hash = SHA-256(message)`, checks it matches
/// the proof's claimed hash, then verifies the Ed25519 signature.
pub fn verify_proof(keys: &Keys, message: &[u8], proof: &Proof) -> Result<(), ProofError> {
    // Recompute packet_hash
    let computed_hash: [u8; 32] = Sha256::digest(message).into();

    if computed_hash != proof.packet_hash {
        return Err(ProofError::HashMismatch);
    }

    let sig = Signature::from_bytes(&proof.signature);
    keys.verify(message, &sig)
        .map_err(|_| ProofError::SignatureMismatch)
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_generate_and_verify_roundtrip() {
        let keys = Keys::generate();
        let message = b"test-message-for-proof";

        let proof = generate_proof(&keys, message);
        assert_eq!(proof.to_bytes().len(), PROOF_LEN);

        verify_proof(&keys, message, &proof).expect("proof should verify");
    }

    #[test]
    fn proof_wire_format_roundtrip() {
        let keys = Keys::generate();
        let proof = generate_proof(&keys, b"wire-format-test");
        let bytes = proof.to_bytes();
        assert_eq!(bytes.len(), 96);

        let proof2 = Proof::from_bytes(&bytes).expect("deserialize");
        assert_eq!(proof.packet_hash, proof2.packet_hash);
        assert_eq!(proof.signature, proof2.signature);

        verify_proof(&keys, b"wire-format-test", &proof2).expect("roundtripped proof");
    }

    #[test]
    fn proof_wrong_message_fails() {
        let keys = Keys::generate();
        let proof = generate_proof(&keys, b"correct-message");

        let err = verify_proof(&keys, b"wrong-message", &proof).unwrap_err();
        assert!(matches!(err, ProofError::HashMismatch));
    }

    #[test]
    fn proof_wrong_key_fails() {
        let alice = Keys::generate();
        let bob = Keys::generate();
        let proof = generate_proof(&alice, b"shared-message");

        let err = verify_proof(&bob, b"shared-message", &proof).unwrap_err();
        assert!(matches!(err, ProofError::SignatureMismatch));
    }

    #[test]
    fn proof_tampered_signature_fails() {
        let keys = Keys::generate();
        let mut proof = generate_proof(&keys, b"tamper-me");
        proof.signature[0] ^= 0xFF;

        let err = verify_proof(&keys, b"tamper-me", &proof).unwrap_err();
        assert!(matches!(err, ProofError::SignatureMismatch));
    }

    #[test]
    fn proof_different_messages_produce_different_signatures() {
        let keys = Keys::generate();
        let p1 = generate_proof(&keys, b"msg-001");
        let p2 = generate_proof(&keys, b"msg-002");
        assert_ne!(p1.signature, p2.signature);
        assert_ne!(p1.packet_hash, p2.packet_hash);
    }

    #[test]
    fn proof_from_bytes_wrong_length() {
        assert!(Proof::from_bytes(&[0u8; 95]).is_err());
        assert!(Proof::from_bytes(&[0u8; 97]).is_err());
        assert!(Proof::from_bytes(&[]).is_err());
    }
}
