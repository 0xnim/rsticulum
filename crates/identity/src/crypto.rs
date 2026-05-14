//! Fernet encryption and key derivation — RNS wire-compatible.
//!
//! ## Key Derivation
//!
//! ```text
//! shared_secret = X25519(our_private, their_public)
//! derived_key   = HKDF-SHA256(shared_secret, salt=dest_hash, info="")
//! ```
//!
//! The 32-byte derived key is split: first 16 bytes = HMAC signing key,
//! last 16 bytes = AES-128-CBC encryption key.
//!
//! ## Token Format (stripped Fernet)
//!
//! ```text
//! IV(16 bytes) || PKCS7-padded AES-128-CBC ciphertext || HMAC-SHA256(32 bytes)
//! ```
//!
//! No version byte or timestamp — matches Python RNS `Token` class.
//!
//! ## Encrypt Flow
//!
//! ```text
//! 1. Generate ephemeral X25519 keypair
//! 2. Prepend ephemeral public key (32 bytes) to output
//! 3. ECDH(ephemeral_private, recipient_public) → shared secret
//! 4. HKDF-SHA256(shared_secret, salt=recipient_hash) → derived key
//! 5. Token.encrypt(plaintext, derived_key) → IV + ciphertext + HMAC
//! ```

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cbc::Decryptor as CbcDecrypt;
use cbc::Encryptor as CbcEncrypt;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret, StaticSecret};
use zeroize::Zeroize;

use crate::{ENCRYPTION_KEY_LEN, RNS_ADDRESS_LEN};

// --- CryptoError ---

/// Errors from cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("encryption failed")]
    Encryption,
    #[error("decryption: {0}")]
    Decryption(String),
    #[error("random number generation failed")]
    Rng,
}

type Aes128CbcEnc = CbcEncrypt<aes::Aes128>;
type Aes128CbcDec = CbcDecrypt<aes::Aes128>;
type HmacSha256 = Hmac<Sha256>;

// --- Constants ---

/// AES-128 key size (also HMAC signing key size since we split 32 → 16+16).
const AES_KEY_SIZE: usize = 16;

/// HMAC-SHA256 output size.
const HMAC_OUT_SIZE: usize = 32;

/// AES block size.
const AES_BLOCK_SIZE: usize = 16;

/// Total Fernet overhead: 16-byte IV + 32-byte HMAC.
pub const FERNET_OVERHEAD: usize = AES_BLOCK_SIZE + HMAC_OUT_SIZE;

/// Ephemeral public key length (X25519).
pub const EPHEMERAL_KEY_LEN: usize = 32;

/// Derived key length (HKDF-SHA256 output).
pub const DERIVED_KEY_LEN: usize = 32;

// --- DerivedKey ---

/// A 32-byte key derived via HKDF-SHA256 from an X25519 shared secret.
///
/// Split into two 16-byte halves for Fernet: signing key + encryption key.
#[derive(Clone, Debug)]
pub struct DerivedKey {
    /// Full 32-byte key material.
    key: [u8; DERIVED_KEY_LEN],
}

impl DerivedKey {
    /// Derive a key from a shared secret and optional salt.
    pub fn new(shared_key: &SharedSecret, salt: Option<&[u8]>) -> Self {
        let salt = salt.unwrap_or(&[0u8; 32]);
        let hk = Hkdf::<Sha256>::new(Some(salt), shared_key.as_bytes());
        let mut key = [0u8; DERIVED_KEY_LEN];
        hk.expand(b"", &mut key).expect("HKDF expand to 32 bytes");
        Self { key }
    }

    /// Derive from a private X25519 key and a public key.
    pub fn from_static(our_key: &StaticSecret, their_key: &PublicKey) -> Self {
        Self::new(&our_key.diffie_hellman(their_key), None)
    }

    /// Derive from an ephemeral X25519 key and a public key (consumes the ephemeral).
    pub fn from_ephemeral(ephemeral: EphemeralSecret, their_key: &PublicKey) -> Self {
        Self::new(&ephemeral.diffie_hellman(their_key), None)
    }

    /// Empty key (all zeros) — for placeholder use.
    pub fn empty() -> Self {
        Self {
            key: [0u8; DERIVED_KEY_LEN],
        }
    }

    pub fn as_bytes(&self) -> &[u8; DERIVED_KEY_LEN] {
        &self.key
    }

    /// HMAC signing key (first 16 bytes).
    pub fn sign_key(&self) -> &[u8] {
        &self.key[..AES_KEY_SIZE]
    }

    /// AES-128 encryption key (last 16 bytes).
    pub fn enc_key(&self) -> &[u8] {
        &self.key[AES_KEY_SIZE..]
    }
}

impl Zeroize for DerivedKey {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl Drop for DerivedKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// --- Fernet ---

/// A stripped-Fernet encryptor/decryptor (no version/timestamp bytes).
///
/// Wire-compatible with Python RNS `RNS.Cryptography.Token`.
pub struct Fernet {
    /// HMAC-SHA256 signing key (16 bytes).
    sign_key: [u8; AES_KEY_SIZE],
    /// AES-128-CBC encryption key (16 bytes).
    enc_key: [u8; AES_KEY_SIZE],
}

impl Fernet {
    /// Create a Fernet instance from a 32-byte derived key.
    pub fn from_derived_key(derived: &DerivedKey) -> Self {
        let mut sign_key = [0u8; AES_KEY_SIZE];
        let mut enc_key = [0u8; AES_KEY_SIZE];
        sign_key.copy_from_slice(derived.sign_key());
        enc_key.copy_from_slice(derived.enc_key());
        Self { sign_key, enc_key }
    }

    /// Encrypt plaintext, producing `IV(16) + ciphertext + HMAC(32)`.
    ///
    /// Returns the encrypted token bytes.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Generate random IV
        let mut iv = [0u8; AES_BLOCK_SIZE];
        use rand::RngCore;
        OsRng.fill_bytes(&mut iv);

        // PKCS7 padding + AES-128-CBC encrypt
        let padded_len = ((plaintext.len() / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
        let token_len = AES_BLOCK_SIZE + padded_len + HMAC_OUT_SIZE;
        let mut token = vec![0u8; token_len];

        token[..AES_BLOCK_SIZE].copy_from_slice(&iv);

        let ct_len = Aes128CbcEnc::new(
            aes::cipher::Key::<aes::Aes128>::from_slice(&self.enc_key),
            (&iv).into(),
        )
        .encrypt_padded_b2b_mut::<Pkcs7>(plaintext, &mut token[AES_BLOCK_SIZE..])
        .map_err(|_| CryptoError::Encryption)?
        .len();

        // HMAC-SHA256 over IV + ciphertext
        let mut mac =
            HmacSha256::new_from_slice(&self.sign_key).map_err(|_| CryptoError::Encryption)?;
        mac.update(&token[..AES_BLOCK_SIZE + ct_len]);
        let tag = mac.finalize().into_bytes();
        token[AES_BLOCK_SIZE + ct_len..].copy_from_slice(&tag);

        Ok(token)
    }

    /// Verify HMAC and decrypt a Fernet token.
    ///
    /// Returns the plaintext bytes.
    pub fn decrypt(&self, token: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if token.len() < FERNET_OVERHEAD + 1 {
            return Err(CryptoError::Decryption("token too short".into()));
        }

        let ct_end = token.len() - HMAC_OUT_SIZE;
        let expected_tag = &token[ct_end..];

        // Verify HMAC
        let mut mac = HmacSha256::new_from_slice(&self.sign_key)
            .map_err(|_| CryptoError::Decryption("hmac init failed".into()))?;
        mac.update(&token[..ct_end]);
        mac.verify_slice(expected_tag)
            .map_err(|_| CryptoError::Decryption("hmac verification failed".into()))?;

        // Decrypt
        let iv: &[u8; AES_BLOCK_SIZE] = token[..AES_BLOCK_SIZE]
            .try_into()
            .map_err(|_| CryptoError::Decryption("invalid IV".into()))?;

        let ciphertext = &token[AES_BLOCK_SIZE..ct_end];
        let mut buf = vec![0u8; ciphertext.len()];

        let pt_len = Aes128CbcDec::new(
            aes::cipher::Key::<aes::Aes128>::from_slice(&self.enc_key),
            iv.into(),
        )
        .decrypt_padded_b2b_mut::<Pkcs7>(ciphertext, &mut buf)
        .map_err(|_| CryptoError::Decryption("decryption failed".into()))?
        .len();

        buf.truncate(pt_len);
        Ok(buf)
    }
}

impl Zeroize for Fernet {
    fn zeroize(&mut self) {
        self.sign_key.zeroize();
        self.enc_key.zeroize();
    }
}

impl Drop for Fernet {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// --- Public API on Keys ---

use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha512};
use rsticulum_crypto::{hkdf_sha256, Token};

use crate::Keys;

impl Keys {
    /// Encrypt plaintext for a recipient identified by their X25519 public key
    /// and RNS address hash (used as HKDF salt).
    ///
    /// Returns `ephemeral_public_key(32) || fernet_token`.
    pub fn encrypt_for(
        &self,
        recipient_public: &[u8; ENCRYPTION_KEY_LEN],
        recipient_hash: &[u8; RNS_ADDRESS_LEN],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let their_pub = PublicKey::from(*recipient_public);
        let ephemeral = EphemeralSecret::random_from_rng(OsRng);
        let ephemeral_pub = PublicKey::from(&ephemeral);
        let derived = DerivedKey::new(&ephemeral.diffie_hellman(&their_pub), Some(recipient_hash));
        let fernet = Fernet::from_derived_key(&derived);
        let token = fernet.encrypt(plaintext)?;

        let mut result = Vec::with_capacity(EPHEMERAL_KEY_LEN + token.len());
        result.extend_from_slice(ephemeral_pub.as_bytes());
        result.extend_from_slice(&token);

        Ok(result)
    }

    /// Decrypt ciphertext produced by [`Keys::encrypt_for`].
    ///
    /// The ciphertext must be `ephemeral_public_key(32) || fernet_token`.
    /// Uses this identity's RNS address hash as the HKDF salt.
    pub fn decrypt_from(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.len() < EPHEMERAL_KEY_LEN + FERNET_OVERHEAD + 1 {
            return Err(CryptoError::Decryption(
                "ciphertext too short for ephemeral key + token".into(),
            ));
        }

        let their_ephemeral: [u8; 32] = ciphertext[..EPHEMERAL_KEY_LEN]
            .try_into()
            .map_err(|_| CryptoError::Decryption("invalid ephemeral key".into()))?;
        let token = &ciphertext[EPHEMERAL_KEY_LEN..];

        let shared = self
            .encryption_secret()
            .diffie_hellman(&PublicKey::from(their_ephemeral));
        // Use our own RNS address as salt — matches encrypt_for which uses
        // the recipient's hash (which is us).
        let derived = DerivedKey::new(&shared, Some(self.rns_address().as_bytes()));
        let fernet = Fernet::from_derived_key(&derived);
        fernet.decrypt(token)
    }
}

// --- X25519 Key Exchange ---

/// Generate an ephemeral X25519 keypair.
pub fn generate_ephemeral_x25519() -> (EphemeralSecret, PublicKey) {
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

/// Convert Ed25519 public key bytes (32 bytes) to X25519 public key.
///
/// This is the standard Curve25519 bijection: Ed25519 uses twisted Edwards,
/// X25519 uses Montgomery form. The conversion uses `VerifyingKey::to_montgomery()`.
pub fn ed25519_pub_to_x25519(ed25519_pub: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    let verifying_key = VerifyingKey::from_bytes(ed25519_pub)
        .map_err(|_| CryptoError::Encryption)?;
    Ok(verifying_key.to_montgomery().to_bytes())
}

/// Convert Ed25519 secret key seed bytes (32 bytes) to X25519 private key.
///
/// Ed25519 secret = SHA-512(seed), first 32 bytes are the scalar.
/// Clamp the scalar per RFC 7748.
pub fn ed25519_secret_to_x25519(ed25519_seed: &[u8; 32]) -> [u8; 32] {
    // SHA-512(seed) → 64 bytes, take first 32 as scalar
    let mut hasher = Sha512::new();
    hasher.update(ed25519_seed);
    let hash = hasher.finalize();
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&hash[..32]);

    // Clamp per RFC 7748:
    // scalar[0] &= 248;  // clear bits 0,1,2
    // scalar[31] &= 127; // clear bit 7 (256th bit)
    // scalar[31] |= 64;  // set bit 6 (255th bit)
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;

    scalar
}

/// Perform ECDH: compute shared secret from an ephemeral X25519 keypair.
pub fn ecdh(secret: EphemeralSecret, public: &PublicKey) -> [u8; 32] {
    let shared = secret.diffie_hellman(public);
    let mut out = [0u8; 32];
    out.copy_from_slice(shared.as_bytes());
    out
}

// --- Packet Encryption Pipeline ---

/// Encrypt a plaintext payload for a recipient with the given Ed25519 keypair.
///
/// Returns the full encrypted token including ephemeral public key.
/// Format: `[ephemeral_x25519_pub(32)] [IV(16)] [ciphertext] [HMAC-SHA256(32)]`
pub fn encrypt_packet(
    plaintext: &[u8],
    _sender_keys: &Keys,
    recipient_ed25519_pub: &[u8; 32],
    recipient_hash: &[u8; RNS_ADDRESS_LEN],
) -> Result<Vec<u8>, CryptoError> {
    // 1. Generate ephemeral X25519 keypair
    let (ephemeral_secret, ephemeral_pub) = generate_ephemeral_x25519();

    // 2. Convert recipient's Ed25519 pubkey → X25519 pubkey
    let recipient_x25519_pub = ed25519_pub_to_x25519(recipient_ed25519_pub)?;
    let recipient_x25519_pubkey = PublicKey::from(recipient_x25519_pub);

    // 3. ECDH → shared_secret (32 bytes)
    let shared_secret = ecdh(ephemeral_secret, &recipient_x25519_pubkey);

    // 4. HKDF-SHA256(shared_secret, salt=recipient_hash) → derived_key (32 bytes)
    let derived_key = hkdf_sha256(32, &shared_secret, Some(recipient_hash), None);
    let key: [u8; 32] = derived_key[..32].try_into().unwrap();

    // 5. Token.encrypt → token
    let token = Token::encrypt(plaintext, &key);

    // 6. Return [ephemeral_x25519_pub] || token
    let mut result = Vec::with_capacity(32 + token.len());
    result.extend_from_slice(ephemeral_pub.as_bytes());
    result.extend_from_slice(&token);
    Ok(result)
}

/// Decrypt a packet encrypted by [`encrypt_packet`].
///
/// The encrypted data is: `[ephemeral_x25519_pub(32)] [token]`
pub fn decrypt_packet(
    encrypted: &[u8],
    recipient_keys: &Keys,
    recipient_hash: &[u8; RNS_ADDRESS_LEN],
) -> Result<Vec<u8>, CryptoError> {
    // 1. Extract ephemeral_x25519_pub (first 32 bytes)
    if encrypted.len() < 32 + 1 {
        return Err(CryptoError::Decryption("ciphertext too short".into()));
    }
    let ephemeral_bytes: [u8; 32] = encrypted[..32]
        .try_into()
        .map_err(|_| CryptoError::Decryption("invalid ephemeral key".into()))?;
    let token_bytes = &encrypted[32..];

    let ephemeral_pub = PublicKey::from(ephemeral_bytes);

    // 2. Convert recipient's Ed25519 secret → X25519 private key (clamped)
    let ed25519_seed = recipient_keys.signing_key().to_bytes();
    let x25519_private = ed25519_secret_to_x25519(&ed25519_seed);

    // 3. ECDH(clamped_secret, ephemeral_pub) → shared_secret
    let clamped_secret = StaticSecret::from(x25519_private);
    let shared = clamped_secret.diffie_hellman(&ephemeral_pub);

    // 4. HKDF(shared_secret, salt=recipient_hash) → derived_key
    let derived_key = hkdf_sha256(32, shared.as_bytes(), Some(recipient_hash), None);
    let key: [u8; 32] = derived_key[..32].try_into().unwrap();

    // 5. Token.decrypt(token, derived_key) → plaintext
    Token::decrypt(token_bytes, &key)
        .map_err(|e| CryptoError::Decryption(e.to_string()))
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;

    #[test]
    fn derived_key_is_32_bytes() {
        let keys = Keys::generate();
        let their_keys = Keys::generate();
        let dk = DerivedKey::from_static(
            keys.encryption_secret(),
            &PublicKey::from(their_keys.encryption_key()),
        );
        assert_eq!(dk.as_bytes().len(), 32);
    }

    #[test]
    fn fernet_roundtrip() {
        let dk = DerivedKey::new(
            &EphemeralSecret::random_from_rng(OsRng)
                .diffie_hellman(&PublicKey::from(&EphemeralSecret::random_from_rng(OsRng))),
            None,
        );
        let fernet = Fernet::from_derived_key(&dk);

        let msg = b"hello world test message";
        let token = fernet.encrypt(msg).expect("encrypt");
        assert_eq!(token.len(), 16 + 32 + 32); // IV(16) + padded(32) + HMAC(32)

        let decrypted = fernet.decrypt(&token).expect("decrypt");
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn fernet_hmac_tamper_detected() {
        let dk = DerivedKey::new(
            &EphemeralSecret::random_from_rng(OsRng)
                .diffie_hellman(&PublicKey::from(&EphemeralSecret::random_from_rng(OsRng))),
            None,
        );
        let fernet = Fernet::from_derived_key(&dk);

        let msg = b"tamper test";
        let mut token = fernet.encrypt(msg).expect("encrypt");

        // Flip a bit in the ciphertext (between IV and HMAC)
        token[20] ^= 0x01;

        assert!(fernet.decrypt(&token).is_err());
    }

    #[test]
    fn encrypt_for_decrypt_from_roundtrip() {
        let alice = Keys::generate();
        let bob = Keys::generate();

        let msg = b"private message from alice to bob";
        let rns_addr = bob.rns_address();

        let ciphertext = alice
            .encrypt_for(&bob.encryption_key(), rns_addr.as_bytes(), msg)
            .expect("encrypt");
        assert_eq!(ciphertext.len(), 128); // eph_pub(32) + IV(16) + padded(48) + HMAC(32)

        let decrypted = bob.decrypt_from(&ciphertext).expect("decrypt");
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn encrypt_for_wrong_recipient_fails() {
        let alice = Keys::generate();
        let bob = Keys::generate();
        let eve = Keys::generate();

        let msg = b"secret for bob only";
        let ciphertext = alice
            .encrypt_for(&bob.encryption_key(), bob.rns_address().as_bytes(), msg)
            .expect("encrypt");

        // Eve tries to decrypt — should fail
        assert!(eve.decrypt_from(&ciphertext).is_err());
    }

    #[test]
    fn derived_key_different_per_salt() {
        let k1 = Keys::generate();
        let k2 = Keys::generate();

        let dk_a = DerivedKey::from_static(
            k1.encryption_secret(),
            &PublicKey::from(k2.encryption_key()),
        );
        // Same shared secret, different salt → different derived key
        let dk_b = DerivedKey::new(
            &k1.encryption_secret()
                .diffie_hellman(&PublicKey::from(k2.encryption_key())),
            Some(b"different salt"),
        );

        assert_ne!(dk_a.as_bytes(), dk_b.as_bytes());
    }

    #[test]
    fn empty_message_roundtrip() {
        let alice = Keys::generate();
        let bob = Keys::generate();

        let ciphertext = alice
            .encrypt_for(&bob.encryption_key(), bob.rns_address().as_bytes(), b"")
            .expect("encrypt empty");

        let decrypted = bob.decrypt_from(&ciphertext).expect("decrypt empty");
        assert!(decrypted.is_empty());
    }

    #[test]
    fn large_message_roundtrip() {
        let alice = Keys::generate();
        let bob = Keys::generate();
        let msg = vec![0xAB; 1024];

        let ciphertext = alice
            .encrypt_for(&bob.encryption_key(), bob.rns_address().as_bytes(), &msg)
            .expect("encrypt large");

        let decrypted = bob.decrypt_from(&ciphertext).expect("decrypt large");
        assert_eq!(decrypted, msg);
    }

    // --- Ed25519 ↔ X25519 key conversion tests ---

    #[test]
    fn ed25519_pub_to_x25519_conversion() {
        let keys = Keys::generate();
        let ed_pub = keys.identity_key_bytes();
        let x25519_pub = ed25519_pub_to_x25519(&ed_pub).expect("conversion");
        assert_eq!(x25519_pub.len(), 32);
    }

    #[test]
    fn ed25519_pub_to_x25519_is_deterministic() {
        let keys = Keys::generate();
        let ed_pub = keys.identity_key_bytes();
        let x1 = ed25519_pub_to_x25519(&ed_pub).expect("first");
        let x2 = ed25519_pub_to_x25519(&ed_pub).expect("second");
        assert_eq!(x1, x2);
    }

    #[test]
    fn ed25519_secret_to_x25519_is_clamped() {
        let keys = Keys::generate();
        let seed = keys.signing_key().to_bytes();
        let x25519_priv = ed25519_secret_to_x25519(&seed);

        // Verify clamping: bits 0,1,2 of first byte are cleared
        assert_eq!(x25519_priv[0] & 0b111, 0);
        // Verify clamping: bit 7 of last byte is clear, bit 6 is set
        assert_eq!(x25519_priv[31] & 0x80, 0);
        assert_eq!(x25519_priv[31] & 0x40, 0x40);
    }

    #[test]
    fn ecdh_both_sides_compute_same_secret() {
        // Alice's ephemeral + Bob's static = Bob's static + Alice's ephemeral
        let (alice_eph_secret, alice_eph_pub) = generate_ephemeral_x25519();
        let bob_static = StaticSecret::random_from_rng(OsRng);
        let bob_pub = PublicKey::from(&bob_static);

        let shared_alice = ecdh(alice_eph_secret, &bob_pub);
        let shared_bob_bytes = bob_static.diffie_hellman(&alice_eph_pub);
        let mut shared_bob = [0u8; 32];
        shared_bob.copy_from_slice(shared_bob_bytes.as_bytes());

        assert_eq!(shared_alice, shared_bob);
    }

    // --- Packet encryption pipeline tests ---

    #[test]
    fn encrypt_decrypt_packet_roundtrip() {
        let sender = Keys::generate();
        let recipient = Keys::generate();
        let hash = *recipient.rns_address().as_bytes();

        let msg = b"secret packet payload for delivery";
        let encrypted =
            encrypt_packet(msg, &sender, &recipient.identity_key_bytes(), &hash)
                .expect("encrypt_packet");
        assert!(encrypted.len() > 32);

        let decrypted =
            decrypt_packet(&encrypted, &recipient, &hash).expect("decrypt_packet");
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn decrypt_packet_wrong_recipient_fails() {
        let sender = Keys::generate();
        let alice = Keys::generate();
        let eve = Keys::generate();
        let hash = *alice.rns_address().as_bytes();

        let msg = b"secret for alice only";
        let encrypted =
            encrypt_packet(msg, &sender, &alice.identity_key_bytes(), &hash)
                .expect("encrypt_packet");

        // Eve tries to decrypt — should fail (different key)
        let eve_hash = *eve.rns_address().as_bytes();
        assert!(decrypt_packet(&encrypted, &eve, &eve_hash).is_err());
    }

    #[test]
    fn encrypt_decrypt_packet_empty_payload() {
        let sender = Keys::generate();
        let recipient = Keys::generate();
        let hash = *recipient.rns_address().as_bytes();

        let encrypted =
            encrypt_packet(b"", &sender, &recipient.identity_key_bytes(), &hash)
                .expect("encrypt empty");
        let decrypted =
            decrypt_packet(&encrypted, &recipient, &hash).expect("decrypt empty");
        assert!(decrypted.is_empty());
    }

    #[test]
    fn encrypt_decrypt_packet_large_payload() {
        let sender = Keys::generate();
        let recipient = Keys::generate();
        let hash = *recipient.rns_address().as_bytes();
        let msg = vec![0xCD; 4096];

        let encrypted =
            encrypt_packet(&msg, &sender, &recipient.identity_key_bytes(), &hash)
                .expect("encrypt large");
        let decrypted =
            decrypt_packet(&encrypted, &recipient, &hash).expect("decrypt large");
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn encrypt_packet_multiplicity_each_unique() {
        let sender = Keys::generate();
        let recipient = Keys::generate();
        let hash = *recipient.rns_address().as_bytes();

        let enc1 = encrypt_packet(b"msg1", &sender, &recipient.identity_key_bytes(), &hash)
            .expect("enc1");
        let enc2 = encrypt_packet(b"msg1", &sender, &recipient.identity_key_bytes(), &hash)
            .expect("enc2");
        assert_ne!(enc1, enc2);
    }

    #[test]
    fn decrypt_packet_tampered_fails() {
        let sender = Keys::generate();
        let recipient = Keys::generate();
        let hash = *recipient.rns_address().as_bytes();

        let msg = b"tamper me";
        let mut encrypted =
            encrypt_packet(msg, &sender, &recipient.identity_key_bytes(), &hash)
                .expect("encrypt");

        // Tamper with a byte in the token section (after ephemeral key)
        encrypted[40] ^= 0x01;

        assert!(decrypt_packet(&encrypted, &recipient, &hash).is_err());
    }
}
