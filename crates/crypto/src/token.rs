use aes::Aes128;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;
type Aes128CbcEnc = cbc::Encryptor<Aes128>;
type Aes128CbcDec = cbc::Decryptor<Aes128>;

/// Errors that can occur during token decryption.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TokenError {
    #[error("token is too short (must be at least 48 bytes)")]
    TooShort,

    #[error("HMAC verification failed")]
    BadHmac,

    #[error("decryption failed (bad padding or ciphertext)")]
    DecryptionFailed,
}

/// RNS Token — simplified Fernet-style authenticated encryption.
///
/// Wire format: `[IV(16)] [ciphertext] [HMAC-SHA256(32)]`
/// Overhead = 48 bytes.
pub struct Token;

impl Token {
    /// Encrypt plaintext with AES-128-CBC using the given 32-byte key.
    ///
    /// `key[0..16]` = HMAC signing key, `key[16..32]` = AES encryption key.
    pub fn encrypt(plaintext: &[u8], key: &[u8; 32]) -> Vec<u8> {
        let signing_key = &key[..16];
        let encryption_key = &key[16..];

        // 1. Generate random 16-byte IV
        let mut iv = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut iv);

        // 2. PKCS7 pad and AES-128-CBC encrypt
        let cipher = Aes128CbcEnc::new(encryption_key.into(), &iv.into());

        // Allocate buffer: plaintext + max padding (one block)
        let mut buf = vec![0u8; plaintext.len() + 16];
        buf[..plaintext.len()].copy_from_slice(plaintext);
        let ciphertext_len = cipher
            .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
            .expect("buffer is large enough for PKCS7 padding")
            .len();
        buf.truncate(ciphertext_len);
        let ciphertext = buf;

        // 3. Compute HMAC-SHA256(signing_key, IV || ciphertext)
        let mut mac =
            HmacSha256::new_from_slice(signing_key).expect("HMAC can take a key of any size");
        mac.update(&iv);
        mac.update(&ciphertext);
        let hmac = mac.finalize().into_bytes();

        // 4. Return IV || ciphertext || hmac
        let mut token = Vec::with_capacity(16 + ciphertext.len() + 32);
        token.extend_from_slice(&iv);
        token.extend_from_slice(&ciphertext);
        token.extend_from_slice(&hmac);
        token
    }

    /// Decrypt token, verifying HMAC first. Returns plaintext or error.
    pub fn decrypt(token: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, TokenError> {
        // Token must be at least 48 bytes: 16 (IV) + 0 (min ciphertext) + 32 (HMAC)
        if token.len() < 48 {
            return Err(TokenError::TooShort);
        }

        let ciphertext_len = token.len() - 48;
        let iv = &token[..16];
        let ciphertext = &token[16..16 + ciphertext_len];
        let expected_hmac = &token[16 + ciphertext_len..];

        // 1. Verify HMAC
        let signing_key = &key[..16];
        let mut mac =
            HmacSha256::new_from_slice(signing_key).expect("HMAC can take a key of any size");
        mac.update(iv);
        mac.update(ciphertext);
        let computed_hmac = mac.finalize().into_bytes();

        if computed_hmac.as_slice() != expected_hmac {
            return Err(TokenError::BadHmac);
        }

        // 2. Decrypt
        let encryption_key = &key[16..];
        let cipher = Aes128CbcDec::new(encryption_key.into(), iv.into());

        let mut buf = ciphertext.to_vec();
        let plaintext = cipher
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .map_err(|_| TokenError::DecryptionFailed)?;

        Ok(plaintext.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        for i in 0..32 {
            key[i] = i as u8;
        }
        key
    }

    #[test]
    fn test_roundtrip() {
        let key = test_key();
        let plaintext = b"Hello, RNS Token!";
        let token = Token::encrypt(plaintext, &key);
        let decrypted = Token::decrypt(&token, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_empty_plaintext() {
        let key = test_key();
        let plaintext = b"";
        let token = Token::encrypt(plaintext, &key);
        let decrypted = Token::decrypt(&token, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_large_payload() {
        let key = test_key();
        let plaintext = vec![0xABu8; 4096];
        let token = Token::encrypt(&plaintext, &key);
        let decrypted = Token::decrypt(&token, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key = test_key();
        let mut wrong_key = test_key();
        wrong_key[0] ^= 1;

        let plaintext = b"secret";
        let token = Token::encrypt(plaintext, &key);
        let result = Token::decrypt(&token, &wrong_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_hmac_fails() {
        let key = test_key();
        let plaintext = b"secret";
        let mut token = Token::encrypt(plaintext, &key);
        // Flip a bit in the HMAC
        let last = token.len() - 1;
        token[last] ^= 1;
        let result = Token::decrypt(&token, &key);
        assert_eq!(result, Err(TokenError::BadHmac));
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = test_key();
        let plaintext = b"secret message here";
        let mut token = Token::encrypt(plaintext, &key);
        // Flip a bit in the ciphertext (at byte 16, just after IV)
        token[16] ^= 1;
        let result = Token::decrypt(&token, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_token_too_short() {
        let key = test_key();
        let result = Token::decrypt(&[0u8; 32], &key);
        assert_eq!(result, Err(TokenError::TooShort));
    }
}
