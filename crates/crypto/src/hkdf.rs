use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// HKDF-SHA256 key derivation (RFC 5869) as used by Python RNS.
///
/// Python RNS uses `salt=zeros(32)` and `context=b""` when none provided.
///
/// # Arguments
/// * `length` - Number of output bytes to produce.
/// * `derive_from` - Input keying material.
/// * `salt` - Optional salt; if None or empty, uses a 32-byte zero array.
/// * `context` - Optional context/info; if None, uses an empty slice.
pub fn hkdf_sha256(
    length: usize,
    derive_from: &[u8],
    salt: Option<&[u8]>,
    context: Option<&[u8]>,
) -> Vec<u8> {
    // Step 1: If salt is None or empty, use [0u8; 32]
    let salt = match salt {
        Some(s) if !s.is_empty() => s,
        _ => &[0u8; 32],
    };

    // Step 2: If context is None, use empty slice
    let context = context.unwrap_or(&[]);

    // Step 3: Extract — PRK = HMAC-SHA256(salt, derive_from)
    let mut mac = HmacSha256::new_from_slice(salt).expect("HMAC can take a key of any size");
    mac.update(derive_from);
    let prk = mac.finalize().into_bytes();

    // Step 4: Expand — T(0) = empty, T(i) = HMAC-SHA256(PRK, T(i-1) || context || i)
    let n = (length + 31) / 32; // ceil(length / 32)
    let mut output = Vec::with_capacity(n * 32);
    let mut t_prev: Vec<u8> = Vec::new();

    for i in 1..=n as u8 {
        let mut mac = HmacSha256::new_from_slice(&prk).expect("HMAC can take a key of any size");
        mac.update(&t_prev);
        mac.update(context);
        mac.update(&[i]);
        let t_i = mac.finalize().into_bytes();
        output.extend_from_slice(&t_i);
        t_prev = t_i.to_vec();
    }

    // Step 5: Return first `length` bytes
    output.truncate(length);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 5869 test vectors (Appendix A)

    #[test]
    fn test_rfc5869_test_case_1() {
        // Test Case 1: Basic test case with SHA-256
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();

        let okm = hkdf_sha256(42, &ikm, Some(&salt), Some(&info));

        let expected = hex::decode(
            "3cb25f25faacd57a90434f64d0362f2a\
             2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865",
        )
        .unwrap();

        assert_eq!(okm, expected);
    }

    #[test]
    fn test_rfc5869_test_case_2() {
        // Test Case 2: Longer input/output
        let ikm = hex::decode(
            "000102030405060708090a0b0c0d0e0f\
             101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f\
             303132333435363738393a3b3c3d3e3f\
             404142434445464748494a4b4c4d4e4f",
        )
        .unwrap();
        let salt = hex::decode(
            "606162636465666768696a6b6c6d6e6f\
             707172737475767778797a7b7c7d7e7f\
             808182838485868788898a8b8c8d8e8f\
             909192939495969798999a9b9c9d9e9f\
             a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        )
        .unwrap();
        let info = hex::decode(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf\
             c0c1c2c3c4c5c6c7c8c9cacbcccdcedf\
             d0d1d2d3d4d5d6d7d8d9dadbdcdddedf\
             e0e1e2e3e4e5e6e7e8e9eaebecedeeef\
             f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        )
        .unwrap();

        let okm = hkdf_sha256(82, &ikm, Some(&salt), Some(&info));

        let expected = hex::decode(
            "b11e398dc80327a1c8e7f78c596a4934\
             4f012eda2d4efad8a050cc4c19afa97c\
             59045a99cac7827271cb41c65e590e09\
             da3275600c2f09b8367793a9aca3db71\
             cc30c58179ec3e87c14c01d5c1f3434f\
             1d87",
        )
        .unwrap();

        assert_eq!(okm, expected);
    }

    #[test]
    fn test_rfc5869_test_case_3() {
        // Test Case 3: Zero-length salt/info
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();

        let okm = hkdf_sha256(42, &ikm, Some(&[]), Some(&[]));

        let expected = hex::decode(
            "8da4e775a563c18f715f802a063c5a31\
             b8a11f5c5ee1879ec3454e5f3c738d2d\
             9d201395faa4b61a96c8",
        )
        .unwrap();

        assert_eq!(okm, expected);
    }

    #[test]
    fn test_zeros_salt_empty_context() {
        let derive_from = b"test key material";
        let okm = hkdf_sha256(64, derive_from, None, None);
        assert_eq!(okm.len(), 64);

        // Should be deterministic
        let okm2 = hkdf_sha256(64, derive_from, None, None);
        assert_eq!(okm, okm2);

        // Different derive_from should produce different output
        let okm3 = hkdf_sha256(64, b"different material", None, None);
        assert_ne!(okm, okm3);
    }

    #[test]
    fn test_short_output() {
        let derive_from = b"key";
        let okm = hkdf_sha256(16, derive_from, None, None);
        assert_eq!(okm.len(), 16);
    }
}
