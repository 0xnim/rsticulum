//! ICN name type — hybrid routing-prefix + content-hash naming.
//!
//! Every name starts with a 32-byte producer hash (BLAKE3 of public key).
//! Additional path components follow. An optional trailing 32-byte content
//! hash self-certifies the content.
//!
//! ## Wire format
//! ```text
//! [count:1][len1:1][bytes1...][len2:1][bytes2...][0xFF if hash][hash:32]
//! ```
//!
//! ## Display format
//! ```text
//! /a1b2c3...d4a7/app/chat?blake3=e7f8...
//! ```

use std::fmt;

/// An error that can occur when parsing a name from bytes.
#[derive(Debug, thiserror::Error)]
pub enum NameError {
    #[error("name has no components")]
    Empty,
    #[error("component length exceeds 255 bytes")]
    ComponentTooLong,
    #[error("buffer too short: expected at least {expected} bytes, got {got}")]
    BufferTooShort { expected: usize, got: usize },
    #[error("missing content hash discriminator")]
    MissingHashDiscriminator,
}

/// Maximum number of components in a name.
pub const MAX_COMPONENTS: usize = 32;

/// Discriminator byte that signals a trailing content hash.
const HASH_DISCRIMINATOR: u8 = 0xFF;

/// A named-data name: routable prefix + optional content hash.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Name {
    pub(crate) components: Vec<Vec<u8>>,
    pub(crate) content_hash: Option<[u8; 32]>,
}

impl Name {
    /// Create a new name with the given producer hash and path components.
    ///
    /// The producer hash is always the first component.
    pub fn new(producer_hash: [u8; 32], path: &[&[u8]]) -> Self {
        let mut components = Vec::with_capacity(1 + path.len());
        components.push(producer_hash.to_vec());
        for p in path {
            components.push(p.to_vec());
        }
        Name {
            components,
            content_hash: None,
        }
    }

    /// Attach a content hash to this name.
    pub fn with_content_hash(mut self, hash: [u8; 32]) -> Self {
        self.content_hash = Some(hash);
        self
    }

    /// Get the producer hash (first component, always 32 bytes).
    pub fn producer_hash(&self) -> &[u8; 32] {
        self.components[0]
            .as_slice()
            .try_into()
            .expect("first component is always 32 bytes")
    }

    /// Get all components including the producer hash.
    pub fn components(&self) -> &[Vec<u8>] {
        &self.components
    }

    /// Get the optional content hash.
    pub fn content_hash(&self) -> Option<&[u8; 32]> {
        self.content_hash.as_ref()
    }

    /// Number of components (including producer hash).
    pub fn len(&self) -> usize {
        self.components.len()
    }

    /// Returns true if the name has no components beyond the producer hash.
    pub fn is_root(&self) -> bool {
        self.components.len() == 1
    }

    /// Check if this name starts with the given prefix.
    pub fn starts_with(&self, prefix: &Name) -> bool {
        if prefix.len() > self.len() {
            return false;
        }
        for (a, b) in self.components.iter().zip(prefix.components.iter()) {
            if a != b {
                return false;
            }
        }
        true
    }

    /// Check if this name is a prefix of another name.
    pub fn is_prefix_of(&self, other: &Name) -> bool {
        other.starts_with(self)
    }

    /// Serialize to wire format bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.components.len() as u8);
        for comp in &self.components {
            buf.push(comp.len() as u8);
            buf.extend_from_slice(comp);
        }
        if let Some(hash) = &self.content_hash {
            buf.push(HASH_DISCRIMINATOR);
            buf.extend_from_slice(hash);
        }
        buf
    }

    /// Deserialize from wire format bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NameError> {
        if bytes.is_empty() {
            return Err(NameError::Empty);
        }
        let count = bytes[0] as usize;
        if count == 0 || count > MAX_COMPONENTS {
            return Err(NameError::Empty);
        }

        let mut pos = 1;
        let mut components = Vec::with_capacity(count);

        for _ in 0..count {
            if pos >= bytes.len() {
                return Err(NameError::BufferTooShort {
                    expected: pos + 1,
                    got: bytes.len(),
                });
            }
            let len = bytes[pos] as usize;
            pos += 1;

            if pos + len > bytes.len() {
                return Err(NameError::BufferTooShort {
                    expected: pos + len,
                    got: bytes.len(),
                });
            }
            components.push(bytes[pos..pos + len].to_vec());
            pos += len;
        }

        // Check for content hash discriminator
        let content_hash = if pos < bytes.len() && bytes[pos] == HASH_DISCRIMINATOR {
            pos += 1;
            if pos + 32 > bytes.len() {
                return Err(NameError::BufferTooShort {
                    expected: pos + 32,
                    got: bytes.len(),
                });
            }
            let hash: [u8; 32] =
                bytes[pos..pos + 32]
                    .try_into()
                    .map_err(|_| NameError::BufferTooShort {
                        expected: pos + 32,
                        got: bytes.len(),
                    })?;
            Some(hash)
        } else {
            None
        };

        Ok(Name {
            components,
            content_hash,
        })
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for comp in &self.components {
            write!(f, "/")?;
            // Print hex for the 32-byte producer hash, raw bytes otherwise (as lossy utf8)
            if comp.len() == 32 {
                // Producer hash — compact hex
                write!(f, "{}", hex_prefix(comp))?;
            } else {
                // Path component — try utf8, fallback to hex
                if let Ok(s) = std::str::from_utf8(comp) {
                    write!(f, "{s}")?;
                } else {
                    write!(f, "{}", hex_prefix(comp))?;
                }
            }
        }
        if let Some(hash) = &self.content_hash {
            write!(f, "?blake3={}", hex_prefix(hash))?;
        }
        Ok(())
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Name(\"{self}\")")
    }
}

fn hex_prefix(bytes: &[u8]) -> String {
    if bytes.len() <= 8 {
        hex::encode(bytes)
    } else {
        format!(
            "{}..{}",
            hex::encode(&bytes[..4]),
            hex::encode(&bytes[bytes.len() - 4..])
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hash(byte: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = byte;
        h
    }

    #[test]
    fn test_name_round_trip() {
        let name =
            Name::new(make_hash(0xAA), &[b"app", b"chat"]).with_content_hash(make_hash(0xBB));
        let bytes = name.to_bytes();
        let parsed = Name::from_bytes(&bytes).unwrap();
        assert_eq!(name, parsed);
        assert_eq!(name.to_string(), parsed.to_string());
    }

    #[test]
    fn test_name_no_content_hash() {
        let name = Name::new(make_hash(0x42), &[b"test"]);
        let bytes = name.to_bytes();
        let parsed = Name::from_bytes(&bytes).unwrap();
        assert_eq!(name, parsed);
        assert_eq!(parsed.content_hash(), None);
        assert_eq!(parsed.producer_hash(), &make_hash(0x42));
    }

    #[test]
    fn test_starts_with() {
        let prefix = Name::new(make_hash(0x01), &[b"app"]);
        let name = Name::new(make_hash(0x01), &[b"app", b"chat", b"v5"]);
        assert!(name.starts_with(&prefix));
        assert!(prefix.is_prefix_of(&name));
    }

    #[test]
    fn test_starts_with_negative() {
        let a = Name::new(make_hash(0x01), &[b"app"]);
        let b = Name::new(make_hash(0x02), &[b"app"]);
        assert!(!a.starts_with(&b));
        assert!(!b.starts_with(&a));
    }

    #[test]
    fn test_prefix_of_different_depth() {
        let prefix = Name::new(make_hash(0x01), &[b"app"]);
        let name = Name::new(make_hash(0x01), &[b"app"]);
        assert!(name.starts_with(&prefix));
        assert!(prefix.starts_with(&name));
    }

    #[test]
    fn test_display() {
        let name = Name::new(make_hash(0xAA), &[b"app", b"chat"]);
        let s = name.to_string();
        assert!(s.starts_with("/aa000000..00000000/app/chat"));
    }

    #[test]
    fn test_display_with_hash() {
        let name = Name::new(make_hash(0x01), &[b"data"]).with_content_hash(make_hash(0xBB));
        let s = name.to_string();
        assert!(s.contains("?blake3="));
    }

    #[test]
    fn test_empty_bytes_error() {
        assert!(Name::from_bytes(&[]).is_err());
    }

    #[test]
    fn test_truncated_bytes_error() {
        let mut bytes = vec![2, 32];
        bytes.extend_from_slice(&make_hash(0x01));
        bytes.push(5); // component length but no data
        assert!(Name::from_bytes(&bytes).is_err());
    }
}
