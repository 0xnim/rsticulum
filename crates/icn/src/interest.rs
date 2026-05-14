//! Interest and Data packet types.
//!
//! Interest: consumer expresses desire for named content.
//! Data: producer responds with signed content.

use std::time::Duration;

use rsticulum_transport::Proof;

use crate::name::Name;

/// An Interest packet — "I want this named data."
#[derive(Clone, Debug, PartialEq)]
pub struct Interest {
    /// The name being requested.
    pub name: Name,
    /// Random nonce for loop detection.
    pub nonce: [u8; 8],
    /// How long the Interest should be kept alive in PIT.
    pub lifetime: Duration,
    /// If true, the Interest can be satisfied by any name that has this
    /// Interest's name as a prefix.
    pub can_be_prefix: bool,
    /// Optional selector for filtering matching Data.
    pub selector: Option<InterestSelector>,
}

impl Interest {
    /// Create a new Interest for the given name.
    pub fn new(name: Name) -> Self {
        let mut nonce = [0u8; 8];
        getrandom::getrandom(&mut nonce).expect("getrandom");
        Interest {
            name,
            nonce,
            lifetime: Duration::from_secs(4),
            can_be_prefix: false,
            selector: None,
        }
    }

    /// Set the Interest lifetime.
    pub fn with_lifetime(mut self, lifetime: Duration) -> Self {
        self.lifetime = lifetime;
        self
    }

    /// Allow prefix matching.
    pub fn with_can_be_prefix(mut self) -> Self {
        self.can_be_prefix = true;
        self
    }

    /// Add a selector for filtering.
    pub fn with_selector(mut self, selector: InterestSelector) -> Self {
        self.selector = Some(selector);
        self
    }

    /// Require fresh content (not from cache).
    pub fn with_must_be_fresh(mut self) -> Self {
        self.selector = Some(InterestSelector {
            must_be_fresh: true,
            ..self.selector.unwrap_or_default()
        });
        self
    }

    /// Serialize to wire format bytes.
    ///
    /// ```text
    /// [name_len:varint][name_bytes...][nonce:8][lifetime_ms:4][flags:1][selector:...]
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let name_bytes = self.name.to_bytes();
        let mut buf = Vec::with_capacity(64 + name_bytes.len());

        // Name: length-prefixed with varint
        write_varint(&mut buf, name_bytes.len() as u64);
        buf.extend_from_slice(&name_bytes);

        // Nonce: 8 bytes
        buf.extend_from_slice(&self.nonce);

        // Lifetime: 4 bytes (milliseconds, big-endian)
        let ms = (self.lifetime.as_millis() as u32).min(u32::MAX);
        buf.extend_from_slice(&ms.to_be_bytes());

        // Flags: 1 byte
        let mut flags: u8 = 0;
        if self.can_be_prefix {
            flags |= 0x01;
        }
        if self.selector.is_some() {
            flags |= 0x02;
        }
        buf.push(flags);

        // Selector data
        if let Some(ref sel) = self.selector {
            sel.write_to(&mut buf);
        }

        buf
    }

    /// Deserialize from wire format bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, InterestError> {
        let mut pos = 0;

        // Name length (varint)
        let (name_len, varint_bytes) = read_varint(bytes).ok_or(InterestError::BufferTooShort)?;
        pos += varint_bytes;

        // Name bytes
        if pos + name_len as usize > bytes.len() {
            return Err(InterestError::BufferTooShort);
        }
        let name = Name::from_bytes(&bytes[pos..pos + name_len as usize])
            .map_err(|_| InterestError::InvalidName)?;
        pos += name_len as usize;

        // Nonce
        if pos + 8 > bytes.len() {
            return Err(InterestError::BufferTooShort);
        }
        let nonce: [u8; 8] = bytes[pos..pos + 8].try_into().unwrap();
        pos += 8;

        // Lifetime
        if pos + 4 > bytes.len() {
            return Err(InterestError::BufferTooShort);
        }
        let lifetime_ms = u32::from_be_bytes(bytes[pos..pos + 4].try_into().unwrap());
        pos += 4;

        // Flags
        if pos >= bytes.len() {
            return Err(InterestError::BufferTooShort);
        }
        let flags = bytes[pos];
        pos += 1;
        let can_be_prefix = flags & 0x01 != 0;
        let has_selector = flags & 0x02 != 0;

        // Selector
        let selector = if has_selector {
            Some(InterestSelector::read_from(&bytes[pos..])?)
        } else {
            None
        };

        Ok(Interest {
            name,
            nonce,
            lifetime: Duration::from_millis(lifetime_ms as u64),
            can_be_prefix,
            selector,
        })
    }
}

/// Selector for filtering matching Data packets.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct InterestSelector {
    /// Only return content with sequence >= this value.
    pub min_sequence: Option<u64>,
    /// Exclude content with these hashes (already seen).
    pub exclude_hashes: Vec<[u8; 32]>,
    /// If true, must NOT be satisfied from ContentStore.
    pub must_be_fresh: bool,
}

impl InterestSelector {
    fn write_to(&self, buf: &mut Vec<u8>) {
        let mut flags: u8 = 0;
        if self.min_sequence.is_some() {
            flags |= 0x01;
        }
        if !self.exclude_hashes.is_empty() {
            flags |= 0x02;
        }
        if self.must_be_fresh {
            flags |= 0x04;
        }
        buf.push(flags);

        if let Some(seq) = self.min_sequence {
            buf.extend_from_slice(&seq.to_be_bytes());
        }
        if !self.exclude_hashes.is_empty() {
            buf.push(self.exclude_hashes.len() as u8);
            for hash in &self.exclude_hashes {
                buf.extend_from_slice(hash);
            }
        }
    }

    fn read_from(bytes: &[u8]) -> Result<Self, InterestError> {
        if bytes.is_empty() {
            return Err(InterestError::BufferTooShort);
        }
        let flags = bytes[0];
        let mut pos = 1;

        let min_sequence = if flags & 0x01 != 0 {
            if pos + 8 > bytes.len() {
                return Err(InterestError::BufferTooShort);
            }
            let seq = u64::from_be_bytes(bytes[pos..pos + 8].try_into().unwrap());
            pos += 8;
            Some(seq)
        } else {
            None
        };

        let exclude_hashes = if flags & 0x02 != 0 {
            if pos >= bytes.len() {
                return Err(InterestError::BufferTooShort);
            }
            let count = bytes[pos] as usize;
            pos += 1;
            let mut hashes = Vec::with_capacity(count);
            for _ in 0..count {
                if pos + 32 > bytes.len() {
                    return Err(InterestError::BufferTooShort);
                }
                hashes.push(bytes[pos..pos + 32].try_into().unwrap());
                pos += 32;
            }
            hashes
        } else {
            Vec::new()
        };

        let must_be_fresh = flags & 0x04 != 0;

        Ok(InterestSelector {
            min_sequence,
            exclude_hashes,
            must_be_fresh,
        })
    }
}

/// An error that can occur when parsing an Interest from bytes.
#[derive(Debug, thiserror::Error)]
pub enum InterestError {
    #[error("buffer too short")]
    BufferTooShort,
    #[error("invalid name")]
    InvalidName,
}

// --- Data packet ---

/// Metadata attached to a Data packet.
#[derive(Clone, Debug, PartialEq)]
pub struct DataMetadata {
    /// BLAKE3 hash of the content (for verification).
    pub content_hash: Option<[u8; 32]>,
    /// Sequence number for mutable content (e.g., manifests).
    pub sequence: Option<u64>,
    /// Freshness status.
    pub freshness: Freshness,
}

/// Whether this Data is fresh from the producer or served from a stale cache.
#[derive(Clone, Debug, PartialEq)]
pub enum Freshness {
    /// Directly from the producer.
    Fresh,
    /// Served from ContentStore, this old.
    Stale { age: Duration },
}

impl Default for Freshness {
    fn default() -> Self {
        Freshness::Fresh
    }
}

/// A Data packet — "Here is the content you asked for."
#[derive(Clone, Debug, PartialEq)]
pub struct Data {
    /// The name of this content.
    pub name: Name,
    /// The content payload.
    pub content: Vec<u8>,
    /// Producer's proof: [hash(32)][sig(64)].
    pub signature: Proof,
    /// Metadata about this Data.
    pub metadata: DataMetadata,
}

impl Data {
    /// Create a new Data packet.
    pub fn new(name: Name, content: Vec<u8>, signature: Proof) -> Self {
        let content_hash = Some(blake3::hash(&content).into());
        Data {
            name,
            content,
            signature,
            metadata: DataMetadata {
                content_hash,
                sequence: None,
                freshness: Freshness::Fresh,
            },
        }
    }

    /// Set the sequence number (for manifests and mutable content).
    pub fn with_sequence(mut self, seq: u64) -> Self {
        self.metadata.sequence = Some(seq);
        self
    }

    /// Mark as served from stale cache.
    pub fn with_staleness(mut self, age: Duration) -> Self {
        self.metadata.freshness = Freshness::Stale { age };
        self
    }

    /// Compute the BLAKE3 hash of name + content (what the proof signs).
    pub fn signed_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.name.to_bytes());
        hasher.update(&self.content);
        *hasher.finalize().as_bytes()
    }

    /// Serialize to wire format bytes.
    ///
    /// ```text
    /// [name_len:varint][name_bytes...][content_len:4][content...][metadata:varint][metadata_bytes...][signature:96]
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let name_bytes = self.name.to_bytes();
        let metadata_bytes = self.metadata.to_bytes();
        let sig_bytes = self.signature.to_bytes();

        let mut buf = Vec::with_capacity(
            16 + name_bytes.len() + self.content.len() + metadata_bytes.len() + sig_bytes.len(),
        );

        // Name
        write_varint(&mut buf, name_bytes.len() as u64);
        buf.extend_from_slice(&name_bytes);

        // Content length (4 bytes big-endian)
        buf.extend_from_slice(&(self.content.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.content);

        // Metadata
        write_varint(&mut buf, metadata_bytes.len() as u64);
        buf.extend_from_slice(&metadata_bytes);

        // Signature
        buf.extend_from_slice(&sig_bytes);

        buf
    }

    /// Deserialize from wire format bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DataError> {
        let mut pos = 0;

        // Name
        let (name_len, varint_bytes) = read_varint(bytes).ok_or(DataError::BufferTooShort)?;
        pos += varint_bytes;
        if pos + name_len as usize > bytes.len() {
            return Err(DataError::BufferTooShort);
        }
        let name = Name::from_bytes(&bytes[pos..pos + name_len as usize])
            .map_err(|_| DataError::InvalidName)?;
        pos += name_len as usize;

        // Content length
        if pos + 4 > bytes.len() {
            return Err(DataError::BufferTooShort);
        }
        let content_len = u32::from_be_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;

        // Content
        if pos + content_len > bytes.len() {
            return Err(DataError::BufferTooShort);
        }
        let content = bytes[pos..pos + content_len].to_vec();
        pos += content_len;

        // Metadata
        let (metadata_len, varint_bytes) =
            read_varint(&bytes[pos..]).ok_or(DataError::BufferTooShort)?;
        pos += varint_bytes;
        if pos + metadata_len as usize > bytes.len() {
            return Err(DataError::BufferTooShort);
        }
        let metadata = DataMetadata::from_bytes(&bytes[pos..pos + metadata_len as usize])?;
        pos += metadata_len as usize;

        // Signature
        if pos + 96 > bytes.len() {
            return Err(DataError::BufferTooShort);
        }
        let signature =
            Proof::from_bytes(&bytes[pos..pos + 96]).map_err(|_| DataError::InvalidSignature)?;

        Ok(Data {
            name,
            content,
            signature,
            metadata,
        })
    }
}

/// An error that can occur when parsing Data from bytes.
#[derive(Debug, thiserror::Error)]
pub enum DataError {
    #[error("buffer too short")]
    BufferTooShort,
    #[error("invalid name")]
    InvalidName,
    #[error("invalid signature bytes")]
    InvalidSignature,
}

// --- Metadata wire format ---

impl DataMetadata {
    /// Serialize to wire format bytes.
    ///
    /// ```text
    /// [flags:1][content_hash?:32][sequence?:8][staleness_secs?:8]
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut flags: u8 = 0;
        if self.content_hash.is_some() {
            flags |= 0x01;
        }
        if self.sequence.is_some() {
            flags |= 0x02;
        }
        if matches!(self.freshness, Freshness::Stale { .. }) {
            flags |= 0x04;
        }

        let mut buf = vec![flags];

        if let Some(hash) = &self.content_hash {
            buf.extend_from_slice(hash);
        }
        if let Some(seq) = self.sequence {
            buf.extend_from_slice(&seq.to_be_bytes());
        }
        if let Freshness::Stale { age } = self.freshness {
            buf.extend_from_slice(&age.as_secs().to_be_bytes());
        }

        buf
    }

    /// Deserialize from wire format bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DataError> {
        if bytes.is_empty() {
            return Err(DataError::BufferTooShort);
        }
        let flags = bytes[0];
        let mut pos = 1;

        let content_hash = if flags & 0x01 != 0 {
            if pos + 32 > bytes.len() {
                return Err(DataError::BufferTooShort);
            }
            let hash = bytes[pos..pos + 32].try_into().unwrap();
            pos += 32;
            Some(hash)
        } else {
            None
        };

        let sequence = if flags & 0x02 != 0 {
            if pos + 8 > bytes.len() {
                return Err(DataError::BufferTooShort);
            }
            let seq = u64::from_be_bytes(bytes[pos..pos + 8].try_into().unwrap());
            pos += 8;
            Some(seq)
        } else {
            None
        };

        let freshness = if flags & 0x04 != 0 {
            if pos + 8 > bytes.len() {
                return Err(DataError::BufferTooShort);
            }
            let age_secs = u64::from_be_bytes(bytes[pos..pos + 8].try_into().unwrap());
            Freshness::Stale {
                age: Duration::from_secs(age_secs),
            }
        } else {
            Freshness::Fresh
        };

        Ok(DataMetadata {
            content_hash,
            sequence,
            freshness,
        })
    }
}

// --- Varint encoding ---

fn write_varint(buf: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        buf.push((value as u8) | 0x80);
        value >>= 7;
    }
    buf.push(value as u8);
}

fn read_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift = 0;
    for (i, &byte) in bytes.iter().enumerate() {
        value |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
        shift += 7;
        if shift >= 64 {
            return None; // overflow
        }
    }
    None // truncated
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hash(byte: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = byte;
        h
    }

    fn test_name() -> Name {
        Name::new(make_hash(0xAA), &[b"test"])
    }

    #[test]
    fn test_interest_round_trip() {
        let interest = Interest::new(test_name())
            .with_lifetime(Duration::from_secs(10))
            .with_can_be_prefix()
            .with_must_be_fresh();

        let bytes = interest.to_bytes();
        let parsed = Interest::from_bytes(&bytes).unwrap();

        assert_eq!(interest.name, parsed.name);
        assert_eq!(interest.nonce, parsed.nonce);
        assert_eq!(interest.lifetime, parsed.lifetime);
        assert_eq!(interest.can_be_prefix, parsed.can_be_prefix);
        assert!(parsed.selector.as_ref().unwrap().must_be_fresh);
    }

    #[test]
    fn test_interest_with_selector() {
        let interest = Interest::new(test_name()).with_selector(InterestSelector {
            min_sequence: Some(5),
            exclude_hashes: vec![make_hash(0x01), make_hash(0x02)],
            must_be_fresh: false,
        });

        let bytes = interest.to_bytes();
        let parsed = Interest::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.selector.as_ref().unwrap().min_sequence, Some(5));
        assert_eq!(parsed.selector.as_ref().unwrap().exclude_hashes.len(), 2);
    }

    #[test]
    fn test_data_round_trip() {
        let content = b"hello icn".to_vec();
        let sig_bytes = vec![0u8; 96];
        let signature = Proof::from_bytes(&sig_bytes).unwrap();
        let data = Data::new(test_name(), content.clone(), signature).with_sequence(42);

        let bytes = data.to_bytes();
        let parsed = Data::from_bytes(&bytes).unwrap();

        assert_eq!(data.name, parsed.name);
        assert_eq!(data.content, parsed.content);
        assert_eq!(parsed.metadata.sequence, Some(42));
        assert_eq!(parsed.metadata.freshness, Freshness::Fresh);
    }

    #[test]
    fn test_data_staleness() {
        let sig_bytes = vec![0u8; 96];
        let signature = Proof::from_bytes(&sig_bytes).unwrap();
        let data = Data::new(test_name(), b"data".to_vec(), signature)
            .with_staleness(Duration::from_secs(3600));

        let bytes = data.to_bytes();
        let parsed = Data::from_bytes(&bytes).unwrap();

        assert!(matches!(
            parsed.metadata.freshness,
            Freshness::Stale {
                age
            } if age == Duration::from_secs(3600)
        ));
    }

    #[test]
    fn test_varint_round_trip() {
        for value in [0u64, 1, 127, 128, 255, 256, 16383, 16384, 1_000_000] {
            let mut buf = Vec::new();
            write_varint(&mut buf, value);
            let (parsed, _len) = read_varint(&buf).unwrap();
            assert_eq!(parsed, value, "varint round-trip failed for {value}");
        }
    }

    #[test]
    fn test_interest_buffer_too_short() {
        assert!(Interest::from_bytes(&[]).is_err());
        assert!(Interest::from_bytes(&[0x01]).is_err());
    }

    #[test]
    fn test_data_buffer_too_short() {
        assert!(Data::from_bytes(&[]).is_err());
        assert!(Data::from_bytes(&[0x01]).is_err());
    }
}
