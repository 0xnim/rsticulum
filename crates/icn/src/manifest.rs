//! Manifest types — the discovery mechanism for ICN.
//!
//! A Manifest is a signed index published by a producer listing what content
//! is available and where to find it. Consumers fetch a producer's manifest
//! to discover content names, then fetch the content by name.
//!
//! For large content split across chunks, a ContentManifest lists chunk names
//! and hashes for verified reassembly.

use rsticulum_identity::Keys;
use serde::{Deserialize, Serialize};

use crate::interest::Data;
use crate::name::Name;

/// A signed manifest listing available content from a producer.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Manifest {
    /// Producer identity hash (matches first component of manifest's ICN name).
    pub producer: [u8; 32],
    /// Monotonic sequence number — higher = newer version.
    pub sequence: u64,
    /// Unix timestamp when this manifest was created.
    pub timestamp: u64,
    /// Content entries available from this producer.
    pub entries: Vec<ManifestEntry>,
    /// Name of the previous manifest version (for history traversal).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous: Option<Name>,
}

/// An entry in a manifest describing available content.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ManifestEntry {
    /// What kind of content this is.
    pub kind: EntryKind,
    /// Human-readable label (e.g., "chat", "sensor-data", "photos").
    pub label: String,
    /// The ICN name where this content lives.
    pub content_name: Name,
    /// Expected BLAKE3 hash of the content (for verification).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<[u8; 32]>,
    /// Size of the content in bytes (if known).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

/// The kind of content an entry points to.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum EntryKind {
    /// A single Data packet — fetch once, done.
    #[serde(rename = "blob")]
    Blob,
    /// An ordered sequence of Data packets — fetch with increasing sequence numbers.
    #[serde(rename = "stream")]
    Stream,
    /// A sub-manifest — recursive discovery for nested namespaces.
    #[serde(rename = "manifest")]
    Manifest,
}

/// A content manifest listing chunks for large content.
///
/// When content is too large for a single Data packet, it's split into
/// chunks. The ContentManifest lists each chunk's name and hash so the
/// consumer can fetch and verify chunks independently.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ContentManifest {
    /// Ordered list of chunks.
    pub chunks: Vec<ChunkRef>,
    /// Total size of the reassembled content.
    pub total_size: u64,
}

/// Reference to a single chunk in a ContentManifest.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ChunkRef {
    /// Full ICN name of this chunk (includes content hash for self-certification).
    pub name: Name,
    /// BLAKE3 hash of this chunk's content.
    pub hash: [u8; 32],
    /// Byte offset in the reassembled content.
    pub offset: u64,
    /// Length of this chunk in bytes.
    pub length: u32,
}

/// Errors that can occur when working with manifests.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid name for manifest: {0}")]
    InvalidName(String),
    #[error("content hash mismatch: expected {expected:?}, got {actual:?}")]
    ContentHashMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
}

impl Manifest {
    /// Parse a Manifest from a Data packet's content.
    ///
    /// The Data packet's content must be valid JSON matching the Manifest schema.
    /// Verifies that the content hash in the Data metadata matches (if present).
    pub fn from_data(data: &Data) -> Result<Self, ManifestError> {
        let manifest: Manifest = serde_json::from_slice(&data.content)?;

        // Verify content hash if present in metadata
        if let Some(expected_hash) = data.metadata.content_hash {
            let actual_hash: [u8; 32] = blake3::hash(&data.content).into();
            if expected_hash != actual_hash {
                return Err(ManifestError::ContentHashMismatch {
                    expected: expected_hash,
                    actual: actual_hash,
                });
            }
        }

        Ok(manifest)
    }

    /// Serialize this manifest to JSON bytes (for use as Data content).
    pub fn to_json(&self) -> Result<Vec<u8>, ManifestError> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Create a signed Data packet from this manifest.
    ///
    /// The Data name is derived from the producer hash: `/<producer>/manifest`.
    /// The Data is signed with the producer's keys.
    pub fn to_data(&self, keys: &Keys) -> Result<Data, ManifestError> {
        let content = self.to_json()?;
        let name = Name::new(self.producer, &[b"manifest"]);

        // Sign the content
        let message_hash = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&name.to_bytes());
            hasher.update(&content);
            *hasher.finalize().as_bytes()
        };
        let signature = rsticulum_transport::generate_proof(keys, &message_hash);

        let mut data = Data::new(name, content, signature);
        data.metadata.sequence = Some(self.sequence);
        data.metadata.content_hash = Some(blake3::hash(&data.content).into());
        Ok(data)
    }

    /// Find an entry by label.
    pub fn find(&self, label: &str) -> Option<&ManifestEntry> {
        self.entries.iter().find(|e| e.label == label)
    }

    /// Check if this manifest is newer than a given sequence number.
    pub fn is_newer_than(&self, seq: u64) -> bool {
        self.sequence > seq
    }
}

impl ContentManifest {
    /// Parse a ContentManifest from Data packet content.
    pub fn from_data(data: &Data) -> Result<Self, ManifestError> {
        Ok(serde_json::from_slice(&data.content)?)
    }

    /// Serialize to JSON bytes.
    pub fn to_json(&self) -> Result<Vec<u8>, ManifestError> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Get the total number of chunks.
    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }
}

// Custom serde for Name (serialize as display string, deserialize from display string)

impl Serialize for Name {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Name {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        // Parse display format back to bytes: /hex/app/chat?blake3=hex
        parse_name_from_display(&s).map_err(serde::de::Error::custom)
    }
}

/// Parse a Name from its Display format.
///
/// Format: `/<producer-hex>/<path...>[?blake3=<hex>]`
fn parse_name_from_display(s: &str) -> Result<Name, String> {
    let s = s.trim_start_matches('/');

    // Split off content hash
    let (name_part, content_hash) = if let Some(qpos) = s.find("?blake3=") {
        let hash_hex = &s[qpos + 8..];
        let hash_hex = expand_compact_hex(hash_hex)?;
        let hash_bytes = hex::decode(&hash_hex).map_err(|e| format!("invalid hash hex: {e}"))?;
        if hash_bytes.len() != 32 {
            return Err("content hash must be 32 bytes".to_string());
        }
        let hash: [u8; 32] = hash_bytes.try_into().unwrap();
        (&s[..qpos], Some(hash))
    } else {
        (s, None)
    };

    // Parse components
    let comp_strings: Vec<&str> = name_part.split('/').filter(|c| !c.is_empty()).collect();
    let mut components = Vec::with_capacity(comp_strings.len());

    for (i, cs) in comp_strings.iter().enumerate() {
        if i == 0 {
            // Producer hash — compact hex (first 4 + .. + last 4)
            let hex_full = expand_compact_hex(cs)?;
            let bytes =
                hex::decode(&hex_full).map_err(|e| format!("invalid producer hash hex: {e}"))?;
            if bytes.len() != 32 {
                return Err("producer hash must be 32 bytes".to_string());
            }
            components.push(bytes);
        } else {
            // Try to decode as hex, otherwise as UTF-8
            if let Ok(bytes) = hex::decode(cs) {
                components.push(bytes);
            } else {
                components.push(cs.as_bytes().to_vec());
            }
        }
    }

    if components.is_empty() {
        return Err("name must have at least a producer hash".to_string());
    }

    Ok(Name {
        components,
        content_hash,
    })
}

fn expand_compact_hex(compact: &str) -> Result<String, String> {
    if let Some(dot_pos) = compact.find("..") {
        let prefix = &compact[..dot_pos];
        let suffix = &compact[dot_pos + 2..];
        let full_len = 64; // 32 bytes = 64 hex chars
        let mid_len = full_len - prefix.len() - suffix.len();
        Ok(format!("{prefix}{}{suffix}", "0".repeat(mid_len)))
    } else {
        Ok(compact.to_string())
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
    fn test_manifest_json_round_trip() {
        let manifest = Manifest {
            producer: make_hash(0xAA),
            sequence: 1,
            timestamp: 1715700000,
            entries: vec![ManifestEntry {
                kind: EntryKind::Blob,
                label: "hello".to_string(),
                content_name: Name::new(make_hash(0xAA), &[b"hello"]),
                content_hash: Some(make_hash(0xBB)),
                size: Some(42),
            }],
            previous: None,
        };

        let json = manifest.to_json().unwrap();
        let parsed: Manifest = serde_json::from_slice(&json).unwrap();
        assert_eq!(manifest, parsed);
    }

    #[test]
    fn test_manifest_with_previous() {
        let prev_name = Name::new(make_hash(0xAA), &[b"manifest"]);
        let manifest = Manifest {
            producer: make_hash(0xAA),
            sequence: 2,
            timestamp: 1715700100,
            entries: vec![],
            previous: Some(prev_name.clone()),
        };

        let json = manifest.to_json().unwrap();
        let parsed: Manifest = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed.previous.as_ref().unwrap(), &prev_name);
    }

    #[test]
    fn test_content_manifest_round_trip() {
        let cm = ContentManifest {
            chunks: vec![ChunkRef {
                name: Name::new(make_hash(0xAA), &[b"chunk", b"0"])
                    .with_content_hash(make_hash(0x01)),
                hash: make_hash(0x01),
                offset: 0,
                length: 1000,
            }],
            total_size: 1000,
        };

        let json = cm.to_json().unwrap();
        let parsed = ContentManifest::from_data(&Data::new(
            Name::new(make_hash(0xAA), &[b"cm"]),
            json,
            rsticulum_transport::Proof::from_bytes(&vec![0u8; 96]).unwrap(),
        ))
        .unwrap();
        assert_eq!(parsed.chunks.len(), 1);
        assert_eq!(parsed.total_size, 1000);
    }

    #[test]
    fn test_manifest_entry_kinds() {
        // Verify EntryKind serialization
        let json = serde_json::to_string(&EntryKind::Blob).unwrap();
        assert_eq!(json, "\"blob\"");
        let json = serde_json::to_string(&EntryKind::Stream).unwrap();
        assert_eq!(json, "\"stream\"");
        let json = serde_json::to_string(&EntryKind::Manifest).unwrap();
        assert_eq!(json, "\"manifest\"");
    }

    #[test]
    fn test_parse_name_from_display() {
        let name_str = "/aa000000..00000000/hello/world";
        let name = parse_name_from_display(name_str).unwrap();
        assert_eq!(name.components().len(), 3);
        assert_eq!(name.components()[1], b"hello");
        assert_eq!(name.components()[2], b"world");
    }

    #[test]
    fn test_parse_name_with_content_hash() {
        let name_str = "/aa000000..00000000/data?blake3=bb00000000000000000000000000000000000000000000000000000000000000";
        let name = parse_name_from_display(name_str).unwrap();
        assert!(name.content_hash().is_some());
    }
}
