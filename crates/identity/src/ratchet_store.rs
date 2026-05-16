//! Ratchet key persistence store.
//!
//! Matches Python RNS `Identity.known_ratchets` behavior.
//! Maps identity_hash (16 bytes) → ratchet_key (32 bytes).
//! Persisted to disk using hex-encoded entries, one per line.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

/// A persisted store for known ratchet keys.
pub struct RatchetStore {
    path: PathBuf,
    cache: RwLock<HashMap<[u8; 16], [u8; 32]>>,
}

impl RatchetStore {
    /// Open (or create) a ratchet store at the given path.
    pub fn open<P: AsRef<Path>>(path: P) -> Self {
        let path = path.as_ref().to_path_buf();
        let cache = if path.exists() {
            std::fs::read_to_string(&path)
                .ok()
                .and_then(|s| Self::parse(&s))
                .unwrap_or_default()
        } else {
            HashMap::new()
        };
        Self {
            path,
            cache: RwLock::new(cache),
        }
    }

    /// Store a ratchet key for an identity.
    pub fn store(
        &self,
        identity_hash: [u8; 16],
        ratchet_key: [u8; 32],
    ) -> Result<(), RatchetStoreError> {
        let mut cache = self.cache.write().map_err(|_| RatchetStoreError::Lock)?;
        cache.insert(identity_hash, ratchet_key);
        self.flush(&cache)?;
        Ok(())
    }

    /// Look up a ratchet key for an identity.
    pub fn lookup(&self, identity_hash: &[u8; 16]) -> Option<[u8; 32]> {
        let cache = self.cache.read().ok()?;
        cache.get(identity_hash).copied()
    }

    /// Remove a ratchet key for an identity.
    pub fn remove(&self, identity_hash: &[u8; 16]) -> Result<(), RatchetStoreError> {
        let mut cache = self.cache.write().map_err(|_| RatchetStoreError::Lock)?;
        cache.remove(identity_hash);
        self.flush(&cache)?;
        Ok(())
    }

    /// List all stored identity hashes.
    pub fn identities(&self) -> Vec<[u8; 16]> {
        let cache = self.cache.read().ok();
        cache
            .map(|c| c.keys().copied().collect())
            .unwrap_or_default()
    }

    /// Number of stored entries.
    pub fn len(&self) -> usize {
        let cache = self.cache.read().ok();
        cache.map(|c| c.len()).unwrap_or(0)
    }

    fn parse(data: &str) -> Option<HashMap<[u8; 16], [u8; 32]>> {
        let mut map = HashMap::new();
        for line in data.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.splitn(2, ':').collect();
            if parts.len() != 2 {
                continue;
            }
            let hash_bytes = hex::decode(parts[0]).ok()?;
            let key_bytes = hex::decode(parts[1]).ok()?;
            if hash_bytes.len() != 16 || key_bytes.len() != 32 {
                continue;
            }
            let mut hash = [0u8; 16];
            let mut key = [0u8; 32];
            hash.copy_from_slice(&hash_bytes);
            key.copy_from_slice(&key_bytes);
            map.insert(hash, key);
        }
        Some(map)
    }

    fn flush(&self, cache: &HashMap<[u8; 16], [u8; 32]>) -> Result<(), RatchetStoreError> {
        let mut output = String::new();
        output.push_str("# Ratchet keys: identity_hash(32 hex):ratchet_key(64 hex)\n");
        for (hash, key) in cache {
            output.push_str(&hex::encode(hash));
            output.push(':');
            output.push_str(&hex::encode(key));
            output.push('\n');
        }
        std::fs::write(&self.path, output).map_err(RatchetStoreError::Io)?;
        Ok(())
    }
}

impl std::fmt::Debug for RatchetStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RatchetStore")
            .field("path", &self.path)
            .finish()
    }
}

#[derive(Debug)]
pub enum RatchetStoreError {
    Lock,
    Io(std::io::Error),
}

impl std::fmt::Display for RatchetStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RatchetStoreError::Lock => write!(f, "ratchet store lock poisoned"),
            RatchetStoreError::Io(e) => write!(f, "ratchet store I/O: {e}"),
        }
    }
}

impl std::error::Error for RatchetStoreError {}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_store_roundtrip() {
        let tmp = NamedTempFile::new().unwrap();
        let store = RatchetStore::open(tmp.path());

        let hash = [0xABu8; 16];
        let key = [0x42u8; 32];

        store.store(hash, key).unwrap();
        assert_eq!(store.lookup(&hash), Some(key));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_remove() {
        let tmp = NamedTempFile::new().unwrap();
        let store = RatchetStore::open(tmp.path());

        let hash = [0xABu8; 16];
        store.store(hash, [0x42u8; 32]).unwrap();
        assert_eq!(store.len(), 1);
        store.remove(&hash).unwrap();
        assert_eq!(store.lookup(&hash), None);
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_persistence_across_reopen() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();

        {
            let store = RatchetStore::open(&path);
            store.store([0xABu8; 16], [0x42u8; 32]).unwrap();
        }

        {
            let store = RatchetStore::open(&path);
            assert_eq!(store.lookup(&[0xABu8; 16]), Some([0x42u8; 32]));
        }
    }

    #[test]
    fn test_identities_list() {
        let tmp = NamedTempFile::new().unwrap();
        let store = RatchetStore::open(tmp.path());

        let h1 = [0x01u8; 16];
        let h2 = [0x02u8; 16];
        store.store(h1, [0xAAu8; 32]).unwrap();
        store.store(h2, [0xBBu8; 32]).unwrap();

        let ids = store.identities();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&h1));
        assert!(ids.contains(&h2));
    }

    #[test]
    fn test_empty_store() {
        let tmp = NamedTempFile::new().unwrap();
        let store = RatchetStore::open(tmp.path());
        assert_eq!(store.len(), 0);
        assert!(store.identities().is_empty());
    }
}
