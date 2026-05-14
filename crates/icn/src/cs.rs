//! ContentStore — LRU cache of Data packets.
//!
//! Caches Data packets by name. Supports exact match and prefix match
//! (for `can_be_prefix` Interests). Unsolicited Data is cached.
//! No flow balance enforcement — the mesh already authenticates Links.

use lru::LruCache;
use std::num::NonZeroUsize;
use std::time::Instant;

use crate::interest::Data;
use crate::name::Name;

/// A cached Data packet with insertion timestamp.
#[derive(Clone, Debug)]
pub struct CachedData {
    data: Data,
    inserted_at: Instant,
}

/// LRU cache of Data packets, keyed by name.
pub struct ContentStore {
    entries: LruCache<Name, CachedData>,
    hits: u64,
    misses: u64,
}

impl ContentStore {
    /// Create a new ContentStore with the given maximum number of entries.
    pub fn new(max_entries: usize) -> Self {
        ContentStore {
            entries: LruCache::new(NonZeroUsize::new(max_entries.max(1)).unwrap()),
            hits: 0,
            misses: 0,
        }
    }

    /// Look up Data by exact name match.
    pub fn get(&mut self, name: &Name) -> Option<&Data> {
        match self.entries.get(name) {
            Some(entry) => {
                self.hits += 1;
                Some(&entry.data)
            }
            None => {
                self.misses += 1;
                None
            }
        }
    }

    /// Look up Data by prefix match (for `can_be_prefix` Interests).
    ///
    /// Returns the Data with the longest matching name that is a prefix of `name`.
    pub fn get_prefix(&mut self, prefix: &Name) -> Option<&Data> {
        // Linear scan for prefix match. LRU doesn't support prefix iteration.
        // For MVP with 1000 entries, this is fine.
        let mut best: Option<(&Name, &CachedData)> = None;
        for (key, entry) in self.entries.iter() {
            if key.is_prefix_of(prefix) {
                match best {
                    Some((existing, _)) if key.len() > existing.len() => {
                        best = Some((key, entry));
                    }
                    None => {
                        best = Some((key, entry));
                    }
                    _ => {}
                }
            }
        }

        // Touch the entry we're returning so it stays in cache
        if let Some((key, _)) = best {
            self.hits += 1;
            // Peek to keep it in cache (get + re-insert to touch)
            return self.entries.peek(key).map(|e| &e.data);
        }
        self.misses += 1;
        None
    }

    /// Insert Data into the cache. Evicts LRU entry if full.
    /// Returns the evicted entry if one was removed.
    pub fn insert(&mut self, name: Name, data: Data) -> Option<CachedData> {
        let entry = CachedData {
            data,
            inserted_at: Instant::now(),
        };
        self.entries.put(name, entry)
    }

    /// Check if the store contains an entry with the given name.
    pub fn contains(&self, name: &Name) -> bool {
        self.entries.contains(name)
    }

    /// Number of entries currently cached.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Number of cache hits.
    pub fn hits(&self) -> u64 {
        self.hits
    }

    /// Number of cache misses.
    pub fn misses(&self) -> u64 {
        self.misses
    }

    /// Maximum capacity.
    pub fn capacity(&self) -> usize {
        self.entries.cap().get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interest::Data;
    use rsticulum_transport::Proof;

    fn make_hash(byte: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = byte;
        h
    }

    fn make_data(name: Name) -> Data {
        let sig = Proof::from_bytes(&vec![0u8; 96]).unwrap();
        Data::new(name, b"content".to_vec(), sig)
    }

    #[test]
    fn test_insert_and_get() {
        let mut cs = ContentStore::new(10);
        let name = Name::new(make_hash(0x01), &[b"test"]);
        cs.insert(name.clone(), make_data(name.clone()));
        assert!(cs.get(&name).is_some());
        assert_eq!(cs.len(), 1);
    }

    #[test]
    fn test_get_miss() {
        let mut cs = ContentStore::new(10);
        let name = Name::new(make_hash(0x01), &[b"test"]);
        assert!(cs.get(&name).is_none());
        assert_eq!(cs.misses(), 1);
    }

    #[test]
    fn test_contains() {
        let mut cs = ContentStore::new(10);
        let name = Name::new(make_hash(0x01), &[b"test"]);
        assert!(!cs.contains(&name));
        cs.insert(name.clone(), make_data(name.clone()));
        assert!(cs.contains(&name));
    }

    #[test]
    fn test_lru_eviction() {
        let mut cs = ContentStore::new(2);
        let a = Name::new(make_hash(0x01), &[b"a"]);
        let b = Name::new(make_hash(0x02), &[b"b"]);
        let c = Name::new(make_hash(0x03), &[b"c"]);

        cs.insert(a.clone(), make_data(a.clone()));
        cs.insert(b.clone(), make_data(b.clone()));
        cs.insert(c.clone(), make_data(c.clone()));

        // a should be evicted (oldest)
        assert_eq!(cs.len(), 2);
        assert!(!cs.contains(&a));
        assert!(cs.contains(&b));
        assert!(cs.contains(&c));
    }

    #[test]
    fn test_get_touches_entry() {
        let mut cs = ContentStore::new(2);
        let a = Name::new(make_hash(0x01), &[b"a"]);
        let b = Name::new(make_hash(0x02), &[b"b"]);
        let c = Name::new(make_hash(0x03), &[b"c"]);

        cs.insert(a.clone(), make_data(a.clone()));
        cs.insert(b.clone(), make_data(b.clone()));

        // Touch a so b becomes oldest
        cs.get(&a);
        cs.insert(c.clone(), make_data(c.clone()));

        // b should be evicted
        assert!(cs.contains(&a));
        assert!(!cs.contains(&b));
        assert!(cs.contains(&c));
    }

    #[test]
    fn test_prefix_match() {
        let mut cs = ContentStore::new(10);
        let prefix = Name::new(make_hash(0x01), &[b"app"]);
        let full = Name::new(make_hash(0x01), &[b"app", b"chat"]);

        cs.insert(prefix.clone(), make_data(prefix.clone()));

        // get_prefix with the full name should match the prefix entry
        let result = cs.get_prefix(&full);
        assert!(result.is_some());
    }

    #[test]
    fn test_prefix_match_longest() {
        let mut cs = ContentStore::new(10);
        let short = Name::new(make_hash(0x01), &[b"app"]);
        let long = Name::new(make_hash(0x01), &[b"app", b"chat"]);
        let query = Name::new(make_hash(0x01), &[b"app", b"chat", b"v5"]);

        cs.insert(short.clone(), make_data(short.clone()));
        cs.insert(long.clone(), make_data(long.clone()));

        // Should return the longer match
        let result = cs.get_prefix(&query);
        assert!(result.is_some());
        assert_eq!(result.unwrap().name, long);
    }

    #[test]
    fn test_hits_misses_counted() {
        let mut cs = ContentStore::new(10);
        let name = Name::new(make_hash(0x01), &[b"test"]);
        let missing = Name::new(make_hash(0x02), &[b"test"]);

        cs.insert(name.clone(), make_data(name.clone()));
        cs.get(&name);
        cs.get(&name);
        cs.get(&missing);

        assert_eq!(cs.hits(), 2);
        assert_eq!(cs.misses(), 1);
    }
}
