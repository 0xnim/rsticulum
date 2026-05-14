//! Forwarding Information Base — prefix → faces mapping.
//!
//! Maps name prefixes to ordered lists of faces with costs.
//! Longest-prefix-match lookup.

use crate::face::FaceId;
use crate::name::Name;

/// An entry in the FIB: a prefix mapped to one or more faces with costs.
#[derive(Clone, Debug, PartialEq)]
pub struct FibEntry {
    pub prefix: Name,
    pub faces: Vec<(FaceId, u8)>, // (face_id, cost), ordered by cost ascending
}

/// Forwarding Information Base.
///
/// Stores prefix → faces mappings. Lookup uses longest-prefix-match.
pub struct Fib {
    entries: Vec<FibEntry>,
}

impl Fib {
    /// Create an empty FIB.
    pub fn new() -> Self {
        Fib {
            entries: Vec::new(),
        }
    }

    /// Insert or update a prefix→face mapping.
    ///
    /// If the prefix already exists, adds the face with the given cost.
    /// If the face already exists for this prefix, updates its cost.
    pub fn insert(&mut self, prefix: Name, face: FaceId, cost: u8) {
        // Find existing entry for this prefix
        for entry in &mut self.entries {
            if entry.prefix == prefix {
                // Update existing face or add new one
                if let Some((_, existing_cost)) = entry.faces.iter_mut().find(|(f, _)| *f == face) {
                    *existing_cost = cost;
                } else {
                    entry.faces.push((face, cost));
                }
                entry.faces.sort_by_key(|(_, c)| *c);
                return;
            }
        }

        // New prefix
        self.entries.push(FibEntry {
            prefix,
            faces: vec![(face, cost)],
        });
    }

    /// Remove a specific face from a prefix.
    ///
    /// If the prefix has no faces after removal, the entry is removed.
    pub fn remove_face(&mut self, prefix: &Name, face: FaceId) {
        self.entries.retain_mut(|entry| {
            if entry.prefix.starts_with(prefix) || prefix.starts_with(&entry.prefix) {
                entry.faces.retain(|(f, _)| *f != face);
                !entry.faces.is_empty()
            } else {
                true
            }
        });
    }

    /// Remove an entire prefix.
    pub fn remove_prefix(&mut self, prefix: &Name) {
        self.entries.retain(|e| !e.prefix.starts_with(prefix));
    }

    /// Look up faces for a name using longest-prefix-match.
    ///
    /// Returns the faces (with costs) for the longest matching prefix,
    /// or None if no prefix matches.
    pub fn lookup(&self, name: &Name) -> Option<Vec<(FaceId, u8)>> {
        let mut best: Option<&FibEntry> = None;

        for entry in &self.entries {
            if name.starts_with(&entry.prefix) {
                match best {
                    Some(current) if entry.prefix.len() > current.prefix.len() => {
                        best = Some(entry);
                    }
                    None => {
                        best = Some(entry);
                    }
                    _ => {}
                }
            }
        }

        best.map(|e| e.faces.clone())
    }

    /// Number of entries in the FIB.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the FIB has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over all FIB entries.
    pub fn iter(&self) -> impl Iterator<Item = &FibEntry> {
        self.entries.iter()
    }
}

impl Default for Fib {
    fn default() -> Self {
        Self::new()
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
    fn test_exact_match() {
        let mut fib = Fib::new();
        let prefix = Name::new(make_hash(0x01), &[b"app"]);
        fib.insert(prefix.clone(), 5, 10);

        let result = fib.lookup(&prefix);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), vec![(5, 10)]);
    }

    #[test]
    fn test_longest_prefix_match() {
        let mut fib = Fib::new();
        let short = Name::new(make_hash(0x01), &[b"app"]);
        let long = Name::new(make_hash(0x01), &[b"app", b"chat"]);
        let query = Name::new(make_hash(0x01), &[b"app", b"chat", b"v5"]);

        fib.insert(short.clone(), 5, 20);
        fib.insert(long.clone(), 3, 10);

        // Should match the longer prefix
        let result = fib.lookup(&query);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), vec![(3, 10)]);
    }

    #[test]
    fn test_no_match() {
        let mut fib = Fib::new();
        fib.insert(Name::new(make_hash(0x01), &[b"app"]), 5, 10);

        let query = Name::new(make_hash(0x02), &[b"app"]);
        assert!(fib.lookup(&query).is_none());
    }

    #[test]
    fn test_multiple_faces_sorted_by_cost() {
        let mut fib = Fib::new();
        let prefix = Name::new(make_hash(0x01), &[]);
        fib.insert(prefix.clone(), 1, 30);
        fib.insert(prefix.clone(), 2, 10);
        fib.insert(prefix.clone(), 3, 20);

        let result = fib.lookup(&prefix).unwrap();
        assert_eq!(result, vec![(2, 10), (3, 20), (1, 30)]);
    }

    #[test]
    fn test_update_existing_face_cost() {
        let mut fib = Fib::new();
        let prefix = Name::new(make_hash(0x01), &[]);
        fib.insert(prefix.clone(), 1, 10);
        fib.insert(prefix.clone(), 1, 5); // update cost

        let result = fib.lookup(&prefix).unwrap();
        assert_eq!(result, vec![(1, 5)]);
    }

    #[test]
    fn test_remove_prefix() {
        let mut fib = Fib::new();
        let prefix = Name::new(make_hash(0x01), &[b"app"]);
        fib.insert(prefix.clone(), 1, 10);
        fib.remove_prefix(&prefix);
        assert!(fib.lookup(&prefix).is_none());
        assert!(fib.is_empty());
    }
}
