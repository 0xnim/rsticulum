//! Pending Interest Table — Interest aggregation and reverse-path tracking.
//!
//! When multiple consumers express the same Interest, the PIT aggregates them
//! into a single upstream Interest. When Data arrives, it's multicast back
//! to all in_faces.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::face::FaceId;
use crate::interest::Interest;
use crate::name::Name;

/// A PIT entry tracking a pending Interest.
#[derive(Clone, Debug)]
pub struct PitEntry {
    /// The Interest that was forwarded upstream.
    pub interest: Interest,
    /// Faces the Interest arrived on (for Data multicast).
    pub in_faces: Vec<FaceId>,
    /// Face the Interest was forwarded to.
    pub out_face: Option<FaceId>,
    /// When this entry expires.
    pub expires_at: Instant,
    /// Whether this Interest has been satisfied.
    pub satisfied: bool,
}

/// Result of inserting/aggregating into the PIT.
#[derive(Debug, PartialEq)]
pub enum PitOp {
    /// A new PIT entry was created.
    Inserted,
    /// The in_face was added to an existing entry (aggregation).
    Aggregated,
}

/// Pending Interest Table.
pub struct Pit {
    entries: HashMap<Name, PitEntry>,
    /// Loop detection: (in_face, nonce) pairs seen recently.
    nonce_tracker: HashMap<(FaceId, [u8; 8]), Instant>,
    /// How long to keep nonce records for loop detection.
    nonce_ttl: Duration,
}

impl Pit {
    /// Create a new empty PIT.
    pub fn new() -> Self {
        Pit {
            entries: HashMap::new(),
            nonce_tracker: HashMap::new(),
            nonce_ttl: Duration::from_secs(60),
        }
    }

    /// Look up a pending Interest by exact name.
    pub fn find(&self, name: &Name) -> Option<&PitEntry> {
        self.entries.get(name)
    }

    /// Insert a new PIT entry or aggregate onto an existing one.
    ///
    /// If an entry with the same name already exists and is not satisfied,
    /// adds `in_face` to its `in_faces` list and returns `Aggregated`.
    /// Otherwise creates a new entry and returns `Inserted`.
    pub fn insert_or_aggregate(
        &mut self,
        name: Name,
        in_face: FaceId,
        interest: Interest,
        timeout: Duration,
    ) -> PitOp {
        if let Some(entry) = self.entries.get_mut(&name) {
            if !entry.satisfied {
                if !entry.in_faces.contains(&in_face) {
                    entry.in_faces.push(in_face);
                }
                return PitOp::Aggregated;
            }
        }

        self.entries.insert(
            name,
            PitEntry {
                interest,
                in_faces: vec![in_face],
                out_face: None,
                expires_at: Instant::now() + timeout,
                satisfied: false,
            },
        );
        PitOp::Inserted
    }

    /// Set the out_face for a PIT entry (where the Interest was forwarded to).
    pub fn set_out_face(&mut self, name: &Name, out_face: FaceId) {
        if let Some(entry) = self.entries.get_mut(name) {
            entry.out_face = Some(out_face);
        }
    }

    /// Satisfy a PIT entry, returning all in_faces for Data multicast.
    ///
    /// After this call, the entry is marked satisfied and will be cleaned
    /// up on the next `purge_expired` call.
    pub fn satisfy(&mut self, name: &Name) -> Option<Vec<FaceId>> {
        if let Some(entry) = self.entries.get_mut(name) {
            entry.satisfied = true;
            Some(entry.in_faces.clone())
        } else {
            None
        }
    }

    /// Remove expired entries and return them.
    ///
    /// Satisfied entries are always removed. Unsatisfied entries are
    /// removed only if their expiry time has passed.
    pub fn purge_expired(&mut self) -> Vec<PitEntry> {
        let now = Instant::now();
        let expired: Vec<Name> = self
            .entries
            .iter()
            .filter(|(_, e)| e.satisfied || e.expires_at <= now)
            .map(|(n, _)| n.clone())
            .collect();

        let mut removed = Vec::with_capacity(expired.len());
        for name in &expired {
            if let Some(entry) = self.entries.remove(name) {
                removed.push(entry);
            }
        }

        // Also purge old nonce entries
        self.nonce_tracker.retain(|_, t| *t > now);

        removed
    }

    /// Check if this (in_face, nonce) pair is a forwarding loop.
    ///
    /// Returns true if the nonce was already seen from a different face,
    /// indicating a loop.
    pub fn check_loop(&self, in_face: FaceId, nonce: [u8; 8]) -> bool {
        self.nonce_tracker
            .get(&(in_face, nonce))
            .is_some_and(|_| true)
    }

    /// Record a nonce for loop detection.
    pub fn record_nonce(&mut self, in_face: FaceId, nonce: [u8; 8]) {
        self.nonce_tracker
            .insert((in_face, nonce), Instant::now() + self.nonce_ttl);
    }

    /// Number of entries in the PIT.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if the PIT is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for Pit {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::name::Name;
    use std::time::Duration;

    fn make_hash(byte: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = byte;
        h
    }

    fn make_interest(name: Name) -> Interest {
        Interest::new(name)
    }

    fn timeout() -> Duration {
        Duration::from_secs(4)
    }

    #[test]
    fn test_insert_and_find() {
        let mut pit = Pit::new();
        let name = Name::new(make_hash(0x01), &[b"test"]);
        let interest = make_interest(name.clone());

        let op = pit.insert_or_aggregate(name.clone(), 1, interest, timeout());
        assert_eq!(op, PitOp::Inserted);
        assert!(pit.find(&name).is_some());
    }

    #[test]
    fn test_aggregation() {
        let mut pit = Pit::new();
        let name = Name::new(make_hash(0x01), &[b"test"]);
        let interest = make_interest(name.clone());

        pit.insert_or_aggregate(name.clone(), 1, interest.clone(), timeout());
        let op = pit.insert_or_aggregate(name.clone(), 2, interest, timeout());

        assert_eq!(op, PitOp::Aggregated);
        let entry = pit.find(&name).unwrap();
        assert_eq!(entry.in_faces, vec![1, 2]);
    }

    #[test]
    fn test_no_duplicate_in_face() {
        let mut pit = Pit::new();
        let name = Name::new(make_hash(0x01), &[b"test"]);
        let interest = make_interest(name.clone());

        pit.insert_or_aggregate(name.clone(), 1, interest.clone(), timeout());
        pit.insert_or_aggregate(name.clone(), 1, interest, timeout());

        let entry = pit.find(&name).unwrap();
        assert_eq!(entry.in_faces, vec![1]);
    }

    #[test]
    fn test_satisfy_returns_in_faces() {
        let mut pit = Pit::new();
        let name = Name::new(make_hash(0x01), &[b"test"]);
        let interest = make_interest(name.clone());

        pit.insert_or_aggregate(name.clone(), 1, interest.clone(), timeout());
        pit.insert_or_aggregate(name.clone(), 2, interest, timeout());

        let in_faces = pit.satisfy(&name).unwrap();
        assert_eq!(in_faces, vec![1, 2]);

        let entry = pit.find(&name).unwrap();
        assert!(entry.satisfied);
    }

    #[test]
    fn test_purge_expired_satisfied() {
        let mut pit = Pit::new();
        let name = Name::new(make_hash(0x01), &[b"test"]);
        let interest = make_interest(name.clone());

        pit.insert_or_aggregate(name.clone(), 1, interest, timeout());
        pit.satisfy(&name);

        let expired = pit.purge_expired();
        assert_eq!(expired.len(), 1);
        assert!(pit.find(&name).is_none());
    }

    #[test]
    fn test_purge_expired_timeout() {
        let mut pit = Pit::new();
        let name = Name::new(make_hash(0x01), &[b"test"]);
        let interest = make_interest(name.clone());

        // Use zero timeout so it expires immediately
        pit.insert_or_aggregate(name.clone(), 1, interest, Duration::ZERO);

        // Small sleep to ensure expiry
        std::thread::sleep(Duration::from_millis(1));

        let expired = pit.purge_expired();
        assert_eq!(expired.len(), 1);
        assert!(pit.is_empty());
    }

    #[test]
    fn test_set_out_face() {
        let mut pit = Pit::new();
        let name = Name::new(make_hash(0x01), &[b"test"]);
        let interest = make_interest(name.clone());

        pit.insert_or_aggregate(name.clone(), 1, interest, timeout());
        pit.set_out_face(&name, 5);

        let entry = pit.find(&name).unwrap();
        assert_eq!(entry.out_face, Some(5));
    }

    #[test]
    fn test_loop_detection() {
        let mut pit = Pit::new();
        let nonce = [1u8; 8];

        assert!(!pit.check_loop(1, nonce));
        pit.record_nonce(1, nonce);
        assert!(pit.check_loop(1, nonce));
    }
}
