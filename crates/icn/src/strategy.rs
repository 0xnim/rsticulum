//! Strategy trait and BestRoute implementation.
//!
//! A Strategy decides which face(s) to forward an Interest to, given
//! the Interest, FIB lookup result, PIT state, and CS state.
//! Strategies are pluggable — swap in Multicast, PathAware, etc.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::face::FaceId;
use crate::interest::{Data, Interest};
use crate::pit::PitEntry;

/// Decision returned by a Strategy.
#[derive(Debug, PartialEq)]
pub enum StrategyDecision {
    /// Forward to a single face.
    ForwardTo(FaceId),
    /// Forward to multiple faces simultaneously.
    Multicast(Vec<FaceId>),
    /// Don't forward — the Interest is already pending (aggregate).
    SuppressAggregate,
    /// Serve directly from ContentStore — no forwarding needed.
    ServeFromCache,
    /// Cannot forward — no matching faces.
    NoRoute,
}

/// A forwarding strategy.
///
/// Called by the Forwarder to decide where to send an Interest.
#[async_trait::async_trait]
pub trait Strategy: Send + Sync {
    /// Decide where to forward an Interest.
    async fn decide(
        &self,
        interest: &Interest,
        fib_faces: &[(FaceId, u8)],
        pit_hit: Option<&PitEntry>,
        cs_hit: Option<&Data>,
    ) -> StrategyDecision;
}

/// BestRoute strategy: forward to the lowest-cost face, with backoff on failure.
///
/// Decision logic:
/// 1. If CS has matching Data and selector is satisfied → ServeFromCache
/// 2. If PIT has matching entry → SuppressAggregate
/// 3. If FIB has faces → ForwardTo the lowest-cost non-backoff face
/// 4. Otherwise → NoRoute
pub struct BestRoute {
    /// Track recent failures per face for backoff.
    failures: Mutex<HashMap<FaceId, FailureRecord>>,
    /// Base backoff duration.
    backoff_base: Duration,
    /// Maximum backoff duration.
    max_backoff: Duration,
}

#[derive(Clone, Debug)]
struct FailureRecord {
    last_failure: Instant,
    consecutive_failures: u32,
}

impl BestRoute {
    /// Create a new BestRoute strategy with default backoff settings.
    pub fn new() -> Self {
        BestRoute {
            failures: Mutex::new(HashMap::new()),
            backoff_base: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
        }
    }

    /// Create with custom backoff settings.
    pub fn with_backoff(base: Duration, max: Duration) -> Self {
        BestRoute {
            failures: Mutex::new(HashMap::new()),
            backoff_base: base,
            max_backoff: max,
        }
    }

    /// Record a failure on a face (called externally after Interest times out).
    pub fn record_failure(&self, face: FaceId) {
        let mut failures = self.failures.lock().unwrap();
        let record = failures.entry(face).or_insert(FailureRecord {
            last_failure: Instant::now(),
            consecutive_failures: 0,
        });
        record.last_failure = Instant::now();
        record.consecutive_failures += 1;
    }

    /// Record a success on a face (clears backoff).
    pub fn record_success(&self, face: FaceId) {
        let mut failures = self.failures.lock().unwrap();
        failures.remove(&face);
    }

    /// Check if a face is in backoff and shouldn't be used.
    fn is_in_backoff(&self, face: FaceId) -> bool {
        let failures = self.failures.lock().unwrap();
        if let Some(record) = failures.get(&face) {
            let backoff = (self.backoff_base * 2u32.pow(record.consecutive_failures.min(6)))
                .min(self.max_backoff);
            record.last_failure.elapsed() < backoff
        } else {
            false
        }
    }

    /// Check if a Data packet satisfies the Interest's selector.
    fn selector_satisfied(interest: &Interest, data: &Data) -> bool {
        if let Some(ref sel) = interest.selector {
            // must_be_fresh: reject stale cached data
            if sel.must_be_fresh {
                if let crate::interest::Freshness::Stale { .. } = data.metadata.freshness {
                    return false;
                }
            }

            // min_sequence: require sequence >= min
            if let Some(min_seq) = sel.min_sequence {
                if let Some(data_seq) = data.metadata.sequence {
                    if data_seq < min_seq {
                        return false;
                    }
                } else {
                    // No sequence on data but min_sequence requested → reject
                    return false;
                }
            }

            // exclude_hashes: reject if content hash matches excluded
            if let Some(content_hash) = data.metadata.content_hash {
                if sel.exclude_hashes.contains(&content_hash) {
                    return false;
                }
            }
        }
        true
    }
}

impl Default for BestRoute {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Strategy for BestRoute {
    async fn decide(
        &self,
        interest: &Interest,
        fib_faces: &[(FaceId, u8)],
        pit_hit: Option<&PitEntry>,
        cs_hit: Option<&Data>,
    ) -> StrategyDecision {
        // 1. Check ContentStore
        if let Some(data) = cs_hit {
            if Self::selector_satisfied(interest, data) {
                return StrategyDecision::ServeFromCache;
            }
        }

        // 2. Check PIT
        if let Some(entry) = pit_hit {
            if !entry.satisfied {
                return StrategyDecision::SuppressAggregate;
            }
        }

        // 3. Find the best face that isn't in backoff
        for (face_id, _cost) in fib_faces {
            if !self.is_in_backoff(*face_id) {
                return StrategyDecision::ForwardTo(*face_id);
            }
        }

        // 4. No reachable faces
        StrategyDecision::NoRoute
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interest::Freshness;
    use crate::name::Name;
    use rsticulum_transport::Proof;

    fn make_hash(byte: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = byte;
        h
    }

    fn make_interest(name: Name) -> Interest {
        Interest::new(name)
    }

    fn make_data(name: Name) -> Data {
        let sig = Proof::from_bytes(&vec![0u8; 96]).unwrap();
        Data::new(name, b"content".to_vec(), sig)
    }

    #[tokio::test]
    async fn test_serve_from_cache() {
        let strategy = BestRoute::new();
        let name = Name::new(make_hash(0x01), &[b"test"]);
        let interest = make_interest(name.clone());
        let data = make_data(name);

        let decision = strategy.decide(&interest, &[], None, Some(&data)).await;
        assert_eq!(decision, StrategyDecision::ServeFromCache);
    }

    #[tokio::test]
    async fn test_must_be_fresh_rejects_stale_cache() {
        let strategy = BestRoute::new();
        let name = Name::new(make_hash(0x01), &[b"test"]);
        let interest = make_interest(name.clone()).with_must_be_fresh();
        let mut data = make_data(name);
        data.metadata.freshness = Freshness::Stale {
            age: Duration::from_secs(3600),
        };

        let decision = strategy.decide(&interest, &[], None, Some(&data)).await;
        assert_eq!(decision, StrategyDecision::NoRoute);
    }

    #[tokio::test]
    async fn test_suppress_aggregate_on_pit_hit() {
        let strategy = BestRoute::new();
        let name = Name::new(make_hash(0x01), &[b"test"]);
        let interest = make_interest(name.clone());
        let pit_entry = PitEntry {
            interest: interest.clone(),
            in_faces: vec![1],
            out_face: Some(2),
            expires_at: Instant::now() + Duration::from_secs(10),
            satisfied: false,
        };

        let decision = strategy
            .decide(&interest, &[], Some(&pit_entry), None)
            .await;
        assert_eq!(decision, StrategyDecision::SuppressAggregate);
    }

    #[tokio::test]
    async fn test_forward_to_best_face() {
        let strategy = BestRoute::new();
        let name = Name::new(make_hash(0x01), &[b"test"]);
        let interest = make_interest(name);
        let fib_faces = vec![(5, 10), (3, 5)];

        let decision = strategy.decide(&interest, &fib_faces, None, None).await;
        assert_eq!(decision, StrategyDecision::ForwardTo(5));
    }

    #[tokio::test]
    async fn test_forward_skips_backoff_face() {
        let strategy = BestRoute::new();
        strategy.record_failure(5);
        let name = Name::new(make_hash(0x01), &[b"test"]);
        let interest = make_interest(name);
        let fib_faces = vec![(5, 5), (3, 10)];

        let decision = strategy.decide(&interest, &fib_faces, None, None).await;
        assert_eq!(decision, StrategyDecision::ForwardTo(3));
    }

    #[tokio::test]
    async fn test_no_route() {
        let strategy = BestRoute::new();
        let name = Name::new(make_hash(0x01), &[b"test"]);
        let interest = make_interest(name);

        let decision = strategy.decide(&interest, &[], None, None).await;
        assert_eq!(decision, StrategyDecision::NoRoute);
    }

    #[test]
    fn test_record_success_clears_backoff() {
        let strategy = BestRoute::new();
        strategy.record_failure(5);
        assert!(strategy.is_in_backoff(5));
        strategy.record_success(5);
        assert!(!strategy.is_in_backoff(5));
    }
}
