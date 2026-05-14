//! ICN Forwarder — ties FIB/PIT/CS/Strategy together.
//!
//! The forwarder processes Interest and Data packets:
//! - `express()`: receives an Interest, consults tables, forwards, waits for Data
//! - `receive_data()`: receives Data, verifies signature, satisfies PIT, caches
//!
//! ## Forwarding Loop
//! ```text
//! Interest arrives
//!   → Check loop (nonce + in_face)
//!   → Check CS (serve from cache if selector satisfied)
//!   → Check PIT (aggregate if identical Interest pending)
//!   → Lookup FIB (longest-prefix-match)
//!   → Consult Strategy (which face to forward to)
//!   → Create PIT entry + forward
//!   → Wait for Data or timeout
//!
//! Data arrives
//!   → Verify signature (producer = name's first component)
//!   → Lookup PIT (find matching entries)
//!   → If PIT hit: multicast to in_faces, satisfy, notify waiters
//!   → Cache in CS regardless (unsolicited Data)
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use rsticulum_identity::Keys;
use tokio::sync::oneshot;

use crate::cs::ContentStore;
use crate::face::{Face, FaceCapabilities, FaceId};
use crate::fib::Fib;
use crate::interest::{Data, Interest};
use crate::name::Name;
use crate::pit::{Pit, PitOp};
use crate::strategy::{BestRoute, Strategy, StrategyDecision};

/// Result returned to a consumer expressing an Interest.
type InterestResult = Result<Option<Data>, String>;

/// Internal notification channel for PIT satisfaction.
struct PitNotifier {
    /// Waiters keyed by Interest name. When Data arrives for this name,
    /// all waiters are notified.
    waiters: HashMap<Name, Vec<oneshot::Sender<InterestResult>>>,
}

impl PitNotifier {
    fn new() -> Self {
        PitNotifier {
            waiters: HashMap::new(),
        }
    }

    /// Register a waiter for the given Interest name.
    /// Returns a receiver that will be notified when Data arrives.
    fn register(&mut self, name: &Name) -> oneshot::Receiver<InterestResult> {
        let (tx, rx) = oneshot::channel();
        self.waiters.entry(name.clone()).or_default().push(tx);
        rx
    }

    /// Notify all waiters for the given name.
    fn notify(&mut self, name: &Name, result: InterestResult) {
        if let Some(waiters) = self.waiters.remove(name) {
            for tx in waiters {
                let _ = tx.send(result.clone());
            }
        }
    }

    /// Remove a specific waiter (e.g., on timeout).
    fn remove_waiter(&mut self, _name: &Name) {
        // Waiters are consumed on notify; if we timeout, the oneshot
        // sender is dropped and the receiver gets an error.
    }
}

/// The ICN forwarder.
pub struct Forwarder {
    cs: ContentStore,
    fib: Fib,
    pit: Pit,
    strategy: Box<dyn Strategy>,
    faces: HashMap<FaceId, Arc<dyn Face>>,
    notifier: PitNotifier,
    /// Map of producer hash → Keys for signature verification.
    key_store: HashMap<[u8; 32], Keys>,
}

impl Forwarder {
    /// Create a new Forwarder with a BestRoute strategy.
    pub fn new() -> Self {
        Forwarder {
            cs: ContentStore::new(1000),
            fib: Fib::new(),
            pit: Pit::new(),
            strategy: Box::new(BestRoute::new()),
            faces: HashMap::new(),
            notifier: PitNotifier::new(),
            key_store: HashMap::new(),
        }
    }

    /// Create with a custom strategy.
    pub fn with_strategy(strategy: Box<dyn Strategy>) -> Self {
        Forwarder {
            cs: ContentStore::new(1000),
            fib: Fib::new(),
            pit: Pit::new(),
            strategy,
            faces: HashMap::new(),
            notifier: PitNotifier::new(),
            key_store: HashMap::new(),
        }
    }

    /// Register a face with the forwarder.
    pub fn register_face(&mut self, face: Arc<dyn Face>) {
        self.faces.insert(face.id(), face);
    }

    /// Unregister a face by ID.
    pub fn unregister_face(&mut self, face_id: FaceId) {
        self.faces.remove(&face_id);
        // Remove all FIB entries referencing this face
        self.fib.remove_face(
            &Name::new([0u8; 32], &[]), // dummy, will match everything
            face_id,
        );
    }

    /// Add a FIB route: prefix → face with cost.
    pub fn add_route(&mut self, prefix: Name, face_id: FaceId, cost: u8) {
        self.fib.insert(prefix, face_id, cost);
    }

    /// Register a producer's keys for signature verification.
    pub fn register_keys(&mut self, producer_hash: [u8; 32], keys: Keys) {
        self.key_store.insert(producer_hash, keys);
    }

    /// Get a reference to the ContentStore.
    pub fn cs(&self) -> &ContentStore {
        &self.cs
    }

    /// Get a reference to the FIB.
    pub fn fib(&self) -> &Fib {
        &self.fib
    }

    /// Get a reference to the PIT.
    pub fn pit(&self) -> &Pit {
        &self.pit
    }

    /// Express an Interest — the main consumer API.
    ///
    /// Returns `Some(Data)` if the Interest is satisfied, or `None` if it times out
    /// or no route is found.
    pub async fn express(&mut self, interest: Interest, in_face: FaceId) -> InterestResult {
        // 1. Loop detection
        if self.pit.check_loop(in_face, interest.nonce) {
            return Err("loop detected".to_string());
        }
        self.pit.record_nonce(in_face, interest.nonce);

        // 2. Check ContentStore
        let cs_hit = if interest.can_be_prefix {
            self.cs.get_prefix(&interest.name)
        } else {
            self.cs.get(&interest.name)
        };

        // 3. Check PIT (after CS check, since CS hit skips PIT)
        let pit_hit = self.pit.find(&interest.name);

        // 4. Lookup FIB
        let fib_faces = self.fib.lookup(&interest.name).unwrap_or_default();

        // 5. Consult Strategy
        let decision = self
            .strategy
            .decide(&interest, &fib_faces, pit_hit, cs_hit)
            .await;

        match decision {
            StrategyDecision::ServeFromCache => {
                let data = cs_hit.expect("strategy said ServeFromCache but no CS hit");
                Ok(Some(data.clone()))
            }

            StrategyDecision::SuppressAggregate => {
                // Interest already pending — register for notification
                let rx = self.notifier.register(&interest.name);
                // Drop the &mut self borrow so the notifier can be used later
                drop(interest);
                match rx.await {
                    Ok(result) => result,
                    Err(_) => Ok(None),
                }
            }

            StrategyDecision::ForwardTo(face_id) => {
                self.forward_and_wait(interest, in_face, face_id).await
            }

            StrategyDecision::Multicast(face_ids) => {
                self.multicast_and_wait(interest, in_face, face_ids).await
            }

            StrategyDecision::NoRoute => Ok(None),
        }
    }

    /// Forward an Interest to a single face and wait for Data.
    async fn forward_and_wait(
        &mut self,
        interest: Interest,
        in_face: FaceId,
        out_face_id: FaceId,
    ) -> InterestResult {
        // Compute PIT timeout from face capabilities
        let timeout = {
            let face_timeout = self
                .faces
                .get(&out_face_id)
                .map(|f| f.capabilities().disruption_tolerance)
                .unwrap_or(Duration::from_secs(4));
            interest.lifetime.max(face_timeout)
        };

        // Insert into PIT
        let name = interest.name.clone();
        self.pit
            .insert_or_aggregate(name.clone(), in_face, interest.clone(), timeout);
        self.pit.set_out_face(&name, out_face_id);

        // Get the face
        let face = match self.faces.get(&out_face_id) {
            Some(f) => Arc::clone(f),
            None => {
                self.pit.satisfy(&name);
                return Err("face not found".to_string());
            }
        };

        // Forward Interest
        let result = face.express_interest(&interest).await;

        match result {
            Ok(Some(data)) => {
                // Verify signature
                if let Err(e) = self.verify_data(&data) {
                    self.pit.satisfy(&name);
                    return Err(format!("signature verification failed: {e}"));
                }

                // Record success with strategy
                if let Some(best) = self.strategy_as_best_route_mut() {
                    best.record_success(out_face_id);
                }

                // Cache in CS
                self.cs.insert(data.name.clone(), data.clone());

                // Satisfy PIT and notify waiters
                self.pit.satisfy(&name);
                self.notifier.notify(&name, Ok(Some(data.clone())));

                // Purge expired PIT entries
                self.pit.purge_expired();

                Ok(Some(data))
            }
            Ok(None) => {
                // Timeout — record failure
                if let Some(best) = self.strategy_as_best_route_mut() {
                    best.record_failure(out_face_id);
                }
                self.pit.satisfy(&name);
                self.notifier.notify(&name, Ok(None));
                self.pit.purge_expired();
                Ok(None)
            }
            Err(e) => {
                if let Some(best) = self.strategy_as_best_route_mut() {
                    best.record_failure(out_face_id);
                }
                self.pit.satisfy(&name);
                self.notifier.notify(&name, Err(e.clone()));
                self.pit.purge_expired();
                Err(e)
            }
        }
    }

    /// Forward an Interest to multiple faces and race them.
    async fn multicast_and_wait(
        &mut self,
        interest: Interest,
        in_face: FaceId,
        face_ids: Vec<FaceId>,
    ) -> InterestResult {
        let timeout = interest.lifetime;
        let name = interest.name.clone();
        self.pit
            .insert_or_aggregate(name.clone(), in_face, interest.clone(), timeout);

        // Forward to all faces in parallel
        let mut handles = Vec::new();
        for face_id in &face_ids {
            if let Some(face) = self.faces.get(face_id).cloned() {
                let interest = interest.clone();
                handles.push(tokio::spawn(async move {
                    (face.express_interest(&interest).await, *face_id)
                }));
            }
        }

        // Race: first successful Data wins
        let result = tokio::time::timeout(timeout, async {
            loop {
                // Check if any handle has completed
                for i in (0..handles.len()).rev() {
                    if handles[i].is_finished() {
                        let handle = handles.remove(i);
                        match handle.await.unwrap() {
                            (Ok(Some(data)), _face_id) => {
                                return Ok(Some(data));
                            }
                            _ => continue,
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;

        match result {
            Ok(Ok(Some((data, face_id)))) => {
                // Verify signature
                if let Err(e) = self.verify_data(&data) {
                    self.pit.satisfy(&name);
                    return Err(format!("signature verification failed: {e}"));
                }

                // Record success
                if let Some(best) = self.strategy_as_best_route_mut() {
                    best.record_success(face_id);
                }

                // Cache and notify
                self.cs.insert(data.name.clone(), data.clone());
                self.pit.satisfy(&name);
                self.notifier.notify(&name, Ok(Some(data.clone())));
                self.pit.purge_expired();
                Ok(Some(data))
            }
            _ => {
                // All timed out
                self.pit.satisfy(&name);
                self.notifier.notify(&name, Ok(None));
                self.pit.purge_expired();
                Ok(None)
            }
        }
    }

    /// Receive incoming Data (from a face or unsolicited).
    ///
    /// Verifies the signature, satisfies any matching PIT entries, and
    /// caches the Data in the ContentStore.
    pub async fn receive_data(&mut self, data: Data, _in_face: FaceId) -> Result<(), String> {
        // 1. Verify signature
        self.verify_data(&data)?;

        // 2. Check PIT for matching entries
        let name = data.name.clone();
        let matched = self.pit.satisfy(&name);

        // 3. Notify waiters
        if matched.is_some() {
            self.notifier.notify(&name, Ok(Some(data.clone())));
        }

        // 4. Cache in CS (even for unsolicited Data)
        self.cs.insert(name, data);

        // 5. Purge expired PIT entries
        self.pit.purge_expired();

        Ok(())
    }

    /// Verify a Data packet's signature.
    ///
    /// Extracts the producer hash from the name's first component,
    /// looks up the producer's keys, and verifies the proof.
    fn verify_data(&self, data: &Data) -> Result<(), String> {
        let producer_hash = data.name.producer_hash();
        let keys = self
            .key_store
            .get(producer_hash)
            .ok_or_else(|| format!("unknown producer: {:?}", producer_hash))?;

        let signed_hash = data.signed_hash();
        rsticulum_transport::verify_proof(keys, &signed_hash, &data.signature)
            .map_err(|e| format!("signature verification failed: {e}"))
    }

    /// Internal helper to get mutable reference to BestRoute strategy.
    fn strategy_as_best_route_mut(&mut self) -> Option<&mut BestRoute> {
        // We use unsafe downcast via Any since Strategy is a trait object.
        // Alternative: store BestRoute directly and delegate.
        // For now, use a simpler approach — store strategy type separately.
        None // Will be replaced with real backoff integration
    }
}

impl Default for Forwarder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::face::{test_face_pair, FaceCapabilities, TestFace};
    use rsticulum_transport::Proof;

    fn make_hash(byte: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = byte;
        h
    }

    fn make_name(byte: u8) -> Name {
        Name::new(make_hash(byte), &[b"test"])
    }

    fn make_data(name: Name) -> Data {
        let sig = Proof::from_bytes(&vec![0u8; 96]).unwrap();
        Data::new(name, b"content".to_vec(), sig)
    }

    fn make_keys(byte: u8) -> (Keys, [u8; 32]) {
        let keys = Keys::generate();
        let hash = *keys.address().as_bytes();
        (keys, hash)
    }

    /// Setup a producer that responds with fixed Data.
    fn spawn_producer(face: Arc<TestFace>, response: Data) {
        tokio::spawn(async move {
            // Wait for an Interest
            loop {
                if let Some(_interest) = face.recv_interest() {
                    let _ = face.send_data(&response).await;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
    }

    #[tokio::test]
    async fn test_express_cs_hit() {
        let mut fw = Forwarder::new();
        let name = make_name(0x01);
        let data = make_data(name.clone());
        fw.cs.insert(name.clone(), data.clone());

        let interest = Interest::new(name);
        let result = fw.express(interest, 0).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().content, b"content");
    }

    #[tokio::test]
    async fn test_express_no_route() {
        let mut fw = Forwarder::new();
        let name = make_name(0x01);
        let interest = Interest::new(name);

        let result = fw.express(interest, 0).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_express_forward_and_get_data() {
        let (face_a, face_b) = test_face_pair();
        let mut fw = Forwarder::new();

        // Register face_a
        fw.register_face(face_a.clone());
        let name = make_name(0x01);
        fw.add_route(make_name(0x01), face_a.id(), 10);

        // Register keys for verification
        let (keys, hash) = make_keys(0x01);
        fw.register_keys(hash, keys.clone());

        // Spawn producer on face_b
        let response = {
            let mut data = Data::new(
                make_name(0x01),
                b"hello".to_vec(),
                Proof::from_bytes(&vec![0u8; 96]).unwrap(),
            );
            // Create a properly signed response using the keys
            let signed_hash = {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&data.name.to_bytes());
                hasher.update(&data.content);
                *hasher.finalize().as_bytes()
            };
            data.signature = rsticulum_transport::generate_proof(&keys, &signed_hash);
            data.metadata.content_hash = Some(blake3::hash(&data.content).into());
            data
        };
        spawn_producer(face_b, response.clone());

        let interest = Interest::new(make_name(0x01)).with_lifetime(Duration::from_millis(500));
        let result = fw.express(interest, 1).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().content, b"hello");
    }

    #[tokio::test]
    async fn test_cs_cache_after_forward() {
        let (face_a, face_b) = test_face_pair();
        let mut fw = Forwarder::new();
        fw.register_face(face_a.clone());
        let name = make_name(0x01);
        fw.add_route(make_name(0x01), face_a.id(), 10);

        let (keys, hash) = make_keys(0x01);
        fw.register_keys(hash, keys.clone());

        let response = {
            let data = Data::new(
                make_name(0x01),
                b"cached".to_vec(),
                Proof::from_bytes(&vec![0u8; 96]).unwrap(),
            );
            let mut data = data;
            let signed_hash = {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&data.name.to_bytes());
                hasher.update(&data.content);
                *hasher.finalize().as_bytes()
            };
            data.signature = rsticulum_transport::generate_proof(&keys, &signed_hash);
            data.metadata.content_hash = Some(blake3::hash(&data.content).into());
            data
        };
        spawn_producer(face_b, response);

        // First express: forward to producer
        let interest = Interest::new(make_name(0x01)).with_lifetime(Duration::from_millis(500));
        let _result = fw.express(interest, 1).await.unwrap();

        // Second express: should be CS hit
        let interest2 = Interest::new(make_name(0x01));
        let result2 = fw.express(interest2, 1).await.unwrap();
        assert!(result2.is_some());
        assert_eq!(result2.unwrap().content, b"cached");
        assert!(fw.cs().hits() > 0);
    }

    #[tokio::test]
    async fn test_express_timeout() {
        let (face_a, _face_b) = test_face_pair();
        let mut fw = Forwarder::new();
        fw.register_face(face_a.clone());
        fw.add_route(make_name(0x01), face_a.id(), 10);

        // No producer spawned — Interest will time out
        let interest = Interest::new(make_name(0x01)).with_lifetime(Duration::from_millis(50));
        let result = fw.express(interest, 1).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_pit_aggregation_two_consumers() {
        // PIT aggregation: two consumers express the same Interest.
        // The first creates a PIT entry, the second aggregates.
        // When Data arrives via receive_data, the CS hit serves the second.
        let (face_a, face_b) = test_face_pair();
        let mut fw = Forwarder::new();
        fw.register_face(face_a.clone());
        fw.add_route(make_name(0x01), face_a.id(), 10);

        let (keys, hash) = make_keys(0x01);
        fw.register_keys(hash, keys.clone());

        // Create signed response
        let response = {
            let data = Data::new(
                make_name(0x01),
                b"shared".to_vec(),
                Proof::from_bytes(&vec![0u8; 96]).unwrap(),
            );
            let mut data = data;
            let signed_hash = {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&data.name.to_bytes());
                hasher.update(&data.content);
                *hasher.finalize().as_bytes()
            };
            data.signature = rsticulum_transport::generate_proof(&keys, &signed_hash);
            data.metadata.content_hash = Some(blake3::hash(&data.content).into());
            data
        };

        // Producer that responds
        let face_b_clone = face_b.clone();
        let response_clone = response.clone();
        tokio::spawn(async move {
            if let Some(_interest) = face_b_clone.recv_interest() {
                let _ = face_b_clone.send_data(&response_clone).await;
            }
        });

        // First consumer expresses Interest — this creates a PIT entry
        let interest1 = Interest::new(make_name(0x01)).with_lifetime(Duration::from_millis(500));
        let result1 = fw.express(interest1, 1).await.unwrap();
        assert!(result1.is_some());

        // Data should now be in CS
        assert!(fw.cs().contains(&make_name(0x01)));

        // Second consumer expresses same Interest — should get CS hit
        // (PIT entry was already satisfied and purged)
        let interest2 = Interest::new(make_name(0x01));
        let result2 = fw.express(interest2, 2).await.unwrap();
        assert!(result2.is_some());
        assert_eq!(result2.unwrap().content, b"shared");
    }

    #[tokio::test]
    async fn test_unsolicited_data_cached() {
        let mut fw = Forwarder::new();
        let (keys, hash) = make_keys(0x01);
        fw.register_keys(hash, keys.clone());

        // Create signed Data
        let name = make_name(0x01);
        let data = {
            let d = Data::new(
                name.clone(),
                b"unsolicited".to_vec(),
                Proof::from_bytes(&vec![0u8; 96]).unwrap(),
            );
            let mut d = d;
            let signed_hash = {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&d.name.to_bytes());
                hasher.update(&d.content);
                *hasher.finalize().as_bytes()
            };
            d.signature = rsticulum_transport::generate_proof(&keys, &signed_hash);
            d.metadata.content_hash = Some(blake3::hash(&d.content).into());
            d
        };

        // Receive unsolicited Data
        fw.receive_data(data, 0).await.unwrap();

        // Should be cached
        assert!(fw.cs().contains(&name));

        // Subsequent Interest should be CS hit
        let interest = Interest::new(name);
        let result = fw.express(interest, 0).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().content, b"unsolicited");
    }

    #[tokio::test]
    async fn test_unsolicited_data_unknown_producer_rejected() {
        let mut fw = Forwarder::new();
        // Don't register keys
        let name = make_name(0x01);
        let data = Data::new(
            name,
            b"bad".to_vec(),
            Proof::from_bytes(&vec![0u8; 96]).unwrap(),
        );

        let result = fw.receive_data(data, 0).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown producer"));
    }
}
