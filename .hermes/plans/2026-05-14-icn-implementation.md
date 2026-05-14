# rsticulum-icn Implementation Plan

> **For Hermes:** Use subagent-driven-development to implement this plan phase by phase.

**Goal:** ICN application layer on rsticulum — content-addressed fetching, manifest discovery, self-certifying names.

**Architecture:** Forwarder (FIB/PIT/CS/Strategy) ported from NDN concepts, implemented with rsticulum identity primitives. Names encode producer identity → self-certifying, no PKI. Manifests are the discovery index. Wire format is compact binary. No NDN TLV, no management protocol, no forwarding pipelines.

**Tech Stack:** Rust, rsticulum-identity/transport/crypto, tokio, blake3, serde_json, lru, thiserror.

---

## Phase 1: Core Types (4 tasks)

### Task 1: Name type

**Files:**
- Create: `crates/icn/src/name.rs`
- Modify: `crates/icn/src/lib.rs`

Name components are binary (length-prefixed). First component is always 32-byte producer hash (BLAKE3 of public key). Optionally ends with 32-byte content hash.

```
Wire: [count:1][len1:1][bytes1...][len2:1][bytes2...][0xFF if hash][hash:32]
```

```rust
pub struct Name {
    components: Vec<Vec<u8>>,
    content_hash: Option<[u8; 32]>,
}

impl Name {
    pub fn new(producer_hash: [u8; 32], path: &[&[u8]]) -> Self;
    pub fn with_content_hash(mut self, hash: [u8; 32]) -> Self;
    pub fn producer_hash(&self) -> &[u8; 32];
    pub fn is_prefix_of(&self, other: &Name) -> bool;
    pub fn starts_with(&self, prefix: &Name) -> bool;
    pub fn to_bytes(&self) -> Vec<u8>;
    pub fn from_bytes(bytes: &[u8]) -> Result<Self>;
}

impl Display for Name {
    // /a1b2c3d4.../app/chat?blake3=e7f8...
}
```

### Task 2: Interest + Data types

**Files:**
- Create: `crates/icn/src/interest.rs`
- Create: `crates/icn/src/data.rs`

```rust
pub struct Interest {
    pub name: Name,
    pub nonce: [u8; 8],
    pub lifetime: Duration,
    pub can_be_prefix: bool,
    pub selector: Option<InterestSelector>,
}

pub struct InterestSelector {
    pub min_sequence: Option<u64>,      // only return seq >= this
    pub exclude_hashes: Vec<[u8; 32]>,  // don't return these
}

pub struct Data {
    pub name: Name,
    pub content: Vec<u8>,
    pub signature: Proof,           // [hash(32)][sig(64)] from rsticulum-transport
    pub metadata: DataMetadata,
}

pub struct DataMetadata {
    pub content_hash: Option<[u8; 32]>,  // BLAKE3 of content
    pub sequence: Option<u64>,           // for mutable content (manifests)
    pub freshness: Freshness,
}

pub enum Freshness {
    Fresh,                          // directly from producer
    Stale { age: Duration },        // from CS, this old
}
```

Wire format for Interest: `[name_bytes:varint][nonce:8][lifetime_ms:4][flags:1][selector_data:...]`
Wire format for Data: `[name_bytes:varint][content_len:4][content:...][metadata_bytes:varint][signature:96]`

### Task 3: Manifest types

**Files:**
- Create: `crates/icn/src/manifest.rs`

```rust
pub struct Manifest {
    pub producer: [u8; 32],
    pub sequence: u64,
    pub timestamp: u64,              // unix seconds
    pub entries: Vec<ManifestEntry>,
    pub previous: Option<Name>,      // for history traversal
}

pub struct ManifestEntry {
    pub kind: EntryKind,
    pub label: String,
    pub content_name: Name,
    pub content_hash: Option<[u8; 32]>,
    pub size: Option<u64>,
}

pub enum EntryKind {
    Blob,        // single Data packet
    Stream,      // ordered sequence
    Manifest,    // recursive (sub-manifest)
}

impl Manifest {
    pub fn from_data(data: &Data) -> Result<Self>;     // JSON decode from data.content
    pub fn to_data(&self, keys: &Keys) -> Data;         // encode as JSON + sign
}

pub struct ContentManifest {
    pub chunks: Vec<ChunkRef>,
    pub total_size: u64,
}

pub struct ChunkRef {
    pub name: Name,
    pub hash: [u8; 32],      // BLAKE3 of chunk
    pub offset: u64,
    pub length: u32,
}
```

Serialization: JSON via serde. Manifests are tiny metadata — JSON is universally parseable. Content itself uses whatever format the app wants.

### Task 4: Update Cargo.toml + lib.rs

```toml
[dependencies]
rsticulum-identity = { path = "../identity" }
rsticulum-crypto = { path = "../crypto" }
rsticulum-transport = { path = "../transport" }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
blake3 = "1"
thiserror = "2"
tokio = { version = "1", features = ["sync", "time", "rt"] }
lru = "0.12"
```

---

## Phase 2: Forwarding Tables (5 tasks)

### Task 5: ContentStore

**File:** `crates/icn/src/cs.rs`

```rust
pub struct ContentStore {
    entries: LruCache<Name, CachedData>,
}

struct CachedData {
    data: Data,
    inserted_at: Instant,
}

impl ContentStore {
    pub fn new(max_entries: usize) -> Self;
    pub fn get(&mut self, name: &Name) -> Option<&Data>;         // exact match
    pub fn get_prefix(&mut self, prefix: &Name) -> Option<&Data>; // prefix match for can_be_prefix
    pub fn insert(&mut self, name: Name, data: Data) -> Option<CachedData>; // evicts if full
    pub fn contains(&self, name: &Name) -> bool;
    pub fn len(&self) -> usize;
}
```

Unsolicited Data is cached (no flow balance enforcement). LRU eviction. Configurable max_entries (default 1000).

### Task 6: Fib

**File:** `crates/icn/src/fib.rs`

```rust
pub struct Fib {
    entries: Vec<FibEntry>,
}

pub struct FibEntry {
    pub prefix: Name,
    pub faces: Vec<(FaceId, u8)>,  // (face_id, cost), ordered by cost asc
}

pub type FaceId = u64;

impl Fib {
    pub fn new() -> Self;
    pub fn insert(&mut self, prefix: Name, face: FaceId, cost: u8);
    pub fn remove_face(&mut self, prefix: &Name, face: FaceId);
    pub fn remove_prefix(&mut self, prefix: &Name);
    pub fn lookup(&self, name: &Name) -> Option<Vec<(FaceId, u8)>>;
}
```

`lookup` does longest-prefix-match. Returns all faces for the matching prefix (strategy picks which to use). Returns None if no match.

### Task 7: Pit

**File:** `crates/icn/src/pit.rs`

```rust
pub struct Pit {
    entries: HashMap<Name, PitEntry>,
    nonce_tracker: HashSet<(FaceId, [u8; 8])>,  // for loop detection
}

pub struct PitEntry {
    pub interest: Interest,
    pub in_faces: Vec<FaceId>,       // faces the Interest arrived on
    pub out_face: Option<FaceId>,    // where it was forwarded
    pub expires_at: Instant,
    pub satisfied: bool,
}

impl Pit {
    pub fn new() -> Self;
    pub fn find(&self, name: &Name) -> Option<&PitEntry>;
    pub fn insert_or_aggregate(&mut self, name: Name, in_face: FaceId, interest: Interest) -> PitOp;
    pub fn satisfy(&mut self, name: &Name) -> Option<Vec<FaceId>>;  // returns in_faces for multicast
    pub fn purge_expired(&mut self) -> Vec<PitEntry>;
    pub fn check_loop(&self, in_face: FaceId, nonce: [u8; 8]) -> bool; // true if loop detected
    pub fn record_nonce(&mut self, in_face: FaceId, nonce: [u8; 8]);
}

pub enum PitOp {
    Inserted,       // new PIT entry created
    Aggregated,     // added in_face to existing entry
}
```

PIT timeout = `max(interest.lifetime, face.capabilities().disruption_tolerance)`.

### Task 8: Face trait + TestFace

**File:** `crates/icn/src/face.rs`

```rust
#[async_trait]
pub trait Face: Send + Sync {
    async fn express_interest(&self, interest: &Interest) -> Result<Option<Data>>;
    async fn send_data(&self, data: &Data) -> Result<()>;
    fn capabilities(&self) -> FaceCapabilities;
    fn id(&self) -> FaceId;
}

pub struct FaceCapabilities {
    pub disruption_tolerance: Duration,
    pub mtu: usize,
    pub is_local: bool,
}

// TestFace for integration testing
pub struct TestFace {
    id: FaceId,
    rx: Mutex<tokio::sync::mpsc::UnboundedReceiver<Interest>>,
    tx: tokio::sync::mpsc::UnboundedSender<Data>,
    // for the other direction
    interest_tx: tokio::sync::mpsc::UnboundedSender<Interest>,
    data_rx: Mutex<tokio::sync::mpsc::UnboundedReceiver<Data>>,
}

pub fn test_face_pair() -> (TestFace, TestFace);
```

### Task 9: Strategy trait + BestRoute

**File:** `crates/icn/src/strategy.rs`

```rust
#[async_trait]
pub trait Strategy: Send + Sync {
    async fn decide(
        &self,
        interest: &Interest,
        fib_faces: &[(FaceId, u8)],
        pit_hit: Option<&PitEntry>,
        cs_hit: Option<&Data>,
    ) -> StrategyDecision;
}

pub enum StrategyDecision {
    ForwardTo(FaceId),
    Multicast(Vec<FaceId>),
    SuppressAggregate,   // already in PIT, just add in_face
    ServeFromCache,      // CS hit
    NoRoute,
}

pub struct BestRoute;

#[async_trait]
impl Strategy for BestRoute {
    async fn decide(&self, interest: &Interest, fib_faces: &[(FaceId, u8)], pit_hit: Option<&PitEntry>, cs_hit: Option<&Data>) -> StrategyDecision {
        // 1. If CS has matching Data AND (not must_be_fresh OR Selector satisfied), serve from cache
        // 2. If PIT has matching entry, aggregate
        // 3. If FIB has faces, forward to lowest-cost face
        // 4. NoRoute
    }
}
```

---

## Phase 3: Forwarder (4 tasks)

### Task 10: Forwarder express loop

**File:** `crates/icn/src/forwarder.rs`

```rust
pub struct Forwarder {
    cs: ContentStore,
    fib: Fib,
    pit: Pit,
    strategy: Box<dyn Strategy>,
    faces: HashMap<FaceId, Arc<dyn Face>>,
}

impl Forwarder {
    pub fn new(strategy: Box<dyn Strategy>) -> Self;

    pub fn register_face(&mut self, face: Arc<dyn Face>);
    pub fn unregister_face(&mut self, face_id: FaceId);

    /// Express an Interest. Returns Some(Data) if satisfied, None if timed out.
    pub async fn express(&mut self, interest: Interest, in_face: FaceId) -> Result<Option<Data>>;
}
```

**express() flow:**

```
1. Check loop (nonce + in_face) → if loop, drop
2. Record nonce
3. Check CS → if hit and selector satisfied, clone and return
4. Check PIT → if identical Interest pending, aggregate, wait on existing
5. Lookup FIB → if no faces, return None (NoRoute)
6. Consult Strategy → get decision
7. If ForwardTo: create PIT entry, call face.express_interest(), wait
8. If Multicast: create PIT entry, race faces, first Data wins
9. If ServeFromCache: return cached Data
10. If SuppressAggregate: wait on existing PIT entry
11. On Data return: cache in CS, satisfy PIT (multicast to in_faces)
12. On timeout: purge PIT entry, return None
13. Purge expired PIT entries
```

### Task 11: Forwarder receive_data + Data verification

```rust
impl Forwarder {
    /// Process incoming Data. Called when Data arrives on a face without a pending Interest.
    pub async fn receive_data(&mut self, data: Data, in_face: FaceId) -> Result<()>;
    
    /// Verify Data signature using producer's public key.
    fn verify_data(&self, data: &Data) -> Result<()>;
}
```

**receive_data() flow:**

```
1. Verify signature (hash name+content, verify against producer key)
2. Lookup PIT by name → if hit, multicast to in_faces, satisfy
3. Cache in CS regardless (unsolicited Data is cached)
```

**verify_data():**
- Extract producer hash from name's first component
- Need producer's public key → lookup from identity announce or local key store
- For MVP: pass a `HashMap<[u8; 32], Keys>` to the forwarder for key lookup
- Verify: `verify_proof(keys, &hash(name + content), &data.signature)`

### Task 12: Forwarder with PIT wait + multicast

Add a notification mechanism for PIT aggregation. When multiple consumers express the same Interest:

```rust
// Internal notification channel
struct PitNotifier {
    waiters: HashMap<Name, Vec<tokio::sync::oneshot::Sender<Result<Option<Data>>>>>,
}

impl PitNotifier {
    fn register(&mut self, name: &Name) -> tokio::sync::oneshot::Receiver<Result<Option<Data>>>;
    fn notify(&mut self, name: &Name, result: Result<Option<Data>>);
}
```

When a PIT entry is satisfied, notify all registered waiters with the Data. When it times out, notify with None.

### Task 13: Face registry + Backoff

```rust
impl Forwarder {
    pub fn register_face(&mut self, face: Arc<dyn Face>);
    
    /// Add FIB entry for a face
    pub fn add_route(&mut self, prefix: Name, face_id: FaceId, cost: u8);
}
```

Strategy tracks failed face attempts to avoid repeatedly trying dead faces:

```rust
struct BestRoute {
    failures: Mutex<HashMap<FaceId, (Instant, u32)>>,  // (last_failure, count)
    backoff_base: Duration,  // 1s
    max_backoff: Duration,   // 30s
}
```

---

## Phase 4: Integration Tests (5 tasks)

### Task 14: Name/Interest/Data round-trip tests

**File:** `crates/icn/tests/types.rs`

- Name → bytes → Name round-trip
- Interest → bytes → Interest round-trip  
- Data → bytes → Data round-trip
- Name Display formatting
- Name prefix matching (`/a/b/c` starts with `/a/b`)
- Name prefix matching negative (`/a/b` does NOT start with `/a/c`)
- Content hash round-trip in name

### Task 15: ContentStore + FIB + PIT unit tests

**File:** `crates/icn/tests/tables.rs`

- CS: insert → get → hit
- CS: get absent → miss
- CS: LRU eviction (insert 1001 into max 1000 cache)
- CS: prefix matching for `can_be_prefix`
- FIB: exact match
- FIB: longest-prefix-match (`/a/b/c` matches `/a/b`)
- FIB: no match → None
- FIB: multiple faces returned in cost order
- PIT: insert → find → hit
- PIT: aggregation (two in_faces)
- PIT: satisfy → returns in_faces, marks satisfied
- PIT: expiry purge
- PIT: loop detection (same nonce, different face)

### Task 16: Strategy tests

**File:** `crates/icn/tests/strategy.rs`

- BestRoute: CS hit → ServeFromCache
- BestRoute: CS hit but must_be_fresh with stale data → ForwardTo
- BestRoute: PIT hit → SuppressAggregate
- BestRoute: FIB hit → ForwardTo lowest cost
- BestRoute: empty FIB → NoRoute
- Backoff: after failure, same face not tried within backoff window

### Task 17: Forwarder integration with TestFace

**File:** `crates/icn/tests/forwarder_integration.rs`

Two-forwarder setup using TestFace pairs:

```
[Consumer Forwarder] ←TestFace→ [Producer Forwarder]
```

Tests:
1. **Consumer expresses Interest → Producer returns Data → Consumer gets Data**
2. **Consumer expresses Interest → CS hit on first forwarder → no upstream Interest**
3. **Two consumers, same Interest → PIT aggregation → one upstream Interest → both get Data**
4. **Consumer expresses Interest → no route → returns None (timeout)**
5. **Unsolicited Data received → cached in CS → subsequent Interest served from CS**

### Task 18: Manifest + ContentManifest tests

**File:** `crates/icn/tests/manifest.rs`

- Manifest JSON round-trip
- Manifest::from_data() → valid
- Manifest::to_data() → signed Data with valid proof
- ContentManifest with chunks
- Freshness: Fresh vs Stale metadata
- InterestSelector: min_sequence filtering in CS

### Task 19: Multi-node Interest/Data flow

**File:** `crates/icn/tests/multi_node.rs`

Three-forwarder chain with TestFace pairs:

```
[Consumer] → [Intermediate] → [Producer]
```

Tests:
1. **Consumer → Intermediate → Producer → Intermediate → Consumer** (full Interest/Data chain)
2. **Intermediate caches Data → second consumer gets CS hit at Intermediate**

---

## Phase 5: LinkFace (2 tasks)

### Task 20: LinkFace implementation

**File:** `crates/icn/src/link_face.rs`

```rust
pub struct LinkFace {
    id: FaceId,
    link: Link,
    capabilities: FaceCapabilities,
}

impl LinkFace {
    pub fn new(id: FaceId, link: Link) -> Self;
}

#[async_trait]
impl Face for LinkFace {
    async fn express_interest(&self, interest: &Interest) -> Result<Option<Data>> {
        // 1. Serialize Interest to bytes
        // 2. Send via link.send()
        // 3. Wait for Data via link.recv() with timeout = interest.lifetime
        // 4. Deserialize Data from bytes
    }

    async fn send_data(&self, data: &Data) -> Result<()> {
        // 1. Serialize Data to bytes
        // 2. Send via link.send()
    }

    fn capabilities(&self) -> FaceCapabilities {
        FaceCapabilities {
            disruption_tolerance: Duration::from_secs(3600), // mesh can survive hours
            mtu: 500,  // rsticulum default MTU
            is_local: false,
        }
    }

    fn id(&self) -> FaceId { self.id }
}
```

### Task 21: LinkFace integration test with rsticulum mesh

**File:** `crates/icn/tests/link_face_integration.rs`

Use rsticulum `Link` between two real identities:

```
[Consumer Forwarder + LinkFace] ←rsticulum Link→ [Producer Forwarder + LinkFace]
```

Test: express Interest → Data flows through real Link → consumer receives Data.

---

## Phase 6: CLI / Demo (post-MVP)

A basic CLI binary that demonstrates the full flow:

```bash
# Producer side
$ rsticulum-icn serve --identity producer.key
  Publishing manifest: /a1b2c3...d4a7/manifest

# Consumer side  
$ rsticulum-icn fetch a1b2c3...d4a7
  Fetching manifest...
  Found: app/chat (stream), app/photos (blob)
  Fetching app/chat...
  [chat messages]
```

This goes in a `rsticulum-icn` binary or in `rsticulum-daemon`.

---

## Crate API Summary

```rust
// Public API surface of rsticulum-icn

// Types
pub use name::Name;
pub use interest::{Interest, InterestSelector};
pub use data::{Data, DataMetadata, Freshness};
pub use manifest::{Manifest, ManifestEntry, EntryKind, ContentManifest, ChunkRef};

// Forwarding
pub use forwarder::Forwarder;
pub use cs::ContentStore;
pub use fib::{Fib, FibEntry, FaceId};
pub use pit::{Pit, PitEntry, PitOp};
pub use face::{Face, FaceCapabilities, TestFace, test_face_pair};
pub use strategy::{Strategy, StrategyDecision, BestRoute};

// Transport integration
pub use link_face::LinkFace;
```

## Dependencies Added

```toml
[dependencies]
rsticulum-identity = { path = "../identity" }
rsticulum-crypto = { path = "../crypto" }
rsticulum-transport = { path = "../transport" }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
blake3 = "1"
thiserror = "2"
tokio = { version = "1", features = ["sync", "time", "rt"] }
lru = "0.12"
async-trait = "0.1"

[dev-dependencies]
tokio = { version = "1", features = ["full"] }
```

## Key Design Decisions (Resolved)

| Decision | Choice | Why |
|----------|--------|-----|
| Content hash | BLAKE3 | Consistency with identity crate, faster than SHA-256 |
| Name wire format | Binary length-prefixed | Compact, simple, Display impl for readability |
| Manifest format | JSON (serde_json) | Self-describing, universally parseable, tiny overhead for metadata |
| ContentStore eviction | LRU | Simple, effective, swappable later |
| Freshness model | InterestSelector with min_sequence | CS can serve newer versions without always going upstream |
| Flow balance | Not enforced | Unsolicited Data is cached — mesh Links are already authenticated |
| Multi-hop forwarding | Not in MVP | rsticulum mesh IS the multi-hop layer |
| LinkFace location | Inside ICN crate | Transport is a core dependency, no reason to separate |
| PIT aggregation | Full support | Multiple consumers → one upstream Interest → multicast Data back |
| Loop detection | Nonce + in_face tracking | Standard NDN technique |
