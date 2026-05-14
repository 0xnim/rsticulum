# rsticulum-icn Design

> **For Hermes:** Use subagent-driven-development to implement this design crate-by-crate.

**Goal:** An ICN (Interest/Data) application layer on rsticulum mesh, with self-certifying names and a manifest discovery system.

**Architecture:** Names carry producer identity for self-certification. Forwarder with FIB/PIT/CS/Strategy — porting NFD's concepts but with rsticulum primitives, not NDN TLV. Manifests are the discovery mechanism: know a producer → fetch manifest → discover content names.

**Tech Stack:** Rust, existing rsticulum crates (identity, transport, crypto), tokio async.

---

## Why This Design

### Ladder of Leverage Assessment

1. **Use directly**: `ndn-rs` (0.0.3-alpha, single maintainer, tightly coupled to NDN TLV). Does not fit rsticulum's identity model or wire format. Rejected.
2. **Fork + modify**: NFD (C++, 96% C++, forwarding pipelines, management protocol, NLSR). Architecture is reference-quality but the implementation is too heavy and uses NDN TLV throughout. Rejected.
3. **Port from scratch**: Take NFD's architectural concepts (FIB/PIT/CS/Strategy/forwarder loop) and reimplement in Rust with rsticulum primitives. This is what we're doing.
4. **Greenfield**: Not needed — FIB/PIT/CS is well-understood architecture.

### What We Keep from NDN Architecture
- **FIB**: prefix → ordered list of faces
- **PIT**: aggregation of identical Interests, reverse-path for Data
- **CS**: LRU cache of Data packets, serves matching Interests
- **Strategy**: pluggable forwarding decision (which face(s) to try)
- **Interest/Data packet model**: consumer expresses Interest, network returns Data

### What We Swap
| NDN | rsticulum-icn |
|-----|---------------|
| TLV wire format | Compact binary (consistent with rsticulum packet crate style) |
| Hierarchical names (e.g. `/edu/ucla/cs/video`) | Hybrid: `/producer-hash/namespace/path?sha256=abc` |
| Separate trust schema / PKI | Name carries producer hash → self-certifying |
| NFD management protocol | None in MVP (static FIB or mesh-discovery-driven) |
| NLSR routing protocol | Mesh path discovery (existing) for FIB population |
| Unix/TCP/UDP faces | rsticulum Link faces (authenticated, quality-tracked) |
| Forwarding pipelines (in/out/content/mgmt) | Simple forwarder loop (Interest→CS→PIT→FIB→forward, Data→PIT→CS→forward) |

---

## Naming Scheme

### Why Hybrid (Not Pure Hierarchical)

Pure hierarchical names (`/com/example/video/chunk/42`) don't encode the producer's identity. You need a separate PKI to verify Data signatures — fetch a certificate, walk a trust chain. In a mesh network where any node might cache and serve Data, you need to verify provenance without knowing the producer in advance.

Self-certifying names solve this: the name IS the verification anchor. But pure content-hash names (`bafy...`) can't route — every name is a leaf, no prefix aggregation.

Hybrid: routable prefix (producer identity) + namespace path + optional content hash.

### Format

```
/<producer-hash>/<namespace>/[...path...][?sha256=<content-hash>]
```

Where `<producer-hash>` is the 32-char hex of the producer's rsticulum `Address` (32-byte BLAKE3 of public key). This IS the routing prefix AND the verification anchor.

Examples:
```
/a1b2c3...d4a7/app/chat/manifest
/a1b2c3...d4a7/app/chat/v/5/chunk/0?sha256=e7f8...
/a1b2c3...d4a7/feeds/sensors/temperature?sha256=1a2b...
```

### FIB Aggregation

FIB lookups use longest-prefix-match on name components. All content from producer `a1b2c3...` routes via the same face(s). The FIB is per-producer, which is correct for a mesh network where you route to identities, not namespaces.

```rust
struct Name {
    components: Vec<NameComponent>,
    content_hash: Option<[u8; 32]>,  // optional SHA-256 content hash
}

enum NameComponent {
    Generic(Vec<u8>),      // opaque bytes
    ProducerHash([u8; 32]), // first component is always this
}
```

Name matching uses longest-prefix-match over components. `/a1b2c3/app/chat` matches FIB entry `/a1b2c3` and `/a1b2c3/app`.

### Wire Encoding

Length-prefixed components, 1 byte per component length. Content hash uses a discriminator byte (`0xFF`):

```
[component_count:1][len:1][bytes...][len:1][bytes...][0xFF if hash present][hash:32]
```

---

## Core Types

### Interest

```rust
struct Interest {
    name: Name,
    nonce: [u8; 8],          // unique per Interest, for loop detection
    lifetime: Duration,       // how long to keep PIT entry alive
    can_be_prefix: bool,      // can match a prefix of the name?
    must_be_fresh: bool,      // must NOT be satisfied from CS
}

// Wire format:
// [name_bytes:varint][nonce:8][lifetime_ms:4][flags:1]
```

### Data

```rust
struct Data {
    name: Name,
    content: Vec<u8>,
    signature: Proof,          // [hash(32)][sig(64)] — from rsticulum-transport
}

// Wire format:
// [name_bytes:varint][content_len:4][content:...][signature:96]
```

**Verification**: hash the (name + content), verify against signature using the producer's public key. The producer's identity hash is in the name's first component. The consumer must have the producer's public key (from rsticulum identity announce or out-of-band).

### Manifest

```rust
struct Manifest {
    producer: [u8; 32],        // matches first component of manifest's name
    sequence: u64,              // monotonic — higher = newer
    timestamp: u64,             // unix seconds
    entries: Vec<ManifestEntry>,
    previous: Option<Name>,     // previous manifest version (for history traversal)
}

struct ManifestEntry {
    kind: EntryKind,
    label: String,              // e.g. "chat", "sensor-data"
    content_name: Name,         // where the content lives
    content_hash: Option<[u8; 32]>,  // expected SHA-256 of content
    size: Option<u64>,
}

enum EntryKind {
    Blob,       // single Data packet
    Stream,     // ordered sequence of Data packets
    Manifest,   // points to another manifest (recursive)
    App,        // WASM application
}
```

Manifest itself is carried as ICN Data — the manifest bytes are the Data content, signed by the producer. `Manifest::from_data(data: &Data) -> Result<Manifest>`.

### ContentManifest

For large content split across chunks:

```rust
struct ContentManifest {
    chunks: Vec<ChunkRef>,
    total_size: u64,
}

struct ChunkRef {
    name: Name,           // full name including content hash
    hash: [u8; 32],       // SHA-256 of chunk content
    offset: u64,
    length: u32,
}
```

---

## Forwarding Architecture

### Face Abstraction

```rust
#[async_trait]
trait Face: Send + Sync {
    /// Send an Interest on this face. Returns the Data or timeout.
    async fn express_interest(&self, interest: &Interest) -> Result<Option<Data>>;
    
    /// Send Data on this face (in response to a previous Interest).
    async fn send_data(&self, data: &Data) -> Result<()>;
    
    /// Face capability hints for PIT/Strategy decisions.
    fn capabilities(&self) -> FaceCapabilities;
    
    /// Unique face ID for FIB/PIT bookkeeping.
    fn id(&self) -> FaceId;
}

struct FaceCapabilities {
    disruption_tolerance: Duration,  // expected max disruption (mesh = hours, backbone = minutes)
    mtu: usize,
    is_local: bool,                  // local face (loopback for testing)
}
```

**LinkFace**: wraps a rsticulum `Link`. Uses the authenticated link to express Interests and receive Data. PIT timeout set from `disruption_tolerance`.

### ContentStore

```rust
struct ContentStore {
    entries: LruCache<Name, CachedData>,
    max_entries: usize,
}

struct CachedData {
    data: Data,
    stale_at: Option<Instant>,  // None = valid forever (immutable data)
}
```

Configurable `max_entries`. Default 1000. Immutable Data (names with content hash) never expire. Stale manifests (served while producer is unreachable) get `stale_at` set so consumers know the data might be old.

### Forwarding Information Base

```rust
struct Fib {
    entries: Vec<FibEntry>,
}

struct FibEntry {
    prefix: Name,
    faces: Vec<(FaceId, u8)>,  // (face_id, cost) — ordered by cost ascending
}

impl Fib {
    /// Longest-prefix-match lookup
    fn lookup(&self, name: &Name) -> Option<&[(FaceId, u8)]>;
    
    /// Add/update prefix mapping
    fn insert(&mut self, prefix: Name, face: FaceId, cost: u8);
    
    /// Remove a face from a prefix
    fn remove(&mut self, prefix: &Name, face: FaceId);
}
```

### Pending Interest Table

```rust
struct Pit {
    entries: HashMap<Name, PitEntry>,
}

struct PitEntry {
    interest: Interest,
    in_faces: Vec<FaceId>,         // faces the Interest arrived on (for Data return)
    out_face: Option<FaceId>,      // face the Interest was forwarded to
    expires_at: Instant,
    satisfied: bool,
}

impl Pit {
    /// Check if identical Interest is already pending (for aggregation)
    fn find(&self, name: &Name) -> Option<&PitEntry>;
    
    /// Insert new PIT entry or aggregate onto existing
    fn insert_or_aggregate(&mut self, name: Name, in_face: FaceId, interest: Interest);
    
    /// Mark satisfied, return all in_faces for Data multicast
    fn satisfy(&mut self, name: &Name) -> Option<Vec<FaceId>>;
    
    /// Remove and return expired entries
    fn purge_expired(&mut self) -> Vec<PitEntry>;
}
```

PIT timeout per entry is `max(interest.lifetime, in_face.capabilities().disruption_tolerance)`. Mesh faces get longer timeouts.

### Strategy (trait)

```rust
#[async_trait]
trait Strategy: Send + Sync {
    /// Decide which face(s) to forward an Interest to, given:
    /// - the Interest
    /// - the FIB lookup result (ordered list of faces)
    /// - the PIT state (is there already a pending Interest?)
    /// - the CS state (is it cached?)
    async fn forward_interest(
        &self,
        interest: &Interest,
        fib_faces: &[(FaceId, u8)],
        pit: &Pit,
        cs: &ContentStore,
    ) -> StrategyDecision;
}

enum StrategyDecision {
    ForwardTo(FaceId),       // send to one face
    MulticastTo(Vec<FaceId>), // send to multiple faces
    Suppress,                // don't forward (e.g., already in PIT)
    Nack(String),            // can't forward (no faces, etc.)
}
```

Default: `BestRoute` — forward to the lowest-cost FIB face that isn't already tried. If the first face times out, try the next.

Future: `Multicast` for discovery, `PathAware` for SCION-optimized forwarding.

### Forwarder

```rust
struct Forwarder {
    fib: Fib,
    pit: Pit,
    cs: ContentStore,
    strategy: Box<dyn Strategy>,
    faces: HashMap<FaceId, Arc<dyn Face>>,
}

impl Forwarder {
    /// Express an Interest — the main API
    async fn express(&mut self, interest: Interest, in_face: FaceId) -> Result<Option<Data>>;
    
    /// Process incoming Data (e.g., from a Link receive)
    async fn receive_data(&mut self, data: Data, in_face: FaceId) -> Result<()>;
    
    /// Register a face for FIB/PIT use
    fn register_face(&mut self, face: Arc<dyn Face>);
}
```

**Forwarder loop** (for `express`):

```
1. Check ContentStore — if cached, return immediately (unless must_be_fresh)
2. Check PIT — if identical Interest pending, aggregate (add in_face to entry), wait
3. Lookup FIB — longest-prefix-match on name
4. Consult Strategy — which face(s) to forward to?
5. Create PIT entry with in_face + out_face
6. Forward Interest via face.express_interest()
7. Wait for Data or timeout
8. If Data: cache in CS, multicast to all in_faces in PIT entry
9. If timeout: remove PIT entry, return None
```

For `receive_data`:

```
1. Verify Data signature (producer = name's first component)
2. Lookup PIT — find matching entry(ies) by name
3. If PIT hit: deliver Data to all in_faces, mark satisfied, cache in CS
4. If no PIT hit: cache in CS anyway (unsolicited Data — useful for pre-caching)
```

---

## Freshness Model for Disruption Tolerance

The core tension: manifests are mutable (new versions appear), but ICN Data is immutable (same name = same content). Under disruption, the producer might be unreachable.

### Stale Manifest Serving

When a consumer fetches `/producer/manifest` with `must_be_fresh=true` and the producer is unreachable:

1. Forwarder checks CS — finds a previous manifest
2. CS serves it with a `StalenessHint: Stale(Duration)` in the Data
3. The Data name includes a staleness parameter: `/producer/manifest?stale=3600` (stale by 1 hour)
4. Consumer decides: use stale data or wait?

The staleness hint is an opaque metadata field in the Data packet, not a naming convention. The consumer application layer decides what to do with it.

### Manifest Polling

For applications that need freshness:
- Poll `/producer/manifest?sequence=N` where N is the last known sequence
- If new sequence exists, get the updated manifest
- If producer unreachable, get stale manifest with staleness hint

This is application-level logic, not in the ICN crate. The crate just provides the mechanism (must_be_fresh flag, staleness metadata).

---

## What the ICN Crate Depends On

```
rsticulum-icn
├── rsticulum-identity   — Address, Keys, Signature (for producer verification)
├── rsticulum-crypto     — SHA-256 (for content hashing)
├── rsticulum-transport  — Link (for LinkFace), Proof (for Data signatures)
├── serde                — serialization of Manifest/ContentManifest
├── thiserror            — error types
├── tokio                — async runtime
└── lru                  — LRU cache for ContentStore
```

**No dependency on**: mesh, packet, interface, backbone, bridge, daemon. The ICN crate is transport-layer agnostic — it works on any Face implementation.

---

## What the ICN Crate Does NOT Do

- **Routing protocol**: FIB is manually populated or driven by mesh path discovery. No NLSR equivalent.
- **Management protocol**: No NFD management socket. Configuration is programmatic.
- **Persistent CS**: Memory-only for MVP. Persistent storage is a future feature.
- **Forwarding pipelines**: No plugin pipeline system. Simple forwarder loop.
- **Certificate/trust management**: Producer identity is in the name. Trust is bootstrapped out-of-band.
- **Application SDK**: That goes in `rsticulum-sdk`.

---

## Testing Strategy

### Unit Tests
- Name parsing, matching, prefix lookup
- Interest/Data wire format round-trip
- Manifest/ContentManifest serialization
- ContentStore eviction and staleness
- FIB longest-prefix-match
- PIT aggregation, satisfaction, expiry
- Strategy decisions (BestRoute, Multicast)
- Data signature verification

### Integration Tests
- Two-node forwarder: consumer expresses Interest, producer responds with Data
- Multi-node: Interest forwarded through intermediate forwarder
- PIT aggregation: two consumers, one Interest upstream
- CS hit: second Interest served from cache
- Manifest freshness: must_be_fresh vs stale CS hit
- Disruption: PIT timeout when producer unreachable

### Mock Face
A `TestFace` that uses channels for in-memory Interest/Data exchange between forwarders. No real network needed.

---

## Implementation Phases

### Phase 1: Types (3-4 tasks)
- `Name` type with parsing, matching, wire encoding
- `Interest` + `Data` types with wire format
- `Manifest` + `ContentManifest` types with serde

### Phase 2: Tables (4-5 tasks)
- `ContentStore` with LRU eviction
- `Fib` with longest-prefix-match
- `Pit` with aggregation and expiry
- `Face` trait + `TestFace` mock

### Phase 3: Forwarder (4-5 tasks)
- `Strategy` trait + `BestRoute` impl
- `Forwarder` with express/receive loops
- Signature verification in receive_data
- Wire up TestFace for integration tests

### Phase 4: Integration (3-4 tasks)
- Two-node forwarder test
- Multi-node Interest/Data flow
- PIT aggregation test
- Manifest end-to-end test

### Phase 5: LinkFace (2-3 tasks)
- `LinkFace` wrapping rsticulum `Link`
- Disruption tolerance from link state
- Integration with real mesh (if ready)

---

## Open Questions

1. **Name component encoding**: binary components (length-prefixed) or text components (like NDN's `/` delimited)? Binary is more compact and simpler to parse, but text is more debuggable. Leaning binary with a `Display` impl that shows hex for readability.

2. **Content hash**: SHA-256 or BLAKE3? We use BLAKE3 for identity addresses (32 bytes), SHA-256 for packet hashes in transport. For content verification, BLAKE3 is faster but SHA-256 is more standard. Leaning BLAKE3 for consistency with identity crate.

3. **LinkFace vs ICN-as-library**: Should the ICN crate include LinkFace, or should that live in daemon/sdk? Including it means the crate depends on transport — but that's fine, transport is a core crate. Including it.

4. **ContentStore eviction policy**: LRU is standard. But for ICN, access frequency might matter more than recency (popular content gets hit repeatedly). LFU would be better but more complex. LRU for MVP.
