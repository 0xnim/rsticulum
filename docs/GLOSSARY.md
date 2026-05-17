# Glossary

## Addressing

| Term | Definition |
|------|-----------|
| **Canonical Address** | `SHA-256(Ed25519_pubkey)` — 32 bytes. The full identity hash. Used at bridge/backbone. |
| **Edge Address (RNS)** | First 16 bytes of the canonical address. Used in edge network (Reticulum) for packet efficiency on low-bandwidth links. |
| **RNS Address** | Same as edge address. 16-byte hex string. |
| **Identity Hash** | Synonym for canonical address. |
| **Producer Hash** | The 64-character hex encoding of a full 32-byte canonical address, used as the root component of ICN names: `/<producer_hash>/...` |
| **Address Translation** | Bridge operation: edge (16B) ↔ backbone (32B) mapping via the Unified Addressing Table. |

## Cryptographic Primitives

| Term | Definition |
|------|-----------|
| **Ed25519** | Edwards-curve digital signature algorithm. 32-byte keys, 64-byte signatures. Used for identity keys and proof handshakes. |
| **X25519** | Elliptic-curve Diffie-Hellman key exchange. Used for link session key derivation. |
| **ECDH** | Elliptic-Curve Diffie-Hellman. The key exchange that produces a shared secret from two X25519 keypairs. |
| **HKDF-SHA256** | HMAC-based Key Derivation Function using SHA-256. Derives AES-256-CBC and HMAC-SHA256 keys from the ECDH shared secret. |
| **SHA-256** | 256-bit cryptographic hash. Used for address derivation and proof-of-work. |
| **BLAKE3** | 256-bit cryptographic hash. Faster than SHA-256, especially on ARM/embedded. Used for ICN content hashing. |
| **HMAC-SHA256** | Hash-based Message Authentication Code using SHA-256. Used for packet authentication and hop-field validation. |
| **AES-256-CBC** | AES in Cipher Block Chaining mode with 256-bit keys. Packet encryption at the edge. |
| **Token** | Simplified Fernet construction used by Python RNS for Link encryption. Wire format: `iv(16) || ciphertext || HMAC(32)`. Supports both AES-128-CBC (32-byte key) and AES-256-CBC (64-byte key). Python default: AES-256-CBC. Signing key = `derived[0:32]`, encryption key = `derived[32:64]`. Random IV. |

## Protocol Concepts

| Term | Definition |
|------|-----------|
| **Link** | An encrypted, authenticated channel between two Reticulum nodes. Established via ECDH + Ed25519 proof handshake. Suspendable by default. |
| **SuspendableLink** | A wrapper around Link that adds session serialization/deserialization — Link is the core encryption engine. On disconnect, session keys and pending messages are serialized to disk. On reconnect, the link resumes. |
| **Proof Handshake** | Zero-RTT trust verification: each side proves ownership of their Ed25519 key by signing a challenge derived from the ECDH shared secret. |
| **Announce** | A broadcast packet declaring a node's presence, identity, and reachable addresses. Flooded through the mesh or forwarded hierarchically. |
| **Hierarchical Announce Forwarding** | Edge nodes announce only to bridges. Bridges aggregate into route summaries and propagate upward. Replaces O(n²) flooding with O(n log n). |
| **Route Summary** | A bridge-generated announcement carrying aggregated edge prefixes and path quality, propagated through the backbone. |
| **Bridge** | A dual-stack node that connects an edge mesh to the backbone. Performs address translation (16B ↔ 32B) and announce aggregation. |
| **Backbone** | The scaling layer. Source-routed identity-based forwarding across multiple mesh domains. SCION-inspired. |
| **ISD** | Isolation Domain. A trust boundary in the backbone. Nodes within an ISD trust each other via threshold membership voting. |
| **Path Segment** | A pre-constructed route through the backbone. Source routing uses up to three segments: up (source to core), core, down (core to destination). |
| **Hop Field** | A single hop in a path segment. Contains a MAC that the receiving AS verifies, preventing path forgery. |
| **Beaconing** | Periodic path discovery in the backbone. Nodes send beacons that accumulate hop fields, forming path segments. |
| **TrustVote** | An Ed25519-signed statement by an ISD member vouching for a new member. N votes admit the new member. |

## ICN / NDN Concepts

ICN functionality is provided as Reticulum protocol extensions for content-named data, rather than as a separate application layer. Content-named Interests and Data packets are carried over Reticulum Links and Faces, inheriting the network's suspendable, always-encrypted transport.

| Term | Definition |
|------|-----------|
| **Content Extension** | The Reticulum protocol extension that adds ICN/NDN content-named data semantics. Provides Interest/Data exchange, in-network caching, and forwarding strategies over Reticulum's encrypted transport layer. |
| **Interest** | A request for named data. Contains a Name (producer hash + path) and optional parameters. Aggregated in the PIT. |
| **Data** | A response to an Interest. Contains the requested content plus a BLAKE3 hash and producer signature. |
| **Name** | An ICN content identifier. Format: `/<64-char-producer-hash>(/<path>)*?blake3=<content_hash>` |
| **PIT** | Pending Interest Table. Tracks outstanding Interests, aggregates duplicates, and routes returning Data to consumers. Default lifetime: 30 minutes. |
| **FIB** | Forwarding Information Base. Maps name prefixes to output faces. Longest-prefix-match routing. |
| **CS** | Content Store. An opportunistic LRU cache of Data packets at every hop. Satisfies Interests without forwarding. |
| **Face** | An ICN network interface abstraction. Transport-agnostic. A `LinkFace` wraps a Reticulum Link. |
| **Forwarder** | The ICN packet processor. Pipeline: Interest → CS → PIT → FIB → Strategy → Face. Data → PIT → CS → Face. |
| **Strategy** | Per-prefix forwarding policy. `BestRoute` (default), `Multicast`, `RoundRobin`, `SubscribeAware`. |
| **Subscription Interest** | A long-lived Interest with `subscribe: true`. Producer pushes multiple Data packets over time. Consumer refreshes to keep alive. |
| **Manifest** | A signed JSON document listing versioned content entries. Maps semantic names to content hashes. Fetched by well-known pointer. |
| **Well-Known Pointer** | A special Interest name (`/<producer>/_manifest`) that returns the latest manifest hash. Like a Git branch pointer. |

## Lifecycle Concepts

| Term | Definition |
|------|-----------|
| **Identity Record** | A signed record containing a node's primary key, timestamps, expiry, and delegation chain. Gossiped through the network. |
| **Identity Event** | A state change in the identity lifecycle: `Publish`, `Rotate`, `Revoke`, `Delegate`. |
| **Key Rotation** | Transitioning from an old key to a new key. The old key signs a delegation to the new key. Both are valid during a grace period. |
| **Key Revocation** | Permanent invalidation of a key. Propagated via gossip. After revocation, the key is never trusted again. |
| **Delegation Chain** | A sequence of signed delegation statements: `Root → A → B → C`. Depth bounded to 3. Verifiers walk the chain to the trusted root. |
| **Gossip Protocol** | Epidemic propagation of identity events. Peers exchange event sets; new events spread through the network. Push + pull. |

## Implementation Crates

| Term | Definition |
|------|-----------|
| **rsticulum** | The Rust implementation of the Reticulum networking stack. The project as a whole. |
| **RNS** | Reticulum Network Stack — the Python reference implementation. `rsticulum` is wire-compatible with RNS. |
| **Workspace** | All crates under the root `Cargo.toml`. 14 crates currently. |

## Network Physics

| Term | Definition |
|------|-----------|
| **MTU** | Maximum Transmission Unit. Edge: ~200 bytes (LoRa) to ~1500 bytes (WiFi). Backbone: ~9000 bytes. |
| **RTT** | Round-Trip Time. Edge: 100ms (WiFi) to 30s (LoRa). Backbone: 10–200ms. |
| **PoW Difficulty** | Proof-of-work target bits. Default 20 bits (~5s CPU per announce). Adaptive based on bridge congestion. |
| **Congestion Signal** | A byte in bridge response packets: `0x00` normal, `0x01` reduce, `0x02` stop. Edge nodes throttle accordingly. |
| **Backpressure** | Bridge→edge congestion signal. Causes edge nodes to increase announce interval and PoW difficulty. |

## Comparison: This Network vs. IP Internet

| Concept | IP Internet | This Network |
|---------|-------------|--------------|
| Address | IP (location) | Identity hash (who you are) |
| Address assignment | ISP/DHCP | Self-generated keypair |
| Name resolution | DNS | Identity hash (no resolution needed) |
| Trust | CA hierarchy | Self-certifying keys |
| Transport | TCP/UDP | Reticulum (suspendable links) |
| Security | TLS (optional) | Always encrypted (ECDH + AES-256-CBC) |
| Data fetching | HTTP GET to server URL | ICN Interest for content hash |
| Mutable data | Server updates | Manifest (immutable hashes, mutable pointer) |
| Caching | CDN (centrally controlled) | In-network (every hop) |
| Disconnection | RST, connection lost | Suspend, wait, resume |
| Routing | BGP (prefix announcement) | Link-state + path discovery (edge), source routing (backbone) |
| Spam prevention | Reputation, blocklists | Proof-of-work |
| Multi-device | Separate accounts/IPs | Key delegation chains |
| Deployment | App store / server | WASM via manifest |

## Standards References

| RFC | Title | Relevance |
|-----|-------|-----------|
| **RFC 8032** | Edwards-Curve Digital Signature Algorithm (Ed25519) | Identity key generation and proof handshake signatures |
| **RFC 7748** | Elliptic Curves for Security (X25519) | ECDH key exchange for link session key derivation |
| **RFC 5869** | HMAC-based Extract-and-Expand Key Derivation Function (HKDF) | Deriving AES-256-CBC and HMAC-SHA256 keys from ECDH shared secret |
| **RFC 6234** | US Secure Hash Algorithms (SHA-256) | Address derivation and proof-of-work hashing |
| **RFC 8569** | Content-Centric Networking (CCNx) Semantics (IRTF) | ICN naming, Interest/Data semantics, and manifest design |
| **RFC 8793** | Information-Centric Networking (ICN): Content-Centric Networking (CCNx) and Named Data Networking (NDN) Terminology (IRTF) | Standard ICN/NDN vocabulary (PIT, FIB, CS, Face, Strategy) |
| **RFC 7476** | Information-Centric Networking: Baseline Scenarios (IRTF) | Foundational ICN use cases and architectural motivation |
| **RFC 7927** | Information-Centric Networking: Research Challenges (IRTF) | Open research problems in ICN deployment, routing, and security |
