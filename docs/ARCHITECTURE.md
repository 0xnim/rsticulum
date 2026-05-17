# Architecture Specification

## Abstract

This network has two layers plus identity. ICN features are not a separate
application layer — they are **Content-Named Extensions to Reticulum**, added
via new packet types (`Interest`, `Data`) alongside existing Reticulum types
(`HEADER_1`, `HEADER_2`, `PROOF`, `DATA`, `ANNOUNCE`). Because Reticulum
relays already see plaintext during forwarding, content-named caching,
Interest aggregation, and named-data semantics can be added without a
separate protocol stack.

```
┌──────────────────────────────────────────────────┐
│                   APPLICATIONS                   │
│  (WASM, CLI tools, IoT logic, chat, feeds)       │
├──────────────────────────────────────────────────┤
│              EDGE / TRANSPORT                    │
│    Reticulum Protocol (rsticulum)                │
│  ┌────────────────────────────────────────┐     │
│  │  Content-Named Extensions to Reticulum  │     │
│  │  Interest/Data packet types             │     │
│  │  ContentStore, PIT, FIB                 │     │
│  │  Manifest system, Subscription Interests│     │
│  │  Named data requests by producer hash   │     │
│  └────────────────────────────────────────┘     │
│  Identity-derived 16-byte addresses              │
│  Proactive link-state + reactive discovery       │
│  Physical agnostic (UDP, serial, radio, LoRa)    │
│  Suspend/reconnect — no RST on timeout           │
│  Rateless announces via hierarchical forwarding  │
├──────────────────────────────────────────────────┤
│              IDENTITY / ADDRESSING               │
│           Cryptographic Addressing               │
│  Address = Public Key hash                       │
│  Delegation, rotation, revocation lifecycle      │
│  No NAT, no spoofing, no allocation              │
└──────────────────────────────────────────────────┘
```

There is no application-layer equivalent to HTTP, DNS, or TLS. Identity
replaces DNS (Ed25519 key hash = address). Content-addressed data replaces
server URLs. Cryptographic proofs replace certificate authorities.
Content-named extensions replace the request-response model with named data
fetching within the transport itself.

There is no separate transport layer — Reticulum *is* the transport. There
is no separate backbone layer — backbone routing is a deployment pattern
within Reticulum (transport instances in special roles), not a separate
protocol.

For a detailed accounting of what each protocol standard does well and what
must be changed for this network, see [ADAPTATIONS.md](../ADAPTATIONS.md).

## 1. Design Principles

### 1.1 Identity-First

Your address is **who you are** (a hash of your Ed25519 public key — [RFC 8032]),
not **where you are plugged in** (an ISP-allocated IP address). There is no
NAT, no DHCP, no address renumbering. Your identity is your address is
your cryptographic key — one namespace, permanently.

**Consequence:** applications route to identities, not to IPs. A message
addressed to `alice@<hash>` reaches Alice regardless of whether she is on
WiFi, satellite, or LoRa. The network's job is to find a path from your
key to hers.

### 1.2 Disruption-Tolerant

Links survive hours or days of disconnection. The network does NOT RST
when a signal drops. It waits. State is serialized to disk. On reconnect,
the link resumes where it left off. This is the default, not an opt-in.

**Consequence:** applications never handle reconnection logic. The network
guarantees eventual delivery or a definitive failure notification —
nothing in between.

### 1.3 Content-Addressed

Fetch data by **what it is** (a content hash), not by **where it lives**
(a server URL). Any copy of the data is equally valid. The network caches
content opportunistically at every hop.

**Consequence:** no link rot, no server dependency, no CDN configuration.
Popular data is automatically replicated. Content integrity is verified
by the hash — you cannot receive wrong data and not know it.

### 1.4 Permissionless

No registrars, no certificate authorities, no gatekeepers. Cryptographic
proof replaces institutional trust. Generate a keypair — you are now on
the network. Your identity is self-certifying.

**Consequence:** the network cannot be censored at the address-allocation
level. There is no authority to ask "may I have an address?" because the
answer is always "you already have one."

### 1.5 Medium-Agnostic

LoRa, serial, WiFi, Ethernet, satellite, optical — any physical medium is
a valid network link. The stack does not care about the underlying
transport. An interface is anything that moves bytes.

**Consequence:** the same application runs unchanged over a 300-baud LoRa
link as over a 10 Gbps fiber link. The only difference is throughput and
latency, which the network adapts to automatically.

## 2. Layer Definitions

### 2.1 Identity Layer

The foundation. Every node has an Ed25519 keypair ([RFC 8032]). The node's
**canonical address** is `SHA-256(public_key)[0..16]` ([RFC 6234]) — a
16-byte identifier used throughout the edge network. The full 32-byte
identity hash is used at the bridge and backbone layers.

**Responsibilities:**
- Generate and store keypairs
- Derive addresses from keys
- Sign and verify messages
- Key delegation chains (sub-identity signing)
- Identity lifecycle: publication, rotation, revocation

**Crates:** `rsticulum-identity`, `rsticulum-crypto`

### 2.2 Transport Layer (Reticulum)

The edge protocol. Handles packet framing, link establishment, routing,
and interface management. Runs over any physical medium via the Interface
abstraction. Content-named extensions are implemented as additional packet
types within this layer.

**Responsibilities:**
- Frame packets (HEADER_1, HEADER_2, PROOF, DATA, ANNOUNCE, INTEREST, DATA_RESPONSE)
- Establish encrypted links via ECDH + proof handshake ([RFC 7748] X25519, [RFC 8032] Ed25519)
- Derive session keys via HKDF-SHA256 ([RFC 5869], [RFC 6234])
- Encrypt packets with AES-256-CBC + HMAC-SHA256 via Token construction
  (signing_key = derived[0:32], encryption_key = derived[32:64],
  wire format: `iv(16) || ciphertext || HMAC(32)`, random IV per encryption)
- Route packets through the mesh (link-state + reactive discovery)
- Manage interfaces (serial, UDP, TCP, radio)
- Suspend and resume links across disconnections
- Announce presence and discover peers
- Hierarchical announce forwarding (via bridges)
- Process ICN Interest/Data packet types for in-network caching and Interest aggregation

**Protocol:** Wire-compatible with Python Reticulum (RNS).

**Crates:** `rsticulum-packet`, `rsticulum-transport`, `rsticulum-interface`,
`rsticulum-mesh`, `rsticulum-destination`, `rsticulum-channel`,
`rsticulum-buffer`, `rsticulum-daemon`

### 2.3 Content-Named Extensions (ICN within Reticulum)

Named data networking implemented as extensions to Reticulum, not as a
separate application layer. New packet types (`Interest`, `Data`) are
carried by the same relay infrastructure that forwards `DATA` and
`ANNOUNCE` packets. Because Reticulum relays already decrypt and re-encrypt
packets during forwarding, they can inspect ICN names, cache Data packets,
and aggregate duplicate Interests — all within the transport forwarding
path.

**Responsibilities:**
- Express Interests for named data
- Publish Data packets in response to Interests
- Cache content opportunistically (ContentStore)
- Aggregate duplicate Interests (Pending Interest Table, [RFC 8569]
  CCNx semantics, [RFC 8793] ICN terminology)
- Forward Interests to producers (Forwarding Information Base)
- Manifest system for mutable content
- Subscription Interests for streaming/live data
- WASM application distribution and execution

**Protocol:** Interest/Data model based on [RFC 8569] (CCNx Semantics) and
NDN, adapted for identity-based naming. Runs as Reticulum packet types on
the existing forwarding infrastructure.

**Crates:** `rsticulum-icn`

### 2.4 Backbone and Bridge (**FUTURE — DESIGN PHASE**)

> ⚠️ **Confidence level: Low.** The bridge crate (`rsticulum-bridge`)
> is a stub (1-line `lib.rs`). The backbone crate (`rsticulum-backbone`)
> is a stub (1-line `lib.rs`). Neither has been implemented. The design
> below represents architectural intent, not working code. Expect
> significant revision based on results from Phase 1–3 implementation.

Scaling layer. When the mesh outgrows single-mesh topology, the backbone
provides identity-based source routing across multiple mesh domains.

**Responsibilities (planned):**
- Path segment construction (beaconing)
- Source routing with verified hop fields
- Bridge protocol (edge ↔ backbone translation)
- Trust boundaries between routing domains (ISDs)
- Congestion signalling and rate limiting

**Protocol:** SCION-inspired, adapted to identity-based forwarding. For
details on what SCION contributes and what must be changed, see
[ADAPTATIONS.md §2](../ADAPTATIONS.md#2-scion-backbone).

## 3. Design Tensions

This section explicitly acknowledges tensions in the architecture —
tradeoffs where two valid approaches answer the same question differently.

### 3.1 ICN Pull Model vs. Reticulum Push Model

Reticulum is fundamentally **push-based**: a producer announces its
presence, establishes Links, and pushes data to known destinations.
Content-named extensions are fundamentally **pull-based**: a consumer
expresses an Interest, and the network routes that Interest to a producer
who responds with Data.

These are two answers to the same question ("how does data reach its
destination?"), and they are in tension:

| | Reticulum Push | ICN Pull |
|---|---|---|
| **Initiation** | Producer pushes to consumer | Consumer pulls from producer |
| **Discovery** | Announce → known destination | Interest → name-based routing |
| **Caching** | Not natively supported | In-network at every hop |
| **Multiparty** | Point-to-point Links | Any consumer can request |
| **Disruption** | Suspend/resume on Links | Interest sits in PIT until satisfied |

The architecture resolves this tension by treating both as packet types
within the same transport. A single Reticulum relay can forward both
push-based DATA packets and pull-based Interest packets. Applications
choose the model that fits their use case: push for real-time chat and
alerts, pull for content distribution and caching.

### 3.2 Relays See Plaintext — In-Network Caching Without ICN

Reticulum relays decrypt each packet to read the destination address during
forwarding (the outer header is cleartext, the payload is encrypted per-hop).
This means a relay **already has access to packet contents** during the
forwarding decision. In theory, relays could cache data without ICN at all —
just store decrypted payloads keyed by content hash and serve them on
future requests.

Why add ICN then? Because ICN provides:
- **Standardised naming** (`/<producer-hash>/<path>?blake3=<hash>`) so relays
  know *what* they're caching
- **Interest aggregation** (PIT) so duplicate requests don't flood the
  network
- **Producer-agnostic retrieval** — any cached copy satisfies the request
  regardless of which node originally published it
- **Semantic layering** — manifest pointers, subscription semantics, content
  types

Plaintext visibility at relays makes ICN-level caching *possible* to
implement cleanly. ICN provides the *semantics* to make it correct.

### 3.3 Content-Named Extensions vs. Stacking ICN on Top

An alternative architecture would be: ICN as an application-layer protocol
running *on top of* Reticulum Links. The ICN forwarder would be a separate
process, communicating over Reticulum like any other application.

This architecture chooses **extensions over stacking** because:
- **One relay, one forwarding path.** Both Reticulum-native and ICN packets
  flow through the same relay code. No double process, no double routing
  table, no translation layer between protocols.
- **Caching at relay granularity.** When a relay forwards a Data packet,
  it can cache it *as part of the forwarding decision*, not as a separate
  application-layer action.
- **Interest aggregation in the relay.** The PIT lives in the relay, so
  duplicate Interests are suppressed at the first common relay, not at
  some separate ICN forwarder that might be topologically distant from
  the congestion point.
- **Unified addressing.** ICN names embed the producer hash (identity),
  which is the same identity used by Reticulum addressing. No
  translation between ICN name spaces and Reticulum addresses.

The cost of extensions: Reticulum's packet type space grows, and relays
must understand ICN semantics. The alternative (stacking) would keep
Reticulum simpler but duplicate infrastructure, routing state, and
caching logic across two layers.

## 4. Packet Flow

### 4.1 Outbound (Application → Network)

```
Application
  │ express_interest(name) or publish_content(data)
  ▼
ICN Forwarder (within Reticulum transport)
  │ Create Interest or Data packet (Reticulum packet type)
  │ Look up face in FIB
  ▼
LinkFace (wraps rsticulum Link)
  │ Serialize ICN packet to bytes
  ▼
Reticulum Transport
  │ Channel → Buffer → Link
  │ Fragment into HEADER_2 + DATA packets
  │ Encrypt with derived session key (AES-256-CBC, random IV)
  ▼
Interface (UDP, serial, radio)
  │ KISS/HDLC framing
  │ Transmit bytes
  ▼
Physical Medium
```

### 4.2 Inbound (Network → Application)

```
Physical Medium
  │ Receive bytes
  ▼
Interface
  │ KISS/HDLC deframing
  │ Deliver raw packet
  ▼
Reticulum Transport
  │ Parse packet type (HEADER_2, PROOF, DATA, ANNOUNCE, INTEREST, DATA_RESPONSE)
  │ If PROOF: complete handshake → establish Link
  │ If DATA on Link: decrypt (AES-256-CBC) → Channel → Buffer → reassemble
  │ If ANNOUNCE: update mesh routing table
  ▼
ICN Packet Processing (if INTEREST or DATA_RESPONSE)
  │ If Interest: check ContentStore → check PIT → forward to FIB
  │ If Data: satisfy PIT entries → cache in ContentStore → deliver to app
  ▼
Application
  │ Receive data or Interest callback
```

### 4.3 Cross-Domain (Edge → Bridge → Backbone → Bridge → Edge) — **FUTURE DESIGN**

> ⚠️ The bridge and backbone crates are stubs. This flow is architectural
> intent, not implemented.

```
Edge Node A                Bridge A             Backbone              Bridge B           Edge Node B
    │                          │                     │                    │                    │
    │──ANNOUNCE (16B addr)───▶│                     │                    │                    │
    │                          │──BRIDGE_ANNOUNCE───▶│                    │                    │
    │                          │  (prefix+32B id)    │──path segment────▶│                    │
    │                          │                     │                    │──BACKBONE_ANNOUNCE─▶│
    │                          │                     │                    │  (prefix+32B id)   │
    │                          │                     │                    │                    │
    │──DATA (16B dest)───────▶│                     │                    │                    │
    │                          │──rewrite to 32B───▶│                    │                    │
    │                          │                     │──hop-by-hop──────▶│                    │
    │                          │                     │                    │──rewrite to 16B──▶│
    │                          │                     │                    │                    │
```

## 5. Address Formats

| Layer | Format | Size | Example |
|-------|--------|------|---------|
| Edge (RNS) | `SHA-256(pubkey)[0..16]` | 16 bytes | `a3f7c8d1e2b4...` |
| Bridge | `SHA-256(pubkey)` | 32 bytes | `a3f7c8d1e2b4...` (full) |
| ICN Name | `/<producer_hash>/<path>?blake3=<content_hash>` | Variable | `/<64-char-hex>/chat/room1` |
| ICN Content | `BLAKE3(content)` | 32 bytes | Full hash |
| Manifest Pointer | Well-known Interest name | Variable | `/<producer>/_manifest` |

**Translation rule:** Edge (16B) → Backbone (32B): bridge looks up the full
identity hash in its announce cache. Backbone (32B) → Edge (16B): bridge
truncates to the first 16 bytes. This is safe because the bridge has already
verified the full key in the backbone path segment.

## 6. Key Data Structures

### 6.1 Link and SuspendableLink

**`Link`** is the core encryption engine. It manages:

- ECDH key exchange (X25519, [RFC 7748])
- Session key derivation (HKDF-SHA256, [RFC 5869], [RFC 6234])
- Packet encryption/decryption (AES-256-CBC Token: signing_key = `derived[0:32]`,
  encryption_key = `derived[32:64]`, wire format `iv(16) || ciphertext || HMAC(32)`)
- Proof handshake (Ed25519 challenge/response, [RFC 8032])
- Channel multiplexing and Buffer streaming

**`SuspendableLink`** wraps `Link` and adds session persistence:

- Serializes derived session keys, held messages, and state to disk on disconnect
- Restores state on reconnect — the wrapped `Link` resumes from where it left off
- Configurable behavior: `LinkConfig.immediate_close: bool` — set to `true` for
  TCP-like semantics (RST on timeout), `false` (default) for disruption tolerance

The architecture path: make `Link` configurable to support suspend-by-default,
with `SuspendableLink` as the standard wrapper providing serialization. The
core encryption and protocol logic stays in `Link`.

### 6.2 Unified Addressing Table (Bridge) — **FUTURE**

> ⚠️ Bridge crate is a stub. This data structure is not yet implemented.

Maintained by every bridge:

```
HashMap<[u8; 32], AddrMapping>

AddrMapping {
    canonical_32: [u8; 32],       // Full identity hash
    rns_16: Option<[u8; 16]>,     // Edge address (if known)
    icn_prefix: Option<Name>,     // ICN producer prefix
    isd_as: Option<String>,       // Backbone routing locator
    transport_quality: f64,       // Path quality metric
    last_seen: u64,               // Unix timestamp
}
```

All packet translation across layers goes through this table. When a
mapping is missing, the bridge queues the packet and sends an
`IdentityQuery` to the relevant layer.

### 6.3 Pending Interest Table (PIT)

```
HashMap<Name, PitEntry>

PitEntry {
    name: Name,
    in_faces: Vec<FaceId>,        // Faces waiting for this data
    expires_at: Instant,          // 30 min default (not 4s)
    subscribe: bool,              // Subscription Interest flag
    nonce: u64,                   // Duplicate detection
}
```

### 6.4 Forwarding Information Base (FIB)

```
HashMap<NamePrefix, Vec<FibEntry>>

FibEntry {
    face: FaceId,
    cost: u64,
    strategy: StrategyType,       // BestRoute, Multicast, etc.
}
```

### 6.5 Content Store (CS)

```
LruCache<Name, CachedData>

CachedData {
    data: Vec<u8>,
    content_type: u16,
    freshness: Instant,
}
```

## 7. Protocol Boundaries

### 7.1 Edge ↔ Bridge — **FUTURE**

```
Edge side:  rsticulum protocol (16B addresses, announces, Links)
Bridge side: modified SCION protocol (32B identities, path segments)

Bridge maintains:
  - Announce cache: edge announces → aggregated route summaries
  - Address mapping: 16B ↔ 32B identity translation
  - Congestion signals: backpressure to edge nodes
```

### 7.2 Content-Named Extensions ↔ Transport

Because ICN features are extensions to Reticulum rather than a separate
layer, there is no protocol boundary — Interest and Data are Reticulum
packet types. The ICN forwarder is part of the transport forwarding path.

However, the **LinkFace** abstraction wraps a Reticulum Link to provide
the ICN Face interface:

```
ICN Forwarder: Interest/Data packets, named content
Transport:      rsticulum Links (encrypted, authenticated channels)

LinkFace:       Wraps a rsticulum Link as an ICN Face. ICN packets
                serialize/deserialize over the Link. No address translation
                needed — the Link already connects two identities.
```

### 7.3 Application ↔ ICN

```
Application:  WASM module or native binary
ICN:          Face API (exposed by transport)

API surface:
  - express_interest(name: Name) → Data
  - publish_content(name: Name, data: Vec<u8>)
  - subscribe(name: Name) → Stream<Data>
  - register_prefix(prefix: Name)
```

## 8. Security Model

### 8.1 Cryptographic Primitives

| Primitive | RFC | Usage |
|-----------|-----|-------|
| Ed25519 | [RFC 8032] | Identity keys, proof handshake signatures |
| X25519 | [RFC 7748] | ECDH key exchange for link session keys |
| HKDF-SHA256 | [RFC 5869] | Key derivation from ECDH shared secret |
| SHA-256 | [RFC 6234] | Address derivation, PoW, HMAC foundation |
| BLAKE3 | — | ICN content hashing (faster than SHA-256 on ARM/embedded) |
| HMAC-SHA256 | [RFC 6234] | Packet authentication, hop-field validation |
| AES-256-CBC | NIST SP 800-38A | Packet encryption (Token construction) |

### 8.2 Token Encryption (AES-256-CBC)

The RNS Token (simplified Fernet construction) encrypts packets:

- **Key derivation:** HKDF-SHA256 expands the ECDH shared secret into a 64-byte
  derived key. Signing key = `derived[0:32]`, encryption key = `derived[32:64]`.
- **Encryption:** AES-256-CBC with PKCS7 padding. A fresh random 16-byte IV is
  generated per encryption and prepended to the ciphertext.
- **Authentication:** HMAC-SHA256 over `iv || ciphertext`, appended as 32 bytes.
- **Wire format:** `iv(16) || ciphertext || HMAC(32)`.
- Python RNS default mode: `Token.MODE_DEFAULT = MODE_AES256_CBC`.

### 8.3 Trust Anchors

There are none — in the traditional sense. Every identity is self-certifying.
Trust is established through:

1. **Direct proof:** `verify(public_key, signature, message)` — you know
   the key, you verify the proof. No third party needed.

2. **Delegation chains:** A → B → C. If you trust A and A vouches for B,
   you can trust B. Chains have bounded depth (max 3).

3. **Threshold trust (ISD):** For backbone routing domains, N of M existing
   members sign a `TrustVote` to admit a new member. No CA, no hierarchy.

### 8.4 Threat Model

| Threat | Mitigation |
|--------|-----------|
| Packet forgery | Ed25519 signatures on all packets ([RFC 8032]) |
| Replay attacks | Sequence numbers + timestamp windows |
| Sybil (mass identity creation) | Proof-of-work on announces (20-bit) |
| Path forgery (backbone) | Hop-field MACs per AS |
| Content poisoning | Content hash verification (BLAKE3) |
| Man-in-the-middle | ECDH key exchange + proof handshake ([RFC 7748], [RFC 8032]) |
| Spam (Interest flooding) | PIT-based rate limiting per face |
| DoS (announce flooding) | Bridge backpressure + PoW difficulty scaling |

### 8.5 What This Model Does NOT Have

- **CRLs / certificate revocation:** Replaced by key rotation in the identity
  lifecycle protocol.
- **PKI / CA hierarchy:** Replaced by self-certifying keys + delegation chains.
- **DNS / address resolution:** Replaced by identity hashes — the address IS
  the resolution.
- **Firewalls / ACLs:** Replaced by cryptographic authentication at the packet
  level — if you can't prove you own the key, you can't claim the address.

## 9. Failure Modes

### 9.1 Node Disconnection

Link enters `Suspended` state (via `SuspendableLink` wrapping). Derived
session keys (AES-256-CBC) and pending messages are serialized to disk.
On reconnect, the link resumes from where it left off. No application-level
reconnect logic.

### 9.2 Bridge Failure — **FUTURE**

Edge nodes detect bridge unreachability (heartbeat timeout). They either:
(a) wait for reconnect (bridge comes back), or (b) discover alternate bridges
via announce propagation. Multiple bridges in a mesh provide redundancy.

### 9.3 Path Failure (Backbone) — **FUTURE**

Source routing with multiple path segments. If path A fails mid-transit, the
source retries with path B. Path segments have 24-hour lifetimes, so cached
alternates are usually available without re-discovery.

### 9.4 Content Unavailable

Interest times out in the PIT. The forwarder sends a NACK to the consumer
(or the application times out). The consumer can retry or fall back to an
alternate producer.

## 10. Performance Characteristics

| Metric | Edge (LoRa) | Edge (WiFi) | Backbone **(future)** |
|--------|------------|-------------|----------|
| MTU | ~200 bytes | ~1500 bytes | ~9000 bytes |
| Link RTT | 100ms–30s | 1–50ms | 10–200ms |
| PIT lifetime | 30 min | 30 min | N/A |
| Path segment lifetime | N/A | N/A | 24h–7d |
| Announce interval | 30–300s | 30–300s | Summary: 60–600s |
| PoW difficulty | 20-bit | 20-bit | N/A |

## 11. References

### IETF RFCs

| RFC | Title | Used For |
|-----|-------|----------|
| [RFC 8032] | Edwards-Curve Digital Signature Algorithm (Ed25519) | Identity keys, proof handshakes |
| [RFC 7748] | Elliptic Curves for Security (X25519) | ECDH key exchange |
| [RFC 5869] | HMAC-based Extract-and-Expand Key Derivation Function (HKDF) | Session key derivation |
| [RFC 6234] | US Secure Hash Algorithms (SHA-256) | Address derivation, HMAC, PoW |
| [RFC 8569] | Content-Centric Networking (CCNx) Semantics | ICN Interest/Data model |
| [RFC 8793] | Information-Centric Networking (ICN): Terminology | ICN naming, PIT, FIB, CS |
| [RFC 7476] | Information-Centric Networking: Baseline Scenarios | ICN use cases |
| [RFC 7927] | Information-Centric Networking: Challenges | ICN deployment challenges |

### Project Documents

| Document | Description |
|----------|-------------|
| [ADAPTATIONS.md](../ADAPTATIONS.md) | What each standard keeps vs. what must change |
| [IMPLEMENTATION.md](IMPLEMENTATION.md) | Crate map, build phases, dev workflow |
| [GLOSSARY.md](GLOSSARY.md) | Terminology reference |
| `docs/rfcs/` | Formal RFCs (0001–0011) for protocol changes |
