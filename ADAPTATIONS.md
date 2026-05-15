# Adaptations — What Each Standard Needs to Change

A line-by-line accounting of what Reticulum, SCION, and ICN/NDN do right, what they
do wrong for a no-IP/no-TCP/no-HTTP internet, and exactly what must be modified.

---

## 1. Reticulum / RNS / rsticulum (Edge Layer)

### Keep As-Is

| Feature | Why It Stays |
|---|---|
| Identity-derived 16-byte addresses (SHA-256 truncated) | Correct for edge — collision risk at scale is acceptable when backbone does full-key routing; 16 bytes keeps packet headers small on low-bandwidth links (LoRa, serial) |
| Physical-medium agnosticism (serial, UDP, radio, I2P) | This is the whole point — any medium is a valid network link |
| Announce-based peer discovery | Correct for edge meshes where topology is flat and nodes come and go |
| Proof handshake for link establishment | Zero-RTT trust verification using Ed25519 — no PKI, no third party, no round trips to a CA |
| KISS/HDLC framing over serial/TCP | Proven wire formats, byte-compatible with existing hardware TNCs and SDRs |
| AES-128-CBC + HMAC-SHA256 packet encryption | Adequate for edge; the key derivation (ECDH + HKDF) is correct; the crypto primitives are standard and auditable |

### Change

#### 1a. Extend address to 32 bytes at the bridge boundary

**What:** The 16-byte RNS address is truncated for packet efficiency. At the
edge↔backbone bridge, frames must carry the full 32-byte identity hash (or the
raw public key) so the backbone can route on it.

**Why:** SCION path construction operates on identities, not hashed-shortened
identities. A 16-byte address has 2⁻¹²⁸ collision space, which is fine for
edge meshes (<10⁴ nodes), but backbone routing tables index on addresses — a
collision silently routes packets to the wrong node. The bridge must map
16-byte edge addresses to 32-byte backbone identities before forwarding.

**How:** The bridge crate (`rsticulum-bridge`) maintains a local mapping:
edge address (16 bytes) ↔ full identity key (32 bytes), learned from announce
payloads which already carry the full identity key. Forwarding packets
edge→backbone rewrites the destination field to the 32-byte form before
handing to the SCION-style path segment.

#### 1b. Add key delegation (sub-identity signing)

**What:** A primary identity can issue a signed delegation statement:
`"I, pubkey_A, authorize pubkey_B as my delegate on device D for the
next 7 days, signature: ..."`. Delegation is recursive but bounded (max depth 3).

**Why:** In a real network, a phone has different hardware keys than a laptop,
but they belong to the same person. Without delegation, each device is a
separate identity — messages addressed to "Alice's phone" can't be
automatically forwarded to "Alice's laptop." This is also how key rotation
works: "I, old_key, delegate to new_key, effective immediately."

**How:** A new packet type (`DELEGATE`) carrying the delegation statement.
Nodes cache delegation chains. When verifying a proof from a delegated key,
the verifier checks the full chain up to the root identity they know. Chain
cache has TTL matching the delegation expiry.

#### 1c. Replace announce flooding with hierarchical announce forwarding

**What:** Instead of every node broadcasting announces on all interfaces,
edge nodes send announces only to their bridge (gateway). The bridge
propagates a *summarised* announce into the backbone: "These 47 nodes
(prefix) are behind me." The backbone announces back summarised: "These
routes are reachable through ISD-AS X."

**Why:** Reticulum announce flooding is O(n²) per node. At 10³ nodes it's
chatty; at 10⁶ it saturates every link. For an internet-scale edge,
announces must be hierarchical — the node only announces locally, the bridge
aggregates and propagates upward. This is how BGP works, and the same
reasoning applies here.

**How:** The bridge implements an announce cache with TTL. When an announce
arrives from the edge, the bridge updates its local table but only forwards
a *route summary* (hash prefix + path quality) to the backbone, not the raw
announce. The backbone pushes a similar summary down to the bridge, which
caches it for edge nodes that request routes.

#### 1d. Baked-in SuspendableLink as the standard link protocol

**What:** The current `rsticulum-transport::SuspendableLink` exists as an
optional add-on. It must become the *only* link type — all links are
suspendable, always. Remove the non-suspendable `Link` entirely or demote it
to a simple wrapper.

**Why:** The vision says "no TCP" — connections must survive hours/days of
disconnection. If a developer reaches for `Link` (non-suspendable) and uses
it in production, their app breaks when the network glitches. Making
suspendable the default means every application automatically gets
disruption tolerance — no opt-in, no forgetting, no surprise failures.

**How:** Rename `SuspendableLink` to `Link`, remove the old `Link`. The
session persistence (serialized derived keys + held messages) is always on.
The old `Link` behavior becomes a configuration option: `immediate_close:
true` for applications that specifically want TCP-like semantics (and
they'd have to think about why).

#### 1e. Add proof-of-work to announce packets (anti-spam)

**What:** Every announce packet embeds a 20-bit proof-of-work: given a
random nonce in the announce, the first 20 bits of `SHA-256(nonce || data)`
must be zero. The bridge verifies this before accepting the announce.

**Why:** Cryptographic identities are free — generate 10⁶ keypairs in a
second and flood announces from all of them. Without cost, the network is
spammable. Proof-of-work doesn't prevent spam (ASICs exist) but *raises the
cost* above the willingness of casual attackers. Five seconds of CPU per
announce per hour is negligible for a legitimate node; 10⁶ announces is
prohibitively expensive.

**How:** Add a `pow_nonce` field to the announce payload format. The
announce sender computes the nonce (brute-force search). The receiver
verifies it. Difficulty adjusts based on bridge congestion — a bridge
under load announces a higher difficulty target, and edge nodes
automatically increase their PoW before sending announces through it.

---

## 2. SCION (Backbone)

### Keep As-Is

| Feature | Why It Stays |
|---|---|
| Source routing with path segments (up-core-down) | The only proven model for scalable, cryptographically-verified routing without a global routing table |
| ISD trust boundaries | Correct abstraction — every node doesn't need to trust every other node, only the local ISD and a small set of peer ISDs |
| Multi-path path construction and selection | Enables congestion avoidance, load balancing, and failure recovery without central coordination |
| Path segment registration (beaconing) | The core discovery mechanism — path segments are discovered and propagated, not computed centrally |
| Hop-field cryptographic validation | Prevents path forgery — each hop field is MAC'd with the AS's key, so a node can't fake being on the path |

### Change

#### 2a. Replace IP-forwarding substrate with identity-based forwarding

**What:** SCION currently encapsulates everything in UDP/IP and forwards
based on IP addresses in the outer header. Replace this: the forwarding
plane operates on 32-byte identity hashes. Each packet carries a
destination identity (not an IP address). Routers forward by looking up the
identity in their path segment table.

**Why:** IP addresses are location-dependent binding — they change when you
move, they're allocated by ISPs, they're a second namespace that must be
mapped to identity. The vision has exactly one namespace: identity hashes.
The outer IP header is an unnecessary indirection that adds complexity
(NAT, DHCP, address renumbering) with zero benefit when identity is already
in the inner header.

**How:** The SCION packet format gains a `dest_identity: [u8; 32]` field.
The outer IP/UDP encapsulation is replaced by direct hop-by-hop identity
forwarding: each router knows the next hop's identity (from path segment
construction), sends the packet directly. The first hop (edge bridge) adds
the path segment header; intermediate hops verify hop fields against
identities (not IP addresses). Remove the IP header entirely — the packet
format is now `[path_segment][dest_identity][hop_fields][payload]`.

#### 2b. Extend path segment lifetime from minutes to hours/days

**What:** SCION path segments expire after ~minutes (default is 10-60
seconds for PCBs). Change the default to 24 hours, with optional extension
up to 7 days. Path segments are cached persistently and reused across
disconnections.

**Why:** Paths must survive network disruption. If a node goes offline for
2 hours and its cached path segments have expired, it must do a full path
discovery handshake on reconnect — that's TCP-style RST behavior, exactly
what the vision says must not happen. Long-lived paths trade routing
freshness for availability, which is the correct trade for a
disruption-tolerant network.

**How:** Increase the PCB `TTL` field maximum in the SCION control plane.
Beacon propagation slows proportionally (fewer beacons), which also reduces
control-plane overhead. Add a `path_renewal` flag: when a node reconnects
after disconnection, it sends a single "still here" beacon to extend the
path segment lifetime, rather than re-discovering from scratch.

#### 2c. Replace hierarchical PKI with identity-based trust

**What:** SCION ISDs use traditional X.509 certificate hierarchies — a root
CA per ISD, intermediate CAs below. Replace with: each ISD publishes a
*trust statement* signed by a threshold of its members
(m-of-n Byzantine agreement). Trust flows from membership, not from a CA.

**Why:** The X.509 PKI is a single point of failure per ISD (compromise the
ISD root CA, forge any path). It also adds bootstrap complexity — every new
node needs a certificate signed by the ISD CA. Identity-based trust means
any existing member can vouch for a new node; trust accumulates through
the network, not through a central authority. This matches the vision's "no
allocation, no authority" principle.

**How:** Define a `TrustVote` message: `[isu_issuer][new_node_key][timestamp][signature]`.
An ISD's trust anchor is a set of bootstrap members (initial members).
New members join when N existing members sign their `TrustVote`. Path
verification checks: (a) the path segment is signed by the originating AS,
(b) that AS's key has accumulated enough votes to be trusted. No X.509,
no CRLs, no CA hierarchy.

#### 2d. Add bridge protocol for edge↔backbone handover

**What:** A new control message `BRIDGE_ANNOUNCE` — sent from bridge to
backbone, contains: `[edge_prefix: 16 bytes] [bridge_key: 32 bytes]
[path_quality: f64] [hop_count: u8]`. The backbone inserts this as a route
to the edge prefix via the bridge. Reverse direction: `BACKBONE_ANNOUNCE`
containing `[isd_as] [reachable_prefix: 32 bytes]`.

**Why:** Without a bridge protocol, the edge and backbone are disconnected
networks — a Reticulum node cannot reach a SCION node, and vice versa. The
bridge protocol defines exactly how addresses translate, how trust
propagates across layers, and how path quality is preserved across the
boundary.

**How:** The bridge listens on both sides. On the edge side, it speaks
rsticulum (identity addresses, announce listening). On the backbone side, it
speaks the modified SCION protocol (identity forwarding, path segment
construction). The bridge protocol is internal to the bridge: a mapping
table of `<edge_addr → backbone_key, quality, expiry>`. When a packet
crosses the boundary, the bridge rewrites the address field and recomputes
the hop fields for the target layer.

---

## 3. ICN / NDN (Application Layer)

### Keep As-Is

| Feature | Why It Stays |
|---|---|
| Interest / Data packet model | Correct — fetch by name, not by location; PIT aggregates duplicate Interests, ContentStore caches popular data |
| Self-certifying content (name = hash of content) | Correct — verifier needs no PKI, just the hash; content integrity is intrinsic |
| In-network caching | Correct — reduces redundant fetches, improves latency in disrupted networks |
| Face abstraction (pluggable transport) | Correct — ICN can run over any transport; our rsticulum LinkFace already implements this |

### Change

#### 3a. Name prefix must always start with producer hash — never hierarchical

**What:** NDN allows any name format (`/com/youtube/video`) but our ICN
*requires* the first component to be a full 32-byte producer identity hash.
Names without a producer hash are rejected at the face level.

**Why:** Hierarchical names encode location assumptions (`/com/youtube/...`
assumes you reach YouTube through the global DNS/HTTP path). This breaks in
a disruption-tolerant network where you might reach the content through a
local cache, a peer mesh, or the satellite backhaul — none of which know
where "com" is. Producer-hash prefixes decouple *what* from *where*:
any copy of the data is equally valid regardless of topological location.

**How:** The `Name` constructor in rsticulum-icn already enforces this
(producer hash is required, path is optional). Formalise in the spec:
"ICN names for this network must match the regex
`/[0-9a-f]{64}(/.*)?(?blake3=[0-9a-f]{64})?$`". Add a wire-format check
at the face receive path that drops names not matching this pattern.

#### 3b. PIT entry lifetime extended from seconds to hours

**What:** Default PIT timeout goes from ~4 seconds (standard NDN) to
configurable minutes/hours. Default: 30 minutes. Forwarder exposes a
`pit_timeout` config parameter.

**Why:** The PIT is the core mechanism for disruption tolerance — an
Interest stays in the PIT until Data arrives or it times out. If the PIT
times out in 4 seconds, a node on a high-latency link (satellite, deep
space, LoRa multi-hop) can never use Interest/Data semantics. The PIT
window must match the expected round-trip time of the slowest reachable
path, not the fastest.

**How:** Increase the `PitEntry::expires_at` calculation in the forwarder
from `Instant::now() + 4s` to `Instant::now() + 30min`. The PIT eviction
strategy changes from "timeout = delete" to "timeout ≥ config →
opportunistically prune expired, but keep at least the latest N entries
even beyond timeout." (The opportunistic prune avoids unbounded memory
growth while keeping entries alive for the full expected window.)

#### 3c. Manifest system for mutable content

**What:** A `Manifest` is a signed JSON document listing versioned content
entries. Each entry maps a semantic name to a content hash, plus metadata
(type, size, timestamp, signature of the publisher). The manifest itself is
fetched by its own content hash, but the hash is published as a "well-known
pointer" — the producer announces `manifest_hash: <latest>` periodically.

**Why:** Content-addressed data is immutable by nature (change the content,
change the hash). But applications need mutable data — a chat room's latest
messages, a firmware update URL, a WASM app binary. The manifest is the
indirection layer: "always fetch the manifest by its latest pointer, then
fetch the specific content by its immutable hash." This is identical to
how Git works (a branch pointer → a commit hash → the tree).

**How:** The `rsticulum-icn Manifest` already exists, but needs:
- A `well_known` Interest name (`/<producer>/_manifest`) that returns the
  latest manifest hash
- A `subscribe` Interest that says "notify me when the manifest changes"
  (long-lived Interest that the producer keeps open and responds to with
  the new manifest hash when it updates)
- Version ordering: manifests include a monotonic sequence number so
  consumers can detect out-of-order updates

#### 3d. WASM app bundle as an ICN data type

**What:** A new content type `application/wasm-module` in the manifest.
The content is a WASM bytecode module. The manifest entry includes:
`{type: "wasm", hash: ..., interface: "app-chat-v1", size: 184320}`.
The consumer fetches the WASM, instantiates it with a sandboxed ICN face,
and the WASM module runs as a first-class application on the network.

**Why:** This is the vision's answer to "how do apps deploy and update on a
network with no servers?" WASM is portable, sandboxed, and can be
incrementally updated (the manifest points to the new WASM hash, the
consumer fetches the diff or the full bytecode). No app store, no server,
no central authority — just a signed manifest and a content hash.

**How:** The ICN daemon includes a WASM runtime (wasmtime/wasmer) that
receives manifest updates, fetches new WASM bytecode, and replaces the
running module. The WASM module has access to a limited ICN API:
`express_interest(name)`, `publish_content(data)`. The interface contract
(`interface: "app-chat-v1"`) ensures the WASM module expects a specific
ICN namespace schema — mismatches are caught at manifest load time.

#### 3e. Subscription Interests for streaming/live data

**What:** A new Interest type with `subscribe: true` flag. The producer
doesn't send one Data packet; instead, it keeps the PIT entry alive and
sends multiple Data packets over time as new content is produced. The
consumer receives each Data packet and (if still interested) keeps the
subscription alive by re-expressing the Interest before the PIT timeout.

**Why:** The standard Interest/Data model is one-shot: one Interest, one
Data. For live feeds (chat, telemetry, price updates, notifications), the
consumer would have to poll by re-expressing Interests in a loop.
Subscriptions convert this to a push model — the consumer expresses
interest once, the producer pushes updates.

**How:** Define a `SubscribeInterest` TLV that extends the standard
Interest: `[name][lifetime:u64][subscribe:bool][nonce:u64]`. The producer,
on receiving `subscribe=true`, creates a long-lived PIT-like entry and
sends Data packets whenever it has new content matching the name. The
consumer sends `Unsubscribe` Interest (`subscribe=false`) to end the
subscription, or simply lets the PIT entry expire.

---

## 4. Cross-Layer Gaps (None of the Three Fill These)

These are problems that must be solved at the boundary between layers —
they don't belong to any single standard.

### 4a. Identity lifecycle protocol

**What:** A new protocol layer (sitting between Identity and Transport) that
handles:
- Key publication ("here is my public key, identity hash is X")
- Key rotation ("I am X, my key changed from K_old to K_new, signature: K_old")
- Key revocation ("I am X, my key K is no longer valid, reason: lost device")
- Delegation chains (1b, above)

**Why:** Reticulum has no key persistence (keys are files). SCION delegates
to CA infrastructure. ICN punts to the application. Without an identity
layer, every higher-layer protocol re-invents its own key management, which
is how we end up with five different address formats for the same node.

**How:** A new `rsticulum-identity-lifecycle` crate that defines:
- `IdentityRecord`: `{primary_key: [u8;32], created: u64, expires: Option<u64>,
  delegation_chain: Vec<Delegation>}`
- `IdentityEvent` enum: `{Publish, Rotate, Revoke, Delegate}`
- An `identity_store` gossip protocol: nodes broadcast identity events to
  peers who cache them. The event TTL is tied to the key expiry.
- The bridge subscribes to identity events for its edge nodes and
  propagates them into the backbone.

### 4b. Unified addressing table (the bridge's core data structure)

**What:** A mapping maintained by every bridge and backbone router:
`<canonical_32_byte_identity> → {rns_16: Option<[u8;16]>,
icn_prefix: Option<Name>, isd_as: Option<String>,
transport_quality: f64, last_seen: u64}>`

**Why:** Every layer has its own address format for the same node. The
bridge's job is to translate. Without a unified table, the bridge's
translation logic is scattered across five different match statements in
five different modules, and it inevitably diverges.

**How:** The unified addressing table lives in `rsticulum-bridge` as a
single `HashMap<[u8;32], AddrMapping>` with eviction by last_seen + TTL.
All packet translation (from any layer to any layer) goes through this
table. When a mapping is missing, the bridge queues the packet and sends
an `IdentityQuery` to the relevant layer.

### 4c. Rate-limited congestion signalling

**What:** If the bridge is overloaded, it signals `backpressure` to its
edge nodes (reduce announce frequency, increase PoW difficulty) and
`congestion` to its backbone peers (reduce path construction rate, use
alternate paths). The signal is a single byte in every response packet.

**Why:** Without rate signalling, the edge can overwhelm the bridge with
announces, Interests, and link requests during reconnection after a
network partition — the "thundering herd" problem. The bridge needs a way
to say "slow down" that's faster than dropping packets and waiting for
timeouts.

**How:** Define a `CongestionSignal` field in the bridge protocol header:
`0x00 = normal`, `0x01 = reduce`, `0x02 = stop`. The bridge sets this
based on CPU load, queue depth, and memory pressure. Edge nodes respect it:
if they receive `0x01`, they double their announce interval and PoW
difficulty; if `0x02`, they stop non-essential traffic entirely.

---

## Summary: What to Build and in What Order

```
Phase               Layer               Deliverable
────────────────────────────────────────────────────────────────
1. Identity         Cross-layer        Identity lifecycle protocol
                                       (rsticulum-identity-lifecycle)

2. Edge             Reticulum          SuspendableLink as default
                                       Hierarchical announce forwarding
                                       Proof-of-work anti-spam

3. Backbone         SCION-similar      Identity-based forwarding
                                       Long-lived path segments
                                       Membership-based trust
                                       Bridge protocol spec

4. Application      ICN                Extended PIT lifetimes
                                       Manifest system
                                       Subscription Interests
                                       WASM module type

5. Integration      Bridge             Unified addressing table
                                       Rate-limited congestion signalling
                                       Edge↔backbone packet translation
                                       End-to-end demo (mesh ↔ backbone)
```
