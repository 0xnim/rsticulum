# 0006: Protocol Evolution Notes

- **Status:** Notes (Future)
- **Consolidates:** Old RFCs 0003, 0004, 0005, 0006, 0009, 0011
- **Prerequisite:** [RFC 0001](0001-identity-based-addressing.md),
  [RFC 0002](0002-suspendable-links.md) stable

---

This document collects design notes on protocol extensions that are out of
scope for the 1:1 parity release but will likely be needed as rsticulum scales
beyond small meshes. These are not RFCs — they are sketches of future work,
captured in one place rather than scattered across six separate stub documents.
Each section covers *what* the change is, *why* it would be needed, *when* to
consider implementing it, and *what* protocol impact it would have. Nothing
here is a commitment; everything is a considered option. The old numbered RFCs
(0003, 0004, 0005, 0006, 0009, 0011) are hereby retired; all their content is
merged below.

---

## 1. Hierarchical Announce Forwarding

**What.** In the baseline edge protocol, every node that hears an announce
floods it to every peer — an O(n²) strategy where n is the number of nodes
in the mesh. Hierarchical announce forwarding replaces this with
bridge-aggregated route summaries: edge nodes send their announces to a local
bridge, which groups them by identity prefix and propagates a single summary
announce onto the backbone (e.g., "prefix 0xA1B2... has 47 active nodes,
reachable via bridge B"). Backbone nodes forward these summaries rather than
individual edge announces. When a backbone node needs a path to a specific
identity, it queries the nearest bridge for the full route. Edge nodes never
see backbone-level announce traffic; bridge nodes compress edge-level announce
traffic by orders of magnitude. The bridge becomes the announce authority for
its edge domain — it knows every node in its mesh, maintains a full routing
table for them, and exports only aggregated reachability to the backbone.
Edge-to-edge communication within the same bridge domain never touches the
backbone; the bridge handles intra-domain forwarding directly using its
complete edge routing table.

**Why.** Announce flooding works at ~10² nodes but breaks down around ~10³.
Consider a mesh of 1,000 nodes, each generating one announce per minute. Every
announce must be forwarded to every other node, producing roughly 1,000,000
announce deliveries per minute. On constrained links — LoRa at ~1 kbps, HF
radio at ~300 bps — this saturates the channel entirely; no application data
can flow, and the network collapses under its own control-plane overhead.
Identity-based addressing makes this worse than IP: there is no subnet
hierarchy to scope broadcasts, no TTL-based horizon, no split-horizon rule.
Every announce is, by default, a global event. Hierarchical forwarding solves
this by introducing scoping boundaries at the bridge layer, turning O(n²) into
O(n + b²) where b is the number of bridges (typically orders of magnitude
smaller than n). The key insight is that backbone nodes don't need to route to
individual edge identities — they only need to know which bridge can reach
which identity prefix. The full routing table stays at the bridge, where it's
small enough to fit in memory and update efficiently.

**When.** The breakpoint depends on link bandwidth and announce frequency, but
as a rough heuristic: consider hierarchical forwarding when mesh size exceeds
~500 nodes on moderate-bandwidth links (>50 kbps) or ~200 nodes on
low-bandwidth links (<10 kbps). The implementation should be deployed as a
capability of the bridge crate — edge nodes need no changes if the bridge
continues to accept and forward unaggregated announces. The transition can be
gradual: deploy bridges that understand both flat and aggregated announces,
configure edge nodes to point at bridges, measure overhead reduction, then
eventually disable flat announce forwarding on the backbone entirely. For
networks that will never exceed a few hundred nodes (a small community mesh, a
farm sensor network), this change may never be needed. The architecture should
support it, but the implementation should not be forced onto deployments that
don't benefit.

**Protocol Impact.** A new backbone-level packet type: `ROUTE_SUMMARY`,
carrying an identity prefix, a count of reachable nodes, a bridge address, and
an expiry timestamp. Bridge nodes implement announce aggregation with
configurable prefix length and TTL. Edge node `ANNOUNCE` packets are unchanged
— the edge protocol has no awareness of summarization. The bridge's Unified
Addressing Table gains a new entry type for summary routes, and backbone
forwarding logic must prefer summary routes over individual announces when both
exist (summary routes are more recent and more authoritative). The bridge must
handle the case where a summary route expires: it queries the responsible
bridge for an update rather than falling back to a stale individual announce.
This is a bridge-layer protocol change; the edge wire protocol is entirely
unaffected, which is the point — scaling the control plane should not require
changing every edge node.

---

## 2. Proof-of-Work on Announces

**What.** Every announce packet gains a 20-bit proof-of-work field. The node
computes a SHA-256 hash over the announce payload (destination hash, announced
identity, signature, timestamps, interface data) concatenated with a 64-bit
nonce, iterating the nonce until the hash begins with 20 zero bits. The nonce
is included in the announce. Receiving nodes verify the PoW in constant time (a
single SHA-256) before processing the announce — announces that fail
verification are dropped silently, never entering the routing table or being
forwarded. The 20-bit difficulty target is a protocol constant, not negotiable:
setting it in the spec prevents a race to the bottom where attackers claim zero
difficulty or where nodes negotiate weak difficulty with colluding peers. The
cost is approximately 2^20 ≈ 1,048,576 hash iterations per announce, roughly
10–50 milliseconds on a modern CPU depending on implementation quality and
hardware.

**Why.** In a network with no cost to join — generate a keypair, hash the
public key, you have an address — Sybil attacks are structurally free. An
attacker can generate a million identities and flood the network with announces
for all of them, overwhelming routing tables and saturating control-plane
bandwidth. No amount of signature verification or rate-limiting can stop this:
the attacker can distribute the attack across many IPs, many interfaces, or
many colluding peers; each announce is individually valid and indistinguishable
from a legitimate one. IP networks mitigate Sybil attacks through scarcity
(IPv4 exhaustion), economic cost (buying address space), and ingress filtering
(BCP 38 — drop packets with spoofed source addresses at the network edge).
Identity-based networks have none of these defenses. Proof-of-work imposes a
small, verifiable cost on each announce that is negligible for a legitimate
node announcing once per minute (~0.01–0.05 seconds of CPU per minute) but
catastrophic for an attacker trying to flood 10,000 announces per second
(~100–500 seconds of CPU per second — impossible on any single machine). The
asymmetry is the point: PoW costs the attacker roughly 10,000× more
CPU-seconds than it costs the defender to verify.

**When.** PoW is not necessary at small scale — a 10-node test mesh has no
Sybil attack surface because no attacker would bother. It becomes necessary
when the network is large enough or valuable enough to attract attackers. This
threshold is social rather than technical: when the network carries traffic
worth disrupting (financial transactions, emergency communications,
infrastructure control), PoW must be on. As a practical guideline, support PoW
verification in all node implementations from the start — the code can exist,
be tested, and be disabled by default via configuration. When a deployment
grows to the point where Sybil attacks become a concern, flip the configuration
flag. For resource-constrained devices (battery-powered sensors,
microcontrollers), PoW generation may be too expensive — these devices can
either use a lower announce frequency (PoW once per hour is fine), delegate
announce generation to a more powerful node, or operate in a trusted sub-mesh
where PoW verification is disabled by mutual agreement. The 20-bit target
should be periodically reviewed against hardware trends: if 2^20 becomes
trivially cheap (sub-millisecond on commodity hardware in 2030), the target may
need to increase, but this is a protocol constant change requiring a version
bump.

**Protocol Impact.** A new field in the `ANNOUNCE` packet: `pow_nonce: u64`
(8 bytes). The PoW is computed over all preceding announce fields plus the
nonce; verification is a single `SHA-256(announce_prefix || pow_nonce)` check
for 20 leading zero bits. This is a backwards-incompatible change to the
announce packet format: old nodes will see an extra 8 bytes they don't
understand and will either reject the announce or parse it incorrectly
(depending on how strict the parser is). The transition requires a protocol
version bump in the announce header so that old nodes can identify and skip
announces in the new format. During a deprecation window (e.g., 6 months),
nodes should accept both formats: parse old-format announces without PoW,
verify new-format announces with PoW, and generate new-format announces with
PoW if the configuration enables it. After the deprecation window, old-format
announces are rejected. The deprecation strategy must be documented in the
announce specification itself, not just in these notes.

---

## 3. Key Delegation

**What.** Key delegation allows identity A to authorize identity B to act on
its behalf, scoped to a specific device identifier and a time window. The
authorization is a signed statement: "I, key_A, authorize key_B for device D,
valid until timestamp T. Signed: key_A." This is intentionally minimal — not a
cryptographic chain, not an X.509 certificate, not a PKI hierarchy. It is a
self-contained assertion that any node can verify given key_A's public key and
the current time. The authorization is carried as a new context type
(`CTX_KEY_DELEGATION`) in `DATA` or `HEADER_2` packets. A node receiving a
packet signed by key_B checks its delegation cache: if it holds a valid (not
expired, matching device) delegation from key_A to key_B, the packet is treated
as originating from identity A. If no valid delegation exists, the packet is
rejected as from an unknown identity. Revocation is handled by publishing a
delegation record with expiry set to 0 or a past timestamp — nodes that see the
revocation remove key_B from their delegation cache for that device.

**Why.** Identity-based addressing binds communication to a single keypair.
This is elegant but rigid. Three real-world use cases break the single-key
model. First, multi-device identity: a user with a phone, a laptop, and a base
station wants all three devices to share one identity ("Alice") without sharing
the same private key — sharing private keys is a security disaster because
compromise of any one device compromises all of them. Second, key rotation: a
user who suspects their key has been compromised wants to rotate to a new key
without losing their identity. Contacts, link state, and reputation should
follow the identity, not the key. Without delegation, rotation means starting
over — a new key is a new identity with zero accumulated trust. Third,
pre-authorization: a sensor network operator wants to pre-authorize replacement
nodes before deployment, so that when a sensor fails and its replacement powers
on, it can immediately participate in the network under the same identity
without out-of-band configuration. Key delegation solves all three use cases
with a single mechanism: the master key signs a delegation to a subordinate
key. The subordinate cannot escalate (it can only act within the scope of the
delegation), and the master can revoke at any time by publishing a revocation
record.

**When.** Needed as soon as multi-device identity or key rotation is a
requirement. For single-device deployments — a fixed base station, a lone
sensor, a command-line tool — delegation can be deferred indefinitely. For any
deployment where a user has more than one device running rsticulum, or where
the identity will persist long enough that key compromise becomes a realistic
threat, delegation should be implemented before the identity accrues state
(contacts, link session keys, content subscriptions, reputation scores) that
would be lost on rotation. The delegation format itself is simple — roughly 140
bytes for the signed statement — so implementation cost is low. The main work
is not the delegation format but the delegation cache: every node must maintain
a map of (delegate_key, device_id) → (delegator_key, expiry) and check it on
every inbound packet from an unknown key. This adds a lookup to the hot path of
packet processing, so the cache must be efficient (a hash map, not a linear
scan). The cache should also be bounded: a node should cap the number of
delegations it stores per delegator identity to prevent a delegator from
exhausting peer memory by issuing millions of delegations.

**Protocol Impact.** A new context type in the packet format:
`CTX_KEY_DELEGATION` (assigned a numeric context ID from the protocol
registry). The context body contains: delegator identity (32 bytes), delegate
identity (32 bytes), device identifier (variable-length UTF-8 string,
length-prefixed), expiry timestamp (u64, Unix epoch seconds), and delegator
Ed25519 signature (64 bytes) over all preceding fields. Total fixed overhead:
~140 bytes plus device identifier length. Receiving nodes cache valid
delegations indexed by (delegate_identity, device_id). When an inbound packet
arrives signed by key K that is not the claimed source identity, the node
checks its delegation cache: if a delegation exists from the claimed identity
to K, covering the current device and not expired, the packet is accepted. This
is a packet-layer protocol change; existing parsers must handle the new context
type gracefully (skip unknown contexts rather than rejecting the packet). The
delegation cache is a new per-node data structure. Care must be taken with
delegation expiry: a delegation that expires mid-session should not tear down
active links — link session keys, once established, should outlive the
delegation that authorized them, since link keys represent a bilateral trust
relationship that survives delegation changes.

---

## 4. Identity Lifecycle

**What.** Identity Lifecycle is the set of protocols by which identities are
published (introduced to the network), rotated (migrated to a new key), and
revoked (permanently retired) in a fully decentralised network. It has two
components. First, key rotation: a signed statement from old_key stating "my
new key is new_key; accept no further messages from old_key after timestamp T."
This is similar to key delegation (section 3) but operates at the identity root
rather than the device level — it changes which key *is* the identity. Second,
a gossip protocol that propagates lifecycle events so that any node in the
network eventually learns about rotation and revocation without depending on a
central authority or a global broadcast. The gossip protocol can be implemented
either as an overlay network (identity-bearing nodes maintain persistent Links
dedicated to lifecycle gossip, exchanging rotation records via epidemic
push/pull) or as new protocol packet types carried over existing
announce/forward paths. The overlay approach is favoured for initial
implementation: it requires no new wire-level packet types, it works even when
announce flooding is disabled (section 1), and it naturally limits propagation
scope to nodes that care (nodes that have cached the old key).

**Why.** Without key rotation, a compromised key is a permanent disaster. The
attacker can impersonate the identity forever — there is no central authority
to appeal to, no certificate revocation list to check, no trusted third party
to declare the key invalid. All state bound to that identity — contacts, link
session keys, content subscriptions, reputation scores, routing table entries —
is captured by the attacker. Key rotation gives the legitimate owner a
cryptographic escape hatch: if they can sign a rotation record with the old key
before the attacker does (or before the attacker publishes a conflicting
rotation), the network migrates to the new key and the attacker's copy of the
old key becomes worthless. But rotation only works if the rotation record
propagates to every node that might have cached the old key. A node that never
received the rotation record will continue to accept the attacker's packets
indefinitely. The gossip protocol solves this propagation problem: it ensures
that rotation records eventually reach all interested nodes, with probabilistic
guarantees rather than absolute ones (no gossip protocol can guarantee 100%
delivery, but epidemic protocols can achieve arbitrary high probability with
sufficient redundancy). The gossip protocol also handles initial identity
publication: when a new node comes online, its neighbours gossip its identity
to the wider network, building the global routing table organically rather than
relying solely on announce flooding.

**When.** Key rotation is needed from the moment an identity carries value
worth stealing — which could be day one for a production deployment, or never
for a test mesh. The gossip protocol for rotation propagation becomes necessary
when the network is large enough that direct neighbour announces don't reach
every node that might cache the old key — roughly the same threshold as
hierarchical announce forwarding (section 1). As a practical sequencing matter,
identity lifecycle should be implemented alongside key delegation (section 3)
since they share infrastructure: both require the ability to verify a signed
statement about an identity, both require a local cache of identity state, and
both touch the packet validation hot path. The gossip overlay can be deferred
past the delegation implementation, since at small scale rotation records can
propagate via existing announce mechanisms. The implementation order: first,
the rotation record format and per-node identity state database; second,
rotation checking in the packet validation path; third, the gossip overlay for
large-scale propagation.

**Protocol Impact.** If the protocol approach is taken (new packet types):
`ID_ROTATION` (old_key hash, new_key, rotation timestamp, old_key signature)
and `ID_REVOCATION` (key hash, revocation timestamp, self-signature). If the
overlay approach is taken, these records are carried as `DATA` packets over a
dedicated identity gossip Link mesh — the overlay nodes form a small-world
graph (each identity node connects to a few peers), exchange rotation records
via periodic push/pull, and cache records with TTL-based expiry. Either way,
every node must maintain an identity state database: a map from identity_hash
to (current_valid_key, rotation_history, last_seen_timestamp). The rotation
check becomes part of packet validation: when a packet arrives, check if a
rotation exists for the claimed source identity; if the packet is signed by a
key that has been rotated out (timestamp > rotation_time), reject it. This
logic must be efficient — the identity state database is consulted on every
inbound packet — so it should be an in-memory hash map, not a disk-backed
database. A subtle threat: an attacker could flood the network with fake
rotation records for identities they don't control, trying to poison the
identity state database and cause legitimate packets to be rejected.
Mitigation: rotation records must be signed by the old key; a node must verify
the signature before accepting the rotation. Forged rotation records (signed by
neither old nor new key) are trivially rejected.

---

## 5. SuspendableLink as Default

**What.** `SuspendableLink` is already implemented as a wrapper around `Link`
that adds session serialization to disk, automatic state restoration on
reconnect, and transparent message requeuing during disconnection. This change
would merge that persistence layer directly into `Link` itself, gated by a
`LinkConfig.suspend: bool` field. When `suspend: true` (the new default), the
link automatically serializes its complete state on disconnection: session keys
(derived from ECDH, so they don't need renegotiation), peer identity, Channel
framing state, Buffer contents, and any queued outbound messages. On
reconnection — when the peer's identity reappears on any interface — the link
deserializes, restores session keys, replays queued messages in order, and
resumes traffic as if nothing happened. When `suspend: false`, the link behaves
identically to the legacy `Link`: disconnection is terminal, all state is
destroyed, and the application receives a definitive disconnection event. The
goal is to make `suspend: true` the default and to eventually eliminate the
`SuspendableLink` wrapper entirely, so that every new link created by
applications gets disruption tolerance without any extra code, configuration,
or awareness.

**Why.** The current two-type design (`Link` + `SuspendableLink`) forces every
application author to make a choice they should not have to make. Most
applications want their links to survive disconnection — it is the entire point
of identity-based transport. If the network binds communication to identities
rather than locations, then "this link to Alice's identity" should survive
Alice switching from WiFi to satellite, her phone going through a tunnel, or
her node rebooting. The link is a relationship between two identities, not
between two ephemeral transport addresses, and relationships persist through
gaps. But the API presents `Link` as the default and `SuspendableLink` as an
opt-in advanced feature. This is backwards. An application author who uses
`Link`, assumes resilience, and discovers at the worst moment that a 30-second
WiFi dropout destroyed their session keys and queued messages will not think "I
should have used SuspendableLink" — they will think "this network is
unreliable." The network is not unreliable; the default API is misconfigured.
Merging the two types and defaulting to persistence fixes the API surface at
the root, eliminating an entire class of bugs and making disruption tolerance
the baseline behaviour that matches the identity-centric architecture.

**When.** This can happen as soon as `SuspendableLink` is proven stable in
integration testing — no new protocol, no wire format change, no coordination
with other implementations. It is purely a Rust API refactor. The merge should
span two release cycles: in the first release, introduce `LinkConfig.suspend`
with default `true`, make `Link` internally delegate to the current
`SuspendableLink` logic when `suspend` is true, deprecate `SuspendableLink` as
a separate public type (with a `#[deprecated]` annotation pointing to the new
config), and update all internal callers to use the new API. In the second
release, remove the `SuspendableLink` type entirely and inline its logic into
`Link`. This two-step process gives downstream users one full release cycle to
migrate. Because this only affects the Rust crate API, other language bindings
(if any exist) are not blocked; they can wrap the new `Link` API whenever
convenient.

**Protocol Impact.** Essentially zero impact on the wire protocol. The `Link`
struct gains a `suspend: bool` field in its `LinkConfig`, and serialization
logic moves from a separate wrapper into the core `Link` type. The on-disk
serialization format (session keys, peer identity, channel state, queued
messages) may benefit from a version field to support future format evolution,
but the initial merge can use the existing `SuspendableLink` format unchanged.
One important behavioral guarantee: when `suspend: false`, disconnection must
immediately drop all resources — this is the legacy `Link` behaviour and must
not be broken, since some applications (short-lived RPC calls, one-shot
queries, stateless request/response) genuinely want immediate teardown and
should not pay the cost of serialization or the complexity of session
resumption. The defaults matter, but the escape hatch must remain. A secondary
consideration: when `suspend: true`, the serialized link state should be stored
in a location that survives process restart (a well-known directory, not
`/tmp`), and the node should scan this directory on startup to restore any
links that were active before shutdown. This makes link persistence survive not
just network disconnection but also deliberate shutdown and restart.

---

## 6. Bridge Protocol

**What.** The Bridge Protocol defines how edge networks hand over packets to
the backbone and how the backbone hands them back to the destination edge. The
core data structure is the Unified Addressing Table (UAT) — a routing database
that maps identity prefixes to one or more next-hop bridge addresses, along
with path cost and expiry metadata. The UAT unifies two addressing schemes:
edge networks use 16-byte truncated identity hashes to keep packet headers
compact on low-bandwidth links; the backbone uses full 32-byte identity hashes
to eliminate collision risk in routing tables that may scale to millions of
entries. The bridge is responsible for translating between these two
representations. An edge node sends a packet to its designated bridge
(configured by the edge node's `bridge_address` setting); the bridge looks up
the destination identity in the UAT, determines which backbone node or peer
bridge can reach it, encapsulates the edge packet in a bridge-layer forwarding
header, and sends it into the backbone. At the destination bridge, the process
is reversed: the bridge strips the backbone header, translates the 32-byte
address back to 16 bytes, and delivers the packet to the destination edge node.
The protocol is SCION-inspired: it cleanly separates the edge path (end-node to
ingress bridge) from the backbone path (bridge to bridge), allowing each layer
to use routing strategies appropriate to its scale and topology without leaking
abstraction boundaries.

**Why.** The 1:1 architecture has a single, flat routing domain: every node
runs the same protocol, every node can (in principle) reach every other node
through direct announce-based path discovery, and there is no structural
distinction between a LoRa sensor and a fiber-connected backbone router. This
simplicity is a virtue at small scale but a liability at large scale. Different
physical domains have radically different characteristics: a home mesh of 10
LoRa sensors has negligible routing state and tolerates high latency; a
city-wide network of WiFi base stations needs sub-second routing convergence
and moderate state; a transcontinental fiber backbone needs sub-millisecond
convergence, massive routing tables, and capacity-aware path selection. Forcing
all of them to use the same routing protocol is the mistake IP made with BGP —
one protocol stretched across every scale, resulting in a protocol that is too
heavy for edges and too fragile for cores. The Bridge Protocol allows each
domain to be an autonomous routing island with its own internal routing
strategy, while bridges provide controlled, authenticated, and policy-enforced
interconnection. Edge domains can be chaotic (announce flooding, opportunistic
links, high churn); the backbone can be tightly managed (explicit topology,
capacity-aware routing, traffic engineering). The bridge is the enforcement
point where these two worlds meet.

**When.** The Bridge Protocol is FUTURE work. The bridge and backbone crates in
the repository are currently stubs — they compile but implement no routing
logic beyond what the Python `bridge.py` script provides (raw HDLC frame relay
between UDP and TCP, with no protocol awareness). Full Bridge Protocol
implementation should begin only after the edge protocol achieves 1:1 parity
with the Python reference implementation and is proven stable in at least one
production deployment. The UAT design should be informed by real edge announce
traffic patterns — how many identities per bridge, how frequently they change,
how much churn the system experiences — rather than speculated from first
principles. Implementation should proceed in four phases: Phase 1, spec the UAT
schema and the bridge-to-bridge handshake protocol (identity exchange,
capability advertisement, prefix announcement). Phase 2, implement bridge
packet forwarding with the UAT — a bridge that can receive edge packets, look
up destinations, and forward to the correct next hop. Phase 3, implement bridge
announce aggregation (section 1) as a UAT population mechanism. Phase 4,
implement inter-backbone routing for multi-backbone deployments (section 7).
Each phase should be testable independently against a small multi-bridge
testbed.

**Protocol Impact.** This is the most complex protocol change in this document
and should not be undertaken lightly. New packet types at the bridge layer
include: `BRIDGE_HANDSHAKE` (bridge identity hash, supported edge prefixes,
capacity metrics, protocol version), `BRIDGE_ROUTE_QUERY` (destination identity
hash, query ID for correlation), `BRIDGE_ROUTE_RESPONSE` (path vector with
per-hop bridge identities and costs, query ID), and `BRIDGE_FORWARD`
(encapsulated edge packet with bridge-layer source-route header). The UAT needs
a well-defined schema — likely a key-value store with identity prefix (variable
length, 1–32 bytes) as key and a list of `(bridge_address, path_cost,
expiry_timestamp, last_updated)` tuples as value. Edge nodes gain a single new
configuration option: `bridge_address`, the 32-byte identity hash of the bridge
to use. If set, all outbound packets are forwarded to the bridge rather than
delivered locally; if unset, the node operates in standalone edge mode. The
bridge must handle address translation bidirectionally: on ingress, map 16-byte
edge destination addresses to 32-byte backbone addresses using a translation
table populated by announce observation; on egress, reverse the mapping.
Address translation is non-trivial because the 16→32 mapping is lossy
(truncation), so the bridge must maintain a bidirectional mapping indexed by
both address lengths. This is fundamental complexity, not implementation
complexity, and must be specified with care.

---

## 7. Backbone Scaling

**What.** Backbone scaling extends the bridge architecture to support multiple
interconnected backbone meshes, each potentially using different internal
routing strategies appropriate to its physical layer and administrative domain.
The mechanism is source-routed identity forwarding, directly inspired by
SCION's path-segment construction model. A source bridge that needs to reach a
destination identity first checks its local UAT; if the destination is
reachable through a directly connected backbone, it constructs a single-segment
path. If not — the destination is in a different backbone — the source bridge
recursively queries neighbouring backbones via their border bridges. Each
queried backbone returns a path segment: a sequence of bridge hops through that
backbone, from its ingress border bridge to its egress border bridge. The
source bridge concatenates these segments into a complete source route and
encodes it as a list of `(backbone_id, egress_bridge, ingress_bridge)` tuples
in the packet header. Each backbone on the path strips its own segment and
forwards according to its internal routing policy — link-state within a fiber
backbone, distance-vector within a satellite mesh, static routes within a fixed
wireless deployment. No backbone exposes its internal topology to any other
backbone; all that crosses administrative boundaries is the reachable identity
prefix and the border bridge addresses.

**Why.** A single backbone mesh is sufficient for regional deployments — a
city, a small country, a single organization. But for internet-scale
deployment, a single backbone becomes a bottleneck for three reasons. First,
routing table size: every bridge must know, directly or indirectly, how to
reach every identity prefix in the world. As the number of identities grows
into the millions or billions, this table exceeds the memory of any single
bridge node and the bandwidth available for routing updates. Second, update
propagation latency: a topology change in one region (a bridge going down, a
new identity prefix being announced) must propagate to every other bridge
before routing converges. In a global single-mesh network, this latency is
bounded by the speed of light and the diameter of the mesh — unacceptable for
real-time traffic. Third, administrative boundaries: different organizations
running different backbones have different routing policies, security
requirements, and trust models. A military backbone and a community mesh should
not share a routing table. Multiple interconnected backbones with source-routed
paths solve all three: each backbone maintains only its own internal routing
table plus reachability to neighbouring backbones; topology changes are
confined to their origin backbone; and policy decisions (which backbone to use
for which traffic) are made by the source bridge, not by a global routing
protocol.

**When.** Backbone scaling is FUTURE work — further out than the Bridge
Protocol itself, which is a prerequisite. It should only be considered when a
single backbone mesh is demonstrably insufficient. The triggering conditions
are measurable: routing table size on bridge nodes exceeds available memory,
routing update latency (time from topology change to global convergence)
exceeds application requirements, or organizational boundaries require explicit
routing policy that a flat mesh cannot express. The SCION project at ETH Zurich
provides over a decade of operational experience with inter-domain source
routing in an identity-centric architecture; rsticulum can and should adapt
those lessons rather than inventing from scratch. Implementation should begin
with a minimal testbed: two backbones (e.g., one LoRa mesh and one WiFi mesh,
each with its own bridge), connected via a pair of border bridges, routing
traffic between them using the path-segment protocol. Only after the
two-backbone case is proven should the design generalize to N backbones with
arbitrary interconnection topology.

**Protocol Impact.** The bridge protocol (section 6) gains inter-backbone
extensions layered on top of the base bridge packet types. New packet types:
`BACKBONE_PATH_SEGMENT` (a backbone advertising its reachable identity prefixes
and border bridge addresses to neighbouring backbones, with cost metrics and
expiry), `BACKBONE_PATH_REQUEST` (query from one backbone's border bridge to
another, asking for a path segment to identity X), `BACKBONE_PATH_RESPONSE`
(the path segment through the queried backbone, as a list of bridge hops with
costs). The bridge forwarding logic gains a recursive path-resolution loop:
check local UAT → if miss, query directly connected neighbour backbones →
concatenate returned segments → cache the complete path with TTL → encode in
source-route header. Packets traversing multiple backbones carry a
source-route header: a variable-length list of `(backbone_id,
next_bridge_address)` hops. Each bridge on the path strips the current hop,
looks up its internal route to the next hop, and forwards — if the next hop is
in a different backbone, the border bridge strips the current backbone segment
and forwards to the ingress bridge of the next backbone. Edge packets are
encapsulated unchanged throughout; the source routing operates entirely at the
bridge layer. The UAT schema gains a `backbone_nexthop` discriminator to
distinguish local-bridge nexthops from inter-backbone nexthops. Backbone border
bridges must implement a path-segment advertisement protocol — this is the core
new complexity and the protocol component most likely to require iteration
based on operational experience.

---

## Summary of Trigger Conditions

| # | Topic | Trigger Condition |
|---|-------|-------------------|
| 1 | Hierarchical announce forwarding | ~500 nodes on moderate links, ~200 on low-bandwidth links |
| 2 | Proof-of-work on announces | Network carries valuable/exploitable traffic; Sybil attacks feasible |
| 3 | Key delegation | User has >1 device, or needs key rotation for a long-lived identity |
| 4 | Identity lifecycle gossip | Network too large for rotate/revoke records to propagate via announces |
| 5 | SuspendableLink as default | `SuspendableLink` proven stable; merge over two release cycles |
| 6 | Bridge protocol | Single mesh domain insufficient; multi-domain deployment needed |
| 7 | Backbone scaling | Single backbone mesh is bottleneck; internet-scale ambition |

---

*These notes are not a specification. They are a roadmap for what comes after
the 1:1 parity release is stable and deployed — what each change is, why it
matters, when to consider implementing it, and how much protocol surface it
touches. Order does not imply priority. Trigger conditions are approximate
heuristics, not hard thresholds. Everything in this document is subject to
revision based on operational experience with real networks at real scale.*
