# RFC 0003: Content-Named Overlay

- **Status:** Design (Overlay — no protocol changes)
- **Layer:** Application
- **Depends on:** [RFC 0001: Identity-Based Addressing](0001-identity-based-addressing.md)
- **Related:** LXMF (application-layer messaging overlay)

## Abstract

This RFC describes a **Content-Named Overlay** — an application-layer content distribution
network built entirely on standard Reticulum Links. It requires **zero changes** to the
Reticulum protocol, wire format, or packet types. Content routers are specialized nodes
that cache and forward content by name, analogous to how LXMF propagation nodes relay
messages. Ordinary Reticulum nodes see nothing different; only nodes that opt into the
overlay participate in content routing.

## Architecture

### Content Routers

Content routers are **opt-in application processes** running on Reticulum nodes. A node
becomes a content router by running the content-routing application — no different from
a node running an LXMF propagation daemon. Content routers communicate with each other
over ordinary Reticulum Links. There are no new packet types, no new Announce contexts,
and no modifications to the Reticulum stack.

### Name Format

Content is identified by a hierarchical name rooted in the producer's identity:

```
/<producer_hash>(/<path-segment>)*?blake3=<content_hash>
```

- **`<producer_hash>`** — the 64-char hex-encoded identity hash of the producer (the
  Reticulum identity address). The name **MUST** start with this. This is what routes
  the Interest — the producer hash is directly resolvable to a Reticulum destination.
- **`<path-segment>`** — zero or more path components (e.g., `/images/cat.jpg`).
- **`?blake3=<content_hash>`** — optional content hash for integrity verification.

Example: `/<producer_hash>/images/cat.jpg?blake3=af1349b9...`

### Core Data Structures

| Structure | Purpose |
|-----------|---------|
| **PIT** (Pending Interest Table) | Aggregates duplicate Interests. Maps Interest name → list of requesting peers. When Data arrives, it is multicast to all requesters and the PIT entry is removed. |
| **CS** (ContentStore) | LRU cache of Data packets indexed by full name (including the blake3 hash parameter). Satisfies Interests from local cache without upstream forwarding. |
| **FIB** (Forwarding Information Base) | Maps name prefix → set of known peer content routers. Built from Reticulum Announces. |

## Interest/Data Flow

### Interest Packet (Overlay Message over Link)

```
Interest {
    name:    "/<producer_hash>/..."   // hierarchical content name
    nonce:   [u8; 4]                  // random, for PIT duplicate detection
    hoplimit: u8                      // TTL (e.g., 64)
}
```

### Data Packet (Overlay Message over Link)

```
Data {
    name:      "/<producer_hash>/...?blake3=<hash>"
    payload:   [u8]                    // the content
    signature: [u8; 64]                // Ed25519 signature by producer
}
```

The signature is verifiable against the producer's identity hash (the root of the name).
This means any consumer — not just content routers — can verify content authenticity
without trusting the delivery path.

### Forwarding Algorithm

When a content router receives an Interest:

1. **Check ContentStore.** If a matching Data packet is cached, return it immediately.
2. **Check PIT.** If this Interest is already pending, add the requester to the PIT
   entry and stop. This aggregates duplicate Interests.
3. **Look up FIB.** Find peer content routers for the longest matching name prefix.
4. **Forward.** Send the Interest over the Reticulum Link to one or more upstream peers.
5. **Wait.** When Data arrives, cache it in the CS, deliver to all PIT requesters
   (multicast), and remove the PIT entry.

Interest forwarding follows the producer hash prefix. Since the producer hash is a
Reticulum identity address, the overlay naturally routes Interests toward the producer
or toward content routers that have cached the producer's content.

## Caching

Content routers implement an LRU ContentStore at the application level. This is entirely
separate from Reticulum's own `CACHE_REQUEST` (Announce context `0x08`), which the
overlay does not use. The ContentStore serves two purposes:

- **Off-path caching.** A content router that has seen Data can satisfy future Interests
  without forwarding them upstream.
- **Producer offloading.** Popular content is served from the cache, reducing load on
  the producer and improving latency.

Cache eviction is size-based LRU. Content routers may optionally implement cache
replacement policies informed by Interest frequency.

## Deployment

Content routers announce themselves via standard Reticulum Announces. Peer content
routers build their FIB by observing these Announces and storing the mapping from
identity hash → known content routers.

A node that wants to retrieve content sends an Interest to any known content router
(the nearest, or one discovered via an Announce). The overlay handles the rest.

Producers publish content by making it available to at least one content router,
which seeds it into the overlay. Subsequent Interests from anywhere in the network
can retrieve the content from any caching router along the path.

## Relationship to Reticulum

This RFC is a **design document**, not a protocol specification. It defines an
application-layer pattern that requires no changes to Reticulum:

- **No new packet types.** Interest and Data are application-layer messages carried
  over standard Reticulum Links, just as LXMF messages are.
- **No new Announce contexts.** Content routers use existing Reticulum Announces.
- **No changes to the wire format.** The overlay is invisible to non-participating nodes.
- **Opt-in participation.** Legacy Reticulum nodes continue functioning exactly as before.
- **Identity-based routing.** The overlay exploits Reticulum's identity-based addressing
  to route Interests toward the producer by publisher hash.

Content-Named Overlay is to content distribution what LXMF is to messaging: a
purpose-built application protocol running on Reticulum's identity-centric transport,
with specialized nodes providing infrastructure services, and full backward
compatibility with all existing nodes.
