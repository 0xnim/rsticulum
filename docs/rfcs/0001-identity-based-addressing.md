# RFC 0001: Identity-Based Addressing

- **Status:** Draft
- **Layer:** Identity
- **Depends on:** None
- **Depended on by:** RFC 0002, RFC 0003, RFC 0004, RFC 0005, RFC 0006, RFC 0007, RFC 0009, RFC 0011

## Abstract

Every node generates an Ed25519 keypair. The address is derived from the public key via SHA-256 — the address **is** the identity. No separate namespace for location, no central allocation authority, no DNS. An address is a permanent, self-certifying identifier: given an address and a signed message, any node can verify origin without consulting any third party.

At the edge layer, addresses are truncated to 16 bytes for compact packet headers on low-bandwidth links (LoRa, serial). At the bridge and backbone layers, the full 32-byte identity hash eliminates collision risk in routing tables of millions of entries.

## Motivation

The existing internet binds addressing to topology. IP addresses encode **where** a host is plugged in, creating systemic problems: scarcity requiring central allocation, mobility breaking addressing, trivial spoofing, NAT as a layering violation, and the dual namespace of DNS. Identity-based addressing eliminates all five: no allocation (hash a keypair — you have an address), address survives mobility, source-authenticated by construction, no NAT, single namespace.

## Specification

### Address Derivation

Every node generates an Ed25519 keypair (32-byte seed, 32-byte public key). Ed25519 is chosen for compact keys/signatures (32/64 bytes), deterministic nonce generation (RFC 8032), and widely available constant-time implementations. Losing the private key means losing the identity — no recovery mechanism exists. This is self-sovereign identity.

The full 32-byte canonical identity hash:

```
identity_hash = SHA-256(public_key)
```

The edge address (RNS wire format) truncates to 16 bytes:

```
edge_address = identity_hash[0..16]
```

This 128-bit address is used in all edge-layer packets (announces, link requests, data, proofs). RNS wire compatibility requires 16-byte addresses at the edge. Collision risk is acceptable at edge scale (see Collision Analysis).

At the bridge and backbone, the full 32-byte hash is used — zero collision tolerance for routing tables indexing millions of identities, cryptographic certainty for identity lifecycle operations, and protection against prefix-collision attacks in path segment construction.

**Address translation:** Bridges translate Edge → Backbone (16B → 32B) by looking up the full hash in their announce cache keyed by the 16-byte edge address. Backbone → Edge (32B → 16B) simply truncates. Missing mappings trigger an `IdentityQuery`.

### Self-Certification

An address is self-certifying — verification requires no external authority:

```
claimed_address == SHA-256(claimed_public_key)[..claimed_address.len()]
```

A node receiving a packet from address `A` with signature `S` performs two local checks: (1) address binding — `A == SHA-256(pubkey)[0..16]`, and (2) signature validity — `ed25519_verify(pubkey, message, S)`. Both are constant-time, requiring no network round-trips. The address **is** the verification.

### Address Properties

Key type: Ed25519 (RFC 8032) · Public key: 32 bytes · Hash: SHA-256 (FIPS 180-4) · Full identity: 32 bytes (256 bits) · Edge address: 16 bytes (128 bits) · Address space: 2^128 (edge), 2^256 (backbone) · Wire encoding: raw bytes · Display: lowercase hex, no separators.

## Collision Analysis

For a 128-bit edge address space with `n` nodes, the birthday bound gives:

```
P(collision) ≈ n² / 2^129    (for n ≪ 2^64)
```

| n | Collision Probability |
|---|---|
| 10^3 (small mesh) | ~1.5 × 10^-33 |
| 10^6 (city-scale) | ~1.5 × 10^-27 |
| 10^9 (global edge) | ~1.5 × 10^-21 |
| 10^15 | ~1.5 × 10^-9 |

For any realistic mesh (up to billions of nodes), collision probability is negligible. The address space is 3.4 × 10^38 addresses. **Mitigation:** every Link establishment exchanges the full public key. If two nodes share a truncated address, the handshake detects the full identity hash mismatch and assigns a local disambiguation tag.

For the 256-bit backbone, collision probability is effectively zero — 2^256 exceeds the estimated atoms in the observable universe. No mitigation is necessary.

**Second-preimage resistance:** finding a second keypair with the same truncated address requires 2^127 hash operations — infeasible. Truncation does not weaken SHA-256; the first 16 bytes are as uniformly distributed as the full 32.

## Security Considerations

The address-key binding is cryptographic, not administrative. No registry to corrupt, no CA to compromise. Impersonation requires either a second preimage (2^127 operations, infeasible) or private key theft — the only practical attack. No central point of failure exists; every node is its own address authority. Sybil attacks are addressed by RFC 0004 (Proof-of-Work Anti-Spam). Key compromise is mitigated by key rotation (RFC 0006: Identity Lifecycle Protocol).

## References

**Normative:** [RFC 8032] Ed25519; [FIPS 180-4] SHA-256.
**Informative:** [RFC 0002] Suspendable Links; [RFC 0004] PoW Anti-Spam; [RFC 0006] Identity Lifecycle; [RFC 0009] Bridge Protocol; [Yggdrasil] Crypto-derived IPv6 overlay.
