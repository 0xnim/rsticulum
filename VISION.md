# Internet, Rebuilt

Connections as durable as files on disk. Identity as the only address. Any physical medium.

## Principles

- **Identity-first** — Your address is who you are (public key hash), not where you are plugged in. No NAT, no allocation, no renaming when you move.
- **Disruption-tolerant** — Links survive hours or days of disconnection. The network does not RST when a signal drops; it waits.
- **Content-addressed** — Fetch data by what it is (content hash), not where it lives (server URL). Any copy is equally valid.
- **Permissionless** — No registrars, no CAs, no gatekeepers. Cryptographic proof replaces institutional trust.
- **Medium-agnostic** — LoRa, serial, WiFi, Ethernet, satellite, optical. Any medium is a valid link; the stack doesn't care.

## The Stack

```
┌──────────────────────────────────────────────────┐
│                   APPLICATIONS                   │
│  (WASM, CLI tools, IoT logic, chat, feeds)       │
├──────────────────────────────────────────────────┤
│               APPLICATION LAYER                  │
│            ICN (Interest / Data)                 │
│  • Named data requests by producer-hash prefix   │
│  • Content-addressed fetching + caching          │
│  • Subscription Interests for streaming data     │
│  • Manifest system for dynamic/mutable content   │
├──────────────────────────────────────────────────┤
│              EDGE / TRANSPORT                    │
│    Reticulum Protocol (rsticulum)                │
│  • Identity-derived 16-byte addresses            │
│  • Proactive link-state + reactive discovery     │
│  • Physical agnostic (UDP, serial, radio, LoRa)  │
│  • Suspend/reconnect — no RST on timeout         │
│  • Rateless announces via hierarchical forwarding │
├──────────────────────────────────────────────────┤
│              IDENTITY / ADDRESSING               │
│           Cryptographic Addressing               │
│  • Address = Public Key hash                     │
│  • Delegation, rotation, revocation lifecycle    │
│  • No NAT, no spoofing, no allocation            │
└──────────────────────────────────────────────────┘
```

The stack has three active layers plus identity. There is no separate transport layer — Reticulum *is* the transport. There is no separate backbone layer — backbone routing is a deployment pattern within Reticulum (transport instances), not a separate protocol. The SCION-inspired backbone is future work for scaling beyond single-mesh topologies.

## Foundation

- **Reticulum** — The protocol this is built on. Mesh networking over any physical medium. Identity-derived 16-byte addresses, proof handshakes, announce-based discovery. [Reference impl](https://github.com/markqvist/Reticulum)
- **rsticulum** — Rust port of Reticulum. Wire-compatible with Python RNS.
- **NDN / CCN** — Interest/Data packet model, PIT, ContentStore. Inspiration for the application layer.
- **SCION** — Source routing with verified path segments, ISD trust boundaries. Inspiration for backbone scaling.
- **Yggdrasil** — Crypto-derived IPv6 overlay at scale. Proves key→address derivation works at internet scale.
- **IPFS** — Content-addressed storage with DHT peer discovery. Proves the content-hash model in production.

## Needs to be Built

In priority order:

1. **rsticulum** — Full Rust implementation of Reticulum. Wire-compatible with Python RNS. (In progress.)
2. **Reticulum protocol evolution** — Suspendable links as default, hierarchical announce forwarding, key delegation, proof-of-work anti-spam. Evolve the protocol; bring upstream RNS along when possible.
3. **Identity lifecycle protocol** — Key publication, rotation, revocation, delegation chains. Sits between identity and transport; required before multi-device identity or key rotation works.
4. **ICN Transport** — Interest/Data for dynamic and live data (not just static files), subscription Interests, extended PIT lifetimes. Runs over Reticulum Links.
5. **Manifest system** — ICN-compatible mutable WASM apps and versioned content via signed manifests with well-known pointers.
6. **WASM application runtime** — Sandboxed WASM modules with a limited ICN API, deployed and updated via the manifest system.
7. **Backbone scaling (SCION-inspired)** — Identity-based forwarding at scale, long-lived path segments, bridge protocol for multi-mesh topologies. Only needed when single-mesh routing is insufficient.

## Implementation

**Primary: Rust** — zero-cost abstractions, no GC, mature async (tokio), strong crypto, WASM-first.

**Secondary: Python** — reference implementations, protocol validation, test tooling.
