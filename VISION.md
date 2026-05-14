# Internet, Rebuilt

A network where connections are as durable as files on disk.

## Principles

- **No IP**: Addresses are identities (public keys), not locations.
- **No TCP**: Connections survive long disruptions (hours/days).
- **No HTTP**: Fetch data by content hash, not server location.

## The Stack

```
┌──────────────────────────────────────────────────┐
│                   APPLICATIONS                   │
│  (WASM, CLI tools, IoT logic, chat, feeds)       │
├──────────────────────────────────────────────────┤
│               APPLICATION LAYER                  │
│            ICN (Interest / Data)                 │
│  • Named data requests                           │
│  • Content-addressed fetching                    │
│  • Manifest system for dynamic WASM              │
├──────────────────────────────────────────────────┤
│                  TRANSPORT LAYER                 │
│         Identity-Based Streams                   │
│  • Suspend/resume on disconnect                  │
│  • Multiplexed over physical links               │
│  • No TCP state machine (no RST on timeout)      │
├──────────────────────────────────────────────────┤
│                CORE / BACKBONE                   │
│                 SCION-inspired                   │
│  • Source-routed, verified paths                 │
│  • ISD trust boundaries                          │
│  • Hop-field validation in packets               │
├──────────────────────────────────────────────────┤
│              EDGE / ACCESS                       │
│    Reticulum Protocol (rsticulum)                │
│  • 16-byte destination addresses                 │
│  • Proactive link-state + reactive discovery     │
│  • Physical agnostic (UDP, serial, radio)        │
├──────────────────────────────────────────────────┤
│              IDENTITY / ADDRESSING               │
│           Cryptographic Addressing               │
│  • Address = Public Key hash                     │
│  • No NAT, no spoofing, no allocation            │
└──────────────────────────────────────────────────┘
```

## Existing Building Blocks

- **Reticulum** — Mesh networking over any physical medium. Lo-fi links (LoRa, serial). [Reference impl](https://github.com/markqvist/Reticulum)
- **rsticulum** — Rust port of Reticulum edge layer. Wire-compatible with Python RNS. [main branch](../main)
- **SCION** — Source routing with verified paths, path-segment construction, ISD trust model.
- **Yggdrasil** — Crypto-derived IPv6 overlay. Key→address derivation at scale.
- **NDN** — Interest/Data packet model. Router caching. NFD forwarding daemon.
- **IPFS** — Content-addressed file storage. DHT peer discovery.

## Needs to be Built

- **Identity Stream Protocol** — Transport that supports suspend/resume, multiplexing, identity-first.
- **SCION-Reticulum Bridge** — Border router daemon stitching edge mesh into backbone.
- **ICN Transport** — Interest/Data for dynamic/live data (not just static files).
- **Manifest System** — ICN-compatible mutable WASM apps via signed version manifests.
- **Network Daemon** — User-space socket API replacement for applications.

## Implementation

**Primary: Rust** — zero-cost abstractions, no GC, mature async (tokio), strong crypto, WASM-first.

**Secondary: Python** — reference implementations, protocol validation, test tooling.
