# Documentation Index

Complete technical specification for the next internet — a network rebuilt
on identity, not location.

## Reading Order

| # | Document | What It Is |
|---|----------|------------|
| 1 | [VISION.md](../VISION.md) | Pitch: principles, stack, why this exists |
| 2 | [ARCHITECTURE.md](ARCHITECTURE.md) | Full architecture: layers, components, packet flow |
| 3 | [ADAPTATIONS.md](../ADAPTATIONS.md) | Protocol adaptation analysis for Reticulum, SCION, ICN |
| 4 | [RFCs](#rfcs) | Formal specifications and design documents |
| 5 | [IMPLEMENTATION.md](IMPLEMENTATION.md) | Crate map, build phases, known gaps |
| 6 | [GLOSSARY.md](GLOSSARY.md) | Terminology, address formats, acronyms |

## RFCs

Three categories: **Reference** (describes existing Reticulum), **Overlay**
(designs that require zero Reticulum changes), and **Notes** (future work).

| RFC | Title | Type | What It Covers |
|-----|-------|------|----------------|
| [0001](rfcs/0001-identity-based-addressing.md) | Identity-Based Addressing | Reference | Ed25519 keys → SHA-256 → 16B edge / 32B backbone addresses |
| [0002](rfcs/0002-suspendable-links.md) | Links & Disruption Tolerance | Reference | Link state machine, ECDH+Ed25519 handshake, AES-256-CBC Token, SuspendableLink session persistence |
| [0003](rfcs/0003-content-named-overlay.md) | Content-Named Overlay | Overlay | Interest/Data flow over standard Links. PIT/CS/FIB at content routers. Zero protocol changes. |
| [0004](rfcs/0004-manifest-system.md) | Manifest System | Overlay | Signed JSON manifests for mutable content. Well-known pointers. Version ordering. |
| [0005](rfcs/0005-wasm-distribution.md) | WASM Distribution | Overlay | WASM as a content type in the manifest. Network distributes; user runs. |
| [0006](rfcs/0006-protocol-evolution.md) | Protocol Evolution Notes | Notes (Future) | Hierarchical announces, PoW, key delegation, identity lifecycle, bridge protocol, backbone. Post-1:1. |

## Overlay vs. Protocol Evolution

The content overlay (RFCs 0003–0005) requires **zero changes to Reticulum**.
Content routers are applications that talk over standard Links, like LXMF
propagation nodes. Not every node is a content router — it's opt-in.

The protocol evolution notes (RFC 0006) describe changes that would require
new Reticulum packet types or fields. These are for scale and security. None
are needed for the initial content-addressed internet.

## Supplementary

| Document | Description |
|----------|-------------|
| [plans/2026-05-14-rns-full-compat.md](plans/2026-05-14-rns-full-compat.md) | Phase 1: RNS wire compatibility |
