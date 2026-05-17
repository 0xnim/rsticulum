# Implementation Guide

Maps the architecture to concrete code. Each RFC corresponds to one or more
Rust crates in the `rsticulum` workspace.

## Crate Map

| Crate | RFC(s) | IETF RFC(s) | Phase | Status | Description |
|-------|--------|-------------|-------|--------|-------------|
| `rsticulum-crypto` | 0001 | RFC 5869 (HKDF), NIST SP 800-38A (AES-CBC) | 1 | 🟢 Done | HKDF-SHA256 key derivation, RNS Token (Fernet-style AES-128-CBC) |
| `rsticulum-identity` | 0001, 0005 | RFC 8032 (Ed25519), RFC 7748 (X25519) | 1 | 🟢 Done (delegation stub) | Ed25519/X25519 keys, 16-byte addresses, ECDH key exchange, key delegation stubs |
| `rsticulum-packet` | — | — | 1 | 🟢 Done | RNS wire-compatible packet format (HEADER_1, HEADER_2, PROOF, DATA, ANNOUNCE, LINKREQUEST) |
| `rsticulum-destination` | — | — | 1 | 🟢 Done | RNS Destination abstraction |
| `rsticulum-transport` | 0002 | RFC 5869, RFC 7748 | 1 | 🟢 Done (AES-256 compat gap) | Link + SuspendableLink, proof handshake, ECDH encrypt/decrypt, Resource |
| `rsticulum-channel` | — | — | 1 | 🟢 Done | Reliable in-order message delivery over Links |
| `rsticulum-buffer` | — | — | 1 | 🟢 Done | Streaming I/O over Channels |
| `rsticulum-interface` | — | — | 1 | 🟢 Done | KISS, HDLC, serial, TCP interfaces |
| `rsticulum-mesh` | — | — | 1 | 🟢 Done | Hybrid routing: link-state + path discovery, announce propagation |
| `rsticulum-daemon` | — | — | 1 | 🟢 Done | Network daemon: identity, Link establishment, Channel, ICN forwarder, mesh routing, announce discovery, local TCP API |
| `rsticulum-icn` | 0007, 0008 | RFC 7927, RFC 8569, RFC 8609, RFC 8793 | 2 | 🟢 Done (61 tests) | Full Forwarder (FIB/PIT/CS/Strategy), Interest/Data packets, LinkFace, Manifest, CLI demo binary |
| `rsticulum-identity-lifecycle` | 0006 | — | 2 | ❌ Not started | Identity lifecycle protocol |
| `rsticulum-bridge` | 0003, 0004, 0009 | — | 3 | Stub | Bridge protocol, announce aggregation, address translation |
| `rsticulum-backbone` | 0011 | RFC 9154 (SCION-inspired, not full SCION) | 4 | Stub | SCION-inspired backbone: path segments, identity forwarding |
| `rsticulum-wasm` | 0010 | — | 4 | ❌ Not started | WASM runtime, application sandbox |
| `rsticulum-sdk` | — | — | 5 | Stub | High-level SDK for application developers |

### IETF RFC Reference Details

| IETF RFC | Title | Relevance |
|----------|-------|-----------|
| RFC 5869 | HMAC-based Extract-and-Expand Key Derivation Function (HKDF) | Key derivation from ECDH shared secret |
| RFC 7748 | Elliptic Curves for Security (X25519) | ECDH key exchange for link encryption |
| RFC 8032 | Ed25519 and Ed448 | Identity key signatures, proof verification |
| RFC 7927 | ICN: Baseline Scenarios | ICN application patterns |
| RFC 8569 | CCNx Semantics | Content naming model |
| RFC 8609 | CCNx Messages in TLV Format | Interest/Data packet structure |
| RFC 8793 | ICN: Ready-to-use Deployment | Forwarder pipeline architecture |

## Known Gaps

### 1. Link Encryption: AES-128-CBC vs AES-256-CBC

**Status:** Not wire-compatible with Python RNS.

The Rust implementation uses AES-128-CBC for both `Token` (Fernet-style) encryption
and link data encryption (`encrypt_for`/`decrypt_from` in `rsticulum-identity`).
Python RNS uses AES-256-CBC via its `Token` implementation, which accepts a
48-byte key (32-byte signing, 16-byte encryption) and uses a 256-bit AES key.

| Aspect | Rust (rsticulum) | Python (RNS) |
|--------|-----------------|--------------|
| AES variant | AES-128-CBC | AES-256-CBC |
| Derived key size | 32 bytes (16 signing + 16 encryption) | 48 bytes (32 signing + 16 encryption) |
| Token key split | `key[0..16]` = HMAC, `key[16..32]` = AES | `key[0..32]` = HMAC, `key[32..48]` = AES |
| Wire format | `[IV(16)] [ciphertext] [HMAC-SHA256(32)]` | Same (only AES key length differs internally) |

**Impact:** Rust nodes can communicate with each other without issue. They cannot
decrypt link data from Python RNS peers, and vice versa. The proof handshake,
packet framing, and identity validation are wire-compatible — only the link
encryption layer differs.

**Resolution path:** Upgrade `rsticulum-crypto::Token` and `DerivedKey` to use
AES-256-CBC with 48-byte derived keys. The HKDF expansion step must produce
48 bytes (32 HMAC + 16 AES) instead of 32 bytes. This is a self-contained
change in the crypto and identity crates.

### 2. HKDF Test Failure (1 test)

One HKDF cross-validation test fails against Python RNS output. The Rust HKDF
implementation produces a different derived key than Python's `HKDF.expand()`
for specific salt+info combinations. This is tracked but does not block
Rust↔Rust communication.

### 3. Key Delegation (RFC 0005)

The identity crate has delegation chain data structures defined but no
verification logic or DELEGATE packet handling. This is a Phase 2 item.

### 4. SuspendableLink as Default (RFC 0002)

Both `Link` and `SuspendableLink` exist in the transport crate. The daemon
uses `Link` by default. Making `SuspendableLink` the default (as specified in
RFC 0002) is a Phase 2 migration task.

### 5. ICN PIT Lifetime

The PIT uses a short default lifetime (~4 seconds, NDN-style). RFC 0007
specifies a 30-minute PIT lifetime for disruption-tolerant operation.

## Build Phases

### Phase 1: RNS Wire Compatibility ✓

**Goal:** Full wire-protocol interoperability with Python RNS.

**Status:** Core wire compatibility achieved. The daemon integrates all protocol
layers and can form links, exchange data, announce peers, and serve applications.

**Milestones:**
- [x] Identity, packet, transport, interface crates — working
- [x] Channel, buffer crates — working
- [x] Daemon event loop — working
- [x] Link establishment integrated into daemon (LINKREQUEST, ECDH, proof handshake)
- [x] Announce propagation and peer discovery
- [x] Local TCP API socket (JSON-line protocol)
- [x] ICN forwarder integrated into daemon
- [x] Cross-validation against Python RNS — 199+ tests passing
- [x] End-to-end integration tests (Python↔Rust lifecycle, link proofs, daemon API)

**Verification:**
```bash
cargo test --workspace
cargo test --test integration_rns_interop
cargo test --test interop_python_rns
```

### Phase 2: Protocol Evolution

**Goal:** Evolve Reticulum protocol for disruption tolerance and scale.

**RFCs:** 0002, 0003, 0004, 0005, 0006

**Milestones:**
- [ ] SuspendableLink integration — merge session persistence into Link as LinkConfig.suspend: bool (default true)
- [ ] Hierarchical announce forwarding — bridge aggregation, route summaries
- [ ] Proof-of-work — 20-bit PoW on announce packets, adaptive difficulty
- [ ] Key delegation — delegation chain verification, DELEGATE packet
- [ ] Identity lifecycle — identity store gossip protocol, rotation, revocation
- [ ] (Upstream Python RNS when possible — backward compatible where feasible)

**Verification:**
```bash
cargo test -p rsticulum-transport    # SuspendableLink default
cargo test -p rsticulum-bridge       # Hierarchical announces
cargo test -p rsticulum-identity     # Delegation chains
cargo test -p rsticulum-identity-lifecycle  # Lifecycle protocol
```

### Phase 3: Application Layer

**Goal:** Content-named extensions with manifest system and subscription Interests.

**RFCs:** 0007, 0008

**Status:** Core ICN functionality already implemented (`rsticulum-icn`).
61 tests passing. Forwarder pipeline (FIB → PIT → CS → Strategy) is complete.
LinkFace connects ICN to Reticulum transport.

**Remaining:**
- [ ] PIT lifetime extension — 30-minute default (configurable)
- [ ] Subscription Interests — `subscribe: true` flag, long-lived PIT entries
- [ ] Manifest integration — well-known pointer, subscribe-to-manifest
- [ ] Content type: `application/wasm-module`
- [ ] Face-level name validation — reject names without producer hash

**Verification:**
```bash
cargo test -p rsticulum-icn
```

### Phase 4: Scale

**Goal:** Multi-mesh routing via backbone.

**RFCs:** 0009, 0010, 0011

**Milestones:**
- [ ] Bridge protocol — BRIDGE_ANNOUNCE, address translation, congestion signals
- [ ] Backbone path construction — beaconing, path segments, hop-field validation
- [ ] Identity-based forwarding — replace IP forwarding in SCION model
- [ ] ISD trust model — threshold membership voting
- [ ] WASM runtime — wasmtime integration, sandbox API, update lifecycle

**Verification:**
```bash
cargo test -p rsticulum-bridge
cargo test -p rsticulum-backbone
cargo test -p rsticulum-wasm
```

### Phase 5: SDK and Tooling

**Goal:** Developer experience — high-level SDK, debugging tools, simulators.

**Milestones:**
- [ ] High-level application SDK (`rsticulum-sdk`)
- [ ] Network simulator (configurable topologies, link quality, latency)
- [ ] CLI tools: `rnsctl` (equivalent to `rnstatus`, `rnprobe`, `rnpath`)
- [ ] WASM toolchain: compile Rust to WASM for rsticulum runtime

## Workspace Structure

```
new_internet/
├── Cargo.toml              # Workspace root
├── VISION.md               # Project vision
├── ADAPTATIONS.md          # Protocol adaptation analysis
├── crates/
│   ├── crypto/             # HKDF, token encryption (AES-128-CBC)
│   ├── identity/           # Keys, addresses, delegation, ECDH encrypt/decrypt
│   ├── packet/             # Wire format parsing
│   ├── transport/          # Link, SuspendableLink, proofs, resources
│   ├── channel/            # Reliable messaging over Links
│   ├── buffer/             # Streaming I/O over Channels
│   ├── interface/          # KISS, HDLC, serial, TCP
│   ├── mesh/               # Routing: link-state + discovery
│   ├── destination/        # RNS Destination abstraction
│   ├── daemon/             # Runtime daemon (full stack integration)
│   ├── icn/                # ICN forwarder, PIT, FIB, CS, Manifest, LinkFace
│   ├── bridge/             # Edge↔Backbone bridge (stub)
│   ├── backbone/           # SCION-inspired backbone (stub)
│   ├── sdk/                # High-level SDK (stub)
│   └── identity-lifecycle/ # (Not yet created)
├── tests/
│   ├── interop_python_rns.rs        # Python RNS cross-validation
│   ├── integration_rns_interop.rs   # Daemon-level interop
│   └── python_rns_helper.py         # Test utilities
├── docs/
│   ├── README.md           # Documentation index
│   ├── ARCHITECTURE.md     # Full architecture spec
│   ├── IMPLEMENTATION.md   # This file
│   ├── GLOSSARY.md         # Terminology
│   ├── rfcs/               # Formal RFCs (0001–0011)
│   └── plans/              # Implementation plans
└── reference-reticulum/    # Python RNS reference (git submodule)
```

## Development Workflow

### Building

```bash
cargo build --workspace
cargo build --release
```

### Testing

```bash
# All tests
cargo test --workspace

# Specific crate
cargo test -p rsticulum-icn
cargo test -p rsticulum-transport

# Integration tests (require Python RNS)
cargo test --test interop_python_rns
cargo test --test integration_rns_interop

# With logging
RUST_LOG=debug cargo test -p rsticulum-daemon -- --nocapture
```

### Cross-Validation

The Python RNS reference implementation lives in `reference-reticulum/`. Tests
in `tests/interop_python_rns.rs` spawn Python `rnsd` instances and cross-validate
packet formats, key derivation, and encryption against `rsticulum` crates.

```bash
# Install Python RNS for cross-val
pip install rns

# Run cross-val tests
cargo test --test interop_python_rns
```

### Adding a Crate

1. Create `crates/<name>/Cargo.toml` and `src/lib.rs`
2. Add to workspace `[members]` in root `Cargo.toml`
3. Add to `[workspace.dependencies]` with path
4. Update `IMPLEMENTATION.md` crate map

## Key Implementation Decisions

### Why Rust

- Zero-cost abstractions — no GC pauses on embedded hardware
- Mature async ecosystem (tokio)
- Strong crypto libraries (ed25519-dalek, x25519-dalek, sha2, hkdf)
- WASM-first — `wasm32-unknown-unknown` target is first-class
- No unsafe by default — memory safety without runtime overhead

### Why No Separate Transport Layer

Reticulum *is* the transport layer. It handles packet framing, encryption, link
management, and routing. Adding a separate transport layer (e.g., QUIC or TCP
over Reticulum) would:
- Duplicate encryption (Reticulum already encrypts per-hop)
- Lose disruption tolerance (TCP RST on timeout)
- Add unnecessary overhead (double framing, double sequencing)

ICN runs directly over Reticulum Links via `LinkFace`. Applications run over
ICN or directly over Reticulum.

### Why AES-128-CBC (current implementation)

The current implementation uses AES-128-CBC for link encryption, matching the
Fernet specification's standard key split (16-byte HMAC key + 16-byte AES key).
Python RNS diverges from standard Fernet by using AES-256-CBC with a 48-byte
key split (32-byte HMAC + 16-byte AES). The Rust implementation will be upgraded
to AES-256-CBC for full Python RNS wire compatibility — see Known Gaps.

### Why scoped-down SCION, not full SCION

Full SCION carries IP inside. Our network doesn't have IP — identity *is* the
address. Adapting SCION means:
- Remove the IP forwarding substrate → replace with identity forwarding
- Remove X.509 PKI → replace with threshold trust
- Extend path lifetimes from minutes → 24 hours+
- Add bridge protocol for edge↔backbone handover

The result is SCION's source-routing architecture applied to an identity-based
network, not a wrapper around IP.
