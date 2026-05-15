# RNS Full Wire Compatibility Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement this plan task-by-task.

**Goal:** Achieve full wire-protocol interoperability with Python RNS — daemon can form Links, exchange data, announce/discover peers, and serve applications over a local API.

**Architecture:** Build missing protocol layers (Channel, Buffer) as new crates. Wire existing Link into the daemon's event loop. Add announce/discovery. Add local API socket. Cross-validate against Python RNS.

**Tech Stack:** Rust 2021, tokio async, rsticulum workspace (12 crates), Python 3.12 cross-val

---

## Pre-Flight Checklist

Before starting ANY task, understand:
- Transport crate has Link (proof handshake, send/recv over HEADER_2), Resource (fragment assembly), PacketTransport
- There's a critical bug in Link::complete_handshake — verifies proof against **local** keys instead of remote
- Daemon currently skips Link entirely — tries raw ICN parsing on incoming frames
- Cross-val tests exist at `tests/interop_python_rns.rs` (spawns Python validator)
- Python RNS available at `tests/python_rns_validator.py`

---

## Task 1: Fix Link::complete_handshake for real interop

**Objective:** Fix Link to verify proofs against the REMOTE peer's public key, not its own.

**Files:**
- Modify: `crates/transport/src/link.rs`

**Details:**
- `complete_handshake()` currently calls `verify_proof(self.local.keys(), ...)` — WRONG
- Must verify against `remote_public_signing_key` (new field `Option<[u8; 32]>`)
- `handle_incoming_proof()` already accepts `remote_keys: &Keys` — correct pattern, but `complete_handshake` needs the same
- Add `set_remote_signing_key(&mut self, key: [u8; 32])` method
- Update tests to use two different keys and verify cross-proof

**Verification:**
```bash
cargo test -p rsticulum-transport
```

---

## Task 2: Create rsticulum-channel crate

**Objective:** Port Python RNS `Channel.py` — reliable in-order message delivery over Links.

**Files:**
- Create: `crates/channel/Cargo.toml`
- Create: `crates/channel/src/lib.rs`
- Create: `crates/channel/src/message.rs`

**Details:**
- `MessageBase` trait — pack/unpack for channel messages
- `SystemMessageType` enum (SMT_STREAM_DATA = 0xFF00, etc.)
- `Channel` struct: wraps Link, provides `send(msg)`, `recv()`, MDU calculation
- Channel envelope: 2-byte message type + 4-byte sequence number + payload
- Sequence number tracking for in-order delivery
- Register handler for incoming system message types
- Add to workspace `Cargo.toml` members and deps

**Dependencies:** rsticulum-transport, rsticulum-identity, tokio, thiserror

**Verification:**
```bash
cargo test -p rsticulum-channel
```

---

## Task 3: Create rsticulum-buffer crate

**Objective:** Port Python RNS `Buffer.py` — streaming I/O over Channels.

**Files:**
- Create: `crates/buffer/Cargo.toml`
- Create: `crates/buffer/src/lib.rs`

**Details:**
- `StreamDataMessage` — encodes binary data with stream_id, eof flag, compression hint
  - Header: 2 bytes (14-bit stream_id, eof bit, compressed bit)
  - Max stream_id: 16383
- `RawChannelReader` — async reader that buffers incoming stream data
  - Registers handler on Channel for SMT_STREAM_DATA
  - Ready callbacks for push notification
  - `read(buf)` pulls from internal buffer
- `RawChannelWriter` — async writer that chunks data into StreamDataMessages
  - MAX_CHUNK_LEN = 16KB
  - Sends EOF on close
- `Buffer` factory: `create_reader()`, `create_writer()`, `create_bidirectional()`
- Add to workspace `Cargo.toml` members and deps

**Dependencies:** rsticulum-channel, tokio, thiserror

**Verification:**
```bash
cargo test -p rsticulum-buffer
```

---

## Task 4: Daemon Link integration

**Objective:** Wire Link into the daemon so it can establish encrypted links with other RNS nodes and route traffic through them.

**Files:**
- Modify: `crates/daemon/src/lib.rs`

**Details:**
- Add `links: HashMap<RnsAddress, Link>` to `Daemon` struct
- In `handle_frame()`:
  1. Parse incoming frame as raw packet (Packet::from_bytes)
  2. If HEADER_2 with transport_id, dispatch to matching Link via `link.deliver()`
  3. If PROOF packet, handle link establishment: `link.handle_incoming_proof()` or `link.complete_handshake()`
  4. If DATA packet on established link, decrypt and buffer for recv
  5. Fall through to ICN parsing only if no Link matches
- Add `send_link()` method for initiating links to new peers
- Track Link lifecycle: pending → handshaking → established → closed

**Verification:**
```bash
cargo test -p rsticulum-daemon
```

---

## Task 5: Announce and Discovery

**Objective:** Port Python RNS `Discovery.py` — interface and identity announcement propagation.

**Files:**
- Modify: `crates/daemon/src/lib.rs` (announce logic)
- Create: `crates/daemon/src/discovery.rs`

**Details:**
- `Announcer` — periodic job that generates IdentityAnnounce packets
  - Uses existing `rsticulum_identity::IdentityAnnounce`
  - Announces reachable addresses on each interface
  - Respects announce interval and bandwidth cap
- `AnnounceHandler` — processes incoming announces
  - Validates announce signature
  - Updates mesh routing table with discovered paths
  - Triggers Link establishment on demand
- Config options: `enable_transport`, `announce_interval`
- **Skip LXMF stamps** for now — simple announces without PoW (RNS accepts unstamped announces for basic discovery)

**Verification:**
```bash
cargo test -p rsticulum-daemon
```

---

## Task 6: Local API socket

**Objective:** TCP socket that applications connect to for express/publish/register.

**Files:**
- Create: `crates/daemon/src/api.rs`
- Modify: `crates/daemon/src/lib.rs`
- Modify: `crates/daemon/src/config.rs`

**Details:**
- TCP listener on configurable host:port (default 127.0.0.1:37428)
- Simple JSON-line protocol:
  - `{"cmd": "express", "dest": "<hash>", "data": "<hex>"}` → sends packet to destination
  - `{"cmd": "publish", "name": "<name>", "data": "<hex>"}` → publishes to ICN forwarder  
  - `{"cmd": "register", "name": "<name>"}` → registers interest, returns data when available
  - `{"cmd": "status"}` → returns daemon state
- Responses: `{"ok": true, "result": ...}` or `{"ok": false, "error": "..."}`
- One connection per client, concurrent via tokio::spawn
- Add `local_api` field to Daemon with `Option<tokio::net::TcpListener>`
- `run()` spawns API listener alongside event loop

**Verification:**
```bash
cargo test -p rsticulum-daemon
```

---

## Task 7: Python RNS integration test

**Objective:** End-to-end cross-validation: two rsticulum daemons ↔ Python RNS.

**Files:**
- Create: `tests/integration_rns_interop.rs`
- Modify: `tests/python_rns_validator.py` (add link establishment test commands)

**Details:**
- **Test 1: Link establishment** — rsticulum daemon initiates link to Python rnsd, verifies handshake completes
- **Test 2: Data exchange** — Send data over established link in both directions
- **Test 3: Announce discovery** — Python node announces, rsticulum daemon discovers and adds route
- **Test 4: Resource transfer** — Send a multi-segment resource over the link
- Each test spawns Python RNS instances and rsticulum daemon in subprocess
- Use loopback UDP interfaces (different ports) for local testing
- Helper: `spawn_python_rnsd(port)` and `spawn_rsticulumd(port)`

**Verification:**
```bash
cargo test --test integration_rns_interop
```

---

## Dependencies Between Tasks

```
Task 1 (Link fix) ──┬──> Task 4 (Daemon Link) ──┬──> Task 7 (Integration test)
                    │                            │
Task 2 (Channel) ───┼──> Task 3 (Buffer) ────────┤
                    │                            │
                    └──> Task 5 (Discovery) ─────┤
                                                 │
                              Task 6 (Local API) ─┘
```

**Parallelizable:** Tasks 1, 2, 5 can start simultaneously. Task 3 depends on 2. Task 4 depends on 1. Task 6 is independent. Task 7 needs all.

---

## Verification Strategy

After all tasks:
```bash
# Full workspace test
cargo test --workspace

# RNS interop test
cargo test --test integration_rns_interop

# Check all crates compile
cargo build --workspace
```

Target: **0 new failures**, all existing tests pass (1 known HKDF fail tolerated).

---

## Next: Reticulum Protocol Evolution

After wire-compatibility is proven, the next phase evolves Reticulum's protocol:

- **SuspendableLink as default** — Make disruption-tolerance the only link type
- **Hierarchical announce forwarding** — Replace O(n²) announce flooding with bridge-aggregated summaries
- **Proof-of-work on announces** — Anti-spam before the network is large enough to attract attackers
- **Key delegation** — Multi-device identity and key rotation
- **Identity lifecycle** — Publication, rotation, revocation protocol

These changes are designed to be backward-compatible where possible, and the Python RNS reference implementation will be brought along when feasible. The full Reticulum protocol evolution is documented in [`ADAPTATIONS.md`](../ADAPTATIONS.md).
