# Full Reticulum 1:1 Wire Compatibility — Implementation Plan

**Status: Phase 1-5 code written, Phase 6 (e2e testing) in progress.**

**Goal:** Full wire-protocol interoperability between rsticulum (Rust) and Python RNS — daemons discover each other, establish links, exchange encrypted data, route through the mesh, and serve applications.

**Architecture:** rsticulum workspace (14 crates) under `crates/`. All protocol layers exist. The remaining work is integration testing, bugfixing edge cases, and aligning the code to match Python RNS 1.2.6 reference behavior.

---

## What's Done ✅

All phases from the original plan have been implemented and committed on `main`:

| Phase | Component | Status |
|---|---|---|
| 1.1 | LINKREQUEST packet handling + responder side | ✅ committed (`bca11cc`) |
| 1.2 | Initiator-side link establishment (connect → LRPROOF) | ✅ committed (`7da3a5f`, `bca11cc`) |
| 1.3 | ECDH-derived link encryption (AES-128-CBC + HMAC) | ✅ committed |
| 2.1 | Announce propagation (Transport table, route forwarding) | ✅ committed (`72626cf`) |
| 2.2 | PATH_REQUEST / PATH_RESPONSE protocol | ✅ committed |
| 3.1 | Keepalive packets (30s interval, 600s stale timeout) | ✅ committed (`b76f954`) |
| 3.2 | RTT measurement on link establishment | ✅ committed (`b654570`) |
| 3.3 | Ratchet key rotation for forward secrecy | ✅ committed (`8f1a8dc`) |
| 4.1 | ResourceAdvertisement protocol | ✅ committed (`08dc6a3`) |
| 5.1 | Persistent identity keys (64-byte hex file) | ✅ exists (`main.rs`) |
| 5.2 | Ratchet persistence store | ✅ committed (`6f3c706`) |
| 6.1 | Python interop test infrastructure | ✅ committed (`b08d42c`) |
| — | Wire-format fixes (signalling 6→3 bytes, LRPROOF dest_hash=link_id, link_id computation) | ✅ committed (`bca11cc`) |
| — | Loopback handling (announce self-filtering in UDP tests) | ✅ committed (`7da3a5f`) |

**Test results:**
- `cargo test --test inprocess_daemon_link` — ✅ passes (0.24s)
- `cargo test --lib --workspace` — ✅ 11 pass, 1 known HKDF failure tolerated
- `cargo test --test e2e_full_interop` — ❌ fails ("daemon stderr closed")

---

## What's Broken ❌

### B1. e2e_full_interop test

**Root cause (confirmed):** Test spawns rsticulumd with `RUST_LOG=error` (line 90 of `e2e_full_interop.rs`). But `main.rs` logs the identity at `tracing::info!` level:
```rust
tracing::info!("Identity: {}", keys.rns_address());
```
With `RUST_LOG=error`, info-level messages are suppressed. The test's `read_daemon_identity()` hangs reading stderr, never sees `Identity:`, and eventually sees EOF.

**Fix:** Change `RUST_LOG` to `info` (or `debug`, matching EnvFilter::new("debug") in main.rs):
```rust
.env("RUST_LOG", "info")
```

### B2. HKDF test failure

`test_rfc5869_test_case_2` in `crates/crypto/src/hkdf.rs` produces wrong output (first diff at byte 0). The implementation doesn't match RFC 5869 test vector 2. This is a bug in the HKDF implementation — it needs to be fixed, not tolerated.

**Priority:** Low (only affects HKDF tests, not the protocol, since the actual protocol uses ECDH+HKDF via a different code path that happens to produce correct results).

---

## What Needs Building Next

Mapped from the [vision branch](https://github.com/…/new_internet/tree/vision) roadmap. In priority order:

### P1. Pass the e2e interop test

**Task:** Fix the `RUST_LOG` env var in `e2e_full_interop.rs`, run the test, iterate on any further failures.

**Files:** `tests/e2e_full_interop.rs`

**Risk:** Low — single env var fix. May uncover more subtle protocol mismatches.

### P2. Multi-hop routing test (3+ daemons)

**Task:** After e2e test passes with a 2-node setup, add a 3-node chain test: A ↔ B ↔ C. A announces, B forwards to C. Verify C discovers A's route.

**Files:** `tests/integration_daemon_to_daemon.rs` (existing, likely times out)

**Risk:** Medium — transport table propagation may have bugs that only appear with 3+ nodes.

### P3. Resource transfer test (cross-impl)

**Task:** Send a multi-segment Resource over a Rust↔Python link. Verify advertisement, segment flow, and reassembly match Python RNS.

**Files:** `tests/e2e_full_interop.rs` (extend), `tests/python_rns_helper.py`

### P4. Fix HKDF implementation

**Task:** Fix `crates/crypto/src/hkdf.rs` `test_rfc5869_test_case_2`. The implementation doesn't match RFC 5869 test vector 2 — likely a bug in the extract-then-expand loop or salt handling.

**Files:** `crates/crypto/src/hkdf.rs`

---

## Phase 2+ Roadmap (from vision branch)

See `ADAPTATIONS.md` on the `vision` branch for full rationale. These are the protocol evolutions that come *after* 1:1 wire compatibility:

### E1. SuspendableLink as the default link type

**What:** All links are disruption-tolerant by default. Remove non-suspendable `Link` entirely, rename `SuspendableLink` → `Link`.

**Why:** The vision says "no TCP — connections must survive hours/days of disconnection." Making suspendable the default means every application automatically gets disruption tolerance.

**Files:** `crates/transport/src/link.rs`, `crates/transport/src/suspendable_link.rs`

### E2. Hierarchical announce forwarding

**What:** Edge nodes announce only to their bridge. Bridge aggregates and summarizes to the backbone. Replaces O(n²) announce flooding.

**Files:** New `crates/bridge/` crate, modify `crates/daemon/src/transport.rs`

### E3. Proof-of-work anti-spam on announces

**What:** Every announce embeds a 20-bit PoW nonce. Bridge verifies before accepting. Difficulty adjusts based on congestion.

**Files:** `crates/identity/src/identity_announce.rs`

### E4. Key delegation (sub-identity signing)

**What:** Primary identity issues signed delegation statement authorizing a sub-key. Max depth 3. Enables multi-device identity and key rotation.

**Files:** New `crates/identity-lifecycle/` crate

### E5. Identity lifecycle protocol

**What:** Key publication, rotation, revocation — a gossip protocol between peers. Sits between Identity and Transport.

**Files:** New `crates/identity-lifecycle/` crate

---

## Remaining Plan Structure

```
Phase/Roadmap          Status       Dependencies
─────────────────────────────────────────────────
P1. Fix e2e test      RIGHT NOW    —
P2. Multi-hop test    Next         P1
P3. Resource xfer     Next         P1
P4. HKDF fix          Anytime      —
E1. SuspendableLink   Post-1.0     Full wire compat
E2. Hier. announce    Post-E1      Bridge crate
E3. PoW anti-spam     Post-1.0     — 
E4. Key delegation    Post-1.0     E5 infra
E5. Identity cycle    Post-1.0     —
```

## Verification Commands

```bash
# Quick feedback loop
cargo build --workspace
cargo test --test inprocess_daemon_link -- --nocapture
cargo test --lib --workspace

# E2E Rust↔Python (requires python3 + rns installed)
cargo test --test e2e_full_interop -- --nocapture

# Full suite (may take >5min)
cargo test --workspace
```
