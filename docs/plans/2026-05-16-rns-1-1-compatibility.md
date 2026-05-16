# Full Reticulum 1:1 Wire Compatibility — Implementation Plan

> **For Hermes:** Use subagent-driven-development skill to implement tasks. Reference the Python RNS source at `/opt/homebrew/lib/python3.12/site-packages/RNS/` for exact protocol behavior.

**Goal:** Full wire-protocol interoperability between rsticulum (Rust) and Python RNS — daemons can discover each other, establish links, exchange data, and route through the mesh.

**Architecture:** Rework link establishment to match Python RNS's three-way handshake (LINKREQUEST → LRPROOF → RTT), implement Transport-layer path discovery, add keepalive/rekeying, and integrate all existing components (Channel, Buffer, Resource) into the correct protocol flow.

**Tech Stack:** Rust 2021, tokio async, rsticulum workspace (14 crates), Python RNS 1.2.6 as reference.

---

## Pre-Flight: Understand the Reference

Before starting ANY task, understand these key files in Python RNS:
- `Link.py` — Full link lifecycle: `__init__`, `handshake`, `prove`, `validate_proof`
- `Transport.py` — Path discovery, announce propagation, link request routing: `inbound`, lines ~1375-2200
- `Packet.py` — `LINKREQUEST` type (0x02), header packing/unpacking
- `Destination.py` — `announce()` format: 64-byte key + 10-byte name_hash + 10-byte random_hash + 0/32-byte ratchet + 64-byte signature
- `Identity.py` — Key format: X25519(32) || Ed25519(32), `hash` derivation, `prove`/`validate`

---

## Phase 1: Link Establishment Protocol

### Task 1.1: Add LINKREQUEST packet type support to daemon

**Objective:** Create the responder side — when a LINKREQUEST arrives, the daemon should create a Link, compute the shared key, and send an LRPROOF response.

**Files:**
- Modify: `crates/daemon/src/lib.rs` (handle_frame, new handle_linkrequest method)
- Modify: `crates/transport/src/link.rs` (add LINKREQUEST initiation)

**Details:**

Python RNS LINKREQUEST flow:
1. Initiator creates Link with `destination`. In `__init__`, it generates a fresh ephemeral X25519 keypair (`prv`/`pub`), builds `request_data = pub_bytes(32) + sig_pub_bytes(32) + signalling_bytes(6)`, and sends as a LINKREQUEST packet (type=0x02).
2. The link_id is derived as `truncated_hash(hashable_part_of_packet)` — this is the 16-byte identifier both sides will use.
3. Responder receives LINKREQUEST, creates a Link (initiator=False), computes ECDH shared key in `handshake()`, sends LRPROOF.

**Step 1: Add `LINKREQUEST` handling in `handle_frame`**

In `crates/daemon/src/lib.rs::handle_frame()`, add a match arm for `LINKREQUEST`:

```rust
LINKREQUEST => {
    self.handle_linkrequest(from, &packet).await?;
}
```

Add the handler method `handle_linkrequest()`:

```rust
async fn handle_linkrequest(
    &mut self,
    from: RnsAddress,
    packet: &Packet,
) -> Result<(), DaemonError> {
    // 1. Verify we know this peer (have their Ed25519 signing key)
    let remote_key = self.peer_keys.get(&from)
        .ok_or_else(|| DaemonError::Other("unknown peer".into()))?;
    
    // 2. Parse request_data: pub_bytes(32) + sig_pub_bytes(32) + signalling_bytes(6)
    let data = &packet.data;
    if data.len() < 70 {
        return Err(DaemonError::Other("invalid LINKREQUEST".into()));
    }
    let initiator_pub_bytes: [u8; 32] = data[..32].try_into().unwrap();
    let initiator_sig_pub_bytes: [u8; 32] = data[32..64].try_into().unwrap();
    let signalling = &data[64..70]; // 2 bytes MTU + 2 bytes flags + 2 bytes reserved
    
    // 3. Compute link_id = truncated_hash(hashable_part)
    // Python RNS: hashable_part = raw[2:] minus signalling bytes appended
    let link_id = compute_link_id_from_request(packet);
    
    // 4. Generate ephemeral X25519 keypair for this link
    let eph_priv = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let eph_pub = x25519_dalek::PublicKey::from(&eph_priv);
    
    // 5. Derive shared key via ECDH
    let peer_pub = x25519_dalek::PublicKey::from(initiator_pub_bytes);
    let shared_secret = eph_priv.diffie_hellman(&peer_pub);
    
    // 6. HKDF derive encryption keys from shared_secret
    let derived_key = hkdf_sha256(
        shared_secret.as_bytes(),
        &link_id,  // salt
        b"rsticulum-link",  // context
    );
    
    // 7. Build LRPROOF response
    // signed_data = link_id + pub_bytes + sig_pub_bytes + signalling_bytes
    let mut signed_data = link_id.to_vec();
    signed_data.extend_from_slice(&eph_pub.to_bytes());
    signed_data.extend_from_slice(&self.keys.identity_key_bytes()); // our Ed25519
    signed_data.extend_from_slice(signalling);
    
    let sig = self.keys.sign(&signed_data);
    let sig_bytes = sig.to_bytes();
    
    // proof_data = signature(64) + pub_bytes(32) + signalling_bytes(6)
    let mut proof_data = sig_bytes.to_vec();
    proof_data.extend_from_slice(&eph_pub.to_bytes());
    proof_data.extend_from_slice(signalling);
    
    // Send as PROOF packet with LRPROOF context
    let response = Packet {
        header_type: HEADER_1, // or HEADER_2? Python uses HEADER_1 for LINKREQUEST, HEADER_2 for transport
        context_flag: FLAG_SET,
        transport_type: TRANSPORT_UNICAST,
        destination_type: DEST_LINK,
        packet_type: PROOF,
        hops: MAX_HOPS,
        destination_hash: *from.as_bytes(),
        transport_id: None,
        context: LRPROOF,
        data: proof_data,
    };
    self.send_to(from, &response.to_bytes()).await?;
    
    // 8. Store pending link state
    // Store the link_id, peer's keys, and derived key for later use
    // ... (detailed in subtask)
    
    Ok(())
}
```

**Step 2: Implement `compute_link_id_from_request`**

```rust
fn compute_link_id_from_request(packet: &Packet) -> [u8; 16] {
    // Python RNS: hashable_part = raw[2:] minus appended signalling bytes
    // Then link_id = truncated_hash(hashable_part)
    let raw = packet.to_bytes();
    let hashable = &raw[2..]; // skip flags + hops
    
    // If there's signalling data appended, the hashable part's length
    // is raw_len - 2 - signalling_len. But if signalling is embedded in
    // the data, it's raw_len - 2 - signalling_len.
    // Python: diff = len(data) - ECPUBSIZE; hashable_part = hashable_part[:-diff]
    const ECPUBSIZE: usize = 32 + 32; // pub_bytes + sig_pub_bytes
    let diff = packet.data.len().saturating_sub(ECPUBSIZE);
    let truncated = &hashable[..hashable.len().saturating_sub(diff)];
    
    let hash = Sha256::digest(truncated);
    let mut id = [0u8; 16];
    id.copy_from_slice(&hash[..16]);
    id
}
```

**Step 3: Update Link struct to support the full lifecycle**

Add fields to `Link`:
- `link_id: [u8; 16]` — the identifier derived from the LINKREQUEST packet
- `shared_key: Option<[u8; 32]>` — derived from ECDH
- `mode: LinkMode` — AES-128-CBC or AES-256-CBC
- `initiator: bool` — whether this side initiated the link
- `ephemeral_priv: Option<StaticSecret>` — our ephemeral X25519 key
- `peer_pub_bytes: Option<[u8; 32]>` — peer's X25519 public key
- `peer_sig_pub_bytes: Option<[u8; 32]>` — peer's Ed25519 public key

Add methods:
- `Link::initiate(destination, our_keys)` — builds LINKREQUEST packet
- `Link::respond(packet, our_keys)` — creates Link from incoming LINKREQUEST
- `Link::handshake()` — ECDH + HKDF derivation
- `Link::prove()` — builds LRPROOF packet (responder)
- `Link::validate_proof(packet)` — verifies LRPROOF, transitions to ACTIVE (initiator)

**Verification:**
- `cargo test -p rsticulum-transport --lib`
- `cargo test -p rsticulum-daemon --lib`

**Commit:**
```bash
git add -A && git commit -m "feat: add LINKREQUEST packet handling and ECDH key exchange"
```

---

### Task 1.2: Implement initiator-side link establishment

**Objective:** When `Daemon::connect()` is called, send a LINKREQUEST (not a PROOF). Handle the LRPROOF response: validate, derive shared key, transition to ACTIVE.

**Files:**
- Modify: `crates/daemon/src/lib.rs` (connect method, LRPROOF handler in handle_proof)
- Modify: `crates/transport/src/link.rs` (initiate method)

**Details:**

Replace the current `Daemon::connect()` which sends a PROOF with one that sends a LINKREQUEST:

```rust
pub async fn connect(&mut self, remote: RnsAddress) -> Result<(), DaemonError> {
    // 1. Generate ephemeral X25519 keypair
    let eph_priv = StaticSecret::random_from_rng(OsRng);
    let eph_pub = PublicKey::from(&eph_priv);
    
    // 2. Build signing keypair for this link
    let sig_priv = SigningKey::generate(&mut OsRng);
    let sig_pub = sig_priv.verifying_key();
    
    // 3. Build request_data: pub_bytes(32) + sig_pub_bytes(32) + signalling(6)
    let mut request_data = eph_pub.to_bytes().to_vec();
    request_data.extend_from_slice(&sig_pub.to_bytes());
    // signalling: 2-byte MTU, 2-byte flags, 2-byte reserved (all 0 for now)
    request_data.extend_from_slice(&[0u8; 6]);
    
    // 4. Send as LINKREQUEST
    let packet = Packet {
        header_type: HEADER_1,
        context_flag: FLAG_UNSET,
        transport_type: TRANSPORT_UNICAST,
        destination_type: DEST_SINGLE,
        packet_type: LINKREQUEST,
        hops: MAX_HOPS,
        destination_hash: *remote.as_bytes(),
        transport_id: None,
        context: NONE,
        data: request_data,
    };
    
    // 5. Compute link_id
    let link_id = compute_link_id_from_request(&packet);
    
    // 6. Store pending link state (link_id, eph_priv, sig_priv, sig_pub, remote, packet)
    self.pending_links.insert(link_id, PendingLink {
        link_id,
        eph_priv,
        sig_priv,
        sig_pub,
        remote,
        sent_packet: packet.clone(),
        sent_at: Instant::now(),
    });
    
    self.send_to(remote, &packet.to_bytes()).await?;
    Ok(())
}
```

**Update LRPROOF handler** in `handle_proof`:

When we receive a PROOF with LRPROOF context (as initiator), we need to:
1. Look up the pending link by the responder's address
2. Parse proof_data: signature(64) + pub_bytes(32) + signalling(6)
3. Derive shared key: ECDH(our_eph_priv, peer_pub)
4. Verify signature: Ed25519.verify(signed_data, signature)
   where signed_data = link_id + peer_pub_bytes + peer_ed25519_pub + signalling
5. Compute derived encryption key via HKDF
6. If valid, transition to ACTIVE, store established channel
7. Send RTT packet (optional — for full compatibility)

**Verification:**
- `cargo test --test inprocess_daemon_link`
- `cargo test -p rsticulum-daemon --lib`

**Commit:**
```bash
git add -A && git commit -m "feat: implement initiator-side link establishment with LINKREQUEST"
```

---

### Task 1.3: Port Link encryption to use derived shared key

**Objective:** Replace the current per-packet encryption (Keys::encrypt_for/decrypt_from) with the Python RNS Link encryption scheme using the ECDH-derived key + HKDF.

**Files:**
- Modify: `crates/transport/src/link.rs`
- Modify: `crates/transport/src/packet_transport.rs` (if used)
- Modify: `crates/identity/src/crypto.rs` (add link encryption modes)

**Details:**

Python RNS Link encryption:
- Mode AES-128-CBC: HKDF derives 32 bytes (16 key + 16 IV)
- Mode AES-256-CBC: HKDF derives 64 bytes (32 key + 16 IV + 16 HMAC)
- HKDF parameters:
  - salt = link_id
  - context = b"ReticulumLinkKey"
  - length = 32 or 64 depending on mode
- Packet encryption uses AES-CBC with PKCS7 padding, then HMAC-SHA256

Implement this in `link.rs`:
- `fn encrypt(&self, plaintext: &[u8]) -> Vec<u8>` — encrypts using derived key
- `fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>` — decrypts using derived key
- Update `send()` and `deliver()` to use this encryption

**Verification:**
- Interop test: Rust packet encrypt → Python decrypt and vice versa
- `cargo test -p rsticulum-transport --lib`

**Commit:**
```bash
git add -A && git commit -m "feat: add ECDH-derived link encryption matching Python RNS"
```

---

## Phase 2: Transport Layer / Path Discovery

### Task 2.1: Port announce propagation (path discovery)

**Objective:** When a daemon receives an announce, it should propagate it to other connected peers (not just consume it). When a daemon wants to reach a destination it doesn't know about, it should send a path request.

**Files:**
- Create: `crates/daemon/src/transport.rs`
- Modify: `crates/daemon/src/lib.rs`

**Details:**

Python RNS Transport:
- `Transport.announce_emitted(packet)` — when we emit an announce, register it
- `Transport.inbound(raw, interface)` — when receiving any packet, check if it needs forwarding
- Path requests: if a packet is for an unknown destination, send PATH_REQUEST
- Path responses: if we know the destination, send the announce back as PATH_RESPONSE
- Announces have TTL: each forward decrements hops, at 0 it stops

Key data structures:
```rust
pub struct TransportTable {
    /// Known routes: dest_hash → (next_hop, quality, hops, expires_at)
    routes: HashMap<[u8; 16], RouteEntry>,
    /// Pending path requests: dest_hash → (requestor, sent_at)
    pending_requests: HashMap<[u8; 16], PathRequestEntry>,
}
```

When a PATH_REQUEST arrives:
1. Check if we know the destination
2. If yes, send the cached announce as PATH_RESPONSE
3. If no and we haven't sent one recently, forward to all peers

When an ANNOUNCE arrives (not PATH_RESPONSE):
1. Update routing table with the sender as next_hop
2. If hop count > 0, decrement and forward to all OTHER peers
3. Cache the announce data for path response purposes

**Verification:**
- Two daemons: A → B → C. A announces, B receives and forwards to C. C sees A.
- `cargo test -p rsticulum-daemon --lib`

**Commit:**
```bash
git add -A && git commit -m "feat: add Transport-layer announce propagation and path discovery"
```

---

### Task 2.2: Add path request/response protocol

**Objective:** When a daemon sends a packet to an unknown destination, it should trigger path discovery rather than silently dropping.

**Files:**
- Modify: `crates/daemon/src/transport.rs`
- Modify: `crates/daemon/src/lib.rs`

**Details:**

When `send_to()` is called and destination is not in `peer_addrs` (the direct peer table):
1. Check Transport routing table for a known route
2. If route found, forward to next_hop
3. If no route, send PATH_REQUEST packet
4. PATH_REQUEST includes destination hash
5. Any peer that knows the route responds with PATH_RESPONSE
6. The PATH_RESPONSE is the cached announce data for that destination
7. Cache the route with quality and TTL

**Verification:**
- Three daemons in a chain: A links to B, B links to C. A sends to C → path discovery finds the route via B.
- `cargo test -p rsticulum-daemon --lib`

**Commit:**
```bash
git add -A && git commit -m "feat: add path request/response protocol for multi-hop routing"
```

---

## Phase 3: Link keepalive, RTT, and rekeying

### Task 3.1: Add keepalive packets

**Objective:** Send periodic KEEPALIVE packets on established links to detect dead peers and maintain route freshness.

**Files:**
- Modify: `crates/transport/src/link.rs`
- Modify: `crates/daemon/src/lib.rs`

**Details:**
- Send KEEPALIVE context packet every KEEPALIVE seconds (default 30)
- If no traffic received for TRAFFIC_TIMEOUT seconds (default 300), send a probe
- If no response for STALE_TIME seconds (default 600), close the link

**Commit:**
```bash
git add -A && git commit -m "feat: add keepalive packets for link health monitoring"
```

### Task 3.2: Add RTT measurement

**Objective:** Measure round-trip time on link establishment and send periodic RTT probes.

**Files:**
- Modify: `crates/transport/src/link.rs`

**Details:**
- On link activation, compute RTT = time since LINKREQUEST was sent
- Send RTT data in LRRTT context packet after establishment
- Track RTT, establishment cost, and establishment rate per link (Python fields)

**Commit:**
```bash
git add -A && git commit -m "feat: add RTT measurement on link establishment"
```

### Task 3.3: Add ratchet key rotation

**Objective:** Implement forward-secrecy via periodic ratchet key rotation on links.

**Files:**
- Modify: `crates/transport/src/link.rs`
- Modify: `crates/daemon/src/lib.rs`

**Details:**
- After link establishment, generate a new X25519 keypair as a "ratchet"
- Send ratchet hash in the next announce for this identity
- Apply ratchet to subsequent packet encryption using HKDF re-keying

**Commit:**
```bash
git add -A && git commit -m "feat: add ratchet key rotation for forward secrecy"
```

---

## Phase 4: Resource Transfer (full compatibility)

### Task 4.1: Add ResourceAdvertisement protocol

**Objective:** Before sending a Resource, advertise it with a ResourceAdvertisement packet so the receiver can prepare to receive.

**Files:**
- Modify: `crates/transport/src/resource.rs`

**Details:**
- Python RNS Resource advertisement: hash, size, segment count, compression info
- Sender sends RESOURCE_ADV context packet before segments
- Receiver responds with RESOURCE_REQ to acknowledge
- Then segments flow

**Commit:**
```bash
git add -A && git commit -m "feat: add ResourceAdvertisement protocol matching Python RNS"
```

---

## Phase 5: Identity lifecycle

### Task 5.1: Persistent identity keys with file storage

**Objective:** Store identity keys in the RNS format (64-byte hex file) and load on startup. The current implementation already does this in `main.rs::load_or_generate_keys` — verify it matches Python's format.

**Files:**
- Review: `crates/daemon/src/main.rs` (load_or_generate_keys)
- Verify format matches Python RNS: `Identity.to_hex()` generates 128 hex chars (64 bytes)

### Task 5.2: Add ratchet persistence

**Objective:** Store and load ratchet keys from disk, matching Python's `Identity.known_ratchets` persistence.

**Files:**
- Create: `crates/identity/src/ratchet_store.rs`

---

## Phase 6: Integration Testing

### Task 6.1: Fix Python interop test infrastructure

**Objective:** Make `tests/node_runner.py` and `tests/python_rns_validator.py` work reliably with unique ports/configdirs per test to avoid flakiness.

**Files:**
- Modify: `tests/python_rns_validator.py`
- Modify: `tests/rns_test_suite/lib/node_runner.py`

**Details:**
- Use `configdir=tempfile.mkdtemp()` to avoid port contention
- Configure RNS to use loopback UDP on unique ports per test
- Add startup readiness signal (JSON line to stdout) so Rust tests know when Python is ready

**Commit:**
```bash
git add -A && git commit -m "fix: make Python interop tests reliable with per-test configdirs"
```

### Task 6.2: End-to-end cross-validation suite

**Objective:** Test each phase with a Python RNS node:
1. LINKREQUEST from Rust → Python parses correctly
2. LINKREQUEST from Python → Rust parses correctly
3. LRPROOF exchange → link established
4. Encrypted data exchange over link
5. Resource transfer
6. Multi-hop routing (3+ nodes)
7. Keepalive timeout / link re-establishment

**Files:**
- Create: `tests/e2e_full_interop.rs`
- Create: `tests/e2e_full_interop.py`

---

## Dependencies Between Phases

```
Phase 1 (Link Protocol) ──┬──> Phase 3 (Keepalive/RTT)
                          │
                          └──> Phase 4 (Resource)
                           
Phase 2 (Transport) ────────> All subsequent (routing needed for multi-hop)

Phase 5 (Identity) ────────> Standalone, can be done anytime

Phase 6 (Testing) ─────────> Depends on Phases 1-5 being complete
```

**Parallelizable:** Phase 5 can be done at any time. Tasks within Phase 1 are sequential (1.1 → 1.2 → 1.3). Phase 2 is independent of Phase 1's details (it works at the announce/packet level).

---

## What Won't Change

These are already correct and don't need modification:
- Packet binary format (HEADER_1/HEADER_2) — verified byte-for-byte
- Address derivation (now SHA-256(64-byte key)[:16])
- HKDF, Fernet token encryption
- Channel (reliable in-order delivery)
- Buffer (streaming I/O)
- KISS/HDLC framing for serial links
- Local API socket

---

## Verification Strategy

After each phase:
```bash
cargo build --workspace
cargo test --lib --workspace  # exclude known HKDF fail
cargo test --test inprocess_daemon_link  # basic link test
cargo test --test integration_two_node_stack  # two-node operations
```

After Phase 1:
```bash
# Full cross-validation with Python RNS
cargo test --test e2e_full_interop  # Python ↔ Rust link + data
```

After Phase 6:
```bash
# Full feature test across all layers
cargo test --workspace
```
