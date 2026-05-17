# RFC 0002: Suspendable Links and Disruption Tolerance

- **Status:** Draft
- **Layer:** Transport
- **Depends on:** [RFC 0001: Identity-Based Addressing](0001-identity-based-addressing.md)

---

## Abstract

**Suspendable Links** add session persistence to rsticulum's core `Link` encryption engine. `Link` provides ECDH key exchange, AES-256-CBC Token encryption, proof handshake, Channel framing, and Buffer management. `SuspendableLink` wraps `Link`, adding session serialization. When enabled via `LinkConfig.suspend: true`, session keys, peer identity, and queued messages survive disconnection. On reconnect, the link resumes where it left off — no new cryptographic handshake, no application-level reconnect logic.

---

## 1. Motivation

TCP, QUIC, and WebSocket treat disconnection as terminal — all state destroyed, full re-handshake required. This forces every application to implement reconnect logic, destroys cryptographic continuity, and punishes the reality of meshes where nodes are "alive but unreachable right now." rsticulum's transport is built on identity, not location. A link to Alice's identity should survive her switching interfaces, going through a tunnel, or rebooting. Links are relationships between identities — they should persist through gaps.

## 2. Specification

### 2.1 State Machine

A Suspendable Link has four states: **Closed → Handshaking → Established → Suspended**. From Suspended, resume transitions back to Handshaking for identity re-verification. `close()` is valid from any state except Closed.

```
       ┌──────────┐                    ┌─────────────────┐
       │  CLOSED  │──establish()──────▶│   HANDSHAKING   │
       └────▲─────┘                    └────────┬────────┘
            │ close()                           │ complete_handshake()
            │                                   ▼
            │                          ┌─────────────────┐
            │                          │   ESTABLISHED   │
            │                          └──┬──────────┬───┘
            │                   suspend() │          │ handle_disconnect()
            │                             ▼          ▼
            │                    ┌──────────────────────┐
            │◀─────close()───────│      SUSPENDED       │
            │                    └──────────┬───────────┘
            │                               │
            │                    resume() + establish()
            │                               │
            └───────────────────────────────┘
```

| State | Meaning |
|-------|---------|
| `Closed` | Link not established or permanently closed. All state destroyed. |
| `Handshaking` | Proof exchange in progress — waiting for remote Ed25519 signature. |
| `Established` | Link active. Session keys derived. Data flows. |
| `Suspended` | Link inactive but cryptographic state and queued messages preserved (memory + optionally disk). |

Key decisions: `resume()` goes to `Handshaking` (not `Established`) — peer identity is re-verified via proof handshake, but the ECDH session key is **reused**, not regenerated. `handle_disconnect()` auto-transitions to `Suspended` on connectivity loss. `close()` from `Established` immediately destroys all state (legacy `suspend: false` behavior).

### 2.2 Handshake Protocol

```
Alice                                    Bob
  │──── PROOF(sig_A(TID_AB)) ───────────▶│
  │◀──── PROOF(sig_B(TID_BA)) ───────────│
  │    [Both derive session key via ECDH] │
  │──── DATA (encrypted) ───────────────▶│
```

1. **ECDH (X25519):** Each side provides an X25519 public key. Shared secret: `DH(local_secret, remote_public)`, fed into **HKDF-SHA256** to derive the 32-byte session key.

2. **Proof Handshake (Ed25519):** Each side signs the **transport ID** (16-byte XOR of both RNS addresses) plus `SHA-256(transport_id)`. Recipient verifies against the known Ed25519 identity key.

3. **Transport ID:** `TID = local_rns XOR remote_rns` — commutative, both parties compute the same value.

4. **Session ID:** `SID = SHA-256(local_rns || remote_rns)[0..16]` — stable identifier surviving interface changes and restarts.

### 2.3 Session Persistence

With `suspend: true` and `storage_path` configured, session state serializes to disk at `{storage_path}/session-{sid}.bin`: session ID, remote RNS address, Ed25519 identity key, X25519 public key, HKDF-derived session key, queued outbound messages, timestamp, and resume count.

On resume, the existing session key is reused (no new ECDH). The proof handshake re-verifies identity. Held messages replay automatically. Without `storage_path`, suspension is in-memory only (survives within process lifetime).

**Security:** Session files contain the key in plaintext — created with `0600` permissions, deleted on `close()`. For high-security deployments, use in-memory-only mode.

### 2.4 Configuration

`LinkConfig.suspend: true` enables persistence. `suspend: false` (default) gives legacy behavior — state destroyed on disconnect. With `storage_path: Some(path)`, sessions survive process restarts; session keys are re-derived from the same ECDH inputs. No RST on timeout — `handle_disconnect()` auto-suspends. `handshake_timeout_ms` (default 30s) is per-attempt, not a session lifetime limit. Links can remain suspended indefinitely.

## 3. Architecture

`SuspendableLink` wraps `Link` — session persistence is merged into `Link` via `LinkConfig.suspend`. The encryption engine (ECDH, AES-256-CBC Token, proof, Channel, Buffer) is unchanged. All internal APIs use `Link`; if suspended, `send()` returns `Ok(None)` (message held). Wire-compatible with Python Reticulum (RNS) — suspension is purely local.

## 4. Security Considerations

**Session key storage:** Serialized sessions contain plaintext keys. Mitigated by `0600` permissions, deletion on close, and in-memory-only option.

**Replay protection:** `replay_held()` re-transmits queued messages with sequence numbers; the remote inbound buffer discards duplicates. Held messages are drained on replay.

**Identity re-verification:** Proof handshake on resume confirms the remote peer holds the same Ed25519 key. Session key is not rotated — avoids full key exchange cost while preventing impersonation.

**Forward secrecy:** Not provided across suspensions by design. The session key survives disconnections, enabling disruption tolerance at the cost of weaker post-compromise security. Set `suspend: false` for full re-handshake on every connection.

**⚠ Known gap:** Python RNS uses AES-256-CBC via Token; rsticulum currently hardcodes AES-128-CBC. Unified AES-256-CBC required for interoperable session resumption.

## 5. References

- [RFC 0001: Identity-Based Addressing](0001-identity-based-addressing.md)
- [RNS Reference Implementation](https://github.com/markqvist/Reticulum)
- [ARCHITECTURE.md](../ARCHITECTURE.md) — Section 2.2 (Transport Layer)
