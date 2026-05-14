# rsticulum

Rust implementation of the [Reticulum](https://reticulum.network) networking stack — a
cryptographic mesh protocol for building resilient networks over any physical medium.

## Crates

| Crate | Status | Description |
|-------|--------|-------------|
| `rsticulum-crypto` | 🟢 | HKDF-SHA256 key derivation, RNS Token (simplified Fernet) |
| `rsticulum-identity` | 🟢 | Ed25519/X25519 keys, 16-byte RNS-compatible addresses |
| `rsticulum-packet` | 🟢 | RNS wire-compatible packet format |
| `rsticulum-destination` | 🟢 | RNS Destination abstraction |
| `rsticulum-transport` | 🟢 | Link, Packet, Resource, proof handshake |
| `rsticulum-interface` | 🟢 | KISS, HDLC, serial, TCP interfaces |
| `rsticulum-mesh` | 🟢 | Hybrid routing: link-state + path discovery |
| `rsticulum-backbone` | stub | SCION-inspired backbone |
| `rsticulum-bridge` | stub | SCION edge bridge |
| `rsticulum-icn` | stub | ICN application layer |
| `rsticulum-daemon` | stub | Network daemon |
| `rsticulum-sdk` | stub | SDK |

## Tests

```
199 passed, 1 failed (known HKDF RFC vector mismatch, Python interop correct)
```

Integration tests cross-validate against Python RNS for HKDF, token encryption,
announce flags, and packet types.
