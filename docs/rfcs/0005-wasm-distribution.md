# 0005: WASM Distribution

- **Status:** Design (Overlay)
- **Layer:** Content
- **Depends on:** [RFC 0004: Manifest System](0004-manifest-system.md)

---

## What It Is

WASM Distribution is a **content type**, not a runtime. It defines how WebAssembly
blobs are published, addressed, and fetched over the content overlay — and
nothing more. A WASM bundle appears in a manifest entry like any other piece
of content:

```json
{
  "my-app": {
    "type": "wasm",
    "hash": "<blake3-hex>",
    "size": 49152
  }
}
```

The network treats this entry the same as `text/plain`, `image/png`, or any
other type: it verifies the hash, caches the blob at content routers, and
delivers it to consumers who express interest. The network does not inspect,
interpret, or execute WASM. It just ships the bytes.

## How It Works

1. **Publish.** A producer compiles their application to a `.wasm` binary,
   hashes it with BLAKE3, and adds an entry to their manifest under a semantic
   name (`my-app`, `weather-sensor-firmware`, etc.).

2. **Discover.** Consumers resolve the producer's latest manifest via the
   standard `/<producer>/_manifest` interest (RFC 0004). The manifest tells
   them the current hash and size of every entry, including WASM blobs.

3. **Fetch.** The consumer issues a content interest for the blob's hash.
   Content routers serve it from their cache or forward the interest toward
   the producer. Same pipeline as any immutable content object.

4. **Cache.** Intermediate content routers cache the WASM blob by hash.
   Subsequent consumers in the same neighbourhood get it from local cache
   with zero additional producer load.

5. **Run (not our problem).** The consumer's local environment — browser,
   `wasmtime`, a microcontroller runtime, whatever — executes the blob.
   The network's job ends at delivery.

## What It Is NOT

- **NOT a runtime.** The daemon has no WASM interpreter, no sandbox, no
  syscall interface. There is zero change to `rsticulumd`.

- **NOT a capability system.** WASM blobs have no special privileges.
  They are opaque bytes. The network cannot grant or deny capabilities
  to WASM — it doesn't know they're WASM beyond the `type` field.

- **NOT a compute platform.** The network does not schedule WASM execution,
  broker function calls, or federate computation. It's a distribution
  mechanism — BitTorrent for WASM, not Lambda for WASM.

- **NOT a protocol change.** No new interest types, no new packet formats,
  no new forwarding rules. WASM rides entirely on the existing content
  overlay. If you can fetch a JPEG, you can fetch a WASM blob.
