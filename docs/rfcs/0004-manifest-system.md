# RFC 0004: Manifest System for Mutable Content

- **Status:** Design (Overlay)
- **Depends on:** [RFC 0001: Identity-Based Addressing](0001-identity-based-addressing.md), [RFC 0003: Content-Named Overlay](0003-hierarchical-announce-forwarding.md)

---

## Abstract

The content layer addresses objects by cryptographic hash — immutable by construction. The Manifest System adds a mutable pointer layer so consumers can discover the *latest* version of a producer's content without an out-of-band index. A **manifest** is a signed, versioned JSON document mapping semantic names to content hashes. The latest manifest hash is discovered via a well-known pointer Interest (`/<producer>/_manifest`). Long-lived **Subscribe Interests** push new manifest versions to consumers as they are published. The structure is analogous to Git: branch pointer → commit hash → tree, adapted for an information-centric network with no central registry.

---

## 1. Motivation

Immutable content addressing creates a bootstrapping problem: a consumer wanting "the latest firmware" cannot know the hash of a not-yet-published version. DNS and HTTP solve this with centralised authorities — antithetical to rsticulum's identity-centric, decentralised architecture. The manifest provides an identity-bound mutable pointer: discovered through the producer's identity, signed by the producer's key, and cacheable by any node.

---

## 2. Format

A manifest is a canonical JSON document signed by the producer's Ed25519 key and addressed by `SHA-256(manifest)`:

```
{
  producer:   <identity_hash>,
  sequence:   <monotonic uint64>,
  timestamp:  <ISO-8601>,
  entries:    { name: { hash, type, size } }
}
```

Each entry maps a semantic name to a content object identified by its SHA-256 hash, a MIME-style content type, and its byte size. Sequence numbers are strictly increasing and form a hash chain via an implicit `previous` field linking each manifest to its predecessor. Manifests are immutable content objects — any change produces a new hash and a new manifest.

---

## 3. Discovery

The hash of the latest manifest is obtained by issuing an Interest to the well-known pointer:

```
/<producer>/_manifest
```

This returns a signed **Pointer Record** containing the latest manifest hash and sequence number. The consumer validates the signature, then fetches the manifest by hash from the content-named overlay. No DNS, no HTTP, no central server — the producer's identity *is* the discovery root.

For push-based updates, a consumer opens a long-lived **Subscribe Interest**:

```
/<producer>/_manifest/_subscribe
```

The producer holds this Interest open and responds with each new manifest as it is published. The consumer includes its `last_known_sequence` so only newer manifests are delivered, and may include a content-type filter to receive notifications only for relevant entry changes.

---

## 4. Content Types

Entries carry a MIME-style `type` field enabling consumers to negotiate and select content. Defined types include: `text/plain`, `text/markdown`, `image/png`, `image/jpeg`, `video/mp4`, `audio/opus`, `application/json`, `application/wasm`, `application/firmware`, and `application/octet-stream` (fallback). The namespace is extensible; experimental types use the `application/x-` prefix.

---

## 5. Security

- **Authenticity:** Every manifest is signed by the producer's Ed25519 private key. Consumers verify the signature against the `producer` field — self-certifying with no external trust anchors.
- **Integrity:** Content is addressed by `SHA-256(content)`. The manifest binds semantic names to these hashes. Any tampering with content produces a different hash that will not match the manifest entry.
- **Versioning:** Monotonic sequence numbers and the hash chain prevent undetected rollback. A consumer receiving a manifest with `sequence <= last_known_sequence` and a different hash rejects it. Sequence gaps are detectable; consumers fetch missing manifests by walking the hash chain.
- **No Reticulum changes required.** The entire system operates over the content-named overlay defined in RFC 0003.
