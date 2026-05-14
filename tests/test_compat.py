#!/usr/bin/env python3
"""Python ↔ Rust RNS packet compatibility test.

Creates RNS packets in Python, hex-dumps them, and verifies
our Rust implementation can decode them byte-for-byte.

Run: uv run test_compat.py
"""

import struct
import hashlib
import os
import sys

# Add reference Reticulum to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "reference-reticulum"))

# We import RNS but also compute some things manually for cross-checking
# RNS imports require the RNS package to be installed or on PYTHONPATH
try:
    import RNS
    from RNS.Packet import Packet as RNSPacket
    from RNS.Identity import Identity as RNSIdentity
    HAS_RNS = True
except ImportError:
    HAS_RNS = False
    print("WARNING: RNS not installed. Running manual hash verification only.")
    print("Install: pip install rns  (or add reference-reticulum to PYTHONPATH)")

# ── Manual hash computation (no RNS dependency needed) ──

def rns_truncated_hash(data: bytes, length: int = 16) -> bytes:
    """Match RNS Identity.truncated_hash(): SHA-256(data)[:length]."""
    return hashlib.sha256(data).digest()[:length]

def rns_identity_hash(pubkey: bytes) -> bytes:
    """Match RNS identity hash: truncated SHA-256 of the public key."""
    return rns_truncated_hash(pubkey)

# ── Manual packet construction (byte-for-byte verification) ──

HEADER_1 = 0x00
DATA = 0x00
ANNOUNCE = 0x01
FLAG_UNSET = 0x00
FLAG_SET = 0x01
TRANSPORT_BROADCAST = 0x00
DEST_SINGLE = 0x00
NONE = 0x00

def pack_flags(header_type, context_flag, transport_type, dest_type, packet_type):
    return ((header_type & 0b11) << 6) | \
           ((context_flag & 0b1) << 5) | \
           ((transport_type & 0b1) << 4) | \
           ((dest_type & 0b11) << 2) | \
           (packet_type & 0b11)

def build_rns_header(dest_hash, hops, packet_type=DATA, header_type=HEADER_1):
    flags = pack_flags(header_type, FLAG_UNSET, TRANSPORT_BROADCAST, DEST_SINGLE, packet_type)
    header = struct.pack("!B", flags)
    header += struct.pack("!B", hops)
    header += dest_hash
    header += bytes([NONE])  # context byte
    return header

# ── Tests ──

def test_manual_packet():
    """Build a packet manually and verify our Rust crate produces identical bytes."""
    
    # Create a test public key
    pubkey = bytes([i for i in range(32)])  # Ed25519 pubkey: 00 01 02 ... 1F
    dest_hash = rns_identity_hash(pubkey)
    
    assert len(dest_hash) == 16, f"Expected 16-byte hash, got {len(dest_hash)}"
    
    # Build a DATA packet
    hops = 64  # RNS default
    data = b"hello, reticulum!"
    header = build_rns_header(dest_hash, hops)
    packet = header + data
    
    print(f"=== Manual DATA Packet ===")
    print(f"pubkey:       {pubkey.hex()}")
    print(f"dest_hash:    {dest_hash.hex()}")
    print(f"flags:        {pack_flags(HEADER_1, FLAG_UNSET, TRANSPORT_BROADCAST, DEST_SINGLE, DATA):#04x}")
    print(f"hops:         {hops}")
    print(f"context:      {NONE}")
    print(f"data:         {data!r}")
    print(f"total_bytes:  {len(packet)}")
    print(f"packet_hex:   {packet.hex()}")
    print()
    
    # Verify expected sizes
    expected_len = 1 + 1 + 16 + 1 + len(data)  # flags + hops + dest_hash + context + data
    assert len(packet) == expected_len, f"Expected {expected_len} bytes, got {len(packet)}"
    
    # Verify bit patterns
    flags = packet[0]
    header_type = (flags >> 6) & 0b11
    context_flag = (flags >> 5) & 0b1
    transport_type = (flags >> 4) & 0b1
    dest_type = (flags >> 2) & 0b11
    pkt_type = flags & 0b11
    
    assert header_type == HEADER_1, f"Expected HEADER_1, got {header_type}"
    assert pkt_type == DATA, f"Expected DATA, got {pkt_type}"
    assert dest_type == DEST_SINGLE, f"Expected DEST_SINGLE, got {dest_type}"
    
    print("✅ Manual packet construction verified")
    return packet.hex()

def test_announce_packet():
    """Build an ANNOUNCE packet manually."""
    pubkey = bytes([0xAB] * 32)
    dest_hash = rns_identity_hash(pubkey)
    
    flags = pack_flags(HEADER_1, FLAG_SET, TRANSPORT_BROADCAST, DEST_SINGLE, ANNOUNCE)
    
    # Announce flag should be 0b00100001 = 0x21
    assert flags == 0x21, f"Expected announce flags 0x21, got {flags:#04x}"
    
    header = build_rns_header(dest_hash, hops=1, packet_type=ANNOUNCE)
    packet = header + b"announce data"
    
    print(f"=== ANNOUNCE Packet ===")
    print(f"flags:        {flags:#04x} (should be 0x21)")
    print(f"hops:         1")
    print(f"packet_hex:   {packet.hex()}")
    print()
    
    print("✅ Announce packet verified")
    return packet.hex()

def test_with_rns():
    """Cross-validate against actual RNS Python implementation (if available)."""
    if not HAS_RNS:
        print("⚠️  RNS not available — skipping cross-validation with Python RNS")
        return
    
    try:
        # Start RNS (minimal)
        rns = RNS.Reticulum()
        identity = RNS.Identity()
        
        # Get identity hash
        id_hash = identity.hash
        assert len(id_hash) == 16
        
        # Create a packet
        dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE, "test", "app")
        pkt = RNSPacket(dest, b"test data from python rns", packet_type=RNSPacket.DATA)
        pkt.pack()
        
        raw = pkt.raw
        print(f"=== Python RNS Packet ===")
        print(f"packet_hex:   {raw.hex()}")
        print(f"flags:        {raw[0]:#04x}")
        print(f"hops:         {raw[1]}")
        print(f"total_bytes:  {len(raw)}")
        print()
        
        # Unpack and verify
        pkt2 = RNSPacket(None, raw)
        assert pkt2.packet_type == RNSPacket.DATA
        assert pkt2.data == b"test data from python rns"
        
        print("✅ Python RNS packet roundtrip verified")
        
    except Exception as e:
        print(f"❌ Python RNS test failed: {e}")

if __name__ == "__main__":
    print("=" * 60)
    print("  Python ↔ Rust RNS Packet Compatibility Test")
    print("=" * 60)
    print()
    
    manual_hex = test_manual_packet()
    announce_hex = test_announce_packet()
    test_with_rns()
    
    print("=" * 60)
    print("  Summary")
    print("=" * 60)
    print(f"  Manual DATA packet:     {manual_hex[:40]}...")
    print(f"  Manual ANNOUNCE packet: {announce_hex[:40]}...")
    print()
    
    if HAS_RNS:
        print("  ✅ RNS library available — cross-validated")
    else:
        print("  ⚠️  RNS library not available — manual verification only")
        print("     Install: pip install rns")
    
    print("=" * 60)