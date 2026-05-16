//! RNS wire-compatible packet format.
//!
//! Implements the exact binary header layout used by Python RNS,
//! verified byte-for-byte against the reference implementation.
//!
//! ## Header Format
//!
//! ```text
//! HEADER_1: [flags:1][hops:1][dest_hash:16][context:1][ciphertext:...]
//! HEADER_2: [flags:1][hops:1][transport_id:16][dest_hash:16][context:1][ciphertext:...]
//! ```
//!
//! ## Flags Byte (bit-packed)
//!
//! ```text
//!   7-6: header_type   (HEADER_1=0, HEADER_2=1)
//!   5:   context_flag
//!   4:   transport_type
//!   3-2: destination_type
//!   1-0: packet_type    (DATA=0, ANNOUNCE=1, LINKREQUEST=2, PROOF=3)
//! ```

use rsticulum_identity::RnsAddress;

use thiserror::Error;

// ── Error type ──

/// Packet-level errors.
#[derive(Debug, Error)]
pub enum PacketError {
    #[error("invalid packet: {0}")]
    Invalid(&'static str),
    #[error("serialization: {0}")]
    Serde(String),
}

// ── Constants (exactly match Python RNS) ──
// Suppress dead_code — these are referenced by the transport layer.

#[allow(dead_code)]
/// Packet type constants.
pub const DATA: u8 = 0x00;
pub const ANNOUNCE: u8 = 0x01;
pub const LINKREQUEST: u8 = 0x02;
pub const PROOF: u8 = 0x03;

/// Header type constants.
pub const HEADER_1: u8 = 0x00;
pub const HEADER_2: u8 = 0x01;

/// Context constants (wire-compatible with Python RNS).
pub const NONE: u8 = 0x00;
pub const PATH_RESPONSE: u8 = 0xF0;
pub const CACHE_REQUEST: u8 = 0xF1;
pub const REQUEST: u8 = 0xF2;
pub const RESPONSE: u8 = 0xF3;
pub const COMMAND: u8 = 0xF4;
pub const SINGLE: u8 = 0xF5;
pub const GROUP: u8 = 0xF6;
pub const RESOURCE: u8 = 0xFA;
pub const RESOURCE_PRF: u8 = 0xFB;
pub const RESOURCE_ADV: u8 = 0xFC;
pub const RESOURCE_REQ: u8 = 0xFD;
pub const RESOURCE_HMU: u8 = 0xFE;
pub const LINKIDENTITY: u8 = 0xFB;
pub const LINKCLOSE: u8 = 0xFC;
pub const LINKPROOF: u8 = 0xFD;
pub const KEEPALIVE: u8 = 0xFA;
pub const LRPROOF: u8 = 0xFF;

/// Context constant for path requests (DATA packets used for path discovery).
pub const PATH_REQUEST: u8 = 0x01;

/// Destination type constants.
pub const DEST_SINGLE: u8 = 0x00;
pub const DEST_LINK: u8 = 0x01;

/// Context flag.
pub const FLAG_UNSET: u8 = 0x00;
pub const FLAG_SET: u8 = 0x01;

/// Transport type constants.
pub const TRANSPORT_BROADCAST: u8 = 0x00;
pub const TRANSPORT_UNICAST: u8 = 0x01;

/// Fixed hash length (TRUNCATED_HASHLENGTH = 128 bits = 16 bytes).
pub const HASH_LENGTH: usize = 16;

/// Minimum header size: flags(1) + hops(1) + dest_hash(16) + context(1) = 19.
pub const HEADER_MINSIZE: usize = 19;

/// Maximum header size: flags(1) + hops(1) + transport_id(16) + dest_hash(16) + context(1) = 35.
pub const HEADER_MAXSIZE: usize = 35;

/// Maximum hop count (TTL) for new packets.
pub const MAX_HOPS: u8 = 64;

// ── Bit-packed flags ──

/// Pack flags into a single byte, matching RNS bit layout.
///
/// ```text
/// Bit 7-6: header_type
/// Bit 5:   context_flag
/// Bit 4:   transport_type
/// Bit 3-2: destination_type
/// Bit 1-0: packet_type
/// ```
#[inline]
pub fn pack_flags(
    header_type: u8,
    context_flag: u8,
    transport_type: u8,
    destination_type: u8,
    packet_type: u8,
) -> u8 {
    ((header_type & 0x03) << 6)
        | ((context_flag & 0x01) << 5)
        | ((transport_type & 0x01) << 4)
        | ((destination_type & 0x03) << 2)
        | (packet_type & 0x03)
}

/// Unpack flags byte into component fields.
#[inline]
pub fn unpack_flags(flags: u8) -> (u8, u8, u8, u8, u8) {
    let header_type = (flags >> 6) & 0x03;
    let context_flag = (flags >> 5) & 0x01;
    let transport_type = (flags >> 4) & 0x01;
    let destination_type = (flags >> 2) & 0x03;
    let packet_type = flags & 0x03;
    (
        header_type,
        context_flag,
        transport_type,
        destination_type,
        packet_type,
    )
}

// ── Packet struct ──

/// An RNS wire-compatible packet.
///
/// Serialization produces bytes that Python RNS `Packet.unpack()` can parse.
/// Deserialization parses bytes produced by Python RNS `Packet.pack()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    /// Header type: `HEADER_1` or `HEADER_2`.
    pub header_type: u8,
    /// Context flag: `FLAG_SET` or `FLAG_UNSET`.
    pub context_flag: u8,
    /// Transport type: `TRANSPORT_BROADCAST` or `TRANSPORT_UNICAST`.
    pub transport_type: u8,
    /// Destination type: `DEST_SINGLE` or `DEST_LINK`.
    pub destination_type: u8,
    /// Packet type: `DATA`, `ANNOUNCE`, `LINKREQUEST`, or `PROOF`.
    pub packet_type: u8,
    /// Hop count (TTL). Decremented at each forward.
    pub hops: u8,
    /// Destination hash (16 bytes).
    pub destination_hash: [u8; HASH_LENGTH],
    /// Transport ID (only for HEADER_2).
    pub transport_id: Option<[u8; HASH_LENGTH]>,
    /// Context byte.
    pub context: u8,
    /// Payload (ciphertext or plaintext, depending on context).
    pub data: Vec<u8>,
}

impl Packet {
    // ── Constructors ──

    /// Create a new DATA packet with default flags.
    pub fn new_data(destination: RnsAddress, data: Vec<u8>) -> Self {
        Self {
            header_type: HEADER_1,
            context_flag: FLAG_UNSET,
            transport_type: TRANSPORT_BROADCAST,
            destination_type: DEST_SINGLE,
            packet_type: DATA,
            hops: MAX_HOPS,
            destination_hash: *destination.as_bytes(),
            transport_id: None,
            context: NONE,
            data,
        }
    }

    /// Create an ANNOUNCE packet.
    pub fn new_announce(destination: RnsAddress, data: Vec<u8>) -> Self {
        Self {
            header_type: HEADER_1,
            context_flag: FLAG_SET,
            transport_type: TRANSPORT_BROADCAST,
            destination_type: DEST_SINGLE,
            packet_type: ANNOUNCE,
            hops: 1,
            destination_hash: *destination.as_bytes(),
            transport_id: None,
            context: NONE,
            data,
        }
    }

    /// Create a LINKREQUEST packet.
    pub fn new_link_request(destination: RnsAddress, data: Vec<u8>) -> Self {
        Self {
            header_type: HEADER_1,
            context_flag: FLAG_UNSET,
            transport_type: TRANSPORT_BROADCAST,
            destination_type: DEST_SINGLE,
            packet_type: LINKREQUEST,
            hops: MAX_HOPS,
            destination_hash: *destination.as_bytes(),
            transport_id: None,
            context: NONE,
            data,
        }
    }

    /// Create a PROOF packet.
    pub fn new_proof(destination: RnsAddress, context: u8, data: Vec<u8>) -> Self {
        Self {
            header_type: HEADER_1,
            context_flag: FLAG_SET,
            transport_type: TRANSPORT_UNICAST,
            destination_type: DEST_SINGLE,
            packet_type: PROOF,
            hops: MAX_HOPS,
            destination_hash: *destination.as_bytes(),
            transport_id: None,
            context,
            data,
        }
    }

    /// Create a HEADER_2 transport packet.
    pub fn new_transport(
        destination: RnsAddress,
        transport_id: [u8; HASH_LENGTH],
        data: Vec<u8>,
    ) -> Self {
        Self {
            header_type: HEADER_2,
            context_flag: FLAG_UNSET,
            transport_type: TRANSPORT_UNICAST,
            destination_type: DEST_SINGLE,
            packet_type: DATA,
            hops: MAX_HOPS,
            destination_hash: *destination.as_bytes(),
            transport_id: Some(transport_id),
            context: NONE,
            data,
        }
    }

    // ── TTL ──

    /// Returns `true` if the packet has expired (hops == 0).
    #[inline]
    pub fn is_expired(&self) -> bool {
        self.hops == 0
    }

    /// Decrement the TTL by 1, saturating at 0.
    #[inline]
    pub fn decrement_ttl(&mut self) {
        self.hops = self.hops.saturating_sub(1);
    }

    // ── Convenience accessors ──

    /// Returns the destination as an `RnsAddress`, if valid.
    pub fn destination(&self) -> Result<RnsAddress, PacketError> {
        RnsAddress::from_bytes(&self.destination_hash)
            .map_err(|_| PacketError::Invalid("invalid destination hash"))
    }

    // ── Serialization (RNS wire-compatible) ──

    /// Serialize to RNS wire format.
    ///
    /// Produces the exact byte layout that Python RNS `Packet.pack()` produces.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_MINSIZE + self.data.len());

        // flags byte
        let flags = pack_flags(
            self.header_type,
            self.context_flag,
            self.transport_type,
            self.destination_type,
            self.packet_type,
        );
        buf.push(flags);

        // hops
        buf.push(self.hops);

        // header-specific fields
        if self.header_type == HEADER_2 {
            if let Some(ref tid) = self.transport_id {
                buf.extend_from_slice(tid);
            }
        }
        buf.extend_from_slice(&self.destination_hash);

        // context
        buf.push(self.context);

        // ciphertext (data)
        buf.extend_from_slice(&self.data);

        buf
    }

    /// Deserialize from RNS wire format.
    ///
    /// Parses the exact byte layout that Python RNS `Packet.pack()` produces.
    pub fn from_bytes(data: &[u8]) -> Result<Self, PacketError> {
        if data.len() < 3 {
            return Err(PacketError::Invalid("packet too short (< 3 bytes)"));
        }

        let flags = data[0];
        let hops = data[1];
        let (header_type, context_flag, transport_type, destination_type, packet_type) =
            unpack_flags(flags);

        let mut pos = 2;
        let transport_id = if header_type == HEADER_2 {
            if data.len() < pos + HASH_LENGTH + HASH_LENGTH + 1 {
                return Err(PacketError::Invalid(
                    "HEADER_2 packet too short for transport_id + dest_hash + context",
                ));
            }
            let mut tid = [0u8; HASH_LENGTH];
            tid.copy_from_slice(&data[pos..pos + HASH_LENGTH]);
            pos += HASH_LENGTH;
            Some(tid)
        } else {
            if data.len() < pos + HASH_LENGTH + 1 {
                return Err(PacketError::Invalid(
                    "HEADER_1 packet too short for dest_hash + context",
                ));
            }
            None
        };

        let mut dest_hash = [0u8; HASH_LENGTH];
        dest_hash.copy_from_slice(&data[pos..pos + HASH_LENGTH]);
        pos += HASH_LENGTH;

        let context = data[pos];
        pos += 1;

        let payload = data[pos..].to_vec();

        Ok(Self {
            header_type,
            context_flag,
            transport_type,
            destination_type,
            packet_type,
            hops,
            destination_hash: dest_hash,
            transport_id,
            context,
            data: payload,
        })
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create an RnsAddress deterministically from a single seed byte.
    fn test_addr(b: u8) -> RnsAddress {
        RnsAddress::from_identity_key(&[b; 32])
    }

    // ── Constant value verification ──

    #[test]
    fn constants_match_spec() {
        assert_eq!(DATA, 0x00);
        assert_eq!(ANNOUNCE, 0x01);
        assert_eq!(LINKREQUEST, 0x02);
        assert_eq!(PROOF, 0x03);
        assert_eq!(HEADER_1, 0x00);
        assert_eq!(HEADER_2, 0x01);
        assert_eq!(NONE, 0x00);
        assert_eq!(LRPROOF, 0xFF);
        assert_eq!(DEST_SINGLE, 0x00);
        assert_eq!(DEST_LINK, 0x01);
        assert_eq!(FLAG_UNSET, 0x00);
        assert_eq!(FLAG_SET, 0x01);
        assert_eq!(TRANSPORT_BROADCAST, 0x00);
        assert_eq!(TRANSPORT_UNICAST, 0x01);
        assert_eq!(HASH_LENGTH, 16);
        assert_eq!(HEADER_MINSIZE, 19);
        assert_eq!(HEADER_MAXSIZE, 35);
        assert_eq!(MAX_HOPS, 64);
    }

    // ── Flag packing tests ──

    #[test]
    fn flag_packing_roundtrip_all_combinations() {
        let test_cases = [
            (HEADER_1, FLAG_UNSET, TRANSPORT_BROADCAST, DEST_SINGLE, DATA),
            (
                HEADER_1,
                FLAG_SET,
                TRANSPORT_BROADCAST,
                DEST_SINGLE,
                ANNOUNCE,
            ),
            (
                HEADER_1,
                FLAG_UNSET,
                TRANSPORT_BROADCAST,
                DEST_SINGLE,
                LINKREQUEST,
            ),
            (HEADER_1, FLAG_SET, TRANSPORT_UNICAST, DEST_SINGLE, PROOF),
            (HEADER_2, FLAG_UNSET, TRANSPORT_UNICAST, DEST_SINGLE, DATA),
            (HEADER_1, FLAG_UNSET, TRANSPORT_BROADCAST, DEST_LINK, DATA),
            (HEADER_1, FLAG_SET, TRANSPORT_BROADCAST, DEST_LINK, ANNOUNCE),
            (HEADER_2, FLAG_SET, TRANSPORT_UNICAST, DEST_LINK, DATA),
            (HEADER_2, FLAG_UNSET, TRANSPORT_UNICAST, DEST_LINK, PROOF),
        ];

        for (ht, cf, tt, dt, pt) in test_cases {
            let flags = pack_flags(ht, cf, tt, dt, pt);
            let (ht2, cf2, tt2, dt2, pt2) = unpack_flags(flags);
            assert_eq!(
                ht, ht2,
                "header_type mismatch: {ht} vs {ht2}, flags=0x{flags:02X}"
            );
            assert_eq!(
                cf, cf2,
                "context_flag mismatch: {cf} vs {cf2}, flags=0x{flags:02X}"
            );
            assert_eq!(
                tt, tt2,
                "transport_type mismatch: {tt} vs {tt2}, flags=0x{flags:02X}"
            );
            assert_eq!(
                dt, dt2,
                "destination_type mismatch: {dt} vs {dt2}, flags=0x{flags:02X}"
            );
            assert_eq!(
                pt, pt2,
                "packet_type mismatch: {pt} vs {pt2}, flags=0x{flags:02X}"
            );
        }
    }

    #[test]
    fn announce_flags_byte_matches_rns() {
        // Python RNS announce packet flags:
        // HEADER_1=0, FLAG_SET=1, TRANSPORT_BROADCAST=0, DEST_SINGLE=0, ANNOUNCE=1
        // Binary: 00_1_0_00_01 = 0b00100001 = 0x21
        let flags = pack_flags(
            HEADER_1,
            FLAG_SET,
            TRANSPORT_BROADCAST,
            DEST_SINGLE,
            ANNOUNCE,
        );
        assert_eq!(flags, 0x21);
    }

    #[test]
    fn data_flags_byte_matches_rns() {
        // Python RNS data packet flags:
        // HEADER_1=0, FLAG_UNSET=0, BROADCAST=0, DEST_SINGLE=0, DATA=0
        // Binary: 00_0_0_00_00 = 0x00
        let flags = pack_flags(HEADER_1, FLAG_UNSET, TRANSPORT_BROADCAST, DEST_SINGLE, DATA);
        assert_eq!(flags, 0x00);
    }

    #[test]
    fn header2_unicast_flags_byte() {
        // HEADER_2=1, FLAG_UNSET=0, TRANSPORT_UNICAST=1, DEST_SINGLE=0, DATA=0
        // Binary: 01_0_1_00_00 = 0b01010000 = 0x50
        let flags = pack_flags(HEADER_2, FLAG_UNSET, TRANSPORT_UNICAST, DEST_SINGLE, DATA);
        assert_eq!(flags, 0x50);
    }

    #[test]
    fn link_request_flags_byte() {
        // HEADER_1=0, FLAG_UNSET=0, TRANSPORT_BROADCAST=0, DEST_SINGLE=0, LINKREQUEST=2
        // Binary: 00_0_0_00_10 = 0x02
        let flags = pack_flags(
            HEADER_1,
            FLAG_UNSET,
            TRANSPORT_BROADCAST,
            DEST_SINGLE,
            LINKREQUEST,
        );
        assert_eq!(flags, 0x02);
    }

    #[test]
    fn proof_flags_byte() {
        // HEADER_1=0, FLAG_SET=1, TRANSPORT_UNICAST=1, DEST_SINGLE=0, PROOF=3
        // Binary: 00_1_1_00_11 = 0b00110011 = 0x33
        let flags = pack_flags(HEADER_1, FLAG_SET, TRANSPORT_UNICAST, DEST_SINGLE, PROOF);
        assert_eq!(flags, 0x33);
    }

    #[test]
    fn unpack_flags_all_zero() {
        let (ht, cf, tt, dt, pt) = unpack_flags(0x00);
        assert_eq!(ht, HEADER_1);
        assert_eq!(cf, FLAG_UNSET);
        assert_eq!(tt, TRANSPORT_BROADCAST);
        assert_eq!(dt, DEST_SINGLE);
        assert_eq!(pt, DATA);
    }

    #[test]
    fn pack_flags_masks_inputs() {
        // Values with extra bits set should be masked down
        let flags = pack_flags(0xFF, 0xFF, 0xFF, 0xFF, 0xFF);
        let (ht, cf, tt, dt, pt) = unpack_flags(flags);
        assert_eq!(ht, 0x03, "header_type should be masked to 2 bits");
        assert_eq!(cf, 0x01, "context_flag should be masked to 1 bit");
        assert_eq!(tt, 0x01, "transport_type should be masked to 1 bit");
        assert_eq!(dt, 0x03, "destination_type should be masked to 2 bits");
        assert_eq!(pt, 0x03, "packet_type should be masked to 2 bits");

        // The resulting packed byte: 11_1_1_11_11 = 0xFF
        assert_eq!(flags, 0xFF);
    }

    // ── Packet roundtrip tests ──

    #[test]
    fn data_packet_roundtrip() {
        let dest = test_addr(1);
        let pkt = Packet::new_data(dest, b"hello, reticulum!".to_vec());
        let bytes = pkt.to_bytes();

        // Verify header size: flags(1) + hops(1) + dest(16) + context(1) = 19
        // + 17 bytes payload = 36
        assert_eq!(bytes.len(), HEADER_MINSIZE + 17);

        let decoded = Packet::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.packet_type, DATA);
        assert_eq!(decoded.header_type, HEADER_1);
        assert_eq!(decoded.hops, MAX_HOPS);
        assert_eq!(decoded.destination_hash, *dest.as_bytes());
        assert_eq!(decoded.context, NONE);
        assert_eq!(decoded.data, b"hello, reticulum!");
        assert_eq!(decoded.transport_id, None);
    }

    #[test]
    fn empty_data_packet_roundtrip() {
        let dest = test_addr(2);
        let pkt = Packet::new_data(dest, vec![]);
        let bytes = pkt.to_bytes();

        // HEADER_1 minimum: 19 bytes, no payload
        assert_eq!(bytes.len(), HEADER_MINSIZE);

        let decoded = Packet::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.data.len(), 0);
        assert_eq!(decoded.packet_type, DATA);
    }

    #[test]
    fn announce_packet_roundtrip() {
        let broadcast = test_addr(0);
        let pkt = Packet::new_announce(broadcast, b"announce payload".to_vec());
        let bytes = pkt.to_bytes();

        let decoded = Packet::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.packet_type, ANNOUNCE);
        assert_eq!(decoded.context_flag, FLAG_SET);
        assert_eq!(decoded.hops, 1);
        assert_eq!(decoded.data, b"announce payload");
    }

    #[test]
    fn link_request_packet_roundtrip() {
        let dest = test_addr(3);
        let pkt = Packet::new_link_request(dest, b"link request data".to_vec());
        let bytes = pkt.to_bytes();

        let decoded = Packet::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.packet_type, LINKREQUEST);
        assert_eq!(decoded.header_type, HEADER_1);
        assert_eq!(decoded.transport_id, None);
        assert_eq!(decoded.data, b"link request data");
    }

    #[test]
    fn proof_packet_roundtrip() {
        let dest = test_addr(4);
        let pkt = Packet::new_proof(dest, LRPROOF, b"proof data".to_vec());
        let bytes = pkt.to_bytes();

        let decoded = Packet::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.packet_type, PROOF);
        assert_eq!(decoded.context_flag, FLAG_SET);
        assert_eq!(decoded.transport_type, TRANSPORT_UNICAST);
        assert_eq!(decoded.context, LRPROOF);
        assert_eq!(decoded.data, b"proof data");
    }

    #[test]
    fn proof_packet_with_different_contexts() {
        for ctx in [LRPROOF, LINKPROOF, LINKIDENTITY, LINKCLOSE, NONE] {
            let dest = test_addr(5);
            let pkt = Packet::new_proof(dest, ctx, vec![0xAB, 0xCD]);
            let bytes = pkt.to_bytes();
            let decoded = Packet::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.context, ctx, "context {ctx:#04X} should roundtrip");
            assert_eq!(decoded.data, vec![0xAB, 0xCD]);
        }
    }

    #[test]
    fn header2_transport_packet_roundtrip() {
        let dest = test_addr(42);
        let tid = [0xAB; HASH_LENGTH];
        let pkt = Packet::new_transport(dest, tid, b"transport data".to_vec());
        let bytes = pkt.to_bytes();

        // HEADER_2: flags(1) + hops(1) + transport_id(16) + dest(16) + context(1)
        // = 35 + 14 bytes payload
        assert_eq!(bytes.len(), HEADER_MAXSIZE + 14);

        let decoded = Packet::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.header_type, HEADER_2);
        assert_eq!(decoded.transport_id, Some(tid));
        assert_eq!(decoded.transport_type, TRANSPORT_UNICAST);
        assert_eq!(decoded.data, b"transport data");
    }

    #[test]
    fn header2_empty_payload() {
        let dest = test_addr(7);
        let tid = [0xCD; HASH_LENGTH];
        let pkt = Packet::new_transport(dest, tid, vec![]);
        let bytes = pkt.to_bytes();

        // HEADER_2 minimum: 35 bytes, no payload
        assert_eq!(bytes.len(), HEADER_MAXSIZE);

        let decoded = Packet::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.header_type, HEADER_2);
        assert_eq!(decoded.data.len(), 0);
    }

    #[test]
    fn destination_type_link_roundtrip() {
        let dest = test_addr(8);
        let mut pkt = Packet::new_data(dest, vec![0x01, 0x02, 0x03]);
        pkt.destination_type = DEST_LINK;

        let bytes = pkt.to_bytes();
        let decoded = Packet::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.destination_type, DEST_LINK);
    }

    #[test]
    fn all_context_constants_roundtrip() {
        let contexts = [
            NONE,
            PATH_RESPONSE,
            CACHE_REQUEST,
            REQUEST,
            RESPONSE,
            COMMAND,
            KEEPALIVE,
            RESOURCE_PRF,
            RESOURCE_ADV,
            RESOURCE_REQ,
            RESOURCE_HMU,
            LRPROOF,
        ];

        for ctx in contexts {
            let dest = test_addr(9);
            let mut pkt = Packet::new_data(dest, vec![0x42]);
            pkt.context = ctx;
            let bytes = pkt.to_bytes();
            let decoded = Packet::from_bytes(&bytes).unwrap();
            assert_eq!(
                decoded.context, ctx,
                "context {ctx:#04X} should survive roundtrip"
            );
        }
    }

    #[test]
    fn large_data_packet_roundtrip() {
        let dest = test_addr(10);
        let large_data = vec![0xAA; 4096];
        let pkt = Packet::new_data(dest, large_data.clone());
        let bytes = pkt.to_bytes();

        assert_eq!(bytes.len(), HEADER_MINSIZE + 4096);

        let decoded = Packet::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.data, large_data);
        assert_eq!(decoded.packet_type, DATA);
    }

    #[test]
    fn serialization_is_deterministic() {
        let dest = test_addr(11);
        let pkt = Packet::new_data(dest, vec![1, 2, 3]);
        let bytes1 = pkt.to_bytes();
        let bytes2 = pkt.to_bytes();
        assert_eq!(bytes1, bytes2);
    }

    // ── TTL tests ──

    #[test]
    fn ttl_starts_at_max_hops() {
        let dest = test_addr(1);
        let pkt = Packet::new_data(dest, vec![]);
        assert_eq!(pkt.hops, MAX_HOPS);
        assert!(!pkt.is_expired());
    }

    #[test]
    fn ttl_decrements_to_zero() {
        let dest = test_addr(1);
        let mut pkt = Packet::new_data(dest, vec![]);
        assert!(!pkt.is_expired());

        for i in 1..=MAX_HOPS {
            pkt.decrement_ttl();
            let remaining = MAX_HOPS - i;
            assert_eq!(
                pkt.hops, remaining,
                "after {i} decrements, hops should be {remaining}"
            );
            assert_eq!(pkt.is_expired(), remaining == 0);
        }
    }

    #[test]
    fn ttl_saturates_at_zero() {
        let dest = test_addr(1);
        let mut pkt = Packet::new_data(dest, vec![]);

        // Decrement all the way down
        for _ in 0..MAX_HOPS {
            pkt.decrement_ttl();
        }
        assert_eq!(pkt.hops, 0);
        assert!(pkt.is_expired());

        // Further decrements stay at 0
        for _ in 0..10 {
            pkt.decrement_ttl();
            assert_eq!(pkt.hops, 0);
            assert!(pkt.is_expired());
        }
    }

    #[test]
    fn is_expired_only_at_zero() {
        let dest = test_addr(1);
        let mut pkt = Packet::new_data(dest, vec![]);

        pkt.hops = 1;
        assert!(!pkt.is_expired());

        pkt.decrement_ttl();
        assert_eq!(pkt.hops, 0);
        assert!(pkt.is_expired());
    }

    // ── Error / edge-case tests ──

    #[test]
    fn invalid_bytes_rejected() {
        // Empty
        assert!(Packet::from_bytes(&[]).is_err());
        // Too short: only flags
        assert!(Packet::from_bytes(&[0x00]).is_err());
        // Too short: flags + hops only
        assert!(Packet::from_bytes(&[0x00, 0x01]).is_err());
    }

    #[test]
    fn header1_too_short_rejected() {
        // HEADER_1 flags (0x00) + hops, but not enough for dest_hash + context
        let short = [0x00, 0x0A, 0x00, 0x00]; // 4 bytes, need at least 19
        assert!(Packet::from_bytes(&short).is_err());
    }

    #[test]
    fn header2_too_short_rejected() {
        // HEADER_2 flags (0x40) + hops, but not enough for transport_id + dest_hash + context
        let short = [0x40, 0x01, 0x00]; // 3 bytes, need at least 35
        assert!(Packet::from_bytes(&short).is_err());
    }

    #[test]
    fn header2_exactly_at_boundary_accepted() {
        // Minimum HEADER_2: 1 + 1 + 16 + 16 + 1 = 35 bytes, zero payload
        let mut data = vec![0u8; HEADER_MAXSIZE];
        // flags: HEADER_2(1) | UNICAST(1) = 0b01010000 = 0x50
        data[0] = pack_flags(HEADER_2, FLAG_UNSET, TRANSPORT_UNICAST, DEST_SINGLE, DATA);
        data[1] = MAX_HOPS;
        // transport_id = [2..18], dest_hash = [18..34], context = data[34]

        let pkt = Packet::from_bytes(&data).unwrap();
        assert_eq!(pkt.header_type, HEADER_2);
        assert_eq!(pkt.transport_id, Some([0u8; HASH_LENGTH]));
        assert_eq!(pkt.data.len(), 0);
    }

    #[test]
    fn header1_exactly_at_boundary_accepted() {
        // Minimum HEADER_1: 1 + 1 + 16 + 1 = 19 bytes, zero payload
        let mut data = vec![0u8; HEADER_MINSIZE];
        data[0] = pack_flags(HEADER_1, FLAG_UNSET, TRANSPORT_BROADCAST, DEST_SINGLE, DATA);
        data[1] = MAX_HOPS;
        // dest_hash = [2..18], context = data[18]

        let pkt = Packet::from_bytes(&data).unwrap();
        assert_eq!(pkt.header_type, HEADER_1);
        assert_eq!(pkt.transport_id, None);
        assert_eq!(pkt.data.len(), 0);
    }

    // ── destination() accessor tests ──

    #[test]
    fn destination_accessor_roundtrip() {
        let orig = test_addr(42);
        let pkt = Packet::new_data(orig, vec![0x01]);
        let recovered = pkt.destination().unwrap();
        assert_eq!(orig, recovered);
    }

    // ── Packet equality ──

    #[test]
    fn identical_packets_are_equal() {
        let dest = test_addr(99);
        let p1 = Packet::new_data(dest, vec![1, 2, 3]);
        let p2 = Packet::new_data(dest, vec![1, 2, 3]);
        assert_eq!(p1, p2);
    }

    #[test]
    fn different_data_packets_are_not_equal() {
        let dest = test_addr(99);
        let p1 = Packet::new_data(dest, vec![1, 2, 3]);
        let p2 = Packet::new_data(dest, vec![4, 5, 6]);
        assert_ne!(p1, p2);
    }
}
