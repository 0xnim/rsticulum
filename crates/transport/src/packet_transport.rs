//! Packet-based transport for sending and receiving RNS packets.
//!
//! Provides a simple send/receive abstraction over RNS packets,
//! supporting fragmentation when data exceeds the MTU.

use crate::error::TransportError;
use rsticulum_identity::RnsAddress;
use rsticulum_packet::Packet;
use std::collections::HashMap;

/// Default Maximum Transmission Unit for packet transport.
pub const DEFAULT_MTU: u16 = 500;

/// Maximum payload per packet (accounting for header overhead).
pub fn max_payload(mtu: u16) -> usize {
    // Header is at most 35 bytes: flags(1) + hops(1) + transport_id(16) + dest_hash(16) + context(1)
    (mtu as usize).saturating_sub(35)
}

/// A buffered packet transport that handles sending and receiving packets.
///
/// Supports fragmentation of large messages into multiple packets and
/// reassembly of fragmented messages on the receiving side.
#[derive(Debug, Default)]
pub struct PacketTransport {
    /// Buffered inbound packets awaiting processing.
    inbound: Vec<Packet>,
    /// Buffered outbound packets awaiting transmission.
    outbound: Vec<Packet>,
    /// MTU for this transport.
    mtu: u16,
    /// Reassembly buffers for fragmented messages, keyed by a fragment ID.
    reassembly: HashMap<u64, ReassemblyBuffer>,
}

/// A buffer for reassembling fragmented messages.
#[derive(Debug)]
struct ReassemblyBuffer {
    /// Expected total number of fragments.
    total: u16,
    /// Fragments received so far (index -> data).
    fragments: HashMap<u16, Vec<u8>>,
    /// Total data length once reassembled.
    data_len: usize,
}

impl PacketTransport {
    /// Create a new packet transport with the default MTU.
    pub fn new() -> Self {
        Self {
            mtu: DEFAULT_MTU,
            ..Default::default()
        }
    }

    /// Create a new packet transport with a custom MTU.
    pub fn with_mtu(mtu: u16) -> Self {
        Self {
            mtu,
            ..Default::default()
        }
    }

    /// Get the MTU.
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Number of pending inbound packets.
    pub fn pending_inbound(&self) -> usize {
        self.inbound.len()
    }

    /// Number of pending outbound packets.
    pub fn pending_outbound(&self) -> usize {
        self.outbound.len()
    }

    /// Prepare a message for sending. Returns one or more packets.
    ///
    /// If the message fits within the MTU, a single packet is returned.
    /// Otherwise the message is fragmented across multiple packets.
    pub fn send_packet(
        &mut self,
        destination: RnsAddress,
        data: Vec<u8>,
    ) -> Result<Vec<Packet>, TransportError> {
        let max_payload = max_payload(self.mtu);

        if data.len() <= max_payload {
            // Single packet
            let packet = Packet::new_data(destination, data);
            self.outbound.push(packet.clone());
            Ok(vec![packet])
        } else {
            // Fragment the data
            let total_fragments = ((data.len() + max_payload - 1) / max_payload) as u16;
            let fragment_id = rand::random::<u64>();
            let mut packets = Vec::with_capacity(total_fragments as usize);

            for (i, chunk) in data.chunks(max_payload).enumerate() {
                let mut fragment_data = Vec::with_capacity(chunk.len() + 10);
                // Fragment header: fragment_id (8 bytes) + fragment_index (2 bytes)
                fragment_data.extend_from_slice(&fragment_id.to_be_bytes());
                fragment_data.extend_from_slice(&(i as u16).to_be_bytes());
                fragment_data.extend_from_slice(&total_fragments.to_be_bytes());
                fragment_data.extend_from_slice(chunk);

                let mut packet = Packet::new_data(destination, fragment_data);
                packet.context = rsticulum_packet::RESOURCE; // reuse RESOURCE context for fragments
                self.outbound.push(packet.clone());
                packets.push(packet);
            }

            Ok(packets)
        }
    }

    /// Receive a packet from the network and buffer it.
    ///
    /// If the packet is part of a fragmented message, it's added to a
    /// reassembly buffer. If it completes a fragmented message, the
    /// assembled message is returned.
    pub fn recv_packet(&mut self, packet: Packet) -> Result<Option<Vec<u8>>, TransportError> {
        if packet.context == rsticulum_packet::RESOURCE {
            // This is a fragment — attempt reassembly
            self.reassemble_fragment(packet)
        } else {
            // Single message
            self.inbound.push(packet.clone());
            Ok(Some(packet.data.clone()))
        }
    }

    /// Drain all pending inbound messages.
    pub fn drain(&mut self) -> Vec<Vec<u8>> {
        let mut messages = Vec::new();
        for pkt in self.inbound.drain(..) {
            messages.push(pkt.data);
        }
        messages
    }

    /// Clear all buffers.
    pub fn clear(&mut self) {
        self.inbound.clear();
        self.outbound.clear();
        self.reassembly.clear();
    }

    // ── Private ──

    fn reassemble_fragment(&mut self, packet: Packet) -> Result<Option<Vec<u8>>, TransportError> {
        if packet.data.len() < 12 {
            return Err(TransportError::InvalidChunkSize(packet.data.len()));
        }

        let fragment_id = u64::from_be_bytes(packet.data[0..8].try_into().unwrap());
        let fragment_index = u16::from_be_bytes(packet.data[8..10].try_into().unwrap());
        let total_fragments = u16::from_be_bytes(packet.data[10..12].try_into().unwrap());
        let chunk = packet.data[12..].to_vec();

        let buf = self
            .reassembly
            .entry(fragment_id)
            .or_insert_with(|| ReassemblyBuffer {
                total: total_fragments,
                fragments: HashMap::new(),
                data_len: 0,
            });

        if buf.total != total_fragments {
            return Err(TransportError::Other("fragment total mismatch".into()));
        }

        buf.data_len += chunk.len();
        buf.fragments.insert(fragment_index, chunk);

        // Check if reassembly is complete
        if buf.fragments.len() == buf.total as usize {
            let mut assembled = Vec::with_capacity(buf.data_len);
            for i in 0..buf.total {
                if let Some(data) = buf.fragments.remove(&i) {
                    assembled.extend_from_slice(&data);
                } else {
                    return Err(TransportError::ResourceSegmentOrder {
                        expected: i as u32,
                        got: u32::MAX,
                    });
                }
            }
            self.reassembly.remove(&fragment_id);
            Ok(Some(assembled))
        } else {
            Ok(None)
        }
    }
}

// ── Free functions ──

/// Convenience function to send a single data packet.
pub fn send_packet(destination: RnsAddress, data: Vec<u8>) -> Packet {
    Packet::new_data(destination, data)
}

/// Convenience function to receive and unpack a packet's data.
pub fn recv_packet(packet: &Packet) -> Vec<u8> {
    packet.data.clone()
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    fn test_addr(b: u8) -> RnsAddress {
        RnsAddress::from_identity_key(&[b; 32])
    }

    #[test]
    fn send_single_packet_within_mtu() {
        let mut transport = PacketTransport::new();
        let dest = test_addr(1);
        let data = b"hello world".to_vec();

        let packets = transport.send_packet(dest, data.clone()).unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].data, data);
    }

    #[test]
    fn send_fragments_large_message() {
        let mut transport = PacketTransport::with_mtu(100);
        let dest = test_addr(2);
        let data = vec![0xAA; 300]; // Should need ~4 packets with MTU 100

        let packets = transport.send_packet(dest, data.clone()).unwrap();
        assert!(packets.len() > 1, "Should fragment into multiple packets");

        // Each fragment should have context == RESOURCE
        for pkt in &packets {
            assert_eq!(pkt.context, rsticulum_packet::RESOURCE);
        }
    }

    #[test]
    fn recv_and_reassemble_fragments() {
        let mut transport = PacketTransport::with_mtu(100);
        let dest = test_addr(3);
        let data = vec![0xBB; 250];

        let packets = transport.send_packet(dest, data.clone()).unwrap();
        assert!(packets.len() > 1);

        // Simulate receiving all fragments
        let mut result = None;
        for pkt in packets {
            let msg = transport.recv_packet(pkt).unwrap();
            if msg.is_some() {
                result = msg;
            }
        }

        assert!(result.is_some(), "Reassembly should complete");
        assert_eq!(result.unwrap(), data);
    }

    #[test]
    fn recv_single_non_fragmented_packet() {
        let mut transport = PacketTransport::new();
        let dest = test_addr(4);
        let data = b"simple message".to_vec();

        let packets = transport.send_packet(dest, data.clone()).unwrap();
        let msg = transport.recv_packet(packets[0].clone()).unwrap();
        assert_eq!(msg, Some(data));
    }

    #[test]
    fn free_function_send_packet() {
        let dest = test_addr(5);
        let data = b"free function test".to_vec();
        let pkt = send_packet(dest, data.clone());
        assert_eq!(pkt.data, data);
        assert_eq!(pkt.packet_type, rsticulum_packet::DATA);
    }

    #[test]
    fn free_function_recv_packet() {
        let dest = test_addr(6);
        let data = b"recv test".to_vec();
        let pkt = send_packet(dest, data.clone());
        let received = recv_packet(&pkt);
        assert_eq!(received, data);
    }

    #[test]
    fn max_payload_calculation() {
        assert_eq!(max_payload(500), 465);
        assert_eq!(max_payload(100), 65);
        // MTU smaller than header should saturate to 0
        assert_eq!(max_payload(30), 0);
    }

    #[test]
    fn drain_clears_inbound() {
        let mut transport = PacketTransport::new();
        let dest = test_addr(7);
        transport.send_packet(dest, b"msg1".to_vec()).unwrap();
        transport.send_packet(dest, b"msg2".to_vec()).unwrap();

        // Feed packets back as received
        let out: Vec<_> = transport.outbound.clone();
        for pkt in &out {
            transport.recv_packet(pkt.clone()).unwrap();
        }

        let drained = transport.drain();
        assert_eq!(drained.len(), 2);
        assert_eq!(transport.pending_inbound(), 0);
    }

    #[test]
    fn clear_resets_all_state() {
        let mut transport = PacketTransport::new();
        let dest = test_addr(8);
        transport.send_packet(dest, b"test".to_vec()).unwrap();
        transport.clear();
        assert_eq!(transport.pending_inbound(), 0);
        assert_eq!(transport.pending_outbound(), 0);
    }
}
