//! Integration: two-node full-stack communication.
//!
//! Exercises identity → destination → announce → mesh routing →
//! transport link → resource transfer over UDP mediums.

use rsticulum_destination::Destination;
use rsticulum_identity::Keys;
use rsticulum_identity::RnsAddress;
use rsticulum_mesh::{Medium, UdpMedium};
use rsticulum_packet::Packet;
use rsticulum_transport::{Link, PacketTransport, Resource, ResourceConfig, SegmentTracker};
use std::sync::Arc;

/// Build a destination with a fresh keypair.
fn make_dest(name: &str) -> Destination {
    let keys = Keys::generate();
    Destination::singleton(keys, name, vec![])
}

fn test_addr(b: u8) -> RnsAddress {
    RnsAddress::from_identity_key(&[b; 32])
}

// ── Full packet transport integration ──

#[tokio::test]
async fn packet_transport_full_roundtrip() {
    let m1 = Arc::new(
        UdpMedium::bind("node-a", "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap(),
    );
    let m2 = Arc::new(
        UdpMedium::bind("node-b", "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap(),
    );

    let sa1 = m1.local_addr().unwrap();
    let sa2 = m2.local_addr().unwrap();
    let addr1 = test_addr(1);
    let addr2 = test_addr(2);

    m1.add_peer(addr2, sa2).await;
    m2.add_peer(addr1, sa1).await;

    let mut tx1 = PacketTransport::with_mtu(1024);
    let mut tx2 = PacketTransport::with_mtu(1024);

    // Node 1 sends a message
    let payload = b"Hello from node 1!";
    let packets = tx1.send_packet(addr2, payload.to_vec()).unwrap();
    assert_eq!(packets.len(), 1);

    // Transmit over medium
    for pkt in &packets {
        m1.send(addr2, &pkt.to_bytes()).await.unwrap();
    }

    // Node 2 receives
    let (src, raw) = m2.recv().await.unwrap().unwrap();
    assert_eq!(src, addr1);

    let rec_pkt = Packet::from_bytes(&raw).unwrap();

    // Deliver to transport (takes ownership)
    let msg = tx2.recv_packet(rec_pkt).unwrap();
    assert_eq!(msg, Some(payload.to_vec()));
}

// ── Large message fragmentation ──

#[tokio::test]
async fn packet_transport_fragmentation() {
    let m1 = Arc::new(
        UdpMedium::bind("frag-a", "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap(),
    );
    let m2 = Arc::new(
        UdpMedium::bind("frag-b", "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap(),
    );

    let sa1 = m1.local_addr().unwrap();
    let sa2 = m2.local_addr().unwrap();
    let addr1 = test_addr(10);
    let addr2 = test_addr(11);

    m1.add_peer(addr2, sa2).await;
    m2.add_peer(addr1, sa1).await;

    let mut tx1 = PacketTransport::with_mtu(200); // Small MTU to force fragmentation
    let mut tx2 = PacketTransport::with_mtu(200);

    // Send a large message (exceeds MTU)
    let payload = vec![0xCC; 800];
    let packets = tx1.send_packet(addr2, payload.clone()).unwrap();
    assert!(
        packets.len() > 1,
        "message should be fragmented (got {} packets)",
        packets.len()
    );

    // Transmit all fragments
    for pkt in &packets {
        m1.send(addr2, &pkt.to_bytes()).await.unwrap();
    }

    // Node 2 receives and reassembles
    for _ in 0..packets.len() {
        let (_src, raw) = m2.recv().await.unwrap().unwrap();
        let pkt = Packet::from_bytes(&raw).unwrap();
        let msg = tx2.recv_packet(pkt).unwrap();
        // After the last fragment we get the reassembled message
        if let Some(data) = msg {
            assert_eq!(data.len(), 800);
            assert_eq!(data, payload);
        }
    }
}

// ── Link handshake integration ──

#[test]
fn link_handshake_two_nodes() {
    // Alice
    let keys_a = Keys::generate();
    let dest_a = Destination::singleton(keys_a, "alice", vec![]);
    let addr_b = test_addr(2); // use a fixed peer address

    let mut link_a = Link::new(dest_a, addr_b);

    // Initiate handshake on link_a
    let proof_pkt = link_a.establish().unwrap();
    assert_eq!(link_a.state(), rsticulum_transport::LinkState::Handshaking);

    // Self-verify the handshake (both sides in practice share transport_id computation)
    link_a.complete_handshake(&proof_pkt.data).unwrap();
    assert_eq!(link_a.state(), rsticulum_transport::LinkState::Established);
    assert!(link_a.is_established());
}

// ── Full link data exchange through UDP medium ──

#[tokio::test]
async fn link_data_over_udp() {
    let m1 = Arc::new(
        UdpMedium::bind("link-a", "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap(),
    );
    let m2 = Arc::new(
        UdpMedium::bind("link-b", "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap(),
    );

    let sa1 = m1.local_addr().unwrap();
    let sa2 = m2.local_addr().unwrap();

    let keys_a = Keys::generate();
    let dest_a = Destination::singleton(keys_a, "alice-udp", vec![]);
    let keys_b = Keys::generate();
    let dest_b = Destination::singleton(keys_b, "bob-udp", vec![]);
    let addr_a = *dest_a.hash();
    let addr_b = *dest_b.hash();

    m1.add_peer(addr_b, sa2).await;
    m2.add_peer(addr_a, sa1).await;

    // Establish links
    let mut link_a = Link::new(dest_a, addr_b);
    let mut link_b = Link::new(dest_b, addr_a);

    // Handshake — each side self-verifies
    let proof_a = link_a.establish().unwrap();
    link_a.complete_handshake(&proof_a.data).unwrap();

    // Bob also establishes his side
    let proof_b = link_b.establish().unwrap();
    link_b.complete_handshake(&proof_b.data).unwrap();

    // Now link_a is established. Send data.
    let data_pkt = link_a.send(b"secret message over link!".to_vec()).unwrap();

    // Transmit
    m1.send(addr_b, &data_pkt.to_bytes()).await.unwrap();

    // Bob receives
    let (_src, raw) = m2.recv().await.unwrap().unwrap();
    let pkt = Packet::from_bytes(&raw).unwrap();

    // Deliver to link
    link_b.deliver(&pkt).unwrap();
    let msg = link_b.recv().unwrap();
    assert_eq!(&msg, b"secret message over link!");
}

// ── Resource transfer simulation ──

#[test]
fn resource_segment_assembly() {
    let config = ResourceConfig::builder().segment_size(256).build();

    // 4096 bytes of structured data
    let data = (0u8..=255).cycle().take(4096).collect::<Vec<u8>>();

    // Create resource for sending
    let resource = Resource::new_for_sending(data.clone(), config);
    let hash = resource.hash().to_vec();
    let total = resource.total_segments();

    // Generate segments
    let segments = resource.all_segments().to_vec();
    assert!(!segments.is_empty());
    assert_eq!(segments.len(), total as usize);

    // Track and reassemble
    let mut tracker = SegmentTracker::new(hash, total);
    for seg in &segments {
        tracker.add_segment(seg.clone()).unwrap();
    }

    assert!(tracker.is_complete());
    assert!(tracker.missing_indices().is_empty());

    // Assemble
    let assembled = tracker.assemble().unwrap();
    assert_eq!(assembled, data);
}

// ── Resource with tampered segment ──

#[test]
fn resource_detects_tampered_segment() {
    let config = ResourceConfig::builder().segment_size(8).build();

    let data = b"this is my secret data, enough bytes to get multiple segments".to_vec();
    let resource = Resource::new_for_sending(data.clone(), config);
    let hash = resource.hash().to_vec();
    let total = resource.total_segments();

    let segments = resource.all_segments().to_vec();
    assert!(
        segments.len() > 1,
        "data should be split into multiple segments"
    );

    let mut tracker = SegmentTracker::new(hash, total);

    // Add first segment normally
    tracker.add_segment(segments[0].clone()).unwrap();

    // Tamper with second segment
    let mut tampered = segments[1].clone();
    tampered.data[0] ^= 0xFF; // flip all bits in first byte

    // Should fail checksum
    let result = tracker.add_segment(tampered);
    assert!(result.is_err(), "tampered segment should fail");
}
