//! In-process daemon link establishment test.
//! Tests daemon-to-daemon link handshake without spawning subprocesses.

use std::sync::Arc;
use std::time::Duration;
use rsticulum_daemon::Daemon;
use rsticulum_identity::Keys;
use rsticulum_mesh::UdpMedium;
use rsticulum_packet::{self as P};

fn build_announce(keys: &Keys) -> P::Packet {
    let rns_addr = keys.rns_address();
    P::Packet {
        header_type: P::HEADER_1,
        context_flag: P::FLAG_UNSET,
        transport_type: P::TRANSPORT_BROADCAST,
        destination_type: P::DEST_SINGLE,
        packet_type: P::ANNOUNCE,
        hops: 1,
        destination_hash: *rns_addr.as_bytes(),
        transport_id: None,
        context: P::NONE,
        data: keys.identity_key_bytes().to_vec(),
    }
}

#[tokio::test]
async fn inprocess_link_establishment() {
    let keys_a = Keys::generate();
    let keys_b = Keys::generate();
    let addr_a = keys_a.rns_address();
    let addr_b = keys_b.rns_address();

    println!("Daemon A: {addr_a}");
    println!("Daemon B: {addr_b}");

    let medium_a = UdpMedium::bind("a", "127.0.0.1:0".parse().unwrap()).await.unwrap();
    let medium_b = UdpMedium::bind("b", "127.0.0.1:0".parse().unwrap()).await.unwrap();

    let port_a = medium_a.local_addr().unwrap().port();
    let port_b = medium_b.local_addr().unwrap().port();
    let b_endpoint = format!("127.0.0.1:{port_b}");
    let a_endpoint = format!("127.0.0.1:{port_a}");

    println!("A on :{port_a}, B on :{port_b}");

    let mut daemon_a = Daemon::new(keys_a.clone());
    let mut daemon_b = Daemon::new(keys_b.clone());
    daemon_a.add_medium(Arc::new(medium_a));
    daemon_b.add_medium(Arc::new(medium_b));

    // Seed peers
    daemon_a.seed_peer(addr_b, &hex::encode(keys_b.identity_key_bytes()), &b_endpoint).await.unwrap();
    daemon_b.seed_peer(addr_a, &hex::encode(keys_a.identity_key_bytes()), &a_endpoint).await.unwrap();
    println!("Peers seeded");

    // Exchange announces
    // A broadcasts → B receives
    println!("A broadcasting announce...");
    daemon_a.media[0].broadcast(&build_announce(&keys_a).to_bytes()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // B receives and processes
    let result = daemon_b.media[0].recv().await;
    println!("B recv: {result:?}");
    if let Ok(Some((from, frame))) = result {
        let pkt = P::Packet::from_bytes(&frame).unwrap();
        println!("B: announce pkt type={}, data_len={}", pkt.packet_type, pkt.data.len());
        daemon_b.handle_frame(from, frame).await.unwrap();
    } else {
        panic!("B did not receive A's announce: {result:?}");
    }

    // B broadcasts → A receives
    println!("B broadcasting announce...");
    daemon_b.media[0].broadcast(&build_announce(&keys_b).to_bytes()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    let result = daemon_a.media[0].recv().await;
    println!("A recv: {result:?}");
    if let Ok(Some((from, frame))) = result {
        let pkt = P::Packet::from_bytes(&frame).unwrap();
        println!("A: announce pkt type={}, data_len={}", pkt.packet_type, pkt.data.len());
        daemon_a.handle_frame(from, frame).await.unwrap();
    } else {
        panic!("A did not receive B's announce: {result:?}");
    }

    println!("=== A connecting to B ===\n");
    println!("A sends LINKREQUEST to B...");
    let connect_result = daemon_a.connect(addr_b).await;
    println!("connect: {connect_result:?}");
    assert!(connect_result.is_ok(), "connect should succeed");

    // B receives and processes the LINKREQUEST
    tokio::time::sleep(Duration::from_millis(200)).await;
    let result = daemon_b.media[0].recv().await;
    println!("B recv: {result:?}");
    if let Ok(Some((from, frame))) = result {
        let pkt = P::Packet::from_bytes(&frame).unwrap();
        println!("B: LINKREQUEST pkt type={}, data_len={}", pkt.packet_type, pkt.data.len());
        // The daemon's handle_frame dispatches LINKREQUEST → handle_linkrequest
        daemon_b.handle_frame(from, frame).await.unwrap();
    } else {
        panic!("B did not receive LINKREQUEST: {result:?}");
    }

    println!("A links={}, B links={}\n", daemon_a.link_count(), daemon_b.link_count());

    // A receives LRPROOF response and processes it (ECDH key exchange)
    tokio::time::sleep(Duration::from_millis(200)).await;
    let result = daemon_a.media[0].recv().await;
    println!("A recv LRPROOF: {result:?}");
    if let Ok(Some((from, frame))) = result {
        let pkt = P::Packet::from_bytes(&frame).unwrap();
        println!("A: response pkt type={}, context={:#04x}, len={}", pkt.packet_type, pkt.context, pkt.data.len());
        // The daemon's handle_frame dispatches PROOF+LRPROOF → handle_proof
        daemon_a.handle_frame(from, frame).await.unwrap();
    } else {
        panic!("A did not receive LRPROOF response: {result:?}");
    }

    println!("=== FINAL: A links={}, B links={} ===", daemon_a.link_count(), daemon_b.link_count());

    assert!(daemon_a.link_count() >= 1,
        "A should have >= 1 link, got {}", daemon_a.link_count());
    assert!(daemon_b.link_count() >= 1,
        "B should have >= 1 link, got {}", daemon_b.link_count());
}
