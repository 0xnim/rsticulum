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

    // Drain any stale packets from A's socket before B's announce
    drain_packets(&daemon_a.media[0]).await;

    // B broadcasts → A receives
    println!("B broadcasting announce...");
    daemon_b.media[0].broadcast(&build_announce(&keys_b).to_bytes()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Loop to handle possible self-received announces from loopback
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let mut a_announce_ok = false;
    while std::time::Instant::now() < deadline {
        if let Ok(Ok(Some((from, frame)))) =
            tokio::time::timeout(Duration::from_millis(100), daemon_a.media[0].recv()).await
        {
            if let Ok(pkt) = P::Packet::from_bytes(&frame) {
                println!("A recv: from={from}, pkt type={}, data_len={}", pkt.packet_type, pkt.data.len());
                if pkt.packet_type == P::ANNOUNCE && from == addr_b {
                    daemon_a.handle_frame(from, frame).await.unwrap();
                    a_announce_ok = true;
                    break;
                } else {
                    println!("A: ignoring misdirected packet from {from} (expected {addr_b})");
                }
            }
        } else {
            break;
        }
    }
    if !a_announce_ok {
        panic!("A did not receive B's announce within deadline");
    }
    println!("=== A connecting to B ===\n");

    // Drain stale packets from both media before link exchange
    drain_packets(&daemon_a.media[0]).await;
    drain_packets(&daemon_b.media[0]).await;

    println!("A sends LINKREQUEST to B...");
    let connect_result = daemon_a.connect(addr_b).await;
    println!("connect: {connect_result:?}");
    assert!(connect_result.is_ok(), "connect should succeed");

    // B receives and processes the LINKREQUEST
    // Loop to handle possible stale packets (loopback from A's broadcast)
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let mut b_lr_ok = false;
    while std::time::Instant::now() < deadline {
        if let Ok(Ok(Some((from, frame)))) =
            tokio::time::timeout(Duration::from_millis(100), daemon_b.media[0].recv()).await
        {
            if let Ok(pkt) = P::Packet::from_bytes(&frame) {
                println!("B recv: from={from}, pkt type={}, data_len={}", pkt.packet_type, pkt.data.len());
                if pkt.packet_type == P::LINKREQUEST && from == addr_a {
                    daemon_b.handle_frame(from, frame).await.unwrap();
                    b_lr_ok = true;
                    break;
                } else {
                    println!("B: ignoring (expected LINKREQUEST from {addr_a})");
                }
            }
        } else {
            break;
        }
    }
    if !b_lr_ok {
        panic!("B did not receive LINKREQUEST within deadline");
    }

    println!("A links={}, B links={}\n", daemon_a.link_count(), daemon_b.link_count());

    // A receives LRPROOF response and processes it (ECDH key exchange)
    // Use a streaming recv: keep reading until we get the PROOF+LRPROOF packet
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let mut found = false;
    while std::time::Instant::now() < deadline {
        // Use timeout to poll without blocking forever
        if let Ok(Ok(Some((from, frame)))) =
            tokio::time::timeout(Duration::from_millis(100), daemon_a.media[0].recv()).await
        {
            if let Ok(pkt) = P::Packet::from_bytes(&frame) {
                println!("A: pkt type={}, context={:#04x}, len={}", pkt.packet_type, pkt.context, pkt.data.len());
                if pkt.packet_type == P::PROOF && pkt.context == P::LRPROOF {
                    println!("A: handling LRPROOF from {from}, B_addr={addr_b}");
                    let result = daemon_a.handle_frame(from, frame).await;
                    println!("A: handle_frame result={result:?}, links={}", daemon_a.link_count());
                    found = true;
                    break;
                } else {
                    // Stale or unexpected packet — just log and continue
                    println!("A: ignoring (expected LRPROOF)");
                    daemon_a.handle_frame(from, frame).await.ok();
                }
            }
        } else {
            break; // no more packets available
        }
    }
    if !found {
        panic!("A did not receive LRPROOF response within deadline");
    }

    println!("=== FINAL: A links={}, B links={} ===", daemon_a.link_count(), daemon_b.link_count());

    assert!(daemon_a.link_count() >= 1,
        "A should have >= 1 link, got {}", daemon_a.link_count());
    assert!(daemon_b.link_count() >= 1,
        "B should have >= 1 link, got {}", daemon_b.link_count());
}

/// Drain any pending packets from a medium (non-blocking).
async fn drain_packets(medium: &Arc<dyn rsticulum_mesh::Medium>) {
    loop {
        match tokio::time::timeout(Duration::from_millis(10), medium.recv()).await {
            Ok(Ok(Some(_))) => continue,
            _ => break,
        }
    }
}
