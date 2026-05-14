//! Integration: packet encode/decode across the wire, including interface framing.
//!
//! Verifies that rsticulum-packet bytes survive a roundtrip through
//! rsticulum-interface KISS and HDLC framing layers.

use rsticulum_identity::RnsAddress;
use rsticulum_interface::{HdlcDecoder, HdlcFrame, KissDecoder, KissFrame, KissFrameResult};
use rsticulum_packet::Packet;

fn test_addr(b: u8) -> RnsAddress {
    RnsAddress::from_identity_key(&[b; 32])
}

// ── Packet roundtrip through KISS framing ──

#[test]
fn packet_via_kiss_frame() {
    let dest = test_addr(1);
    let pkt = Packet::new_data(dest, b"hello through KISS!".to_vec());
    let wire = pkt.to_bytes();

    // Encode as KISS frame
    let kiss = KissFrame::encode(&wire);

    // Decode the KISS frame
    let mut decoder = KissDecoder::new();
    let mut recovered_wire = None;
    for &byte in &kiss {
        if let Some(KissFrameResult {
            command: 0x00,
            data,
        }) = decoder.feed(byte)
        {
            recovered_wire = Some(data);
        }
    }

    let recovered_wire = recovered_wire.expect("KISS decode should yield a frame");

    // Parse the recovered wire as a packet
    let recovered_pkt = Packet::from_bytes(&recovered_wire).expect("should parse");
    assert_eq!(recovered_pkt.data, b"hello through KISS!");
    assert_eq!(recovered_pkt.destination_hash, *dest.as_bytes());
}

// ── Packet roundtrip through HDLC framing ──

#[test]
fn packet_via_hdlc_frame() {
    let dest = test_addr(2);
    let payload = (0..255u8).collect::<Vec<u8>>(); // full byte range
    let pkt = Packet::new_data(dest, payload.clone());
    let wire = pkt.to_bytes();

    // Encode as HDLC frame
    let hdlc = HdlcFrame::encode(&wire);

    // Verify the middle has no bare FLAG (0x7E) — that would break framing.
    // 0x7D (ESC) is expected: it's the escape prefix in the encode itself (e.g. ESC+0x5E).
    let middle = &hdlc[1..hdlc.len() - 1];
    assert!(!middle.contains(&0x7E), "no bare 0x7E FLAG in payload");

    // Decode the HDLC frame
    let mut decoder = HdlcDecoder::new();
    let mut recovered_wire = None;
    for &byte in &hdlc {
        if let Some(data) = decoder.feed(byte) {
            recovered_wire = Some(data);
        }
    }

    let recovered_wire = recovered_wire.expect("HDLC decode should yield a frame");

    // Parse the recovered wire as a packet
    let recovered_pkt = Packet::from_bytes(&recovered_wire).expect("should parse");
    assert_eq!(recovered_pkt.data, payload);
    assert_eq!(recovered_pkt.destination_hash, *dest.as_bytes());
}

// ── Multiple packets in a single KISS stream ──

#[test]
fn multiple_packets_via_kiss_stream() {
    let mut stream = Vec::new();
    let dest = test_addr(3);

    for i in 0..5u8 {
        let pkt = Packet::new_data(dest, vec![i; 50]);
        let wire = pkt.to_bytes();
        stream.extend(KissFrame::encode(&wire));
    }

    let mut decoder = KissDecoder::new();
    let mut recovered = Vec::new();

    for &byte in &stream {
        if let Some(KissFrameResult { data, .. }) = decoder.feed(byte) {
            let pkt = Packet::from_bytes(&data).expect("should parse");
            recovered.push(pkt.data.clone());
        }
    }

    assert_eq!(recovered.len(), 5);
    for i in 0..5u8 {
        assert_eq!(recovered[i as usize], vec![i; 50]);
    }
}

// ── Large packet through HDLC (exceeding typical radio MTU) ──

#[test]
fn large_packet_via_hdlc() {
    let dest = test_addr(4);
    let large_data = vec![0xAB; 40960]; // 40KB
    let pkt = Packet::new_data(dest, large_data.clone());
    let wire = pkt.to_bytes();

    let hdlc = HdlcFrame::encode(&wire);

    let mut decoder = HdlcDecoder::new();
    let mut recovered = None;
    for &byte in &hdlc {
        if let Some(data) = decoder.feed(byte) {
            recovered = Some(data);
        }
    }

    let recovered = recovered.expect("HDLC decode");
    let rec_pkt = Packet::from_bytes(&recovered).expect("parse");
    assert_eq!(rec_pkt.data.len(), 40960);
}
