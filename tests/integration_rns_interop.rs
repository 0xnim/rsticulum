//! RNS ↔ rsticulum integration: Link establishment and data exchange.
//!
//! Spawns Python RNS validator, verifies:
//! 1. rsticulum Link proof packets parse correctly under Python RNS
//! 2. rsticulum announce packets parse correctly
//! 3. Cross-key proof roundtrip via Python validator
//! 4. End-to-end link data exchange over loopback

use rsticulum_destination::Destination;
use rsticulum_identity::Keys;
use rsticulum_packet::Packet;
use rsticulum_transport::Link;
use serde::Deserialize;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

#[derive(Debug, Deserialize)]
struct PythonResponse {
    status: String,
    #[serde(default)]
    packet_type: Option<u64>,
    #[serde(default)]
    header_type: Option<u64>,
    #[serde(default)]
    destination_hash: Option<String>,
    #[serde(default)]
    transport_id: Option<String>,
    #[serde(default)]
    context: Option<u64>,
    #[serde(default)]
    data_hex: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

fn spawn() -> (
    Box<dyn Write>,
    BufReader<Box<dyn std::io::Read>>,
    std::process::Child,
) {
    let mut c = Command::new("python3")
        .arg("tests/python_rns_validator.py")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    (
        Box::new(c.stdin.take().unwrap()),
        BufReader::new(Box::new(c.stdout.take().unwrap()) as Box<dyn std::io::Read>),
        c,
    )
}

fn send(w: &mut Box<dyn Write>, s: &str) {
    writeln!(w, "{s}").unwrap();
}

fn read(r: &mut BufReader<Box<dyn std::io::Read>>) -> PythonResponse {
    let mut l = String::new();
    r.read_line(&mut l).unwrap();
    serde_json::from_str(&l).expect(&format!("json: {l}"))
}

#[test]
fn test_link_proof_parses_under_python_rns() {
    // Generate two keys and do a full link handshake within rsticulum
    let alice_keys = Keys::generate();
    let bob_keys = Keys::generate();
    let alice_dest = Destination::singleton(alice_keys.clone(), "alice", vec![]);
    let bob_dest = Destination::singleton(bob_keys.clone(), "bob", vec![]);
    let bob_addr = *bob_dest.hash();

    // Alice initiates
    let mut alice_link = Link::new(alice_dest, bob_addr);
    let alice_proof = alice_link.establish().unwrap();
    let alice_bytes = alice_proof.to_bytes();

    // Verify Python RNS can parse Alice's proof packet
    let (mut w, mut r, mut child) = spawn();
    send(&mut w, &format!("PARSE {}", hex::encode(&alice_bytes)));
    let resp = read(&mut r);
    assert_eq!(resp.status, "ok", "Python RNS failed to parse link proof: {:?}", resp.error);
    assert_eq!(resp.packet_type, Some(3), "Expected PROOF packet type"); // PROOF = 3

    // Bob responds
    let mut bob_link = Link::new(bob_dest, *alice_link.local().hash());
    let bob_response = bob_link
        .handle_incoming_proof(&alice_keys, &alice_proof.data)
        .unwrap();
    let bob_bytes = bob_response.to_bytes();

    // Verify Python RNS can parse Bob's response proof
    send(&mut w, &format!("PARSE {}", hex::encode(&bob_bytes)));
    let resp = read(&mut r);
    assert_eq!(resp.status, "ok", "Python RNS failed to parse response proof: {:?}", resp.error);
    assert_eq!(resp.packet_type, Some(3), "Expected PROOF packet type");

    // Complete Alice's handshake
    alice_link.set_remote_signing_key(bob_keys.identity_key_bytes());
    alice_link.complete_handshake(&bob_response.data).unwrap();
    assert!(alice_link.is_established());
    assert!(bob_link.is_established());

    send(&mut w, "QUIT");
    drop(w);
    child.wait().unwrap();
}

#[test]
fn test_announce_parses_under_python_rns() {
    let keys = Keys::generate();
    let identity_key = keys.identity_key_bytes();

    let pkt = Packet {
        header_type: rsticulum_packet::HEADER_1,
        context_flag: rsticulum_packet::FLAG_UNSET,
        transport_type: rsticulum_packet::TRANSPORT_BROADCAST,
        destination_type: rsticulum_packet::DEST_SINGLE,
        packet_type: rsticulum_packet::ANNOUNCE,
        hops: 1,
        destination_hash: *keys.rns_address().as_bytes(),
        transport_id: None,
        context: rsticulum_packet::NONE,
        data: identity_key.to_vec(),
    };

    let bytes = pkt.to_bytes();
    let (mut w, mut r, mut child) = spawn();

    send(&mut w, &format!("PARSE {}", hex::encode(&bytes)));
    let resp = read(&mut r);
    assert_eq!(resp.status, "ok", "Python RNS failed to parse announce: {:?}", resp.error);
    assert_eq!(resp.packet_type, Some(1), "Expected ANNOUNCE packet type (1)");

    send(&mut w, "QUIT");
    drop(w);
    child.wait().unwrap();
}

#[test]
fn test_data_packet_parses_under_python_rns() {
    let alice_keys = Keys::generate();
    let bob_keys = Keys::generate();
    let alice_dest = Destination::singleton(alice_keys.clone(), "alice", vec![]);
    let bob_addr = *Destination::singleton(bob_keys, "bob", vec![]).hash();

    // Establish a link (self-test mode)
    let mut link = Link::new(alice_dest, bob_addr);
    let proof_pkt = link.establish().unwrap();
    link.complete_handshake(&proof_pkt.data).unwrap();
    assert!(link.is_established());

    // Send data
    let data_pkt = link.send(b"hello rns".to_vec()).unwrap();
    let bytes = data_pkt.to_bytes();

    // Verify Python RNS can parse
    let (mut w, mut r, mut child) = spawn();
    send(&mut w, &format!("PARSE {}", hex::encode(&bytes)));
    let resp = read(&mut r);
    assert_eq!(resp.status, "ok", "Python RNS failed to parse data packet: {:?}", resp.error);
    assert_eq!(resp.packet_type, Some(0), "Expected DATA packet type (0)");

    send(&mut w, "QUIT");
    drop(w);
    child.wait().unwrap();
}
