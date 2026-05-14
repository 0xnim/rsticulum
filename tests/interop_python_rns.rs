//! RNS ↔ rsticulum cross-validation: packet parsing + crypto compatibility.
//!
//! Spawns Python RNS validator, verifies:
//! 1. All packet types parse correctly
//! 2. HKDF-SHA256 produces identical keys
//! 3. Token (Fernet) encrypt/decrypt is cross-compatible

use serde::Deserialize;
use rsticulum_crypto::{hkdf_sha256, Token};
use rsticulum_identity::RnsAddress;
use rsticulum_interface::{KissDecoder, KissFrame};
use rsticulum_packet::Packet;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

#[derive(Debug, Deserialize)]
struct PythonResponse {
    status: String,
    #[serde(default)] packet_type: Option<u64>,
    #[serde(default)] hops: Option<u64>,
    #[serde(default)] destination_hash: Option<String>,
    #[serde(default)] context: Option<u64>,
    #[serde(default)] data_len: Option<u64>,
    #[serde(default)] data_hex: Option<String>,
    #[serde(default)] header_type: Option<u64>,
    #[serde(default)] transport_type: Option<u64>,
    #[serde(default)] context_flag: Option<u64>,
    #[serde(default)] transport_id: Option<String>,
    #[serde(default)] announce_flags: Option<String>,
    #[serde(default)] error: Option<String>,
    #[serde(default)] derived_hex: Option<String>,
    #[serde(default)] token_hex: Option<String>,
    #[serde(default)] token_len: Option<u64>,
    #[serde(default)] plaintext_hex: Option<String>,
}

fn spawn() -> (Box<dyn Write>, BufReader<Box<dyn std::io::Read>>, std::process::Child) {
    let mut c = Command::new("python3").arg("tests/python_rns_validator.py")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn().unwrap();
    (Box::new(c.stdin.take().unwrap()), BufReader::new(Box::new(c.stdout.take().unwrap()) as Box<dyn std::io::Read>), c)
}
fn send(w: &mut Box<dyn Write>, s: &str) { writeln!(w, "{s}").unwrap(); }
fn read(r: &mut BufReader<Box<dyn std::io::Read>>) -> PythonResponse {
    let mut l = String::new(); r.read_line(&mut l).unwrap();
    serde_json::from_str(&l).expect(&format!("json: {l}"))
}
fn addr(b: u8) -> RnsAddress { RnsAddress::from_identity_key(&[b; 32]) }

// ── Packet parsing ──

#[test] fn python_parses_all_rust_packet_types() {
    let (mut s, mut r, mut c) = spawn();
    let d = addr(42); let dh = hex::encode(d.as_bytes());
    for (lbl, pkt, et, eh, ecf, etr) in [
        ("DATA",         Packet::new_data(d, b"dp".to_vec()),           0x00,64,0x00,0x00),
        ("ANNOUNCE",     Packet::new_announce(d, b"ap".to_vec()),       0x01,1, 0x01,0x00),
        ("LINK_REQUEST", Packet::new_link_request(d, b"lr".to_vec()),  0x02,64,0x00,0x00),
        ("PROOF",        Packet::new_proof(d, 0xFF, b"pp".to_vec()),   0x03,64,0x01,0x01),
    ] { send(&mut s, &format!("PARSE {}", hex::encode(pkt.to_bytes())));
        let resp = read(&mut r); assert_eq!(resp.status, "ok", "{lbl}: {resp:?}");
        assert_eq!(resp.packet_type.unwrap() as u8, et); assert_eq!(resp.hops.unwrap() as u8, eh);
        assert_eq!(resp.destination_hash.as_deref().unwrap(), dh);
        assert_eq!(resp.context_flag.unwrap() as u8, ecf);
        assert_eq!(resp.transport_type.unwrap() as u8, etr);
    } send(&mut s, "QUIT"); c.wait().unwrap();
}

#[test] fn announce_flags() {
    let (mut s, mut r, mut c) = spawn(); send(&mut s, "ANNOUNCE_FLAGS");
    let resp = read(&mut r);
    let f = u8::from_str_radix(resp.announce_flags.as_deref().unwrap().trim_start_matches("0x"), 16).unwrap();
    assert_eq!(f, 0x21); assert_eq!(rsticulum_packet::pack_flags(0x00,0x01,0x00,0x00,0x01), 0x21);
    send(&mut s, "QUIT"); c.wait().unwrap();
}

#[test] fn large_payload() {
    let (mut s, mut r, mut c) = spawn();
    let p: Vec<u8> = (0u8..=255).cycle().take(2048).collect();
    send(&mut s, &format!("PARSE {}", hex::encode(Packet::new_data(addr(55), p.clone()).to_bytes())));
    let resp = read(&mut r); assert_eq!(resp.status, "ok");
    assert_eq!(resp.data_hex.as_deref().unwrap(), hex::encode(&p));
    send(&mut s, "QUIT"); c.wait().unwrap();
}

// ── Crypto cross-validation ──

#[test] fn hkdf_matches_python() {
    let (mut s, mut r, mut c) = spawn();

    // Known IKM: 32 bytes 0x00..0x1f
    let ikm = [
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
    ];
    let ikm_hex = hex::encode(ikm);

    // Rust HKDF
    let rust_key = hkdf_sha256(32, &ikm, None, None);

    // Python HKDF
    send(&mut s, &format!("HKDF_DERIVE 32 {ikm_hex}"));
    let resp = read(&mut r);
    assert_eq!(resp.status, "ok", "python hkdf: {resp:?}");
    assert_eq!(resp.derived_hex.as_deref().unwrap(), hex::encode(&rust_key),
        "HKDF derived key mismatch");

    send(&mut s, "QUIT"); c.wait().unwrap();
}

#[test] fn token_encrypt_decrypt_cross_compat() {
    let (mut s, mut r, mut c) = spawn();

    // Generate a random 32-byte key
    let mut key = [0u8; 32];
    getrandom::getrandom(&mut key).unwrap();
    let key_hex = hex::encode(key);

    let plaintext = b"Rust encrypts, Python decrypts -- cross-compat verified!";
    let pt_hex = hex::encode(plaintext);

    // Rust encrypts
    let token = Token::encrypt(plaintext, &key);

    // Python decrypts
    send(&mut s, &format!("TOKEN_DECRYPT {} {key_hex}", hex::encode(&token)));
    let resp = read(&mut r);
    assert_eq!(resp.status, "ok", "python decrypt: {resp:?}");
    assert_eq!(resp.plaintext_hex.as_deref().unwrap(), pt_hex,
        "python decrypted wrong payload");

    // Python encrypts, Rust decrypts
    send(&mut s, &format!("TOKEN_ENCRYPT {key_hex} {pt_hex}"));
    let resp = read(&mut r);
    assert_eq!(resp.status, "ok", "python encrypt: {resp:?}");
    let py_token = hex::decode(resp.token_hex.as_deref().unwrap()).unwrap();
    let decrypted = Token::decrypt(&py_token, &key).expect("rust decrypt python token");
    assert_eq!(decrypted, plaintext, "rust decrypt mismatch");

    // Wrong key should fail
    let mut wrong_key = key;
    wrong_key[0] ^= 1;
    send(&mut s, &format!("TOKEN_DECRYPT {} {}", hex::encode(&token), hex::encode(wrong_key)));
    let resp = read(&mut r);
    assert_eq!(resp.status, "error", "wrong key should error");

    send(&mut s, "QUIT"); c.wait().unwrap();
}
