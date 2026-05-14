//! ICN Demo — full manifest+content pipeline with two forwarders.
//!
//! Producer publishes a manifest listing available content.
//! Consumer fetches the manifest, discovers content names, fetches content.
//! Uses TestFace for in-process communication — no network needed.
//!
//! Run: cargo run -p rsticulum-icn --bin icn-demo

use std::sync::Arc;
use std::time::Duration;

use rsticulum_icn::{
    face::{test_face_pair, TestFace},
    Data, EntryKind, Forwarder, Interest, Manifest, ManifestEntry, Name,
};
use rsticulum_identity::Keys;

fn main() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(demo());
}

async fn demo() {
    println!("╔══════════════════════════════════════════════╗");
    println!("║        rsticulum-icn — Pipeline Demo         ║");
    println!("╚══════════════════════════════════════════════╝\n");

    // ── Setup ──

    let producer_keys = Keys::generate();
    let consumer_keys = Keys::generate();

    let producer_hash: [u8; 32] = *producer_keys.address().as_bytes();

    println!("Producer: {}", hex_prefix(&producer_hash));
    println!(
        "Consumer: {}\n",
        hex_prefix(consumer_keys.address().as_bytes())
    );

    // ── Producer side ──

    let mut producer_fw = Forwarder::new();
    producer_fw.register_keys(producer_hash, producer_keys.clone());

    // Build a manifest
    let manifest = Manifest {
        producer: producer_hash,
        sequence: 1,
        timestamp: 1715700000,
        entries: vec![ManifestEntry {
            kind: EntryKind::Blob,
            label: "hello".to_string(),
            content_name: Name::new(producer_hash, &[b"hello"]),
            content_hash: None,
            size: None,
        }],
        previous: None,
    };

    // Sign the manifest as ICN Data
    let manifest_data = manifest.to_data(&producer_keys).unwrap();
    println!("[Producer] Published manifest v{}", manifest.sequence);
    println!("[Producer]   Entries:");
    for entry in &manifest.entries {
        println!(
            "[Producer]     - {} ({}) → {}",
            entry.label,
            format_entry_kind(&entry.kind),
            entry.content_name
        );
    }

    // Create the content Data
    let hello_content =
        b"Hello from rsticulum-icn!\nThis content was fetched by name, not location.\n";
    let hello_name = Name::new(producer_hash, &[b"hello"]);
    let hello_data = {
        let mut data = Data::new(
            hello_name.clone(),
            hello_content.to_vec(),
            rsticulum_transport::Proof::from_bytes(&vec![0u8; 96]).unwrap(),
        );
        let signed_hash = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&data.name.to_bytes());
            hasher.update(&data.content);
            *hasher.finalize().as_bytes()
        };
        data.signature = rsticulum_transport::generate_proof(&producer_keys, &signed_hash);
        data.metadata.content_hash = Some(blake3::hash(&data.content).into());
        data
    };

    // Register in producer's CS (simulates publishing)
    producer_fw
        .cs_mut()
        .insert(manifest_data.name.clone(), manifest_data.clone());
    producer_fw
        .cs_mut()
        .insert(hello_name.clone(), hello_data.clone());
    println!("[Producer] Content cached in CS\n");

    // ── Consumer side ──

    let (face_a, face_b) = test_face_pair();
    let mut consumer_fw = Forwarder::new();

    // Register producer keys for verification
    consumer_fw.register_keys(producer_hash, producer_keys.clone());

    // Set up FIB: route producer's namespace to face_a
    let producer_prefix = Name::new(producer_hash, &[]);
    consumer_fw.register_face(face_a.clone());
    consumer_fw.add_route(producer_prefix.clone(), face_a.id(), 10);

    // Spawn producer forwarder handler that responds to Interests
    let producer_fw = std::sync::Mutex::new(producer_fw);
    tokio::spawn(async move {
        loop {
            if let Some(interest) = face_b.recv_interest() {
                let mut fw = producer_fw.lock().unwrap();
                let cs_hit = fw.cs_mut().get(&interest.name).cloned();
                if let Some(data) = cs_hit {
                    let _ = face_b.send_data(&data).await;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });

    // ── Fetch manifest ──

    let manifest_name = Name::new(producer_hash, &[b"manifest"]);
    let manifest_interest = Interest::new(manifest_name.clone())
        .with_can_be_prefix()
        .with_lifetime(Duration::from_secs(5));

    println!("[Consumer] Express Interest: {}", manifest_name);

    let result = consumer_fw.express(manifest_interest, 0).await;
    match result {
        Ok(Some(data)) => {
            println!(
                "[Consumer] ✓ Received manifest Data ({} bytes)",
                data.content.len()
            );

            let manifest = Manifest::from_data(&data).unwrap();
            println!("[Consumer]   Producer: {}", hex_prefix(&manifest.producer));
            println!("[Consumer]   Sequence: v{}", manifest.sequence);
            println!("[Consumer]   Entries:");

            for entry in &manifest.entries {
                println!(
                    "[Consumer]     - {} ({})",
                    entry.label,
                    format_entry_kind(&entry.kind)
                );

                // Fetch the content
                let content_interest =
                    Interest::new(entry.content_name.clone()).with_lifetime(Duration::from_secs(5));

                println!("[Consumer]   Fetching {} ...", entry.content_name);

                let content_result = consumer_fw.express(content_interest, 0).await;
                match content_result {
                    Ok(Some(content_data)) => {
                        println!(
                            "[Consumer]   ✓ Received {} ({} bytes)",
                            content_data.name,
                            content_data.content.len()
                        );

                        // Verify content hash
                        if let Some(expected_hash) = content_data.metadata.content_hash {
                            let actual_hash: [u8; 32] = blake3::hash(&content_data.content).into();
                            if expected_hash == actual_hash {
                                println!("[Consumer]   ✓ Content hash verified");
                            } else {
                                println!("[Consumer]   ✗ Content hash MISMATCH!");
                            }
                        }

                        // Print content (if text)
                        if let Ok(s) = std::str::from_utf8(&content_data.content) {
                            println!("[Consumer]   ── Content ──");
                            for line in s.lines() {
                                println!("[Consumer]     {line}");
                            }
                            println!("[Consumer]   ────────────");
                        }
                    }
                    Ok(None) => println!("[Consumer]   ✗ Timeout"),
                    Err(e) => println!("[Consumer]   ✗ Error: {e}"),
                }
            }
        }
        Ok(None) => println!("[Consumer] ✗ Manifest not found"),
        Err(e) => println!("[Consumer] ✗ Error: {e}"),
    }

    println!("\n╔══════════════════════════════════════════════╗");
    println!("║              Pipeline Complete               ║");
    println!("╚══════════════════════════════════════════════╝");
}

fn hex_prefix(bytes: &[u8]) -> String {
    if bytes.len() <= 8 {
        hex::encode(bytes)
    } else {
        format!(
            "{}..{}",
            hex::encode(&bytes[..4]),
            hex::encode(&bytes[bytes.len() - 4..])
        )
    }
}

fn format_entry_kind(kind: &EntryKind) -> &str {
    match kind {
        EntryKind::Blob => "blob",
        EntryKind::Stream => "stream",
        EntryKind::Manifest => "manifest",
    }
}
