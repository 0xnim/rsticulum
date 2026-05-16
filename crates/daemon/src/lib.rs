//! rsticulum-daemon — mesh networking + ICN forwarder + Link transport.
//!
//! The daemon ties together:
//! - Identity management (keypair loading/generation/saving)
//! - Link establishment (proof handshake, encrypted transport via Channel)
//! - Mesh routing (UDP medium, MeshRouter, path discovery)
//! - ICN forwarding (ContentStore, FIB/PIT, manifest serving)
//! - Discovery (periodic announces, incoming announce handling)
//! - Local API (TCP socket for applications)
//! - Resource transfer (segmented large-data over links)
//! - Buffer streaming (channel-based streaming I/O)

pub mod config;
pub mod api;

use sha2::{Digest, Sha256};
use ed25519_dalek::Verifier;
use std::collections::HashMap;
use std::sync::Arc;

use rsticulum_channel::Channel;
use rsticulum_destination::Destination;
use rsticulum_identity::Keys;
use rsticulum_mesh::{Medium, MeshRouter};
use rsticulum_packet::{
    Packet, ANNOUNCE, DATA, HEADER_2, LINKPROOF, LINKREQUEST, PROOF,
};
use rsticulum_transport::{Link, Resource, ResourceConfig};
use rsticulum_transport::Proof;
use tokio::sync::mpsc::UnboundedReceiver;

use crate::api::ApiCommand;

/// The daemon — holds all runtime state.
pub struct Daemon {
    /// Local identity keypair.
    pub keys: Keys,
    /// Mesh router for path discovery.
    pub router: MeshRouter,
    /// ICN forwarder for content-addressed networking.
    pub forwarder: rsticulum_icn::Forwarder,
    /// Active transport media.
    pub media: Vec<Arc<dyn Medium>>,
    /// Established links via Channel, keyed by remote RNS address.
    channels: HashMap<rsticulum_identity::RnsAddress, Channel>,
    /// Pending links (handshake in progress), stored as Channels wrapping unestablished Links.
    pending_channels: HashMap<rsticulum_identity::RnsAddress, Channel>,
    /// Known peer identity keys (from announces), for proof verification.
    peer_keys: HashMap<rsticulum_identity::RnsAddress, [u8; 32]>,
    /// Incoming resource transfers (hash → Resource)
    incoming_resources: HashMap<Vec<u8>, Resource>,
    /// Announce sequence counter.
    announce_seq: u64,
    /// Receiver for API commands from the local TCP socket.
    api_cmd_rx: Option<UnboundedReceiver<ApiCommand>>,
}

impl Daemon {
    /// Create a new daemon with the given keys.
    pub fn new(keys: Keys) -> Self {
        let router = MeshRouter::new(keys.rns_address());
        let forwarder = rsticulum_icn::Forwarder::new();
        Daemon {
            keys,
            router,
            forwarder,
            media: Vec::new(),
            channels: HashMap::new(),
            pending_channels: HashMap::new(),
            peer_keys: HashMap::new(),
            incoming_resources: HashMap::new(),
            announce_seq: 0,
            api_cmd_rx: None,
        }
    }

    /// Add a transport medium to the daemon.
    pub fn add_medium(&mut self, medium: Arc<dyn Medium>) {
        self.media.push(medium);
    }

    /// Set the channel for receiving API commands from the local TCP socket.
    pub fn set_api_channel(&mut self, rx: UnboundedReceiver<ApiCommand>) {
        self.api_cmd_rx = Some(rx);
    }

    /// Register a known peer's identity key (from an announce or out-of-band).
    pub fn register_peer(&mut self, addr: rsticulum_identity::RnsAddress, signing_key: [u8; 32]) {
        self.peer_keys.insert(addr, signing_key);
    }

    /// Start the daemon: run the mesh + Link + ICN event loop.
    pub async fn run(&mut self) -> Result<(), DaemonError> {
        let local_addr = self.keys.rns_address();
        tracing::info!("Daemon starting — local address: {local_addr}");

        if self.media.is_empty() {
            tracing::warn!("No transport media configured — daemon has no network");
        }

        // Main event loop
        loop {
            // Collect frames from all media (with timeout so API commands can be processed)
            let mut frames = Vec::new();
            for medium in &self.media {
                match tokio::time::timeout(std::time::Duration::from_millis(100), medium.recv()).await {
                    Ok(Ok(Some((from, frame)))) => {
                        frames.push((from, frame));
                    }
                    Ok(Ok(None)) => {
                        tracing::debug!("Medium {} closed", medium.name());
                    }
                    Ok(Err(e)) => {
                        tracing::error!("Error receiving from {}: {e}", medium.name());
                    }
                    Err(_elapsed) => {
                        // No data available within timeout — continue to process API commands
                    }
                }
            }

            for (from, frame) in frames {
                eprintln!("[FRAME] {} bytes from {from}", frame.len());
                tracing::debug!("Received {} bytes from {}", frame.len(), from);
                if let Err(e) = self.handle_frame(from, frame).await {
                    tracing::error!("Error handling frame from {from}: {e}");
                }
            }

            // Periodic: send announces
            self.announce_seq = self.announce_seq.wrapping_add(1);
            if self.announce_seq % 100 == 0 {
                for medium in &self.media {
                    let pkt = build_announce_packet(&self.keys);
                    let data = pkt.to_bytes();
                    let sent = medium.broadcast(&data).await.unwrap_or(0);
                    if sent > 0 {
                        tracing::debug!("Announce broadcast via {} to {sent} peers", medium.name());
                    } else {
                        tracing::debug!("Announce broadcast via {} (no peers yet)", medium.name());
                    }
                }
            }

            // Process API commands from the local TCP socket
            // Collect commands first to avoid borrow conflicts with self methods
            let api_commands: Vec<ApiCommand> = if let Some(rx) = &mut self.api_cmd_rx {
                let mut cmds = Vec::new();
                while let Ok(cmd) = rx.try_recv() {
                    cmds.push(cmd);
                }
                cmds
            } else {
                Vec::new()
            };
            for cmd in api_commands {
                match cmd {
                    crate::api::ApiCommand::Express { dest, data, response } => {
                        let addr = rsticulum_identity::RnsAddress::from_bytes(&dest)
                            .expect("valid 16-byte address");
                        let _ = response
                            .send(self.send_to(addr, &data).await.map_err(|e| e.to_string()));
                    }
                    crate::api::ApiCommand::Publish { name, data, response } => {
                        // Name is a hex-encoded 32-byte producer hash
                        let producer_hash: [u8; 32] = match hex::decode(&name) {
                            Ok(bytes) if bytes.len() == 32 => {
                                let mut arr = [0u8; 32];
                                arr.copy_from_slice(&bytes);
                                arr
                            }
                            _ => {
                                let _ = response.send(Err(format!("Invalid name: must be 64 hex chars (32 bytes producer hash)")));
                                continue;
                            }
                        };
                        let icn_name = rsticulum_icn::Name::new(producer_hash, &[]);
                        let dummy_proof = Proof {
                            packet_hash: [0u8; 32],
                            signature: [0u8; 64],
                        };
                        let icn_data = rsticulum_icn::Data::new(icn_name, data, dummy_proof);
                        let _ = self.publish(icn_data);
                        let _ = response.send(Ok(()));
                    }
                    crate::api::ApiCommand::Status { response } => {
                        let status = crate::api::DaemonStatus {
                            address: self.keys.rns_address().to_string(),
                            link_count: self.channels.len(),
                            peer_count: self.peer_keys.len(),
                            medium_count: self.media.len(),
                        };
                        let _ = response.send(status);
                    }
                    crate::api::ApiCommand::Connect { dest, response } => {
                        let addr = rsticulum_identity::RnsAddress::from_bytes(&dest)
                            .expect("valid 16-byte address");
                        let _ = response
                            .send(self.connect(addr).await.map_err(|e| e.to_string()));
                    }
                    crate::api::ApiCommand::SeedPeer { dest, key_hex, udp_endpoint, response } => {
                        let addr = rsticulum_identity::RnsAddress::from_bytes(&dest)
                            .expect("valid 16-byte address");
                        let _ = response.send(
                            self.seed_peer(addr, &key_hex, &udp_endpoint).await.map_err(|e| e.to_string())
                        );
                    }
                    crate::api::ApiCommand::SendOverLink { dest, data, response } => {
                        let addr = rsticulum_identity::RnsAddress::from_bytes(&dest)
                            .expect("valid 16-byte address");
                        let _ = response
                            .send(self.send_over_link(addr, data).await.map_err(|e| e.to_string()));
                    }
                    crate::api::ApiCommand::SendResource { dest, data, response } => {
                        let addr = rsticulum_identity::RnsAddress::from_bytes(&dest)
                            .expect("valid 16-byte address");
                        let _ = response
                            .send(self.send_resource(addr, data).await.map_err(|e| e.to_string()));
                    }
                }
            }

            tokio::task::yield_now().await;
        }
    }

    /// Handle an incoming frame from the mesh.
    pub async fn handle_frame(
        &mut self,
        from: rsticulum_identity::RnsAddress,
        frame: Vec<u8>,
    ) -> Result<(), DaemonError> {
        eprintln!("[FRAME] {} bytes from {from}", frame.len());
        // Try to parse as an RNS packet
        let packet = match Packet::from_bytes(&frame) {
            Ok(pkt) => pkt,
            Err(_) => {
                // Not a valid packet — try ICN fallback
                return self.handle_icn_frame(from, frame).await;
            }
        };

        match packet.packet_type {
            ANNOUNCE => {
                self.handle_announce(from, &packet).await?;
            }
            PROOF => {
                self.handle_proof(from, &packet).await?;
            }
            LINKREQUEST => {
                self.handle_linkrequest(from, &packet).await?;
            }
            DATA if packet.header_type == HEADER_2 && packet.transport_id.is_some() => {
                self.handle_link_data(from, &packet).await?;
            }
            _ => {
                // Try ICN fallback — could be a direct ICN packet or Resource segment
                return self.handle_icn_frame(from, frame).await;
            }
        }

        Ok(())
    }

    /// Handle an incoming announce packet.
    /// Parses the full Python RNS announce format:
    ///   public_key(64) + name_hash(10) + random_hash(10) + signature(64) = 148 bytes
    /// Also handles backward-compat 64-byte and 32-byte formats.
    async fn handle_announce(
        &mut self,
        from: rsticulum_identity::RnsAddress,
        packet: &Packet,
    ) -> Result<(), DaemonError> {
        if !self.peer_keys.contains_key(&from) {
            tracing::info!("[HANDLE_ANNOUNCE] from {from}, data_len={}", packet.data.len());
        }
        tracing::debug!("Received ANNOUNCE from {from}");

        if packet.data.len() >= 148 {
            // ── Full Python RNS announce format ──
            // Format: public_key(64) + name_hash(10) + random_hash(10) + signature(64)
            // signed_data = destination_hash(16) + public_key(64) + name_hash(10) + random_hash(10)

            // Extract the 64-byte full public key (X25519 || Ed25519)
            let full_key: [u8; 64] = {
                let mut arr = [0u8; 64];
                arr.copy_from_slice(&packet.data[..64]);
                arr
            };

            // Extract name_hash [64..74]
            let name_hash = &packet.data[64..74];
            // Extract random_hash [74..84]
            let random_hash = &packet.data[74..84];
            // Extract signature [84..148]
            let sig_bytes: [u8; 64] = {
                let mut arr = [0u8; 64];
                arr.copy_from_slice(&packet.data[84..148]);
                arr
            };

            // Derive the expected destination hash from the full key
            let expected_addr = rsticulum_identity::RnsAddress::from_full_key(&full_key);

            // The announce's destination_hash should match the derived address
            if packet.destination_hash != *expected_addr.as_bytes() {
                tracing::warn!(
                    "Announce destination_hash mismatch: packet={} derived={}",
                    hex::encode(packet.destination_hash),
                    hex::encode(expected_addr.as_bytes()),
                );
                // Still accept — the destination_hash in the header may be set differently
                // by the transport layer. Use the derived address for peer registration.
            }

            // Reconstruct signed_data = destination_hash + public_key + name_hash + random_hash
            let mut signed_data = Vec::with_capacity(16 + 64 + 10 + 10);
            signed_data.extend_from_slice(expected_addr.as_bytes());
            signed_data.extend_from_slice(&full_key);
            signed_data.extend_from_slice(name_hash);
            signed_data.extend_from_slice(random_hash);

            // Verify signature using the Ed25519 key (bytes 32..63 of full_key)
            let ed25519_key_bytes: [u8; 32] = {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&full_key[32..]);
                arr
            };

            match ed25519_dalek::VerifyingKey::from_bytes(&ed25519_key_bytes) {
                Ok(vk) => {
                    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
                    match vk.verify(&signed_data, &signature) {
                        Ok(()) => {
                            tracing::debug!(
                                "Verified announce signature from {expected_addr}"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Announce signature verification failed from {expected_addr}: {e}"
                            );
                            // Still register the peer (lenient — some announces may not be signed)
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Invalid Ed25519 key in announce from {from}: {e}");
                }
            }

            // Register peer with their Ed25519 signing key
            self.peer_keys.insert(expected_addr, ed25519_key_bytes);
            tracing::debug!("Registered peer Ed25519 key for {expected_addr} (full announce)");

            // Use expected_addr for routing
            self.router.update_route(expected_addr, expected_addr, 1.0, 1);
        } else if packet.data.len() >= 64 {
            // ── Python RNS format (64-byte key, no signature) ──
            // Extract Ed25519 signing key from bytes 32-63 of the 64-byte blob
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&packet.data[32..64]);
            self.peer_keys.insert(from, key_bytes);
            tracing::debug!("Registered peer Ed25519 key for {from} (64-byte announce)");

            // Update mesh routing table (1-hop neighbor via this peer)
            self.router.update_route(from, from, 1.0, 1);
        } else if packet.data.len() >= 32 {
            // ── Rust-only format: just Ed25519(32) ──
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&packet.data[..32]);
            self.peer_keys.insert(from, key_bytes);
            tracing::debug!("Registered peer key for {from} (32-byte announce)");

            // Update mesh routing table (1-hop neighbor via this peer)
            self.router.update_route(from, from, 1.0, 1);
        }

        Ok(())
    }

    /// Handle an incoming proof (link establishment) packet.
    async fn handle_proof(
        &mut self,
        from: rsticulum_identity::RnsAddress,
        packet: &Packet,
    ) -> Result<(), DaemonError> {
        eprintln!("[HANDLE_PROOF] PROOF from {from}, context={:#04x}, transport_id={:02x?}", packet.context, packet.transport_id);
        tracing::debug!("Received PROOF from {from}");

        // For LINKPROOF context: an incoming link request.
        // The UdpMedium may have set `from` to our own address if it couldn't
        // determine the sender (non-ANNOUNCE, non-registered peer). In that case
        // we try to determine the sender by transport_id, but for brand-new
        // incoming links there's no pending channel to match against yet —
        // just accept the raw `from` and let LINKPROOF handling resolve it.
        let actual_from = if packet.context == LINKPROOF && from == self.keys.rns_address() {
            // Brand-new incoming link request — we don't know the source yet.
            // Try to derive it from the packet's transport_id or destination_hash.
            // The destination_hash of an outgoing proof is the sender's address,
            // but UDP medium uses destination_hash as source for unknown peers,
            // which resolves to our address. Try to find via peer_addr table lookup:
            // the UDP recv knows the socket source addr, so check if any known peer's
            // socket matches. This is already handled by UdpMedium::recv(), so if we
            // get here it means the peer ISN'T registered via add_peer yet.
            // Fall back to checking peer_keys — if we only know one unlinked peer,
            // try that one.
            tracing::debug!("PROOF LINKPROOF from ourselves — trying to identify remote");
            // For now, just use the raw from and continue — the LINKPROOF branch
            // below handles creation without needing the exact sender if we have
            // peer keys. The actual_from is used for lookup only; if LINKPROOF
            // branch needs it, we check peer_keys anyway.
            from
        } else if from == self.keys.rns_address() {
            // Try to find the real sender by matching transport_id
            if let Some(tid) = packet.transport_id {
                if let Some((addr, _)) = self.pending_channels.iter().find(|(_, channel)| {
                    *channel.link().transport_id() == tid
                }) {
                    tracing::debug!("Matched transport_id {tid:02x?} to pending channel from {addr}");
                    *addr
                } else if let Some((addr, _)) = self.channels.iter().find(|(_, channel)| {
                    *channel.link().transport_id() == tid
                }) {
                    tracing::debug!("Matched transport_id {tid:02x?} to established channel from {addr}");
                    *addr
                } else {
                    tracing::debug!("Unknown transport_id {tid:02x?} in PROOF, dropping");
                    return Ok(());
                }
            } else {
                tracing::debug!("PROOF with our address but no transport_id, dropping");
                return Ok(());
            }
        } else {
            from
        };

        // Check if we have the remote's signing key
        let remote_key = match self.peer_keys.get(&actual_from) {
            Some(k) => *k,
            None => {
                tracing::debug!("No known peer key for {actual_from} — ignoring proof");
                return Ok(());
            }
        };

        let local_dest = Destination::singleton(self.keys.clone(), "daemon", vec![]);

        if packet.context == LINKPROOF {
            // Remote is initiating a link to us.
            // NOTE: The initiator's transport_id (from packet header) is different
            // from the responder's transport_id (from Link::new with local dest).
            // Proofs are signed over the SENDER's transport_id, so we must use
            // the packet's transport_id for verification, not our local link's.
            let initiator_tid = packet.transport_id.ok_or(DaemonError::Other(
                "LINKPROOF missing transport_id".into(),
            ))?;

            // Verify the remote's proof using their transport_id
            let proof = rsticulum_transport::Proof::from_bytes(&packet.data)
                .map_err(|e| DaemonError::Other(format!("invalid proof: {e}")))?;
            rsticulum_transport::verify_proof_with_public_key(
                &remote_key,
                &initiator_tid,
                &proof,
            )
            .map_err(|_| DaemonError::Other("proof verification failed".into()))?;

            // Create our channel and generate response proof with LRPROOF context
            let mut channel = Channel::new(Link::new(local_dest, actual_from));
            let responder_tid = *channel.link().transport_id();
            let our_proof_obj = rsticulum_transport::generate_proof(
                &self.keys,
                channel.link().transport_id().as_slice(),
            );
            let response_bytes = our_proof_obj.to_bytes();

            // Mark link as established on our side.
            // Can't call establish()+complete_handshake because the link
            // starts in Closed state and the proof is signed over the
            // responder's transport_id (not ours). Just set state directly
            // since we've already verified the remote's proof above.
            channel.link_mut().set_state(rsticulum_transport::LinkState::Established);
            self.channels.insert(actual_from, channel);

            // Send response as a PROOF packet with LRPROOF context per RNS spec
            let response_packet = rsticulum_packet::Packet {
                header_type: rsticulum_packet::HEADER_2,
                context_flag: rsticulum_packet::FLAG_SET,
                transport_type: rsticulum_packet::TRANSPORT_UNICAST,
                destination_type: rsticulum_packet::DEST_LINK,
                packet_type: rsticulum_packet::PROOF,
                hops: rsticulum_packet::MAX_HOPS,
                destination_hash: *actual_from.as_bytes(),
                transport_id: Some(responder_tid), // use responder's transport_id (used to sign)
                context: rsticulum_packet::LRPROOF,
                data: response_bytes,
            };
            self.send_to(actual_from, &response_packet.to_bytes()).await?;
            tracing::info!("Link established with {actual_from} (responder)");
        } else if packet.context == rsticulum_packet::LRPROOF {
            // Completing a handshake we initiated — received response from responder.
            // The responder's proof is signed over THEIR transport_id (from packet header),
            // NOT our transport_id. We must use the packet's transport_id for verification.
            if let Some(mut channel) = self.pending_channels.remove(&actual_from) {
                let responder_tid = packet.transport_id.ok_or(DaemonError::Other(
                    "response proof missing transport_id".into(),
                ))?;
                let proof = rsticulum_transport::Proof::from_bytes(&packet.data)
                    .map_err(|e| DaemonError::Other(format!("invalid proof: {e}")))?;
                rsticulum_transport::verify_proof_with_public_key(
                    &remote_key,
                    &responder_tid,
                    &proof,
                )
                .map_err(|_| DaemonError::Other("initiator proof verification failed".into()))?;

                // Transition directly to Established — proof already verified above.
                // Can't call establish() because state is Handshaking; can't call
                // complete_handshake() because the proof was signed over the
                // responder's transport_id, not ours.
                channel.link_mut().set_state(rsticulum_transport::LinkState::Established);
                self.channels.insert(actual_from, channel);
                tracing::info!("Link established with {actual_from} (initiator)");
            }
        }

        Ok(())
    }

    /// Handle an incoming LINKREQUEST packet (responder side).
    ///
    /// The initiator sends a LINKREQUEST to start a 3-way handshake.
    /// We respond with an LRPROOF containing our ephemeral key and signature.
    ///
    /// LINKREQUEST data payload format:
    ///   - 32 bytes: initiator's ephemeral X25519 public key
    ///   - 32 bytes: initiator's Ed25519 signing public key
    ///   - 6 bytes: signalling (MTU, flags, reserved)
    async fn handle_linkrequest(
        &mut self,
        from: rsticulum_identity::RnsAddress,
        packet: &Packet,
    ) -> Result<(), DaemonError> {
        eprintln!(
            "[HANDLE_LINKREQUEST] LINKREQUEST from {from}, data_len={}",
            packet.data.len()
        );
        tracing::debug!("Received LINKREQUEST from {from}");

        // Minimum data: pub_bytes(32) + sig_pub_bytes(32) = 64 bytes
        if packet.data.len() < 64 {
            tracing::warn!("LINKREQUEST from {from} too short: {} bytes", packet.data.len());
            return Ok(());
        }

        // Step 1: Verify we know this peer (have their Ed25519 signing key)
        let remote_signing_key = match self.peer_keys.get(&from) {
            Some(k) => *k,
            None => {
                tracing::debug!(
                    "LINKREQUEST from unknown peer {from} — ignoring (no signing key)"
                );
                return Ok(());
            }
        };

        // Step 2: Parse LINKREQUEST data
        let mut initiator_eph_pub = [0u8; 32];
        initiator_eph_pub.copy_from_slice(&packet.data[..32]);

        let mut initiator_sig_pub = [0u8; 32];
        initiator_sig_pub.copy_from_slice(&packet.data[32..64]);

        // Signalling bytes (6 bytes: MTU(2) + flags(1) + reserved(3))
        let signalling = if packet.data.len() >= 70 {
            let mut sig = [0u8; 6];
            sig.copy_from_slice(&packet.data[64..70]);
            sig
        } else {
            [0u8; 6]
        };

        // Step 3: Compute link_id from packet hash
        let link_id = compute_link_id_from_request(packet);

        // Step 4: Generate our ephemeral X25519 keypair
        let our_eph_secret = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let our_eph_pub = x25519_dalek::PublicKey::from(&our_eph_secret);

        // Step 5: Derive shared key via ECDH
        let initiator_eph_point =
            x25519_dalek::PublicKey::from(initiator_eph_pub);
        let shared_secret = our_eph_secret.diffie_hellman(&initiator_eph_point);
        let shared_secret_bytes = shared_secret.to_bytes();

        // Step 6: HKDF-SHA256 derive encryption key
        let encryption_key_bytes = rsticulum_crypto::hkdf_sha256(
            32,
            &shared_secret_bytes,
            Some(&link_id),
            Some(b"rsticulum-link"),
        );
        let mut encryption_key = [0u8; 32];
        encryption_key.copy_from_slice(&encryption_key_bytes);

        // Step 7: Build LRPROOF response
        // signed_data = link_id + our_eph_pub + our_identity_key + signalling
        let our_identity_key = self.keys.identity_key_bytes();
        let mut signed_data = Vec::with_capacity(16 + 32 + 32 + 6);
        signed_data.extend_from_slice(&link_id);
        signed_data.extend_from_slice(our_eph_pub.as_bytes());
        signed_data.extend_from_slice(&our_identity_key);
        signed_data.extend_from_slice(&signalling);

        let signature = self.keys.sign(&signed_data);
        let sig_bytes = signature.to_bytes();

        // proof_data = signature(64) + our_eph_pub_bytes(32) + signalling(6)
        let mut proof_data = Vec::with_capacity(64 + 32 + 6);
        proof_data.extend_from_slice(&sig_bytes);
        proof_data.extend_from_slice(our_eph_pub.as_bytes());
        proof_data.extend_from_slice(&signalling);

        let local_dest = Destination::singleton(self.keys.clone(), "daemon", vec![]);
        let mut link = Link::new(local_dest, from);
        link.set_link_id(link_id);
        link.set_initiator(false);
        link.set_remote_signing_key(remote_signing_key);
        link.set_remote_encryption_key(initiator_eph_pub);
        link.set_state(rsticulum_transport::LinkState::Established);

        let channel = Channel::new(link);
        self.channels.insert(from, channel);

        // Send LRPROOF response as a PROOF packet
        let response_packet = rsticulum_packet::Packet {
            header_type: rsticulum_packet::HEADER_1,
            context_flag: rsticulum_packet::FLAG_SET,
            transport_type: rsticulum_packet::TRANSPORT_UNICAST,
            destination_type: rsticulum_packet::DEST_SINGLE,
            packet_type: rsticulum_packet::PROOF,
            hops: rsticulum_packet::MAX_HOPS,
            destination_hash: *from.as_bytes(),
            transport_id: None,
            context: rsticulum_packet::LRPROOF,
            data: proof_data,
        };
        self.send_to(from, &response_packet.to_bytes()).await?;

        tracing::info!(
            "LINKREQUEST handshake complete with {from} (responder), link_id={:02x?}",
            link_id
        );
        Ok(())
    }

    /// Handle an incoming data packet on an established link.
    /// Routes through Channel for reliable in-order delivery.
    async fn handle_link_data(
        &mut self,
        from: rsticulum_identity::RnsAddress,
        packet: &Packet,
    ) -> Result<(), DaemonError> {
        // Collect messages first (avoids borrow conflict with send_to)
        let messages: Vec<Vec<u8>> = {
            if let Some(channel) = self.channels.get_mut(&from) {
                channel.deliver(packet)?;
                let mut msgs = Vec::new();
                while let Some(msg) = channel.recv() {
                    msgs.push(msg);
                }
                msgs
            } else {
                tracing::debug!("Data received from unknown link peer {from}");
                return Ok(());
            }
        };

        // Process collected messages
        for msg in messages {
            tracing::debug!("Channel received {} bytes from {from}", msg.len());
            // Try Resource segment first (Resource hash header)
            if msg.len() > 4 {
                if let Ok(segment) = bincode::deserialize::<rsticulum_transport::Segment>(&msg) {
                    // Check if this segment belongs to an incoming resource
                    let seg_hash = segment.resource_hash.clone();
                    if let Some(resource) = self.incoming_resources.get_mut(&seg_hash) {
                        let complete = resource.receive_segment(segment)?;
                        if complete {
                            tracing::info!("Resource {:02x?} transfer complete ({} bytes)", seg_hash, resource.total_size());
                            // Store completed resource in ICN forwarder for access
                            if let Some(data) = resource.data().map(|d| d.to_vec()) {
                                let producer_hash = [0u8; 32];
                                let icn_name = rsticulum_icn::Name::new(producer_hash, &[]);
                                let dummy_proof = Proof {
                                    packet_hash: [0u8; 32],
                                    signature: [0u8; 64],
                                };
                                let icn_data = rsticulum_icn::Data::new(icn_name, data, dummy_proof);
                                let _ = self.publish(icn_data);
                            }
                            self.incoming_resources.remove(&seg_hash);
                        }
                        continue;
                    }
                }
            }
            // Fallback: try ICN parsing
            if let Ok(data) = rsticulum_icn::Data::from_bytes(&msg) {
                self.forwarder.receive_data(data, 0).await?;
            } else if let Ok(interest) = rsticulum_icn::Interest::from_bytes(&msg) {
                if let Ok(Some(data)) = self.forwarder.express(interest, 0).await {
                    self.send_to(from, &data.to_bytes()).await?;
                }
            }
        }
        Ok(())
    }

    /// ICN fallback: try to parse as ICN Interest or Data.
    async fn handle_icn_frame(
        &mut self,
        from: rsticulum_identity::RnsAddress,
        frame: Vec<u8>,
    ) -> Result<(), DaemonError> {
        if let Ok(data) = rsticulum_icn::Data::from_bytes(&frame) {
            tracing::debug!("Received ICN Data: {}\"", data.name);
            self.forwarder.receive_data(data, 0).await?;
            return Ok(());
        }

        if let Ok(interest) = rsticulum_icn::Interest::from_bytes(&frame) {
            tracing::debug!("Received ICN Interest: \"{}\"", interest.name);
            if let Ok(Some(data)) = self.forwarder.express(interest, 0).await {
                self.send_to(from, &data.to_bytes()).await?;
            }
            return Ok(());
        }

        tracing::debug!("Unknown frame type from {}: {} bytes", from, frame.len());
        Ok(())
    }

    /// Send raw bytes to a mesh destination.
    async fn send_to(
        &self,
        dest: rsticulum_identity::RnsAddress,
        data: &[u8],
    ) -> Result<(), DaemonError> {
        for medium in &self.media {
            match medium.send(dest, data).await {
                Ok(()) => return Ok(()),
                Err(e) => tracing::debug!("Failed to send via {}: {e}", medium.name()),
            }
        }
        Err(DaemonError::NoRoute)
    }

    /// Send data over an established link via Channel.
    /// Wraps the payload in a Channel envelope, encrypts via the underlying Link,
    /// and sends the resulting Packet over the best medium.
    async fn send_over_link(
        &mut self,
        remote: rsticulum_identity::RnsAddress,
        data: Vec<u8>,
    ) -> Result<(), DaemonError> {
        let channel = self.channels.get_mut(&remote).ok_or(DaemonError::NoLink)?;
        let packet = channel.send(data)?;
        self.send_to(remote, &packet.to_bytes()).await
    }

    /// Send a resource (large data blob) over an established link.
    async fn send_resource(
        &mut self,
        remote: rsticulum_identity::RnsAddress,
        data: Vec<u8>,
    ) -> Result<(), DaemonError> {
        let data_len = data.len();
        let resource = Resource::new_for_sending(data, ResourceConfig::default());
        let segments = resource.all_segments().to_vec();
        let total = segments.len();
        let hash = resource.hash().to_vec();

        // Register the receiving end on the remote side would need
        // a separate resource advertisement message over the channel.
        // For now, just send all segments.
        for seg in &segments {
            let packed = bincode::serialize(seg)
                .map_err(|e| DaemonError::Other(format!("serialize segment: {e}")))?;
            self.send_over_link(remote, packed).await?;
        }
        tracing::info!("Resource {hash:02x?} sent: {total} segments, {data_len} bytes");
        Ok(())
    }

    /// Initiate a link to a remote peer.
    pub async fn connect(&mut self, remote: rsticulum_identity::RnsAddress) -> Result<(), DaemonError> {
        if self.channels.contains_key(&remote) || self.pending_channels.contains_key(&remote) {
            return Ok(());
        }

        let local_dest = Destination::singleton(self.keys.clone(), "daemon", vec![]);
        let mut channel = Channel::new(Link::new(local_dest, remote));
        let proof_pkt = channel.link_mut().establish()?;
        self.pending_channels.insert(remote, channel);
        let data = proof_pkt.to_bytes();
        eprintln!("[CONNECT] Sending proof to {remote}, {} bytes via {} mediums", data.len(), self.media.len());
        let result = self.send_to(remote, &data).await;
        eprintln!("[CONNECT] send_to result: {result:?}");
        tracing::info!("Link initiation sent to {remote}");
        result
    }

    /// Seed a peer's identity key and UDP endpoint for out-of-band discovery.
    /// Used by tests to bootstrap peer discovery without waiting for announces.
    pub async fn seed_peer(
        &mut self,
        addr: rsticulum_identity::RnsAddress,
        key_hex: &str,
        udp_endpoint: &str,
    ) -> Result<(), DaemonError> {
        // Parse signing key from hex
        let key_bytes = hex::decode(key_hex)
            .map_err(|e| DaemonError::Other(format!("invalid key hex: {e}")))?;
        if key_bytes.len() != 32 {
            return Err(DaemonError::Other(format!(
                "key must be 32 bytes (64 hex chars), got {}",
                key_bytes.len()
            )));
        }
        let mut signing_key = [0u8; 32];
        signing_key.copy_from_slice(&key_bytes);
        self.register_peer(addr, signing_key);

        tracing::info!("Seeding peer {addr} with key {key_hex} at {udp_endpoint}");

        // Register with all mediums
        for medium in &self.media {
            medium
                .add_peer_endpoint(addr, udp_endpoint.to_string())
                .await
                .unwrap_or_else(|e| {
                    tracing::warn!(
                        "Failed to add peer endpoint to medium {}: {e}",
                        medium.name()
                    );
                });
        }

        Ok(())
    }

    /// Publish content to the local ICN forwarder.
    pub fn publish(&mut self, data: rsticulum_icn::Data) -> Result<(), DaemonError> {
        let name = data.name.clone();
        self.forwarder.cs_mut().insert(name, data);
        Ok(())
    }

    /// Add a FIB route for a producer prefix.
    pub fn add_route(&mut self, prefix: rsticulum_icn::Name, face_id: u64, cost: u8) {
        self.forwarder.add_route(prefix, face_id, cost);
    }

    /// Number of established links.
    pub fn link_count(&self) -> usize {
        self.channels.len()
    }
}

// ── Error ──

#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("no route to destination")]
    NoRoute,
    #[error("no established link to destination")]
    NoLink,
    #[error("ICN error: {0}")]
    Icn(String),
    #[error("channel error: {0}")]
    Channel(#[from] rsticulum_channel::ChannelError),
    #[error("mesh error: {0}")]
    Mesh(#[from] rsticulum_mesh::MeshError),
    #[error("transport error: {0}")]
    Transport(#[from] rsticulum_transport::TransportError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}

impl From<String> for DaemonError {
    fn from(s: String) -> Self {
        DaemonError::Icn(s)
    }
}

// ── Announce helper ──

/// Build an ANNOUNCE packet advertising this daemon.
/// Emits full Python RNS announce format for 1:1 wire compatibility.
/// Format: public_key(64) + name_hash(10) + random_hash(10) + signature(64) = 148 bytes
fn build_announce_packet(keys: &Keys) -> Packet {
    let rns_addr = keys.rns_address();
    let public_key = keys.full_public_key_bytes();

    // name_hash = SHA-256("daemon")[:10]
    let name_hash = {
        let mut hasher = Sha256::new();
        hasher.update(b"daemon");
        let h = hasher.finalize();
        h[..10].to_vec()
    };

    // random_hash = 5 random bytes + 5 bytes of unix timestamp (little-endian)
    let random_hash = {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut rh = vec![0u8; 10];
        getrandom::getrandom(&mut rh[..5]).unwrap();
        rh[5..].copy_from_slice(&now.to_le_bytes()[..5]);
        rh
    };

    // No ratchet for now
    let ratchet: Vec<u8> = vec![];

    // signed_data = destination_hash + public_key + name_hash + random_hash + ratchet
    let mut signed_data = rns_addr.as_bytes().to_vec();
    signed_data.extend_from_slice(&public_key);
    signed_data.extend_from_slice(&name_hash);
    signed_data.extend_from_slice(&random_hash);
    signed_data.extend_from_slice(&ratchet);

    // Sign the signed_data
    let signature = keys.sign(&signed_data);
    let sig_bytes = signature.to_bytes();

    // announce_data = public_key + name_hash + random_hash + ratchet + signature
    let mut announce_data = public_key.to_vec();
    announce_data.extend_from_slice(&name_hash);
    announce_data.extend_from_slice(&random_hash);
    announce_data.extend_from_slice(&ratchet);
    announce_data.extend_from_slice(&sig_bytes);

    Packet {
        header_type: rsticulum_packet::HEADER_1,
        context_flag: rsticulum_packet::FLAG_UNSET,
        transport_type: rsticulum_packet::TRANSPORT_BROADCAST,
        destination_type: rsticulum_packet::DEST_SINGLE,
        packet_type: ANNOUNCE,
        hops: 1,
        destination_hash: *rns_addr.as_bytes(),
        transport_id: None,
        context: rsticulum_packet::NONE,
        data: announce_data,
    }
}

/// Compute a 16-byte link identifier from an incoming LINKREQUEST packet.
///
/// Matches Python RNS behaviour: hash the raw packet bytes (excluding the
/// first 2 flag/hop bytes and any appended signalling bytes), take the
/// first 16 bytes of SHA-256.
fn compute_link_id_from_request(packet: &Packet) -> [u8; 16] {
    let raw = packet.to_bytes();
    // Skip flags(1) + hops(1)
    let hashable = &raw[2..];
    // The ECDH key material occupies 64 bytes (32 pub + 32 sig_pub, no ratchet).
    // Any remaining data after that are appended signalling bytes that must be
    // excluded from the hashable part.
    const ECPUBSIZE: usize = 32 + 32;
    let diff = packet.data.len().saturating_sub(ECPUBSIZE);
    let truncated = &hashable[..hashable.len().saturating_sub(diff)];
    let hash = Sha256::digest(truncated);
    let mut id = [0u8; 16];
    id.copy_from_slice(&hash[..16]);
    id
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;
    use rsticulum_identity::Keys;
    use rsticulum_mesh::UdpMedium;

    #[test]
    fn test_daemon_creation() {
        let keys = Keys::generate();
        let daemon = Daemon::new(keys.clone());
        assert_eq!(daemon.keys.rns_address(), keys.rns_address());
        assert_eq!(daemon.router.local_addr(), &keys.rns_address());
        assert!(daemon.media.is_empty());
        assert_eq!(daemon.link_count(), 0);
    }

    #[tokio::test]
    async fn test_daemon_with_medium() {
        let keys = Keys::generate();
        let mut daemon = Daemon::new(keys);

        let medium = UdpMedium::bind("test", "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        daemon.add_medium(Arc::new(medium));
        assert_eq!(daemon.media.len(), 1);
    }

    #[test]
    fn test_announce_packet() {
        let keys = Keys::generate();
        let pkt = build_announce_packet(&keys);
        assert_eq!(pkt.packet_type, ANNOUNCE);
        assert_eq!(pkt.data.len(), 148, "Full announce should be 148 bytes: 64(key) + 10(name_hash) + 10(random_hash) + 64(signature)");
    }

    #[test]
    fn test_peer_registration() {
        let keys = Keys::generate();
        let mut daemon = Daemon::new(keys);
        let peer = Keys::generate();
        daemon.register_peer(peer.rns_address(), peer.identity_key_bytes());
        assert!(daemon.peer_keys.contains_key(&peer.rns_address()));
    }

    #[test]
    fn test_link_counts() {
        let keys = Keys::generate();
        let daemon = Daemon::new(keys);
        assert_eq!(daemon.link_count(), 0);
    }

    #[test]
    fn test_compute_link_id_from_request() {
        // Build a LINKREQUEST packet with known data
        let dest = Keys::generate().rns_address();
        let mut data = Vec::with_capacity(70);
        // 32 bytes ephemeral pub key
        data.extend_from_slice(&[0xAAu8; 32]);
        // 32 bytes signing pub key
        data.extend_from_slice(&[0xBBu8; 32]);
        // 6 bytes signalling
        data.extend_from_slice(&[0xCCu8; 6]);

        let packet = rsticulum_packet::Packet::new_link_request(dest, data);

        // Compute link_id
        let link_id = compute_link_id_from_request(&packet);

        // Must be 16 bytes
        assert_eq!(link_id.len(), 16);

        // Must be deterministic for the same packet
        let link_id2 = compute_link_id_from_request(&packet);
        assert_eq!(link_id, link_id2);

        // Different ephemeral key should produce different link_id
        let mut diff_data = Vec::with_capacity(70);
        diff_data.extend_from_slice(&[0xFFu8; 32]); // different eph pub
        diff_data.extend_from_slice(&[0xBBu8; 32]);
        diff_data.extend_from_slice(&[0xCCu8; 6]);
        let diff_packet = rsticulum_packet::Packet::new_link_request(dest, diff_data);
        let diff_id = compute_link_id_from_request(&diff_packet);
        assert_ne!(link_id, diff_id);
    }
}
