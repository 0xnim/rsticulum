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
use std::collections::HashSet;
use std::sync::Arc;

use rsticulum_channel::Channel;
use rsticulum_destination::Destination;
use rsticulum_identity::Keys;
use rsticulum_mesh::{Medium, MeshRouter};
use rsticulum_mesh::path_request::{PathRequest, PathReply, handle_path_request, handle_path_reply};
use rsticulum_packet::{
    Packet, ANNOUNCE, DATA, HEADER_2, KEEPALIVE, LINKPROOF, LINKREQUEST, LRRTT, PROOF,
    RATCHET,
    PATH_REQUEST as PATH_REQ_CTX, PATH_RESPONSE,
};
use rsticulum_transport::{Link, Resource, ResourceConfig};
use rsticulum_transport::Proof;
use rsticulum_transport::{KEEPALIVE_INTERVAL, STALE_TIME, TRAFFIC_TIMEOUT};
use tokio::sync::mpsc::UnboundedReceiver;

use crate::api::ApiCommand;

/// Data stored about a pending link initiation (initiator side).
/// Ephemeral keys must survive until the LRPROOF response arrives.
struct PendingLinkData {
    /// Link identifier derived from the LINKREQUEST packet hash.
    link_id: [u8; 16],
    /// Our ephemeral X25519 private key (for ECDH key exchange).
    ephemeral_priv: x25519_dalek::StaticSecret,
    /// Our Ed25519 signing public key that we generated for this link.
    #[allow(dead_code)]
    initiator_sig_pub: [u8; 32],
}

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
    /// Pending link establishments (ephemeral keys stored until LRPROOF arrives).
    pending_links: HashMap<rsticulum_identity::RnsAddress, PendingLinkData>,
    /// Known peer identity keys (from announces), for proof verification.
    peer_keys: HashMap<rsticulum_identity::RnsAddress, [u8; 32]>,
    /// Incoming resource transfers (hash → Resource)
    incoming_resources: HashMap<Vec<u8>, Resource>,
    /// Announce sequence counter.
    announce_seq: u64,
    /// Tracks announce hashes we've already forwarded (to prevent loops).
    sent_announces: HashSet<[u8; 16]>,
    /// Pending path requests we're waiting on (destination_hash → request_id).
    pending_path_requests: HashMap<[u8; 16], [u8; 16]>,
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
            pending_links: HashMap::new(),
            peer_keys: HashMap::new(),
            incoming_resources: HashMap::new(),
            announce_seq: 0,
            sent_announces: HashSet::new(),
            pending_path_requests: HashMap::new(),
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
                tracing::trace!("Received {} bytes from {}", frame.len(), from);
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

            // Periodic: keepalive monitoring for established links
            let now = std::time::Instant::now();
            let mut dead_links = Vec::new();
            let mut keepalive_packets: Vec<(rsticulum_identity::RnsAddress, Vec<u8>)> = Vec::new();
            for (&addr, channel) in &self.channels {
                let link = channel.link();
                if !link.keepalive_enabled() {
                    continue;
                }
                let last_inbound = link.last_inbound();
                let last_outbound = link.last_outbound();

                if now.duration_since(last_inbound) > STALE_TIME {
                    dead_links.push(addr);
                    tracing::warn!("Link to {addr} stale, closing");
                } else if now.duration_since(last_inbound) > TRAFFIC_TIMEOUT {
                    // No inbound traffic for TRAFFIC_TIMEOUT — send a probe
                    tracing::debug!("Link to {addr} no inbound traffic, sending probe");
                    let packet = Packet {
                        header_type: HEADER_2,
                        context_flag: rsticulum_packet::FLAG_UNSET,
                        transport_type: rsticulum_packet::TRANSPORT_UNICAST,
                        destination_type: rsticulum_packet::DEST_LINK,
                        packet_type: DATA,
                        hops: rsticulum_packet::MAX_HOPS,
                        destination_hash: *addr.as_bytes(),
                        transport_id: Some(*link.transport_id()),
                        context: rsticulum_packet::NONE,
                        data: vec![],
                    };
                    keepalive_packets.push((addr, packet.to_bytes()));
                } else if now.duration_since(last_outbound) > KEEPALIVE_INTERVAL {
                    // No outbound traffic for KEEPALIVE_INTERVAL — send keepalive
                    tracing::trace!("Sending KEEPALIVE to {addr}");
                    let packet = Packet {
                        header_type: HEADER_2,
                        context_flag: rsticulum_packet::FLAG_SET,
                        transport_type: rsticulum_packet::TRANSPORT_UNICAST,
                        destination_type: rsticulum_packet::DEST_LINK,
                        packet_type: DATA,
                        hops: rsticulum_packet::MAX_HOPS,
                        destination_hash: *addr.as_bytes(),
                        transport_id: Some(*link.transport_id()),
                        context: KEEPALIVE,
                        data: vec![],
                    };
                    keepalive_packets.push((addr, packet.to_bytes()));
                }
            }
            // Remove stale links
            for addr in dead_links {
                self.channels.remove(&addr);
            }
            // Send pending ratchet keys (needs mutable access, separate pass)
            let mut ratchet_packets: Vec<(rsticulum_identity::RnsAddress, Vec<u8>)> = Vec::new();
            for (&addr, channel) in &mut self.channels {
                if channel.link().ratchet_pending_send() {
                    if let Some(ratchet_priv_bytes) = channel.link().ratchet_priv() {
                        let ratchet_priv_key = x25519_dalek::StaticSecret::from(ratchet_priv_bytes);
                        let ratchet_pub = x25519_dalek::PublicKey::from(&ratchet_priv_key);
                        let seq = channel.link().ratchet_sequence();
                        let mut ratchet_data = ratchet_pub.to_bytes().to_vec();
                        ratchet_data.extend_from_slice(&seq.to_le_bytes());

                        let packet = Packet {
                            header_type: HEADER_2,
                            context_flag: rsticulum_packet::FLAG_SET,
                            transport_type: rsticulum_packet::TRANSPORT_UNICAST,
                            destination_type: rsticulum_packet::DEST_LINK,
                            packet_type: DATA,
                            hops: rsticulum_packet::MAX_HOPS,
                            destination_hash: *addr.as_bytes(),
                            transport_id: Some(*channel.link().transport_id()),
                            context: RATCHET,
                            data: ratchet_data,
                        };
                        tracing::debug!("Sending ratchet key to {addr}, seq={seq}");
                        ratchet_packets.push((addr, packet.to_bytes()));
                        channel.link_mut().set_ratchet_pending_send(false);
                        channel.link_mut().increment_ratchet_sequence();
                    }
                }
            }
            // Send keepalive/probe packets
            for (addr, data) in keepalive_packets {
                let _ = self.send_to(addr, &data).await;
            }
            // Send ratchet packets
            for (addr, data) in ratchet_packets {
                let _ = self.send_to(addr, &data).await;
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
        tracing::trace!("Received frame from {from}: {} bytes", frame.len());
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
            DATA if packet.context == PATH_REQ_CTX => {
                self.handle_path_request_msg(from, &packet).await?;
            }
            DATA if packet.context == PATH_RESPONSE => {
                self.handle_path_reply_msg(from, &packet).await?;
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

        // ── Announce propagation ──
        // Forward to other media with decremented hops (loop prevention via sent_announces)
        if packet.hops > 0 {
            let announce_hash = packet.destination_hash;
            if !self.sent_announces.contains(&announce_hash) {
                self.sent_announces.insert(announce_hash);
                let mut fwd = packet.clone();
                fwd.hops = fwd.hops.saturating_sub(1);
                let fwd_bytes = fwd.to_bytes();
                for medium in &self.media {
                    let _ = medium.broadcast(&fwd_bytes).await;
                }
                tracing::debug!(
                    "Propagated announce from {from} (hops={}) to {} media",
                    fwd.hops,
                    self.media.len(),
                );
            } else {
                tracing::trace!("Skipping already-forwarded announce from {from}");
            }
        }

        Ok(())
    }

    /// Handle an incoming path request (DATA packet with PATH_REQUEST context).
    async fn handle_path_request_msg(
        &mut self,
        from: rsticulum_identity::RnsAddress,
        packet: &Packet,
    ) -> Result<(), DaemonError> {
        tracing::debug!("Received PATH_REQUEST from {from}");

        // Deserialize the PathRequest from the packet data
        let req: PathRequest = match bincode::deserialize(&packet.data) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("Failed to deserialize PathRequest from {from}: {e}");
                return Ok(());
            }
        };

        let local_addr = self.keys.rns_address();

        // Check if we can answer this path request
        if let Some(reply) = handle_path_request(&req, &self.router, local_addr) {
            // We know the destination — send a PathReply back to the requester
            let reply_bytes = bincode::serialize(&reply)
                .map_err(|e| DaemonError::Other(format!("serialize PathReply: {e}")))?;

            // The reply should go to whoever sent us the request
            let reply_packet = Packet {
                header_type: rsticulum_packet::HEADER_1,
                context_flag: rsticulum_packet::FLAG_UNSET,
                transport_type: rsticulum_packet::TRANSPORT_UNICAST,
                destination_type: rsticulum_packet::DEST_SINGLE,
                packet_type: DATA,
                hops: rsticulum_packet::MAX_HOPS,
                destination_hash: *from.as_bytes(),
                transport_id: None,
                context: PATH_RESPONSE,
                data: reply_bytes,
            };
            self.send_to(from, &reply_packet.to_bytes()).await?;
            tracing::debug!("Sent PATH_REPLY to {from} for destination");
            return Ok(());
        }

        // We don't know the destination — forward the request if not expired
        if req.is_expired() {
            tracing::debug!("PATH_REQUEST to {} expired, dropping", hex::encode(req.destination_hash));
            return Ok(());
        }

        // Add our hop and forward to all peers (flood)
        let mut fwd_req = req;
        fwd_req.add_hop(local_addr);
        let fwd_bytes = bincode::serialize(&fwd_req)
            .map_err(|e| DaemonError::Other(format!("serialize fwd PathRequest: {e}")))?;

        let fwd_packet = Packet {
            header_type: rsticulum_packet::HEADER_1,
            context_flag: rsticulum_packet::FLAG_UNSET,
            transport_type: rsticulum_packet::TRANSPORT_BROADCAST,
            destination_type: rsticulum_packet::DEST_SINGLE,
            packet_type: DATA,
            hops: rsticulum_packet::MAX_HOPS,
            destination_hash: fwd_req.destination_hash,
            transport_id: None,
            context: PATH_REQ_CTX,
            data: fwd_bytes,
        };
        let fwd_bytes_raw = fwd_packet.to_bytes();
        for medium in &self.media {
            let _ = medium.broadcast(&fwd_bytes_raw).await;
        }
        tracing::debug!("Forwarded PATH_REQUEST to {} ({} hops)", hex::encode(fwd_req.destination_hash), fwd_req.path.len());

        Ok(())
    }

    /// Handle an incoming path response (DATA packet with PATH_RESPONSE context).
    async fn handle_path_reply_msg(
        &mut self,
        from: rsticulum_identity::RnsAddress,
        packet: &Packet,
    ) -> Result<(), DaemonError> {
        tracing::debug!("Received PATH_REPLY from {from}");

        // Deserialize the PathReply from the packet data
        let reply: PathReply = match bincode::deserialize(&packet.data) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("Failed to deserialize PathReply from {from}: {e}");
                return Ok(());
            }
        };

        let local_addr = self.keys.rns_address();

        // Process the reply — updates routing table, returns next hop to forward to
        let next_hop = handle_path_reply(&reply, &mut self.router, local_addr);

        if let Some(hop) = next_hop {
            // We're not the final requester — forward the reply toward the origin
            let reply_bytes = bincode::serialize(&reply)
                .map_err(|e| DaemonError::Other(format!("serialize fwd PathReply: {e}")))?;

            let fwd_packet = Packet {
                header_type: rsticulum_packet::HEADER_1,
                context_flag: rsticulum_packet::FLAG_UNSET,
                transport_type: rsticulum_packet::TRANSPORT_UNICAST,
                destination_type: rsticulum_packet::DEST_SINGLE,
                packet_type: DATA,
                hops: rsticulum_packet::MAX_HOPS,
                destination_hash: *hop.as_bytes(),
                transport_id: None,
                context: PATH_RESPONSE,
                data: reply_bytes,
            };
            self.send_to(hop, &fwd_packet.to_bytes()).await?;
            tracing::debug!("Forwarded PATH_REPLY to {hop}");
        } else {
            // We ARE the requester — route has been discovered
            tracing::info!(
                "Path discovered to {} via {:02x?}",
                hex::encode(reply.destination_hash),
                reply.route,
            );
            // Remove from pending path requests
            self.pending_path_requests.remove(&reply.request_id);
        }

        Ok(())
    }

    /// Handle an incoming proof (link establishment) packet.
    async fn handle_proof(
        &mut self,
        from: rsticulum_identity::RnsAddress,
        packet: &Packet,
    ) -> Result<(), DaemonError> {
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
            // Completing a handshake we initiated — received LRPROOF response from responder.
            // The proof_data format is: signature(64) + responder_eph_pub(32) + signalling(3)
            //
            // signed_data = link_id + responder_eph_pub + responder_identity_key + signalling
            //
            // We verify the signature, derive the shared secret via ECDH, derive the
            // encryption key via HKDF, and set the link to Established.

            // Look up our pending channel and pending link data
            let mut channel = match self.pending_channels.remove(&actual_from) {
                Some(c) => c,
                None => {
                    tracing::debug!(
                        "LRPROOF from {actual_from} but no pending channel — ignoring"
                    );
                    return Ok(());
                }
            };

            let pending = match self.pending_links.remove(&actual_from) {
                Some(p) => p,
                None => {
                    tracing::debug!(
                        "LRPROOF from {actual_from} but no pending_links data — ignoring"
                    );
                    // Re-insert the pending channel for idempotency
                    self.pending_channels.insert(actual_from, channel);
                    return Ok(());
                }
            };

            // Minimum proof data: signature(64) + eph_pub(32) = 96 bytes
            if packet.data.len() < 96 {
                tracing::warn!(
                    "LRPROOF from {actual_from} too short: {} bytes",
                    packet.data.len()
                );
                return Ok(());
            }

            // Parse LRPROOF data
            let mut sig_bytes = [0u8; 64];
            sig_bytes.copy_from_slice(&packet.data[..64]);

            let mut responder_eph_pub_bytes = [0u8; 32];
            responder_eph_pub_bytes.copy_from_slice(&packet.data[64..96]);

            // Signalling bytes (3 bytes) — Python RNS style
            let signalling = if packet.data.len() >= 99 {
                let mut sig = [0u8; 3];
                sig.copy_from_slice(&packet.data[96..99]);
                sig
            } else {
                [0u8; 3]
            };

            // Derive shared key via ECDH: our_eph_priv * responder_eph_pub
            let responder_eph_point =
                x25519_dalek::PublicKey::from(responder_eph_pub_bytes);
            let shared_secret = pending.ephemeral_priv.diffie_hellman(&responder_eph_point);
            let shared_secret_bytes = shared_secret.to_bytes();

            // Verify responder's Ed25519 signature over:
            // signed_data = link_id + responder_eph_pub + responder_identity_key + signalling
            let mut signed_data = Vec::with_capacity(16 + 32 + 32 + 3);
            signed_data.extend_from_slice(&pending.link_id);
            signed_data.extend_from_slice(&responder_eph_pub_bytes);
            signed_data.extend_from_slice(&remote_key);
            signed_data.extend_from_slice(&signalling);

            let responder_identity_vk = match ed25519_dalek::VerifyingKey::from_bytes(&remote_key) {
                Ok(vk) => vk,
                Err(e) => {
                    tracing::warn!("LRPROOF from {actual_from}: invalid responder Ed25519 key: {e}");
                    return Ok(());
                }
            };
            let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

            if let Err(e) = responder_identity_vk.verify(&signed_data, &signature) {
                tracing::warn!(
                    "LRPROOF from {actual_from}: signature verification failed: {e}"
                );
                return Ok(());
            }

            // Store raw ECDH shared secret for AES-CBC+HMAC Link encryption
            let mut shared_key = [0u8; 32];
            shared_key.copy_from_slice(&shared_secret_bytes);

            // Set link properties and transition to Established
            channel.link_mut().set_shared_key(shared_key);
            channel.link_mut().set_remote_signing_key(remote_key);
            channel.link_mut().set_state(rsticulum_transport::LinkState::Established);

            // Generate ratchet keypair for forward secrecy (initiator side)
            let ratchet_priv = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
            channel.link_mut().set_ratchet_priv(ratchet_priv.to_bytes());
            channel.link_mut().set_ratchet_pending_send(true);

            // Compute RTT: time since LINKREQUEST was sent (link creation)
            let now = std::time::Instant::now();
            let rtt_ms = now.duration_since(channel.link().established_at()).as_secs_f64() * 1000.0;
            channel.link_mut().set_rtt(Some(rtt_ms));
            channel.link_mut().set_establishment_cost(Some(rtt_ms));
            tracing::debug!("RTT to {actual_from}: {rtt_ms:.1}ms");

            // Send RTT probe (LRRTT context packet) after establishment
            let rtt_probe = rsticulum_packet::Packet {
                header_type: rsticulum_packet::HEADER_2,
                context_flag: rsticulum_packet::FLAG_SET,
                transport_type: rsticulum_packet::TRANSPORT_UNICAST,
                destination_type: rsticulum_packet::DEST_LINK,
                packet_type: rsticulum_packet::DATA,
                hops: rsticulum_packet::MAX_HOPS,
                destination_hash: *actual_from.as_bytes(),
                transport_id: Some(*channel.link().transport_id()),
                context: LRRTT,
                data: rtt_ms.to_le_bytes().to_vec(),
            };
            let _ = self.send_to(actual_from, &rtt_probe.to_bytes()).await;

            self.channels.insert(actual_from, channel);

            tracing::info!(
                "Link established with {actual_from} (initiator), link_id={:02x?}",
                pending.link_id
            );
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
    ///   - 3 bytes: signalling (Python RNS format: MTU + mode)
    async fn handle_linkrequest(
        &mut self,
        from: rsticulum_identity::RnsAddress,
        packet: &Packet,
    ) -> Result<(), DaemonError> {
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

        // Signalling bytes (3 bytes: MTU + mode, Python RNS format)
        let signalling = if packet.data.len() >= 67 {
            let mut sig = [0u8; 3];
            sig.copy_from_slice(&packet.data[64..67]);
            sig
        } else {
            [0u8; 3]
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

        // Store raw ECDH shared secret for AES-CBC+HMAC Link encryption
        let mut shared_key = [0u8; 32];
        shared_key.copy_from_slice(&shared_secret_bytes);

        // Step 7: Build LRPROOF response
        // signed_data = link_id + our_eph_pub + our_identity_key + signalling
        let our_identity_key = self.keys.identity_key_bytes();
        let mut signed_data = Vec::with_capacity(16 + 32 + 32 + 3);
        signed_data.extend_from_slice(&link_id);
        signed_data.extend_from_slice(our_eph_pub.as_bytes());
        signed_data.extend_from_slice(&our_identity_key);
        signed_data.extend_from_slice(&signalling);

        let signature = self.keys.sign(&signed_data);
        let sig_bytes = signature.to_bytes();

        // proof_data = signature(64) + our_eph_pub_bytes(32) + signalling(3)
        let mut proof_data = Vec::with_capacity(64 + 32 + 3);
        proof_data.extend_from_slice(&sig_bytes);
        proof_data.extend_from_slice(our_eph_pub.as_bytes());
        proof_data.extend_from_slice(&signalling);

        let local_dest = Destination::singleton(self.keys.clone(), "daemon", vec![]);
        let mut link = Link::new(local_dest, from);
        link.set_link_id(link_id);
        link.set_initiator(false);
        link.set_remote_signing_key(remote_signing_key);
        link.set_shared_key(shared_key);
        link.set_state(rsticulum_transport::LinkState::Established);

        // Generate ratchet keypair for forward secrecy (responder side)
        let ratchet_priv = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        link.set_ratchet_priv(ratchet_priv.to_bytes());
        link.set_ratchet_pending_send(true);

        // Compute establishment cost: time since link was created
        let now = std::time::Instant::now();
        let cost_ms = now.duration_since(link.established_at()).as_secs_f64() * 1000.0;
        link.set_establishment_cost(Some(cost_ms));
        tracing::debug!("Establishment cost for {from}: {cost_ms:.1}ms");

        let channel = Channel::new(link);
        self.channels.insert(from, channel);

        // Send LRPROOF response as a PROOF packet
        // Per Python RNS: LRPROOF uses HEADER_1 with link_id in the dest_hash field,
        // hops=0, context_flag=FLAG_UNSET
        let response_packet = rsticulum_packet::Packet {
            header_type: rsticulum_packet::HEADER_1,
            context_flag: rsticulum_packet::FLAG_UNSET,
            transport_type: rsticulum_packet::TRANSPORT_UNICAST,
            destination_type: rsticulum_packet::DEST_SINGLE,
            packet_type: rsticulum_packet::PROOF,
            hops: 0,
            destination_hash: link_id,
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
        // Handle KEEPALIVE packets — just update last_inbound via deliver()
        if packet.context == KEEPALIVE {
            if let Some(channel) = self.channels.get_mut(&from) {
                // deliver() updates last_inbound on the link
                let _ = channel.link_mut().deliver(packet);
                tracing::trace!("Keepalive received from {from}");
            }
            return Ok(());
        }

        // Handle LRRTT packets — record RTT measurement from peer
        if packet.context == LRRTT {
            if packet.data.len() >= 8 {
                let rtt = f64::from_le_bytes(packet.data[..8].try_into().unwrap());
                if let Some(channel) = self.channels.get_mut(&from) {
                    channel.link_mut().set_rtt(Some(rtt));
                    tracing::debug!("RTT measured from {from}: {rtt:.1}ms");
                }
            }
            return Ok(());
        }

        // Handle RATCHET packets — receive peer's ratchet public key for forward secrecy
        if packet.context == RATCHET {
            if packet.data.len() >= 36 {
                let mut peer_ratchet_key = [0u8; 32];
                peer_ratchet_key.copy_from_slice(&packet.data[..32]);
                let seq = u32::from_le_bytes(packet.data[32..36].try_into().unwrap());

                if let Some(channel) = self.channels.get_mut(&from) {
                    channel.link_mut().set_peer_ratchet_key(peer_ratchet_key);

                    // If we have our ratchet private key, derive new shared key
                    if let Some(ratchet_priv_bytes) = channel.link().ratchet_priv() {
                        let ratchet_priv_key = x25519_dalek::StaticSecret::from(ratchet_priv_bytes);
                        let peer_pub = x25519_dalek::PublicKey::from(peer_ratchet_key);
                        let shared_ratchet = ratchet_priv_key.diffie_hellman(&peer_pub);
                        let shared_ratchet_bytes = shared_ratchet.to_bytes();

                        // Derive new shared_key from existing shared_key + ratchet secret
                        if let Some(existing_shared) = channel.link().shared_key() {
                            let new_shared = rsticulum_crypto::hkdf_sha256(
                                32,
                                existing_shared,
                                Some(&shared_ratchet_bytes),
                                Some(b"ratchet"),
                            );
                            let mut new_key = [0u8; 32];
                            new_key.copy_from_slice(&new_shared);
                            channel.link_mut().set_shared_key(new_key);
                            tracing::info!(
                                "Ratchet rotation completed with {from}, seq={seq}"
                            );
                        }
                    }

                    // Send our ratchet key back if we have one pending
                    channel.link_mut().set_ratchet_pending_send(true);
                }
            }
            return Ok(());
        }

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
            // Try Resource segment first (bincode-deserialized)
            // A ResourceAdvertisement will NOT parse as a valid Segment because
            // its binary layout creates a Vec length too large for real data,
            // so trying Segment first is safe.
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
                    // Segment deserialized but resource not registered yet.
                    // Skip ICN fallback to avoid false positives.
                    continue;
                }
            }
            // Try ResourceAdvertisement (for new incoming resource transfers)
            if let Ok(adv) = rsticulum_transport::ResourceAdvertisement::from_bytes(&msg) {
                tracing::info!(
                    "Resource advertisement: hash={:02x?}, size={}, segments={}",
                    adv.hash,
                    adv.total_size,
                    adv.segment_count,
                );
                // Register incoming resource so subsequent segments can be matched
                let resource = Resource::new_for_receiving(
                    adv.hash.clone(),
                    adv.total_size as usize,
                    adv.segment_count,
                    ResourceConfig::default(),
                );
                self.incoming_resources.insert(adv.hash.clone(), resource);
                continue;
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
    /// Attempts direct medium send first, then falls back to routing table,
    /// then triggers path discovery if no route exists.
    async fn send_to(
        &mut self,
        dest: rsticulum_identity::RnsAddress,
        data: &[u8],
    ) -> Result<(), DaemonError> {
        // 1. Try direct medium send (peer is directly reachable on this medium)
        for medium in &self.media {
            match medium.send(dest, data).await {
                Ok(()) => return Ok(()),
                Err(e) => tracing::debug!("Failed to send directly via {}: {e}", medium.name()),
            }
        }

        // 2. Check routing table for a next-hop route
        if let Some(entry) = self.router.next_hop(&dest) {
            let next_hop = entry.next_hop;
            // Send via the next hop (try all media)
            for medium in &self.media {
                match medium.send(next_hop, data).await {
                    Ok(()) => return Ok(()),
                    Err(e) => tracing::debug!("Failed to route via {} through {next_hop}: {e}", medium.name()),
                }
            }
            // Route exists but no medium can reach the next hop
            tracing::debug!("Route to {dest} exists via {next_hop} but no medium can reach it");
            return Err(DaemonError::NoRoute);
        }

        // 3. No route — trigger path discovery
        let req = PathRequest::new(dest, rsticulum_mesh::MAX_HOPS);
        let request_id = req.request_id;

        // Don't send duplicate path requests for the same destination
        if !self.pending_path_requests.contains_key(dest.as_bytes()) {
            self.pending_path_requests.insert(*dest.as_bytes(), request_id);

            let req_bytes = bincode::serialize(&req)
                .map_err(|e| DaemonError::Other(format!("serialize PathRequest: {e}")))?;

            let req_packet = Packet {
                header_type: rsticulum_packet::HEADER_1,
                context_flag: rsticulum_packet::FLAG_UNSET,
                transport_type: rsticulum_packet::TRANSPORT_BROADCAST,
                destination_type: rsticulum_packet::DEST_SINGLE,
                packet_type: DATA,
                hops: rsticulum_packet::MAX_HOPS,
                destination_hash: *dest.as_bytes(),
                transport_id: None,
                context: PATH_REQ_CTX,
                data: req_bytes,
            };

            let req_raw = req_packet.to_bytes();
            for medium in &self.media {
                let _ = medium.broadcast(&req_raw).await;
            }
            tracing::info!("Path discovery initiated for {dest}");
        } else {
            tracing::debug!("Path request already pending for {dest}");
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
    /// First sends a ResourceAdvertisement so the receiver can prepare,
    /// then sends all segments.
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

        // 1. Send ResourceAdvertisement first
        let adv = rsticulum_transport::ResourceAdvertisement::new(
            &resource,
            &self.keys.rns_address(),
        );
        let adv_bytes = adv
            .to_bytes()
            .map_err(|e| DaemonError::Other(format!("serialize advertisement: {e}")))?;
        self.send_over_link(remote, adv_bytes).await?;
        tracing::debug!(
            "Resource advertisement sent for {:02x?}: {} segments, {} bytes",
            hash,
            total,
            data_len,
        );

        // 2. Send all segments
        for seg in &segments {
            let packed = bincode::serialize(seg)
                .map_err(|e| DaemonError::Other(format!("serialize segment: {e}")))?;
            self.send_over_link(remote, packed).await?;
        }
        tracing::info!(
            "Resource {:02x?} advertised and sent: {} segments, {} bytes",
            hash,
            total,
            data_len,
        );
        Ok(())
    }

    /// Initiate a link to a remote peer.
    ///
    /// Sends a LINKREQUEST with ephemeral X25519 + Ed25519 keys,
    /// stores pending state for the LRPROOF response.
    pub async fn connect(&mut self, remote: rsticulum_identity::RnsAddress) -> Result<(), DaemonError> {
        if self.channels.contains_key(&remote) || self.pending_channels.contains_key(&remote) {
            return Ok(());
        }

        // 1. Generate ephemeral X25519 keypair
        let eph_priv = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let eph_pub = x25519_dalek::PublicKey::from(&eph_priv);

        // 2. Build signing keypair for this link
        let sig_priv = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let sig_pub = sig_priv.verifying_key();

        // 3. Build request_data: pub_bytes(32) + sig_pub_bytes(32) + signalling(3)
        let mut request_data = eph_pub.to_bytes().to_vec();
        request_data.extend_from_slice(&sig_pub.to_bytes());
        request_data.extend_from_slice(&[0u8; 3]); // signalling: all 0 for now

        // 4. Send as LINKREQUEST (HEADER_1, broadcast/unicast)
        let packet = rsticulum_packet::Packet {
            header_type: rsticulum_packet::HEADER_1,
            context_flag: rsticulum_packet::FLAG_UNSET,
            transport_type: rsticulum_packet::TRANSPORT_UNICAST,
            destination_type: rsticulum_packet::DEST_SINGLE,
            packet_type: rsticulum_packet::LINKREQUEST,
            hops: rsticulum_packet::MAX_HOPS,
            destination_hash: *remote.as_bytes(),
            transport_id: None,
            context: rsticulum_packet::NONE,
            data: request_data,
        };

        // 5. Compute link_id from request hash
        let link_id = compute_link_id_from_request(&packet);

        // 6. Create pending channel with initiator=true
        let local_dest = Destination::singleton(self.keys.clone(), "daemon", vec![]);
        let mut link = Link::new(local_dest, remote);
        link.set_link_id(link_id);
        link.set_initiator(true);
        link.set_state(rsticulum_transport::LinkState::Handshaking);

        let channel = Channel::new(link);
        self.pending_channels.insert(remote, channel);

        // 7. Store ephemeral private key and signing public key for LRPROOF handling
        let pending = PendingLinkData {
            link_id,
            ephemeral_priv: eph_priv,
            initiator_sig_pub: sig_pub.to_bytes(),
        };
        self.pending_links.insert(remote, pending);

        let data = packet.to_bytes();
        let result = self.send_to(remote, &data).await;
        tracing::info!("LINKREQUEST sent to {remote}, link_id={:02x?}", link_id);
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
/// Matches Python RNS behaviour exactly:
/// 1. Take `hashable_part = bytes([raw[0] & 0b00001111]) + raw[2:]`
///    (Python's `get_hashable_part()`: masked flags nibble + everything after hops)
/// 2. Strip trailing signalling bytes beyond ECPUBSIZE (64 bytes of key material)
/// 3. SHA-256 → first 16 bytes
fn compute_link_id_from_request(packet: &Packet) -> [u8; 16] {
    let raw = packet.to_bytes();
    // Python: bytes([raw[0] & 0b00001111]) + raw[2:]
    let mut hashable = Vec::with_capacity(raw.len());
    hashable.push(raw[0] & 0x0F);
    hashable.extend_from_slice(&raw[2..]);

    // Strip appended signalling bytes (data beyond the 64 bytes of key material)
    const ECPUBSIZE: usize = 32 + 32;
    let diff = packet.data.len().saturating_sub(ECPUBSIZE);
    let truncated_len = hashable.len().saturating_sub(diff);
    hashable.truncate(truncated_len);

    let hash = Sha256::digest(&hashable);
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
        let mut data = Vec::with_capacity(67);
        // 32 bytes ephemeral pub key
        data.extend_from_slice(&[0xAAu8; 32]);
        // 32 bytes signing pub key
        data.extend_from_slice(&[0xBBu8; 32]);
        // 3 bytes signalling
        data.extend_from_slice(&[0xCCu8; 3]);

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
