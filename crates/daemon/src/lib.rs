//! rsticulum-daemon — mesh networking + ICN forwarder + Link transport.
//!
//! The daemon ties together:
//! - Identity management (keypair loading/generation/saving)
//! - Link establishment (proof handshake, encrypted transport)
//! - Mesh routing (UDP medium, MeshRouter, path discovery)
//! - ICN forwarding (ContentStore, FIB/PIT, manifest serving)
//! - Discovery (periodic announces, incoming announce handling)
//! - Local API (TCP socket for applications)

pub mod config;
pub mod api;

use std::collections::HashMap;
use std::sync::Arc;

use rsticulum_destination::Destination;
use rsticulum_identity::Keys;
use rsticulum_mesh::{Medium, MeshRouter};
use rsticulum_packet::{
    Packet, ANNOUNCE, DATA, HEADER_2, LINKPROOF, PROOF,
};
use rsticulum_transport::Link;
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
    /// Established links, keyed by remote RNS address.
    links: HashMap<rsticulum_identity::RnsAddress, Link>,
    /// Pending links (handshake in progress).
    pending_links: HashMap<rsticulum_identity::RnsAddress, Link>,
    /// Known peer identity keys (from announces), for proof verification.
    peer_keys: HashMap<rsticulum_identity::RnsAddress, [u8; 32]>,
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
            links: HashMap::new(),
            pending_links: HashMap::new(),
            peer_keys: HashMap::new(),
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
            // Collect frames from all media
            let mut frames = Vec::new();
            for medium in &self.media {
                match medium.recv().await {
                    Ok(Some((from, frame))) => {
                        frames.push((from, frame));
                    }
                    Ok(None) => {
                        tracing::debug!("Medium {} closed", medium.name());
                    }
                    Err(e) => {
                        tracing::error!("Error receiving from {}: {e}", medium.name());
                    }
                }
            }

            for (from, frame) in frames {
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
                    let addr = self.keys.rns_address();
                    if let Err(e) = medium.send(addr, &data).await {
                        tracing::debug!("Announce send failed via {}: {e}", medium.name());
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
                            link_count: self.links.len(),
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
                }
            }

            tokio::task::yield_now().await;
        }
    }

    /// Handle an incoming frame from the mesh.
    async fn handle_frame(
        &mut self,
        from: rsticulum_identity::RnsAddress,
        frame: Vec<u8>,
    ) -> Result<(), DaemonError> {
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
            DATA if packet.header_type == HEADER_2 && packet.transport_id.is_some() => {
                self.handle_link_data(from, &packet).await?;
            }
            _ => {
                return self.handle_icn_frame(from, frame).await;
            }
        }

        Ok(())
    }

    /// Handle an incoming announce packet.
    async fn handle_announce(
        &mut self,
        from: rsticulum_identity::RnsAddress,
        packet: &Packet,
    ) -> Result<(), DaemonError> {
        tracing::debug!("Received ANNOUNCE from {from}");

        // Extract identity key from announce data if present
        if packet.data.len() >= 32 {
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&packet.data[..32]);
            self.peer_keys.insert(from, key_bytes);
            tracing::debug!("Registered peer key for {from}");
        }

        // Update mesh routing table (1-hop neighbor via this peer)
        self.router.update_route(from, from, 1.0, 1);
        Ok(())
    }

    /// Handle an incoming proof (link establishment) packet.
    async fn handle_proof(
        &mut self,
        from: rsticulum_identity::RnsAddress,
        packet: &Packet,
    ) -> Result<(), DaemonError> {
        tracing::debug!("Received PROOF from {from}");

        // Check if we have the remote's signing key
        let remote_key = match self.peer_keys.get(&from) {
            Some(k) => *k,
            None => {
                tracing::debug!("No known peer key for {from} — ignoring proof");
                return Ok(());
            }
        };

        let local_dest = Destination::singleton(self.keys.clone(), "daemon", vec![]);

        if packet.context == LINKPROOF {
            // Remote is initiating a link to us
            let mut link = Link::new(local_dest, from);
            link.set_remote_signing_key(remote_key);

            // We're the responder: verify their proof and generate a response
            // The remote's proof is signed by them, and we verify against their key
            // But handle_incoming_proof expects &Keys (full keypair).
            // We only have the public key, so we complete_handshake instead.
            match link.complete_handshake(&packet.data) {
                Ok(()) => {
                    // Generate our own proof to send back
                    let our_proof = link.establish()?;
                    self.links.insert(from, link);
                    let reply_data = our_proof.to_bytes();
                    self.send_to(from, &reply_data).await?;
                    tracing::info!("Link established with {from} (responder)");
                }
                Err(e) => {
                    tracing::debug!("Proof verification failed from {from}: {e}");
                }
            }
        } else {
            // Completing a handshake we initiated
            if let Some(mut link) = self.pending_links.remove(&from) {
                link.set_remote_signing_key(remote_key);
                match link.complete_handshake(&packet.data) {
                    Ok(()) => {
                        self.links.insert(from, link);
                        tracing::info!("Link established with {from} (initiator)");
                    }
                    Err(e) => {
                        tracing::debug!("Handshake completion failed with {from}: {e}");
                    }
                }
            }
        }

        Ok(())
    }

    /// Handle an incoming data packet on an established link.
    async fn handle_link_data(
        &mut self,
        from: rsticulum_identity::RnsAddress,
        packet: &Packet,
    ) -> Result<(), DaemonError> {
        // Collect messages first (avoids borrow conflict with send_to)
        let messages: Vec<Vec<u8>> = {
            if let Some(link) = self.links.get_mut(&from) {
                link.deliver(packet)?;
                let mut msgs = Vec::new();
                while let Some(msg) = link.recv() {
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
            tracing::debug!("Link received {} bytes from {from}", msg.len());
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
            tracing::debug!("Received ICN Data: {}", data.name);
            self.forwarder.receive_data(data, 0).await?;
            return Ok(());
        }

        if let Ok(interest) = rsticulum_icn::Interest::from_bytes(&frame) {
            tracing::debug!("Received ICN Interest: {}", interest.name);
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

    /// Initiate a link to a remote peer.
    pub async fn connect(&mut self, remote: rsticulum_identity::RnsAddress) -> Result<(), DaemonError> {
        if self.links.contains_key(&remote) || self.pending_links.contains_key(&remote) {
            return Ok(());
        }

        let local_dest = Destination::singleton(self.keys.clone(), "daemon", vec![]);
        let mut link = Link::new(local_dest, remote);

        let proof_pkt = link.establish()?;
        self.pending_links.insert(remote, link);

        let data = proof_pkt.to_bytes();
        self.send_to(remote, &data).await?;
        tracing::info!("Link initiation sent to {remote}");
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
        self.links.len()
    }
}

// ── Error ──

#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("no route to destination")]
    NoRoute,
    #[error("ICN error: {0}")]
    Icn(String),
    #[error("mesh error: {0}")]
    Mesh(#[from] rsticulum_mesh::MeshError),
    #[error("transport error: {0}")]
    Transport(#[from] rsticulum_transport::TransportError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<String> for DaemonError {
    fn from(s: String) -> Self {
        DaemonError::Icn(s)
    }
}

// ── Announce helper ──

/// Build an ANNOUNCE packet advertising this daemon.
fn build_announce_packet(keys: &Keys) -> Packet {
    let identity_key = keys.identity_key_bytes();
    let rns_addr = keys.rns_address();

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
        data: identity_key.to_vec(),
    }
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
        assert_eq!(pkt.data.len(), 32); // identity key
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
}