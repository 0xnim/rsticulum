//! RNS Link — bidirectional authenticated transport channel.
//!
//! A Link is established between two destinations using a proof-based
//! handshake. Once established, data can be sent and received reliably.
//!
//! ## Lifecycle
//!
//! ```text
//!   Closed ──[establish]──> Handshaking ──[proof verified]──> Established
//!     ^                                                           |
//!     └─────────────────────[close]───────────────────────────────┘
//! ```

use crate::error::TransportError;
use crate::proof::{generate_proof, verify_proof, verify_proof_with_public_key, Proof};
use rsticulum_destination::Destination;
use rsticulum_identity::{Keys, RnsAddress};
use rsticulum_packet::{Packet, DATA, DEST_LINK, HEADER_2, TRANSPORT_UNICAST};
use std::sync::Arc;

// ── Link configuration ──

/// Configuration for a Link.
#[derive(Debug, Clone)]
pub struct LinkConfig {
    /// Maximum Transmission Unit for this link.
    pub mtu: u16,
    /// Maximum number of retries for proof handshake.
    pub max_retries: u32,
    /// Timeout for handshake (not yet wired to real I/O — placeholder).
    pub handshake_timeout_ms: u64,
}

impl Default for LinkConfig {
    fn default() -> Self {
        Self {
            mtu: 500,
            max_retries: 3,
            handshake_timeout_ms: 30_000,
        }
    }
}

impl LinkConfig {
    /// Create a new [`LinkConfigBuilder`].
    pub fn builder() -> LinkConfigBuilder {
        LinkConfigBuilder::default()
    }
}

/// Builder for [`LinkConfig`].
#[derive(Debug, Default)]
pub struct LinkConfigBuilder {
    mtu: Option<u16>,
    max_retries: Option<u32>,
    handshake_timeout_ms: Option<u64>,
}

impl LinkConfigBuilder {
    pub fn mtu(mut self, mtu: u16) -> Self {
        self.mtu = Some(mtu);
        self
    }

    pub fn max_retries(mut self, retries: u32) -> Self {
        self.max_retries = Some(retries);
        self
    }

    pub fn handshake_timeout_ms(mut self, ms: u64) -> Self {
        self.handshake_timeout_ms = Some(ms);
        self
    }

    pub fn build(self) -> LinkConfig {
        LinkConfig {
            mtu: self.mtu.unwrap_or(500),
            max_retries: self.max_retries.unwrap_or(3),
            handshake_timeout_ms: self.handshake_timeout_ms.unwrap_or(30_000),
        }
    }
}

// ── Link state ──

/// The current state of a Link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    /// Link has not been established yet.
    Closed,
    /// Proof handshake is in progress.
    Handshaking,
    /// Link is fully established and ready for data transfer.
    Established,
}

// ── Link ──

/// A bidirectional transport channel between two RNS destinations.
///
/// Links use Ed25519 proofs to establish authenticated connections. Once
/// established, data is sent over HEADER_2 packets with per-link transport IDs.
#[derive(Debug)]
pub struct Link {
    /// The local destination.
    local: Arc<Destination>,
    /// The remote destination's RNS address.
    remote: RnsAddress,
    /// The remote's X25519 encryption public key (set during handshake).
    /// When set, `send()` encrypts and `deliver()` decrypts automatically.
    remote_encryption_key: Option<[u8; 32]>,
    /// The remote's Ed25519 signing (identity) public key.
    /// Must be set before `complete_handshake()` for real interop.
    remote_signing_key: Option<[u8; 32]>,
    /// Link configuration.
    config: LinkConfig,
    /// Current link state.
    state: LinkState,
    /// Unique transport ID for this link (16 bytes).
    transport_id: [u8; 16],
    /// Inbound message buffer (for recv).
    inbound: Vec<Vec<u8>>,
    /// Outbound message buffer (for send).
    outbound: Vec<Packet>,
}

impl Link {
    /// Create a new unestablished Link.
    ///
    /// The transport ID is derived from the two destinations' RNS addresses
    /// XOR'd together to produce a deterministic but unique identifier.
    pub fn new(local: Destination, remote: RnsAddress) -> Self {
        let transport_id = Self::derive_transport_id(local.hash(), &remote);
        Self {
            local: Arc::new(local),
            remote,
            remote_encryption_key: None,
            remote_signing_key: None,
            config: LinkConfig::default(),
            state: LinkState::Closed,
            transport_id,
            inbound: Vec::new(),
            outbound: Vec::new(),
        }
    }

    /// Create a new Link with custom configuration.
    pub fn with_config(local: Destination, remote: RnsAddress, config: LinkConfig) -> Self {
        let transport_id = Self::derive_transport_id(local.hash(), &remote);
        Self {
            local: Arc::new(local),
            remote,
            remote_encryption_key: None,
            remote_signing_key: None,
            config,
            state: LinkState::Closed,
            transport_id,
            inbound: Vec::new(),
            outbound: Vec::new(),
        }
    }

    // ── Accessors ──

    /// The local destination.
    pub fn local(&self) -> &Destination {
        &self.local
    }

    /// The remote RNS address.
    pub fn remote(&self) -> &RnsAddress {
        &self.remote
    }

    /// Current link state.
    pub fn state(&self) -> LinkState {
        self.state
    }

    /// The transport ID for this link.
    pub fn transport_id(&self) -> &[u8; 16] {
        &self.transport_id
    }

    /// The link configuration.
    pub fn config(&self) -> &LinkConfig {
        &self.config
    }

    /// Returns `true` if the link is established.
    pub fn is_established(&self) -> bool {
        self.state == LinkState::Established
    }

    /// Set the remote's X25519 encryption public key.
    ///
    /// Once set, all subsequent `send()` calls will encrypt data and
    /// all `deliver()` calls will decrypt data automatically.
    pub fn set_remote_encryption_key(&mut self, key: [u8; 32]) {
        self.remote_encryption_key = Some(key);
    }

    /// Set the remote's Ed25519 signing (identity) public key.
    ///
    /// Required before `complete_handshake()` for real interop.
    /// Without this, proof verification will fail against a remote peer.
    pub fn set_remote_signing_key(&mut self, key: [u8; 32]) {
        self.remote_signing_key = Some(key);
    }

    /// Returns `true` if encryption is active on this link.
    pub fn is_encrypted(&self) -> bool {
        self.remote_encryption_key.is_some()
    }

    // ── Lifecycle ──

    /// Initiate the proof handshake by generating a link request packet.
    ///
    /// Returns the PROOF packet that should be sent to the remote peer.
    /// Caller is responsible for actual transmission.
    pub fn establish(&mut self) -> Result<Packet, TransportError> {
        match self.state {
            LinkState::Closed => {
                self.state = LinkState::Handshaking;
                let proof = generate_proof(self.local.keys(), self.transport_id.as_slice());
                let proof_bytes = proof.to_bytes();

                let packet = Packet {
                    header_type: HEADER_2,
                    context_flag: rsticulum_packet::FLAG_SET,
                    transport_type: TRANSPORT_UNICAST,
                    destination_type: DEST_LINK,
                    packet_type: rsticulum_packet::PROOF,
                    hops: rsticulum_packet::MAX_HOPS,
                    destination_hash: *self.remote.as_bytes(),
                    transport_id: Some(self.transport_id),
                    context: rsticulum_packet::LINKPROOF,
                    data: proof_bytes,
                };

                Ok(packet)
            }
            LinkState::Handshaking => Err(TransportError::LinkAlreadyEstablished),
            LinkState::Established => Err(TransportError::LinkAlreadyEstablished),
        }
    }

    /// Complete the handshake by verifying a proof received from the remote peer.
    ///
    /// Requires `set_remote_signing_key()` to have been called first for real
    /// interop. Falls back to local-key verification only for legacy self-tests.
    ///
    /// Returns `Ok(())` if the proof is valid and the link transitions to Established.
    pub fn complete_handshake(&mut self, proof_bytes: &[u8]) -> Result<(), TransportError> {
        match self.state {
            LinkState::Handshaking => {
                let proof = Proof::from_bytes(proof_bytes)
                    .map_err(|e| TransportError::ProofError(e.to_string()))?;

                // Verify against remote signing key if set (real interop).
                // Otherwise fall back to local-key verification (legacy self-test).
                if let Some(ref remote_key) = self.remote_signing_key {
                    verify_proof_with_public_key(
                        remote_key,
                        self.transport_id.as_slice(),
                        &proof,
                    )
                    .map_err(|_| TransportError::SignatureVerification)?;
                } else {
                    verify_proof(
                        self.local.keys(),
                        self.transport_id.as_slice(),
                        &proof,
                    )
                    .map_err(|_| TransportError::SignatureVerification)?;
                }

                self.state = LinkState::Established;
                Ok(())
            }
            LinkState::Closed => Err(TransportError::LinkNotEstablished),
            LinkState::Established => Err(TransportError::LinkAlreadyEstablished),
        }
    }

    /// Handle an incoming proof from the remote side (responder path).
    ///
    /// When a remote initiates a link with us, we receive their proof packet.
    /// This verifies the proof and transitions to Established, returning a
    /// confirmation packet to send back.
    pub fn handle_incoming_proof(
        &mut self,
        remote_keys: &Keys,
        proof_bytes: &[u8],
    ) -> Result<Packet, TransportError> {
        match self.state {
            LinkState::Closed | LinkState::Handshaking => {
                let proof = Proof::from_bytes(proof_bytes)
                    .map_err(|e| TransportError::ProofError(e.to_string()))?;

                verify_proof(remote_keys, self.transport_id.as_slice(), &proof)
                    .map_err(|_| TransportError::SignatureVerification)?;

                self.state = LinkState::Established;

                // Generate a response proof
                let response_proof =
                    generate_proof(self.local.keys(), self.transport_id.as_slice());
                let response_bytes = response_proof.to_bytes();

                Ok(Packet {
                    header_type: HEADER_2,
                    context_flag: rsticulum_packet::FLAG_SET,
                    transport_type: TRANSPORT_UNICAST,
                    destination_type: DEST_LINK,
                    packet_type: rsticulum_packet::PROOF,
                    hops: rsticulum_packet::MAX_HOPS,
                    destination_hash: *self.remote.as_bytes(),
                    transport_id: Some(self.transport_id),
                    context: rsticulum_packet::LRPROOF,
                    data: response_bytes,
                })
            }
            LinkState::Established => Err(TransportError::LinkAlreadyEstablished),
        }
    }

    /// Close the link, returning it to the `Closed` state.
    pub fn close(&mut self) -> Result<(), TransportError> {
        match self.state {
            LinkState::Closed => Err(TransportError::LinkClosed),
            LinkState::Handshaking | LinkState::Established => {
                self.state = LinkState::Closed;
                self.inbound.clear();
                self.outbound.clear();
                Ok(())
            }
        }
    }

    // ── Data transfer ──

    /// Queue data for sending over the link.
    ///
    /// Returns a HEADER_2 DATA packet ready for transmission.
    /// If a remote encryption key is set, data is encrypted before
    /// being placed in the packet.
    pub fn send(&mut self, data: Vec<u8>) -> Result<Packet, TransportError> {
        if self.state != LinkState::Established {
            return Err(TransportError::LinkNotEstablished);
        }

        let payload = if let Some(ref remote_key) = self.remote_encryption_key {
            self.local
                .keys()
                .encrypt_for(remote_key, self.remote.as_bytes(), &data)
                .map_err(|e| TransportError::Other(format!("encryption: {e}")))?
        } else {
            data
        };

        if payload.len() > self.config.mtu as usize {
            return Err(TransportError::InvalidChunkSize(payload.len()));
        }

        let packet = Packet {
            header_type: HEADER_2,
            context_flag: rsticulum_packet::FLAG_UNSET,
            transport_type: TRANSPORT_UNICAST,
            destination_type: DEST_LINK,
            packet_type: DATA,
            hops: rsticulum_packet::MAX_HOPS,
            destination_hash: *self.remote.as_bytes(),
            transport_id: Some(self.transport_id),
            context: rsticulum_packet::NONE,
            data: payload,
        };

        self.outbound.push(packet.clone());
        Ok(packet)
    }

    /// Receive data from a packet delivered to this link.
    ///
    /// If the packet's transport ID matches, its payload is buffered and
    /// can be retrieved with [`Link::recv`]. If a remote encryption key
    /// is set, data is decrypted before buffering.
    pub fn deliver(&mut self, packet: &Packet) -> Result<(), TransportError> {
        if self.state != LinkState::Established {
            return Err(TransportError::LinkNotEstablished);
        }

        if packet.transport_id != Some(self.transport_id) {
            return Err(TransportError::Other("transport ID mismatch".into()));
        }

        let data = if self.remote_encryption_key.is_some() {
            self.local
                .keys()
                .decrypt_from(&packet.data)
                .map_err(|e| TransportError::Other(format!("decryption: {e}")))?
        } else {
            packet.data.clone()
        };

        self.inbound.push(data);
        Ok(())
    }

    /// Retrieve the next buffered inbound message, if any.
    pub fn recv(&mut self) -> Option<Vec<u8>> {
        if self.inbound.is_empty() {
            None
        } else {
            Some(self.inbound.remove(0))
        }
    }

    /// Number of pending inbound messages.
    pub fn pending_inbound(&self) -> usize {
        self.inbound.len()
    }

    /// Number of queued outbound packets.
    pub fn pending_outbound(&self) -> usize {
        self.outbound.len()
    }

    // ── Private helpers ──

    /// Derive a 16-byte transport ID from local and remote addresses.
    fn derive_transport_id(local: &RnsAddress, remote: &RnsAddress) -> [u8; 16] {
        let mut id = [0u8; 16];
        for i in 0..16 {
            id[i] = local.as_bytes()[i] ^ remote.as_bytes()[i];
        }
        id
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;
    use rsticulum_identity::Keys;

    fn make_dest(name: &str) -> Destination {
        let keys = Keys::generate();
        Destination::singleton(keys, name, vec![])
    }

    #[test]
    fn link_new_is_closed() {
        let local = make_dest("alice");
        let remote_dest = make_dest("bob");
        let remote_addr = *remote_dest.hash();
        let link = Link::new(local, remote_addr);
        assert_eq!(link.state(), LinkState::Closed);
        assert!(!link.is_established());
    }

    #[test]
    fn link_establish_handshake_cycle() {
        let local = make_dest("alice");
        let remote_dest = make_dest("bob");
        let remote_addr = *remote_dest.hash();

        let mut link = Link::new(local, remote_addr);

        // Initiate handshake
        let proof_packet = link.establish().expect("establish should succeed");
        assert_eq!(link.state(), LinkState::Handshaking);
        assert_eq!(proof_packet.packet_type, rsticulum_packet::PROOF);

        // Complete handshake
        link.complete_handshake(&proof_packet.data)
            .expect("handshake should complete");
        assert_eq!(link.state(), LinkState::Established);
        assert!(link.is_established());
    }

    #[test]
    fn link_send_recv_data() {
        let local = make_dest("alice");
        let remote_dest = make_dest("bob");
        let remote_addr = *remote_dest.hash();

        let mut link = Link::new(local, remote_addr);
        link.establish().unwrap();
        // Use a separate established link for the actual send/recv test
        let mut link2 = make_established_link();
        let pkt = link2
            .send(b"hello world".to_vec())
            .expect("send should work");
        assert_eq!(&pkt.data, b"hello world");

        // Deliver the same packet to the link to simulate receiving
        link2.deliver(&pkt).expect("deliver should work");
        let msg = link2.recv().expect("should have message");
        assert_eq!(msg, b"hello world");
    }
    #[test]
    fn link_send_when_closed_fails() {
        let local = make_dest("alice");
        let remote = make_dest("bob");
        let mut link = Link::new(local, *remote.hash());
        let err = link.send(b"data".to_vec()).unwrap_err();
        assert!(matches!(err, TransportError::LinkNotEstablished));
    }

    #[test]
    fn link_close_clears_buffers() {
        let mut link = make_established_link();
        let _ = link.send(b"msg".to_vec()).unwrap();
        assert_eq!(link.pending_outbound(), 1);
        link.close().unwrap();
        assert_eq!(link.state(), LinkState::Closed);
        assert_eq!(link.pending_outbound(), 0);
        assert_eq!(link.pending_inbound(), 0);
    }

    #[test]
    fn link_config_builder() {
        let config = LinkConfig::builder()
            .mtu(1024)
            .max_retries(5)
            .handshake_timeout_ms(60_000)
            .build();
        assert_eq!(config.mtu, 1024);
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.handshake_timeout_ms, 60_000);
    }

    #[test]
    fn link_config_defaults() {
        let config = LinkConfig::default();
        assert_eq!(config.mtu, 500);
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.handshake_timeout_ms, 30_000);
    }

    #[test]
    fn link_with_config() {
        let local = make_dest("alice");
        let remote = make_dest("bob");
        let config = LinkConfig {
            mtu: 800,
            ..Default::default()
        };
        let link = Link::with_config(local, *remote.hash(), config);
        assert_eq!(link.config().mtu, 800);
    }

    #[test]
    fn transport_id_is_deterministic() {
        let local = make_dest("alice");
        let remote = make_dest("bob");
        let a1 = *local.hash();
        let a2 = *remote.hash();
        let id1 = Link::derive_transport_id(&a1, &a2);
        let id2 = Link::derive_transport_id(&a1, &a2);
        assert_eq!(id1, id2);
    }

    #[test]
    fn link_cannot_establish_twice() {
        let mut link = make_established_link();
        let err = link.establish().unwrap_err();
        assert!(matches!(err, TransportError::LinkAlreadyEstablished));
    }

    #[test]
    fn link_send_exceeds_mtu_fails() {
        let mut link = make_established_link();
        let big_data = vec![0u8; 600]; // MTU default is 500
        let err = link.send(big_data).unwrap_err();
        assert!(matches!(err, TransportError::InvalidChunkSize(600)));
    }

    // ── Helpers ──

    fn make_established_link() -> Link {
        let local = make_dest("alice");
        let remote_dest = make_dest("bob");
        let remote_addr = *remote_dest.hash();
        let mut link = Link::new(local, remote_addr);
        let pkt = link.establish().unwrap();
        // Self-test: no remote signing key set, falls back to local verification
        link.complete_handshake(&pkt.data).unwrap();
        link
    }

    #[test]
    fn link_cross_key_handshake() {
        // Alice initiates, Bob responds, Alice verifies with Bob's key
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let alice_dest = Destination::singleton(alice_keys.clone(), "alice", vec![]);
        let bob_dest = Destination::singleton(bob_keys.clone(), "bob", vec![]);
        let alice_addr = *alice_dest.hash();
        let bob_addr = *bob_dest.hash();

        // Alice → creates link to Bob, establishes (generates proof signed by alice)
        let mut alice_link = Link::new(alice_dest, bob_addr);
        let alice_proof_packet = alice_link.establish().unwrap();

        // Bob → receives alice's proof, verifies with alice's public key
        // handle_incoming_proof: remote_keys = the peer who sent the proof (alice)
        let mut bob_link = Link::new(bob_dest, alice_addr);
        let bob_response = bob_link
            .handle_incoming_proof(&alice_keys, &alice_proof_packet.data)
            .unwrap();

        // Alice → completes handshake with Bob's response, using Bob's public key
        alice_link.set_remote_signing_key(bob_keys.identity_key_bytes());
        alice_link
            .complete_handshake(&bob_response.data)
            .unwrap();

        assert!(alice_link.is_established());
        assert!(bob_link.is_established());
    }

    #[test]
    fn link_cross_key_wrong_signing_key_fails() {
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();
        let eve_keys = Keys::generate();
        let alice_dest = Destination::singleton(alice_keys.clone(), "alice", vec![]);
        let bob_addr = *Destination::singleton(bob_keys.clone(), "bob", vec![]).hash();

        let mut alice_link = Link::new(alice_dest, bob_addr);
        alice_link.establish().unwrap();

        // Set Eve's key instead of Bob's — should fail
        alice_link.set_remote_signing_key(eve_keys.identity_key_bytes());

        let proof_bytes = generate_proof(&bob_keys, alice_link.transport_id.as_slice());
        let err = alice_link
            .complete_handshake(&proof_bytes.to_bytes())
            .unwrap_err();
        assert!(matches!(err, TransportError::SignatureVerification));
    }
}
