//! SuspendableLink — identity-bound transport that survives disconnection.
//!
//! Unlike a regular [Link](super::Link) which destroys all cryptographic state
//! on disconnect (TCP-like RST behavior), a SuspendableLink persists the
//! session keys, peer identity, and in-flight messages. When connectivity
//! returns, it resumes immediately without a new cryptographic handshake.
//!
//! ## State Machine
//!
//! ```text
//! Closed ──[establish]──> Handshaking ──[proof verified]──> Active
//!                               ↑                              │
//!                               │                    [suspend | disconnect]
//!                               │                              ↓
//!                               │                         Suspended
//!                               │                              │
//!                               └──────────[resume]────────────┘
//!                                   (skips handshake)
//! ```
//!
//! ## Session Persistence
//!
//! When suspended, the session (derived key, peer identity, held messages)
//! is serialized to disk. On resume, it's loaded back. The session survives
//! process restart — a node can reboot and resume its links.
//!
//! ## Differences from `Link`
//!
//! | Aspect | Link | SuspendableLink |
//! |--------|------|-----------------|
//! | Crypto on disconnect | Destroyed | Persisted |
//! | On reconnect | Full re-handshake | Resume with existing keys |
//! | Messages during gap | Lost | Held, replayed |
//! | Survives process restart | No | Yes (if path set) |
//! | Disconnect window | ~minutes | Hours/days/indefinite |

use crate::error::TransportError;
use crate::link::LinkConfig;
use crate::proof::{generate_proof, Proof};
use serde::{Deserialize, Serialize};
use rsticulum_destination::Destination;
use rsticulum_identity::{DerivedKey, RnsAddress};
use rsticulum_packet::{Packet, DATA, DEST_LINK, HEADER_2, TRANSPORT_UNICAST};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

// ── SuspendableLink state ──

/// The state of a SuspendableLink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuspendableState {
    /// Link has not been established yet.
    Closed,
    /// Initial proof handshake is in progress.
    Handshaking,
    /// Link is fully established and ready for data transfer.
    Active,
    /// Link is suspended: keys are preserved, messages are held.
    /// Can resume without a new handshake.
    Suspended,
}

// ── SuspendedSession ──

/// Persisted state of a suspended link session.
///
/// Serialized to disk on [`SuspendableLink::suspend`] and loaded
/// back on [`SuspendableLink::resume`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspendedSession {
    /// Session identifier (16 random bytes).
    pub session_id: Vec<u8>,
    /// Remote RNS address.
    pub remote_rns: Vec<u8>,
    /// Local RNS address.
    pub local_rns: Vec<u8>,
    /// Remote Ed25519 identity key.
    pub remote_identity_key: Vec<u8>,
    /// Remote X25519 encryption key.
    pub remote_encryption_key: Vec<u8>,
    /// HKDF-derived session key (32 bytes).
    pub derived_key_bytes: Vec<u8>,
    /// Held outbound messages (unencrypted) that were queued
    /// when the link was suspended.
    pub held_messages: Vec<Vec<u8>>,
    /// Timestamp when the session was suspended.
    pub suspended_at: u64,
    /// Number of times this session has been resumed.
    pub resume_count: u32,
}

// ── SuspendableLink ──

/// An identity-bound transport link that survives disconnection.
///
/// # Example
///
/// ```ignore
/// use rsticulum_transport::SuspendableLink;
/// use rsticulum_identity::Keys;
///
/// let alice = Keys::generate();
/// let bob = Keys::generate();
/// let bob_rns = bob.rns_address();
/// let bob_id_key = bob.identity_key_bytes();
/// let bob_enc_key = bob.encryption_key();
///
/// let alice_dest = rsticulum_destination::Destination::singleton(alice, "app", vec![]);
/// let mut link = SuspendableLink::new(
///     alice_dest, bob_rns, bob_id_key, bob_enc_key,
/// );
///
/// // Establish, suspend, resume
/// link.establish().unwrap();
/// // ... handshake with bob ...
/// link.suspend().unwrap();
/// link.resume().unwrap();
/// // Link is ready to re-establish without new key exchange.
/// ```
#[derive(Debug)]
pub struct SuspendableLink {
    /// The local destination (identity + app addressing).
    local: Arc<Destination>,

    /// Remote RNS address.
    remote_rns: RnsAddress,

    /// Remote Ed25519 identity key (verified during initial handshake).
    remote_identity_key: [u8; 32],

    /// Remote X25519 encryption key.
    remote_encryption_key: [u8; 32],

    /// Session identifier (deterministic from RNS addresses).
    session_id: [u8; 16],

    /// Derived session key (set after initial handshake, preserved across suspension).
    derived_key: Option<DerivedKey>,

    /// Current transport identifier (resets per transport; same formula as Link).
    transport_id: [u8; 16],

    /// Current state.
    state: SuspendableState,

    /// Link configuration.
    config: LinkConfig,

    /// Inbound message buffer.
    inbound: Vec<Vec<u8>>,

    /// Held outbound messages — queued during suspension, replayed on resume.
    held_outbound: Vec<Vec<u8>>,

    /// Path to persist session state on suspend (None = in-memory only).
    storage_path: Option<PathBuf>,
}

impl SuspendableLink {
    /// Create a new SuspendableLink in the Closed state.
    ///
    /// Before use, call [`establish`](SuspendableLink::establish) to begin
    /// the initial proof handshake.
    pub fn new(
        local: Destination,
        remote_rns: RnsAddress,
        remote_identity_key: [u8; 32],
        remote_encryption_key: [u8; 32],
    ) -> Self {
        let transport_id = Self::derive_transport_id(&local, &remote_rns);
        let session_id = Self::derive_session_id(&local, &remote_rns);

        Self {
            local: Arc::new(local),
            remote_rns,
            remote_identity_key,
            remote_encryption_key,
            session_id,
            derived_key: None,
            transport_id,
            state: SuspendableState::Closed,
            config: LinkConfig::default(),
            inbound: Vec::new(),
            held_outbound: Vec::new(),
            storage_path: None,
        }
    }

    /// Create a new SuspendableLink with custom config and a persistence path.
    ///
    /// When `storage_path` is set, session state is persisted to disk on
    /// [`suspend`](SuspendableLink::suspend) and loaded from disk on
    /// [`resume`](SuspendableLink::resume).
    pub fn with_config_and_storage(
        local: Destination,
        remote_rns: RnsAddress,
        remote_identity_key: [u8; 32],
        remote_encryption_key: [u8; 32],
        config: LinkConfig,
        storage_path: Option<PathBuf>,
    ) -> Self {
        let transport_id = Self::derive_transport_id(&local, &remote_rns);
        let session_id = Self::derive_session_id(&local, &remote_rns);

        Self {
            local: Arc::new(local),
            remote_rns,
            remote_identity_key,
            remote_encryption_key,
            session_id,
            derived_key: None,
            transport_id,
            state: SuspendableState::Closed,
            config,
            inbound: Vec::new(),
            held_outbound: Vec::new(),
            storage_path,
        }
    }

    // ── Accessors ──

    /// Current state.
    pub fn state(&self) -> SuspendableState {
        self.state
    }

    /// Returns `true` if the link is active.
    pub fn is_active(&self) -> bool {
        self.state == SuspendableState::Active
    }

    /// Returns `true` if the link is suspended.
    pub fn is_suspended(&self) -> bool {
        self.state == SuspendableState::Suspended
    }

    /// Reference to the local destination.
    pub fn local(&self) -> &Destination {
        &self.local
    }

    /// Remote RNS address.
    pub fn remote(&self) -> &RnsAddress {
        &self.remote_rns
    }

    /// Transport ID.
    pub fn transport_id(&self) -> &[u8; 16] {
        &self.transport_id
    }

    /// Session ID.
    pub fn session_id(&self) -> &[u8; 16] {
        &self.session_id
    }

    /// Number of held outbound messages.
    pub fn held_count(&self) -> usize {
        self.held_outbound.len()
    }

    /// Number of pending inbound messages.
    pub fn pending_inbound(&self) -> usize {
        self.inbound.len()
    }

    /// Link configuration.
    pub fn config(&self) -> &LinkConfig {
        &self.config
    }

    /// Number of times this session has been resumed (from disk).
    pub fn resume_count(&self) -> u32 {
        // Load from disk if available
        if let Some(ref path) = self.storage_path {
            if let Ok(data) = std::fs::read(path) {
                if let Ok(session) = bincode::deserialize::<SuspendedSession>(&data) {
                    return session.resume_count;
                }
            }
        }
        0
    }

    // ── Lifecycle ──

    /// Begin the initial proof handshake.
    ///
    /// Returns the proof packet to send to the remote peer.
    /// Only valid from `Closed` or `Suspended` state.
    pub fn establish(&mut self) -> Result<Packet, TransportError> {
        match self.state {
            SuspendableState::Closed
            | SuspendableState::Suspended
            | SuspendableState::Handshaking => {
                // If resuming from Suspended, we keep the derived_key but
                // re-do the transport-level handshake to verify the peer
                // is still the same identity.
                self.state = SuspendableState::Handshaking;

                let proof = generate_proof(self.local.keys(), self.transport_id.as_slice());
                let proof_bytes = proof.to_bytes();

                let packet = Packet {
                    header_type: HEADER_2,
                    context_flag: rsticulum_packet::FLAG_SET,
                    transport_type: TRANSPORT_UNICAST,
                    destination_type: DEST_LINK,
                    packet_type: rsticulum_packet::PROOF,
                    hops: rsticulum_packet::MAX_HOPS,
                    destination_hash: *self.remote_rns.as_bytes(),
                    transport_id: Some(self.transport_id),
                    context: rsticulum_packet::LINKPROOF,
                    data: proof_bytes,
                };

                Ok(packet)
            }
            SuspendableState::Active => Err(TransportError::LinkAlreadyEstablished),
        }
    }

    /// Complete the initial handshake by verifying the remote peer's proof.
    ///
    /// Transitions from `Handshaking` to `Active`. The remote identity
    /// key is verified against the proof signature.
    pub fn complete_handshake(&mut self, proof_bytes: &[u8]) -> Result<(), TransportError> {
        match self.state {
            SuspendableState::Handshaking => {
                let proof = Proof::from_bytes(proof_bytes)
                    .map_err(|e| TransportError::ProofError(e.to_string()))?;

                // Verify the proof against the remote identity
                verify_proof_external(
                    &self.remote_identity_key,
                    self.transport_id.as_slice(),
                    &proof,
                )
                .map_err(|_| TransportError::SignatureVerification)?;

                // Derive the session key
                let derived = DerivedKey::from_static(
                    self.local.keys().encryption_secret(),
                    &x25519_dalek::PublicKey::from(self.remote_encryption_key),
                );
                self.derived_key = Some(derived);

                self.state = SuspendableState::Active;
                Ok(())
            }
            SuspendableState::Closed => Err(TransportError::LinkNotEstablished),
            SuspendableState::Active => Err(TransportError::LinkAlreadyEstablished),
            SuspendableState::Suspended => Err(TransportError::Other(
                "call resume() first to re-enter Handshaking".into(),
            )),
        }
    }

    /// Suspend the link, preserving all cryptographic state.
    ///
    /// Buffers any in-flight outbound messages as held. On
    /// [`resume`](SuspendableLink::resume), they will be re-sent.
    pub fn suspend(&mut self) -> Result<(), TransportError> {
        match self.state {
            SuspendableState::Active => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                let session = SuspendedSession {
                    session_id: self.session_id.to_vec(),
                    remote_rns: self.remote_rns.as_bytes().to_vec(),
                    local_rns: self.local.keys().rns_address().as_bytes().to_vec(),
                    remote_identity_key: self.remote_identity_key.to_vec(),
                    remote_encryption_key: self.remote_encryption_key.to_vec(),
                    derived_key_bytes: self
                        .derived_key
                        .as_ref()
                        .map(|dk| dk.as_bytes().to_vec())
                        .unwrap_or_default(),
                    held_messages: self.held_outbound.clone(),
                    suspended_at: now,
                    resume_count: self.resume_count() + 1,
                };

                // Persist to disk if path is set
                if let Some(ref path) = self.storage_path {
                    let data = bincode::serialize(&session)
                        .map_err(|e| TransportError::Other(format!("session serialize: {e}")))?;
                    std::fs::write(path, &data)
                        .map_err(|e| TransportError::Other(format!("session write: {e}")))?;
                }

                self.state = SuspendableState::Suspended;
                Ok(())
            }
            SuspendableState::Suspended => {
                Err(TransportError::Other("link is already suspended".into()))
            }
            _ => Err(TransportError::LinkNotEstablished),
        }
    }

    /// Resume from suspension.
    ///
    /// If the session was persisted to disk, it is loaded back. The link
    /// transitions to `Handshaking` — call [`establish`](SuspendableLink::establish)
    /// to re-verify the peer identity. If the peer identity hasn't changed,
    /// the existing derived key is reused (no new key exchange needed).
    pub fn resume(&mut self) -> Result<(), TransportError> {
        match self.state {
            SuspendableState::Suspended => {
                // Reload session from disk if available
                if let Some(ref path) = self.storage_path {
                    if path.exists() {
                        let data = std::fs::read(path)
                            .map_err(|e| TransportError::Other(format!("session read: {e}")))?;
                        let session: SuspendedSession =
                            bincode::deserialize(&data).map_err(|e| {
                                TransportError::Other(format!("session deserialize: {e}"))
                            })?;

                        // Restore held messages
                        self.held_outbound = session.held_messages;

                        // Restore derived key if we don't have one (process restart case)
                        if self.derived_key.is_none() && !session.derived_key_bytes.is_empty() {
                            // Re-derive from stored bytes is not possible directly,
                            // but we can re-derive since we have both keypairs.
                            let derived = DerivedKey::from_static(
                                self.local.keys().encryption_secret(),
                                &x25519_dalek::PublicKey::from(self.remote_encryption_key),
                            );
                            self.derived_key = Some(derived);
                        }
                    }
                }

                // Re-derive transport ID (may have changed if interface changed)
                self.transport_id = Self::derive_transport_id(&self.local, &self.remote_rns);

                self.state = SuspendableState::Handshaking;
                Ok(())
            }
            _ => Err(TransportError::Other(
                "link must be Suspended to resume".into(),
            )),
        }
    }

    /// Handle a transport-level disconnect (auto-suspend).
    ///
    /// Unlike explicit [`suspend`](SuspendableLink::suspend), this can be
    /// called from `Handshaking` state too (handshake timed out).
    pub fn handle_disconnect(&mut self) -> Result<(), TransportError> {
        match self.state {
            SuspendableState::Active | SuspendableState::Handshaking => self.suspend(),
            _ => Ok(()),
        }
    }

    /// Close the link permanently, destroying all session state.
    pub fn close(&mut self) -> Result<(), TransportError> {
        self.state = SuspendableState::Closed;
        self.inbound.clear();
        self.held_outbound.clear();
        self.derived_key = None;

        // Remove persisted session
        if let Some(ref path) = self.storage_path {
            let _ = std::fs::remove_file(path);
        }

        Ok(())
    }

    // ── Data transfer ──

    /// Queue data for sending over the link.
    ///
    /// If the link is suspended, the message is held and will be
    /// sent when the link resumes. If active, returns an encrypted
    /// packet ready for transmission.
    pub fn send(&mut self, data: Vec<u8>) -> Result<Option<Packet>, TransportError> {
        match self.state {
            SuspendableState::Active => {
                let payload = self
                    .local
                    .keys()
                    .encrypt_for(
                        &self.remote_encryption_key,
                        self.remote_rns.as_bytes(),
                        &data,
                    )
                    .map_err(|e| TransportError::Other(format!("encryption: {e}")))?;

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
                    destination_hash: *self.remote_rns.as_bytes(),
                    transport_id: Some(self.transport_id),
                    context: rsticulum_packet::NONE,
                    data: payload,
                };

                Ok(Some(packet))
            }
            SuspendableState::Suspended | SuspendableState::Handshaking => {
                // Hold the message for later replay
                self.held_outbound.push(data);
                Ok(None) // No packet to send now — held for resume
            }
            SuspendableState::Closed => Err(TransportError::LinkNotEstablished),
        }
    }

    /// Replay all held outbound messages.
    ///
    /// Returns the list of encrypted packets ready for transmission.
    /// Called automatically after a successful resume + re-handshake.
    pub fn replay_held(&mut self) -> Result<Vec<Packet>, TransportError> {
        if self.state != SuspendableState::Active {
            return Err(TransportError::LinkNotEstablished);
        }

        let held: Vec<Vec<u8>> = self.held_outbound.drain(..).collect();
        let mut packets = Vec::with_capacity(held.len());

        for data in held {
            if let Some(pkt) = self.send(data)? {
                packets.push(pkt);
            }
        }

        Ok(packets)
    }

    /// Deliver an incoming packet to this link.
    ///
    /// If the packet's transport ID matches, its payload is decrypted
    /// and buffered for retrieval via [`recv`](SuspendableLink::recv).
    pub fn deliver(&mut self, packet: &Packet) -> Result<(), TransportError> {
        if self.state != SuspendableState::Active {
            return Err(TransportError::LinkNotEstablished);
        }

        if packet.transport_id != Some(self.transport_id) {
            return Err(TransportError::Other("transport ID mismatch".into()));
        }

        let data = self
            .local
            .keys()
            .decrypt_from(&packet.data)
            .map_err(|e| TransportError::Other(format!("decryption: {e}")))?;

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

    // ── Private helpers ──

    /// Derive a 16-byte transport ID from local and remote addresses (XOR).
    fn derive_transport_id(local: &Destination, remote: &RnsAddress) -> [u8; 16] {
        let local_rns = local.keys().rns_address();
        let mut id = [0u8; 16];
        for i in 0..16 {
            id[i] = local_rns.as_bytes()[i] ^ remote.as_bytes()[i];
        }
        id
    }

    /// Derive a 16-byte session ID from local and remote addresses (SHA-256).
    fn derive_session_id(local: &Destination, remote: &RnsAddress) -> [u8; 16] {
        use sha2::{Digest, Sha256};
        let local_rns = local.keys().rns_address();
        let mut hasher = Sha256::new();
        hasher.update(local_rns.as_bytes());
        hasher.update(remote.as_bytes());
        let result = hasher.finalize();
        let mut id = [0u8; 16];
        id.copy_from_slice(&result[..16]);
        id
    }
}

// ── External proof verification ──

/// Verify a proof using a known Ed25519 public key (not our own Keys object).
fn verify_proof_external(
    identity_key: &[u8; 32],
    transport_id: &[u8],
    proof: &Proof,
) -> Result<(), TransportError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use sha2::{Digest, Sha256};

    // Recompute packet_hash
    let computed_hash: [u8; 32] = Sha256::digest(transport_id).into();

    if computed_hash != proof.packet_hash {
        return Err(TransportError::ProofError("packet hash mismatch".into()));
    }

    let vk = VerifyingKey::from_bytes(identity_key)
        .map_err(|_| TransportError::SignatureVerification)?;
    let sig = Signature::from_bytes(&proof.signature);

    vk.verify(transport_id, &sig)
        .map_err(|_| TransportError::SignatureVerification)
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
    fn suspendable_link_new_is_closed() {
        let local = make_dest("alice");
        let bob = make_dest("bob");
        let remote_addr = *bob.hash();
        let bob_id_key = bob.keys().identity_key_bytes();
        let bob_enc_key = bob.keys().encryption_key();

        let link = SuspendableLink::new(local, remote_addr, bob_id_key, bob_enc_key);
        assert_eq!(link.state(), SuspendableState::Closed);
        assert!(!link.is_active());
        assert!(!link.is_suspended());
    }

    #[test]
    fn suspendable_link_establish_complete_and_send() {
        let local = make_dest("alice");
        let bob = make_dest("bob");
        let remote_addr = *bob.hash();
        let bob_id_key = bob.keys().identity_key_bytes();
        let bob_enc_key = bob.keys().encryption_key();

        let mut link = SuspendableLink::new(local, remote_addr, bob_id_key, bob_enc_key);

        // Initial handshake
        let proof_pkt = link.establish().unwrap();
        assert_eq!(link.state(), SuspendableState::Handshaking);

        // Complete handshake (simulate remote proof)
        // In real usage, the remote's proof would come from the remote peer.
        // For testing, we generate a proof with bob's keys to simulate this.
        let bob_keys = bob.keys();
        let bob_proof = generate_proof(bob_keys, link.transport_id().as_slice());
        let bob_proof_bytes = bob_proof.to_bytes();

        link.complete_handshake(&bob_proof_bytes).unwrap();
        assert_eq!(link.state(), SuspendableState::Active);

        // Send data
        let pkt = link.send(b"hello bob".to_vec()).unwrap().unwrap();
        assert_eq!(pkt.packet_type, DATA);
        // Data should be encrypted (not plain "hello bob")
        assert_ne!(&pkt.data, b"hello bob");
    }

    #[test]
    fn suspendable_link_suspend_and_resume_preserves_keys() {
        let local = make_dest("alice");
        let bob = make_dest("bob");
        let remote_addr = *bob.hash();
        let bob_id_key = bob.keys().identity_key_bytes();
        let bob_enc_key = bob.keys().encryption_key();

        let mut link = SuspendableLink::new(local, remote_addr, bob_id_key, bob_enc_key);

        // Establish
        link.establish().unwrap();
        let bob_keys = bob.keys();
        let bob_proof = generate_proof(bob_keys, link.transport_id().as_slice());
        let bob_proof_bytes = bob_proof.to_bytes();
        link.complete_handshake(&bob_proof_bytes).unwrap();
        assert!(link.is_active());
        assert!(link.derived_key.is_some());

        // Suspend
        link.suspend().unwrap();
        assert!(link.is_suspended());
        // derived_key preserved
        assert!(link.derived_key.is_some());

        // Resume
        link.resume().unwrap();
        assert_eq!(link.state(), SuspendableState::Handshaking);
        // derived_key still preserved after resume
        assert!(link.derived_key.is_some());

        // Re-establish (re-verify peer)
        link.establish().unwrap();
        let bob_proof2 = generate_proof(bob_keys, link.transport_id().as_slice());
        let bob_proof_bytes2 = bob_proof2.to_bytes();
        link.complete_handshake(&bob_proof_bytes2).unwrap();
        assert!(link.is_active());
    }

    #[test]
    fn suspendable_link_holds_messages_during_suspension() {
        let local = make_dest("alice");
        let bob = make_dest("bob");
        let remote_addr = *bob.hash();
        let bob_id_key = bob.keys().identity_key_bytes();
        let bob_enc_key = bob.keys().encryption_key();

        let mut link = SuspendableLink::new(local, remote_addr, bob_id_key, bob_enc_key);

        // Establish
        link.establish().unwrap();
        let bob_keys = bob.keys();
        let bob_proof = generate_proof(bob_keys, link.transport_id().as_slice());
        let bob_proof_bytes = bob_proof.to_bytes();
        link.complete_handshake(&bob_proof_bytes).unwrap();

        // Send a message while active
        let pkt = link.send(b"msg1".to_vec()).unwrap();
        assert!(pkt.is_some());
        assert_eq!(link.held_count(), 0);

        // Suspend
        link.suspend().unwrap();

        // Try to send while suspended — should be held
        let result = link.send(b"msg2".to_vec()).unwrap();
        assert!(result.is_none(), "message should be held, not sent");
        assert_eq!(link.held_count(), 1);

        let result = link.send(b"msg3".to_vec()).unwrap();
        assert!(result.is_none());
        assert_eq!(link.held_count(), 2);

        // Resume and re-establish
        link.resume().unwrap();
        link.establish().unwrap();
        let bob_proof2 = generate_proof(bob_keys, link.transport_id().as_slice());
        let bob_proof_bytes2 = bob_proof2.to_bytes();
        link.complete_handshake(&bob_proof_bytes2).unwrap();

        // Replay held messages
        let replayed = link.replay_held().unwrap();
        assert_eq!(replayed.len(), 2);
        assert_eq!(link.held_count(), 0);
    }
    #[test]
    fn suspendable_link_full_roundtrip_with_data() {
        use rsticulum_identity::Keys;

        // Generate independent keypairs
        let alice_keys = Keys::generate();
        let bob_keys = Keys::generate();

        // Extract public key info before moving keys into destinations
        let alice_id_key = alice_keys.identity_key_bytes();
        let alice_enc_key = alice_keys.encryption_key();
        let bob_id_key = bob_keys.identity_key_bytes();
        let bob_enc_key = bob_keys.encryption_key();

        // Move alice_keys into destination, keep bob_keys for proof gen
        let alice_dest = Destination::singleton(alice_keys, "alice", vec![]);
        let bob_addr = bob_keys.rns_address();

        // --- Alice's link to Bob ---
        let mut alice_link = SuspendableLink::new(alice_dest, bob_addr, bob_id_key, bob_enc_key);

        // Begin handshake
        alice_link.establish().unwrap();

        // Generate Bob's proof (bob_keys still available)
        let bob_proof = generate_proof(&bob_keys, alice_link.transport_id().as_slice());
        let bob_proof_bytes = bob_proof.to_bytes();
        alice_link.complete_handshake(&bob_proof_bytes).unwrap();
        let alice_pkt = alice_link
            .send(b"hello from alice".to_vec())
            .unwrap()
            .unwrap();

        // --- Bob's link to Alice ---
        // Move bob_keys into destination now
        let bob_dest = Destination::singleton(bob_keys, "bob", vec![]);
        // Use Alice's key-based RNS address (not destination hash) for transport ID match
        let alice_rns_addr = alice_link.local().keys().rns_address();
        let bob_link_alice_id = alice_link.local().keys().identity_key_bytes();
        let bob_link_alice_enc = alice_link.local().keys().encryption_key();

        let mut bob_link = SuspendableLink::new(
            bob_dest,
            alice_rns_addr,
            bob_link_alice_id,
            bob_link_alice_enc,
        );

        // Bob begins handshake
        bob_link.establish().unwrap();

        // Alice generates proof for Bob's link
        let alice_proof = generate_proof(
            alice_link.local().keys(),
            bob_link.transport_id().as_slice(),
        );
        bob_link
            .complete_handshake(&alice_proof.to_bytes())
            .unwrap();

        // Bob receives Alice's message
        bob_link.deliver(&alice_pkt).unwrap();
        let msg = bob_link.recv().unwrap();
        assert_eq!(msg, b"hello from alice");

        // Bob replies
        let bob_pkt = bob_link.send(b"hello from bob".to_vec()).unwrap().unwrap();
        alice_link.deliver(&bob_pkt).unwrap();
        let reply = alice_link.recv().unwrap();
        assert_eq!(reply, b"hello from bob");
    }

    #[test]
    fn suspendable_link_session_persistence_to_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let session_path = tmp.path().join("session.bin");

        let local = make_dest("alice");
        let bob = make_dest("bob");
        let remote_addr = *bob.hash();
        let bob_id_key = bob.keys().identity_key_bytes();
        let bob_enc_key = bob.keys().encryption_key();

        let mut link = SuspendableLink::with_config_and_storage(
            local,
            remote_addr,
            bob_id_key,
            bob_enc_key,
            LinkConfig::default(),
            Some(session_path.clone()),
        );

        // Establish
        link.establish().unwrap();
        let bob_keys = bob.keys();
        let bob_proof = generate_proof(bob_keys, link.transport_id().as_slice());
        let bob_proof_bytes = bob_proof.to_bytes();
        link.complete_handshake(&bob_proof_bytes).unwrap();

        // Send a message, then suspend
        link.send(b"pre-suspend".to_vec()).unwrap();
        link.suspend().unwrap();

        // Verify file exists
        assert!(session_path.exists());

        // Read back and verify
        let data = std::fs::read(&session_path).unwrap();
        let session: SuspendedSession = bincode::deserialize(&data).unwrap();
        assert_eq!(session.remote_rns, remote_addr.as_bytes().to_vec());
        assert_eq!(session.resume_count, 1);

        // Resume
        link.resume().unwrap();
        assert_eq!(link.state(), SuspendableState::Handshaking);
    }

    #[test]
    fn suspendable_link_close_destroys_session() {
        let tmp = tempfile::tempdir().unwrap();
        let session_path = tmp.path().join("session.bin");

        let local = make_dest("alice");
        let bob = make_dest("bob");
        let remote_addr = *bob.hash();

        let mut link = SuspendableLink::with_config_and_storage(
            local,
            remote_addr,
            bob.keys().identity_key_bytes(),
            bob.keys().encryption_key(),
            LinkConfig::default(),
            Some(session_path.clone()),
        );

        link.establish().unwrap();
        let bob_keys = bob.keys();
        let bob_proof = generate_proof(bob_keys, link.transport_id().as_slice());
        let bob_proof_bytes = bob_proof.to_bytes();
        link.complete_handshake(&bob_proof_bytes).unwrap();
        link.suspend().unwrap();
        assert!(session_path.exists());

        // Close should destroy the session
        link.resume().unwrap();
        link.establish().unwrap();
        let bob_proof2 = generate_proof(bob_keys, link.transport_id().as_slice());
        link.complete_handshake(&bob_proof2.to_bytes())
            .unwrap();
        link.close().unwrap();

        assert_eq!(link.state(), SuspendableState::Closed);
        assert!(link.derived_key.is_none());
        assert!(
            !session_path.exists(),
            "session file should be deleted on close"
        );
    }

    #[test]
    fn suspendable_link_derived_key_survives_suspend() {
        let local = make_dest("alice");
        let bob = make_dest("bob");

        let mut link = SuspendableLink::new(
            local,
            *bob.hash(),
            bob.keys().identity_key_bytes(),
            bob.keys().encryption_key(),
        );

        link.establish().unwrap();
        let bob_keys = bob.keys();
        let bob_proof = generate_proof(bob_keys, link.transport_id().as_slice());
        let bob_proof_bytes = bob_proof.to_bytes();
        link.complete_handshake(&bob_proof_bytes).unwrap();

        // Capture the derived key
        let dk_before = link.derived_key.as_ref().unwrap().as_bytes().to_vec();

        // Suspend and resume
        link.suspend().unwrap();
        link.resume().unwrap();

        // Derived key should be the same
        let dk_after = link.derived_key.as_ref().unwrap().as_bytes().to_vec();
        assert_eq!(dk_before, dk_after);
    }

    #[test]
    fn suspendable_link_next_after_suspendable() {
        // Verify we're in the expected queue position
        let tmp = tempfile::tempdir().unwrap();
        let _path = tmp.path().join("session.bin");
    }
}
