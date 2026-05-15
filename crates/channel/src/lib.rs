//! rsticulum-channel — reliable in-order messages over RNS Links.
//!
//! Port of Python RNS `Channel.py`. Channels provide:
//! - Deterministic message envelope (type + sequence + payload)
//! - In-order delivery with out-of-order buffering
//! - System message type dispatching
//! - MDU-aware message sizing

mod message;

use rsticulum_packet::Packet;
use rsticulum_transport::Link;
use std::collections::{HashMap, VecDeque};
use thiserror::Error;

pub use message::{MessageBase, SystemMessageType};

// ── Error ──

#[derive(Debug, Error)]
pub enum ChannelError {
    #[error("link not established")]
    LinkNotReady,
    #[error("message too large: {0} bytes > MDU {1}")]
    MessageTooLarge(usize, usize),
    #[error("transport error: {0}")]
    Transport(#[from] rsticulum_transport::TransportError),
}

// ── Channel ──

/// A reliable in-order message channel over an RNS Link.
///
/// Each channel wraps a single Link and adds:
/// - Message type tags (`SystemMessageType`)
/// - Sequence numbering for ordering
/// - Handler registration for incoming message types
pub struct Channel {
    link: Link,
    /// Outbound sequence counter.
    outgoing_seq: u32,
    /// Next expected inbound sequence number.
    incoming_seq: u32,
    /// Buffered out-of-order messages, keyed by sequence number.
    reorder_buffer: HashMap<u32, Vec<u8>>,
    /// In-order message queue ready for `recv()`.
    ready: VecDeque<Vec<u8>>,
    /// Registered message handlers: msg_type → handler.
    handlers: HashMap<u16, Box<dyn Fn(&[u8]) + Send + Sync>>,
}

impl Channel {
    /// Create a new channel over an unestablished link.
    pub fn new(link: Link) -> Self {
        Self {
            link,
            outgoing_seq: 0,
            incoming_seq: 0,
            reorder_buffer: HashMap::new(),
            ready: VecDeque::new(),
            handlers: HashMap::new(),
        }
    }

    /// The maximum data unit for this channel.
    /// Link MTU minus 6-byte envelope overhead (2 type + 4 seq).
    pub fn mdu(&self) -> usize {
        self.link.config().mtu as usize - 6
    }

    /// Whether the underlying link is established and ready.
    pub fn is_ready(&self) -> bool {
        self.link.is_established()
    }

    /// Access the underlying link.
    pub fn link(&self) -> &Link {
        &self.link
    }

    /// Mutable access to the underlying link.
    pub fn link_mut(&mut self) -> &mut Link {
        &mut self.link
    }

    // ── Sending ──

    /// Send a payload over the channel.
    ///
    /// Wraps payload in a channel envelope with `SMT_CHANNEL_DATA` and
    /// the next sequence number. Returns the packet ready for transmission.
    pub fn send(&mut self, payload: Vec<u8>) -> Result<Packet, ChannelError> {
        self.send_typed(SystemMessageType::SMT_CHANNEL_DATA, payload)
    }

    /// Send a payload with a specific message type.
    pub fn send_typed(&mut self, msg_type: SystemMessageType, payload: Vec<u8>) -> Result<Packet, ChannelError> {
        if payload.len() > self.mdu() {
            return Err(ChannelError::MessageTooLarge(payload.len(), self.mdu()));
        }

        let seq = self.outgoing_seq;
        self.outgoing_seq = self.outgoing_seq.wrapping_add(1);

        let envelope = message::ChannelEnvelope {
            message_type: msg_type as u16,
            sequence_number: seq,
            payload,
        };

        let packed = envelope.pack();
        self.link.send(packed).map_err(ChannelError::Transport)
    }

    // ── Receiving ──

    /// Deliver an incoming packet to this channel.
    ///
    /// Unwraps the channel envelope from the link frame, buffers
    /// out-of-order messages, and places in-order messages in the
    /// ready queue.
    pub fn deliver(&mut self, packet: &Packet) -> Result<(), ChannelError> {
        // First deliver to the underlying link for decryption
        self.link.deliver(packet)?;

        // Then drain link's inbound queue and process envelopes
        while let Some(data) = self.link.recv() {
            let envelope = message::ChannelEnvelope::unpack(&data)
                .map_err(|e| ChannelError::Transport(
                    rsticulum_transport::TransportError::Other(format!("envelope: {e}"))
                ))?;

            // Check if this is a system message with a registered handler
            if let Some(handler) = self.handlers.get(&envelope.message_type) {
                // Dispatch to handler — these bypass the in-order queue
                handler(&envelope.payload);
                continue;
            }

            let seq = envelope.sequence_number;

            if seq == self.incoming_seq {
                // In order — deliver immediately
                self.ready.push_back(envelope.payload);
                self.incoming_seq = self.incoming_seq.wrapping_add(1);

                // Drain any buffered messages that are now in order
                while let Some(payload) = self.reorder_buffer.remove(&self.incoming_seq) {
                    self.ready.push_back(payload);
                    self.incoming_seq = self.incoming_seq.wrapping_add(1);
                }
            } else if seq > self.incoming_seq && seq.wrapping_sub(self.incoming_seq) < 1000 {
                // Out of order but within reasonable window — buffer
                self.reorder_buffer.insert(seq, envelope.payload);
            }
            // else: very old or future sequence — drop
        }

        Ok(())
    }

    /// Receive the next in-order message.
    ///
    /// Returns `None` if no messages are ready.
    pub fn recv(&mut self) -> Option<Vec<u8>> {
        self.ready.pop_front()
    }

    /// Number of messages ready for `recv()`.
    pub fn pending(&self) -> usize {
        self.ready.len()
    }

    // ── Handlers ──

    /// Register a handler for a system message type.
    ///
    /// Handlers receive the raw payload and are called during `deliver()`.
    pub fn register_handler(
        &mut self,
        msg_type: SystemMessageType,
        handler: impl Fn(&[u8]) + Send + Sync + 'static,
    ) {
        self.handlers.insert(msg_type as u16, Box::new(handler));
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;
    use rsticulum_destination::Destination;
    use rsticulum_identity::Keys;

    fn make_keys(name: &str) -> (Keys, Destination) {
        let keys = Keys::generate();
        let dest = Destination::singleton(keys.clone(), name, vec![]);
        (keys, dest)
    }

    fn make_established_channel() -> Channel {
        let (_, alice) = make_keys("alice");
        let (_, bob) = make_keys("bob");
        let bob_addr = *bob.hash();

        let mut link = Link::new(alice, bob_addr);
        let pkt = link.establish().unwrap();
        link.complete_handshake(&pkt.data).unwrap();

        Channel::new(link)
    }

    #[test]
    fn channel_new_is_not_ready() {
        let (_, alice) = make_keys("alice");
        let (_, bob) = make_keys("bob");
        let link = Link::new(alice, *bob.hash());
        let channel = Channel::new(link);
        assert!(!channel.is_ready());
    }

    #[test]
    fn channel_send_recv_roundtrip() {
        let mut channel = make_established_channel();

        // Send
        let pkt = channel.send(b"hello channel".to_vec()).unwrap();
        assert!(channel.outgoing_seq > 0);

        // Deliver the same packet back (simulating loopback)
        channel.deliver(&pkt).unwrap();

        // Receive
        let msg = channel.recv().unwrap();
        assert_eq!(msg, b"hello channel");
    }

    #[test]
    fn channel_in_order_sequencing() {
        let mut channel = make_established_channel();

        let pkts: Vec<_> = (0..5)
            .map(|i| channel.send(format!("msg-{i}").into_bytes()).unwrap())
            .collect();

        for pkt in &pkts {
            channel.deliver(pkt).unwrap();
        }

        for i in 0..5 {
            let msg = channel.recv().unwrap();
            assert_eq!(msg, format!("msg-{i}").as_bytes());
        }
    }

    #[test]
    fn channel_out_of_order_reordering() {
        let mut channel = make_established_channel();

        // Generate packets
        let pkt0 = channel.send(b"msg-0".to_vec()).unwrap();
        let pkt1 = channel.send(b"msg-1".to_vec()).unwrap();
        let pkt2 = channel.send(b"msg-2".to_vec()).unwrap();

        // Deliver out of order: 2, 0, 1
        channel.deliver(&pkt2).unwrap();
        assert_eq!(channel.pending(), 0); // Not in order yet

        channel.deliver(&pkt0).unwrap();
        assert_eq!(channel.pending(), 1); // 0 is in order, 1 not yet

        channel.deliver(&pkt1).unwrap();
        assert_eq!(channel.pending(), 3); // Now 0,1,2 all ready

        assert_eq!(channel.recv().unwrap(), b"msg-0");
        assert_eq!(channel.recv().unwrap(), b"msg-1");
        assert_eq!(channel.recv().unwrap(), b"msg-2");
    }

    #[test]
    fn channel_message_too_large() {
        let mut channel = make_established_channel();
        let big = vec![0u8; channel.mdu() + 1];
        let err = channel.send(big).unwrap_err();
        assert!(matches!(err, ChannelError::MessageTooLarge(..)));
    }

    #[test]
    fn channel_send_when_link_not_established() {
        let (_, alice) = make_keys("alice");
        let (_, bob) = make_keys("bob");
        let link = Link::new(alice, *bob.hash());
        let mut channel = Channel::new(link);
        let err = channel.send(b"test".to_vec()).unwrap_err();
        assert!(matches!(err, ChannelError::Transport(..)));
    }
}
