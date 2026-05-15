//! Channel envelope and message types.
//!
//! Wire format:
//! ```text
//! [message_type: 2 bytes BE] [sequence_number: 4 bytes BE] [payload: ..]
//! ```
//! Total overhead: 6 bytes.

use thiserror::Error;

// ── System message types ──

/// System-reserved message types for channel control.
///
/// Python RNS defines these in `RNS/Channel.py`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SystemMessageType {
    /// Standard channel data message.
    #[allow(non_camel_case_types)]
    SMT_CHANNEL_DATA = 0x0000,
    /// Stream data (used by Buffer for streaming I/O).
    #[allow(non_camel_case_types)]
    SMT_STREAM_DATA = 0xFF00,
}

/// Trait for types that can be sent over a channel.
pub trait MessageBase {
    /// Pack this message into bytes.
    fn pack(&self) -> Vec<u8>;
    /// Unpack bytes into this message.
    fn unpack(data: &[u8]) -> Result<Self, String>
    where
        Self: Sized;
    /// The message type identifier.
    fn msgtype(&self) -> u16;
}

// ── Channel envelope ──

const ENVELOPE_HEADER_LEN: usize = 6; // 2 (type) + 4 (seq)

#[derive(Debug, Error)]
pub enum EnvelopeError {
    #[error("envelope too short: {0} bytes, need at least {ENVELOPE_HEADER_LEN}")]
    TooShort(usize),
}

/// A channel envelope wrapping a message for transmission.
#[derive(Debug, Clone)]
pub struct ChannelEnvelope {
    /// Message type identifier.
    pub message_type: u16,
    /// Sequence number (wrapping u32, big-endian on wire).
    pub sequence_number: u32,
    /// The message payload.
    pub payload: Vec<u8>,
}

impl ChannelEnvelope {
    /// Pack the envelope into wire format.
    pub fn pack(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(ENVELOPE_HEADER_LEN + self.payload.len());
        buf.extend_from_slice(&self.message_type.to_be_bytes());
        buf.extend_from_slice(&self.sequence_number.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Unpack an envelope from wire format.
    pub fn unpack(data: &[u8]) -> Result<Self, EnvelopeError> {
        if data.len() < ENVELOPE_HEADER_LEN {
            return Err(EnvelopeError::TooShort(data.len()));
        }

        let message_type = u16::from_be_bytes([data[0], data[1]]);
        let sequence_number = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);
        let payload = data[ENVELOPE_HEADER_LEN..].to_vec();

        Ok(Self {
            message_type,
            sequence_number,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_roundtrip() {
        let env = ChannelEnvelope {
            message_type: SystemMessageType::SMT_CHANNEL_DATA as u16,
            sequence_number: 42,
            payload: b"test-payload".to_vec(),
        };

        let packed = env.pack();
        let unpacked = ChannelEnvelope::unpack(&packed).unwrap();

        assert_eq!(unpacked.message_type, env.message_type);
        assert_eq!(unpacked.sequence_number, env.sequence_number);
        assert_eq!(unpacked.payload, env.payload);
    }

    #[test]
    fn envelope_too_short() {
        let err = ChannelEnvelope::unpack(&[0; 3]).unwrap_err();
        assert!(matches!(err, EnvelopeError::TooShort(3)));
    }

    #[test]
    fn envelope_stream_data_type() {
        let env = ChannelEnvelope {
            message_type: SystemMessageType::SMT_STREAM_DATA as u16,
            sequence_number: 1,
            payload: vec![0xAA, 0xBB],
        };

        let packed = env.pack();
        assert_eq!(packed.len(), 8); // 6 header + 2 payload
        assert_eq!(packed[0..2], [0xFF, 0x00]); // SMT_STREAM_DATA BE
    }
}
