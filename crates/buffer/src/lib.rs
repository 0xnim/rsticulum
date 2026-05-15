//! rsticulum-buffer — streaming I/O over RNS Channels.
//!
//! Port of Python RNS `Buffer.py`. Provides:
//! - `StreamDataMessage` — binary data chunks with stream_id, EOF, compression hint
//! - `RawChannelReader` — async buffered reader for incoming stream data
//! - `RawChannelWriter` — async writer that chunks and sends stream data
//! - `Buffer` — factory for creating reader/writer pairs

use rsticulum_channel::{Channel, SystemMessageType};
use std::sync::{Arc, Mutex};
use thiserror::Error;
use tokio::sync::Notify;

// ── Stream Data Message ──

/// Maximum stream ID (14 bits).
pub const STREAM_ID_MAX: u16 = 0x3FFF;

/// Overhead per stream data message: 2 bytes header.
const STREAM_HEADER_LEN: usize = 2;

/// Maximum chunk length for compression attempts.
pub const MAX_CHUNK_LEN: usize = 1024 * 16;

/// Bit flag for EOF.
const FLAG_EOF: u16 = 0x8000;
/// Bit flag for compressed data.
const FLAG_COMPRESSED: u16 = 0x4000;

/// A stream data message sent over a Channel.
///
/// Wire format:
/// ```text
/// [2 bytes BE header] [data...]
/// Header bits: [EOF:1] [Compressed:1] [stream_id:14]
/// ```
#[derive(Debug, Clone)]
pub struct StreamDataMessage {
    pub stream_id: u16,
    pub data: Vec<u8>,
    pub eof: bool,
    pub compressed: bool,
}

impl StreamDataMessage {
    /// Pack into wire format.
    pub fn pack(&self) -> Vec<u8> {
        let mut header: u16 = self.stream_id & STREAM_ID_MAX;
        if self.eof {
            header |= FLAG_EOF;
        }
        if self.compressed {
            header |= FLAG_COMPRESSED;
        }

        let mut buf = Vec::with_capacity(STREAM_HEADER_LEN + self.data.len());
        buf.extend_from_slice(&header.to_be_bytes());
        buf.extend_from_slice(&self.data);
        buf
    }

    /// Unpack from wire format.
    pub fn unpack(data: &[u8]) -> Result<Self, BufferError> {
        if data.len() < STREAM_HEADER_LEN {
            return Err(BufferError::InvalidFormat("too short".into()));
        }

        let header = u16::from_be_bytes([data[0], data[1]]);
        let stream_id = header & STREAM_ID_MAX;
        let eof = (header & FLAG_EOF) != 0;
        let compressed = (header & FLAG_COMPRESSED) != 0;
        let payload = data[STREAM_HEADER_LEN..].to_vec();

        Ok(Self {
            stream_id,
            data: payload,
            eof,
            compressed,
        })
    }

    /// Maximum data length per chunk (channel MDU - 2 byte header).
    pub fn max_data_len(mdu: usize) -> usize {
        mdu.saturating_sub(STREAM_HEADER_LEN)
    }
}

// ── Error ──

#[derive(Debug, Error)]
pub enum BufferError {
    #[error("invalid format: {0}")]
    InvalidFormat(String),
    #[error("channel error: {0}")]
    Channel(#[from] rsticulum_channel::ChannelError),
    #[error("transport error: {0}")]
    Transport(#[from] rsticulum_transport::TransportError),
    #[error("stream closed")]
    StreamClosed,
}

// ── Raw Channel Reader ──

/// Buffered reader for incoming stream data on a channel.
///
/// Receives `StreamDataMessage`s on a given stream_id, buffers them,
/// and provides `read()` for consuming applications.
pub struct RawChannelReader {
    stream_id: u16,
    buffer: Arc<Mutex<Vec<u8>>>,
    eof: Arc<Mutex<bool>>,
    notify: Arc<Notify>,
    _channel: Channel, // kept alive
}

impl RawChannelReader {
    /// Create a new reader, registering a handler on the channel.
    pub fn new(mut channel: Channel, stream_id: u16) -> Self {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let eof = Arc::new(Mutex::new(false));
        let notify = Arc::new(Notify::new());

        let buf_clone = buffer.clone();
        let eof_clone = eof.clone();
        let notify_clone = notify.clone();

        // Register handler for SMT_STREAM_DATA on this stream_id
        channel.register_handler(
            SystemMessageType::SMT_STREAM_DATA,
            move |data| {
                if let Ok(msg) = StreamDataMessage::unpack(data) {
                    if msg.stream_id == stream_id {
                        if msg.eof {
                            *eof_clone.lock().unwrap() = true;
                        }
                        if !msg.data.is_empty() {
                            buf_clone.lock().unwrap().extend_from_slice(&msg.data);
                        }
                        // Wake waiters
                        notify_clone.notify_one();
                    }
                }
            },
        );

        Self {
            stream_id,
            buffer,
            eof,
            notify,
            _channel: channel,
        }
    }

    /// Read available data into the provided buffer.
    ///
    /// Returns the number of bytes read. Returns 0 if no data and not EOF.
    /// Returns an error with 0 bytes if stream is closed (EOF and buffer empty).
    pub async fn read(&self, buf: &mut [u8]) -> Result<usize, BufferError> {
        loop {
            let available = {
                let inner = self.buffer.lock().unwrap();
                inner.len()
            };

            if available > 0 {
                let mut inner = self.buffer.lock().unwrap();
                let to_read = available.min(buf.len());
                buf[..to_read].copy_from_slice(&inner[..to_read]);
                inner.drain(..to_read);
                return Ok(to_read);
            }

            // Check EOF
            if *self.eof.lock().unwrap() {
                return Ok(0); // EOF, no more data
            }

            // Wait for more data
            self.notify.notified().await;
        }
    }

    /// Check if the stream has reached EOF and the buffer is empty.
    pub fn is_closed(&self) -> bool {
        *self.eof.lock().unwrap() && self.buffer.lock().unwrap().is_empty()
    }

    /// The stream ID this reader listens on.
    pub fn stream_id(&self) -> u16 {
        self.stream_id
    }
}

// ── Raw Channel Writer ──

/// Writer that chunks data into `StreamDataMessage`s and sends them over a channel.
pub struct RawChannelWriter {
    stream_id: u16,
    channel: Channel,
    max_data_len: usize,
}

impl RawChannelWriter {
    /// Create a new writer.
    pub fn new(channel: Channel, stream_id: u16) -> Self {
        let mdu = channel.mdu();  // used only for max_data_len calculation
        let max_data_len = StreamDataMessage::max_data_len(mdu);
        Self {
            stream_id,
            channel,
            max_data_len,
        }
    }

    /// Write data to the stream.
    ///
    /// Chunks data into `max_data_len`-sized pieces and sends them.
    /// Returns the number of bytes processed.
    pub async fn write(&mut self, data: &[u8]) -> Result<usize, BufferError> {
        if data.is_empty() {
            return Ok(0);
        }

        let chunk = if data.len() > self.max_data_len {
            &data[..self.max_data_len]
        } else {
            data
        };

        let msg = StreamDataMessage {
            stream_id: self.stream_id,
            data: chunk.to_vec(),
            eof: false,
            compressed: false,
        };

        let packed = msg.pack();
        let _pkt = self.channel.send_typed(SystemMessageType::SMT_STREAM_DATA, packed)?;

        Ok(chunk.len())
    }

    /// Close the stream by sending an EOF message.
    pub async fn close(&mut self) -> Result<(), BufferError> {
        let msg = StreamDataMessage {
            stream_id: self.stream_id,
            data: vec![],
            eof: true,
            compressed: false,
        };

        let packed = msg.pack();
        self.channel.send_typed(SystemMessageType::SMT_STREAM_DATA, packed)?;
        Ok(())
    }

    /// The maximum data payload per chunk.
    pub fn max_data_len(&self) -> usize {
        self.max_data_len
    }

    /// Access the underlying channel.
    pub fn channel(&self) -> &Channel {
        &self.channel
    }
}

// ── Buffer factory ──

/// Static factory for creating buffered I/O pairs.
pub struct Buffer;

impl Buffer {
    /// Create a reader for receiving stream data.
    pub fn create_reader(channel: Channel, stream_id: u16) -> RawChannelReader {
        RawChannelReader::new(channel, stream_id)
    }

    /// Create a writer for sending stream data.
    pub fn create_writer(channel: Channel, stream_id: u16) -> RawChannelWriter {
        RawChannelWriter::new(channel, stream_id)
    }

    /// Create a bidirectional buffer pair.
    ///
    /// Returns (reader, writer). The caller must provide two channels
    /// or use Arc<Mutex<Channel>> for shared access in real usage.
    /// This is a convenience wrapper for create_reader / create_writer.
    pub fn create_bidirectional(
        recv_channel: Channel,
        send_channel: Channel,
        receive_id: u16,
        send_id: u16,
    ) -> (RawChannelReader, RawChannelWriter) {
        let reader = RawChannelReader::new(recv_channel, receive_id);
        let writer = RawChannelWriter::new(send_channel, send_id);
        (reader, writer)
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_data_message_roundtrip() {
        let msg = StreamDataMessage {
            stream_id: 42,
            data: b"hello stream".to_vec(),
            eof: false,
            compressed: false,
        };

        let packed = msg.pack();
        let unpacked = StreamDataMessage::unpack(&packed).unwrap();

        assert_eq!(unpacked.stream_id, 42);
        assert_eq!(unpacked.data, b"hello stream");
        assert!(!unpacked.eof);
        assert!(!unpacked.compressed);
    }

    #[test]
    fn stream_data_message_eof() {
        let msg = StreamDataMessage {
            stream_id: 1,
            data: vec![],
            eof: true,
            compressed: false,
        };

        let packed = msg.pack();
        assert_eq!(packed.len(), 2); // 2 bytes header, no data

        let unpacked = StreamDataMessage::unpack(&packed).unwrap();
        assert!(unpacked.eof);
        assert_eq!(unpacked.stream_id, 1);
    }

    #[test]
    fn stream_data_message_large_id() {
        let msg = StreamDataMessage {
            stream_id: 16383, // STREAM_ID_MAX
            data: vec![0xAB],
            eof: false,
            compressed: false,
        };

        let packed = msg.pack();
        let unpacked = StreamDataMessage::unpack(&packed).unwrap();
        assert_eq!(unpacked.stream_id, 16383);
    }

    #[test]
    fn stream_data_message_too_short() {
        let err = StreamDataMessage::unpack(&[0x00]).unwrap_err();
        assert!(matches!(err, BufferError::InvalidFormat(..)));
    }

    #[test]
    fn max_data_len_computation() {
        let mdu = 500;
        let max = StreamDataMessage::max_data_len(mdu);
        assert_eq!(max, 498); // 500 - 2

        let mdu_small = 1;
        let max_small = StreamDataMessage::max_data_len(mdu_small);
        assert_eq!(max_small, 0); // saturating
    }
}
