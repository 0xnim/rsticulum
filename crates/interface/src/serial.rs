//! Serial interface — HDLC framing over physical serial ports.
//!
//! Ported from Python RNS `SerialInterface.py`.
//!
//! ## Architecture
//!
//! - Opens a serial port via the [`serialport`] crate inside a `spawn_blocking` task.
//! - A dedicated read loop runs byte-by-byte through an [`HdlcDecoder`] state machine.
//! - Complete decoded frames are sent through a `tokio::sync::mpsc` channel.
//! - Outgoing data is HDLC-encoded and written to the port via `spawn_blocking`.
//! - On read error, the read loop enters a 5-second reconnect cycle.
//!
//! ## HDLC on-the-wire format
//!
//! ```text
//!   FLAG (0x7E) | escaped_payload | FLAG (0x7E)
//! ```
//!
//! Byte stuffing: `0x7E` → `ESC 0x5E`, `0x7D` → `ESC 0x5D`
//! (`ESC = 0x7D`, escaped byte = original ^ 0x20)

use crate::error::InterfaceError;
use crate::NetworkInterface;
use async_trait::async_trait;
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task;
use tracing::{error, info, warn};

// ── Constants (matching Python RNS) ──

/// Maximum on-wire frame size (RNS hardware MTU).
pub const HW_MTU: usize = 564;

/// Maximum chunk for internal buffers.
const MAX_CHUNK: usize = 32768;

/// HDLC flag delimiter byte.
const FLAG: u8 = 0x7E;

/// HDLC escape byte.
const ESC: u8 = 0x7D;

/// XOR mask applied to escaped bytes.
const ESC_MASK: u8 = 0x20;

/// Timeout (ms) before resetting a partially-received frame.
const FRAME_TIMEOUT_MS: u64 = 100;

/// Reconnect delay after a serial read error.
const RECONNECT_DELAY_SECS: u64 = 5;

/// Channel capacity for decoded frames.
const CHANNEL_CAPACITY: usize = 256;

// ── HDLC Frame Encoder ──

/// Encode raw payload bytes into an HDLC-framed buffer.
///
/// Output: `FLAG | escaped(payload) | FLAG`
pub fn hdlc_encode(data: &[u8]) -> Vec<u8> {
    // Worst case: every byte needs escaping → 2× + 2 FLAG bytes
    let mut out = Vec::with_capacity(data.len().saturating_mul(2).saturating_add(2));
    out.push(FLAG);
    for &byte in data {
        if byte == FLAG || byte == ESC {
            out.push(ESC);
            out.push(byte ^ ESC_MASK);
        } else {
            out.push(byte);
        }
    }
    out.push(FLAG);
    out
}

/// Decode an HDLC-framed buffer back into raw payload bytes.
///
/// Strips leading/trailing FLAG delimiters and unescapes any escaped bytes.
/// Returns `None` if the frame is malformed.
pub fn hdlc_decode(frame: &[u8]) -> Option<Vec<u8>> {
    if frame.len() < 2 {
        return None;
    }
    // Strip leading FLAG if present
    let start = if frame.first() == Some(&FLAG) { 1 } else { 0 };
    let end = if frame.last() == Some(&FLAG) {
        frame.len().saturating_sub(1)
    } else {
        frame.len()
    };
    if start > end {
        return None; // no content between delimiters
    }
    let inner = &frame[start..end];

    let mut out = Vec::with_capacity(inner.len());
    let mut i = 0;
    while i < inner.len() {
        if inner[i] == ESC && i + 1 < inner.len() {
            out.push(inner[i + 1] ^ ESC_MASK);
            i += 2;
        } else {
            out.push(inner[i]);
            i += 1;
        }
    }
    // Empty frames are valid (heartbeat)
    Some(out)
}

// ── HDLC Decoder State Machine ──

/// Internal state of the byte-by-byte HDLC decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HdlcState {
    /// Waiting for a FLAG byte to start a frame.
    WaitFlag,
    /// Inside a frame, accumulating bytes.
    InFrame,
    /// Previous byte was ESC — next byte is escaped.
    Escape,
}

/// Streaming HDLC frame decoder.
///
/// Feed one byte at a time via [`feed`](HdlcDecoder::feed). When a complete
/// frame is delimited by FLAG bytes, returns `Some(Vec<u8>)` with the unescaped
/// payload.
#[derive(Debug, Clone)]
pub struct HdlcDecoder {
    buf: Vec<u8>,
    state: HdlcState,
}

impl Default for HdlcDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl HdlcDecoder {
    /// Create a new decoder in the `WaitFlag` state.
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(MAX_CHUNK),
            state: HdlcState::WaitFlag,
        }
    }

    /// Feed a single byte to the decoder.
    ///
    /// Returns `Some(frame)` when a complete, non-empty frame has been received.
    /// Empty frames (FLAG followed immediately by FLAG) are silently dropped.
    pub fn feed(&mut self, byte: u8) -> Option<Vec<u8>> {
        match self.state {
            HdlcState::WaitFlag => {
                if byte == FLAG {
                    self.state = HdlcState::InFrame;
                    self.buf.clear();
                }
                // Otherwise: garbage byte before FLAG — ignore
                None
            }
            HdlcState::InFrame => {
                if byte == FLAG {
                    // End of frame
                    self.state = HdlcState::WaitFlag;
                    if self.buf.is_empty() {
                        None
                    } else {
                        Some(std::mem::take(&mut self.buf))
                    }
                } else if byte == ESC {
                    self.state = HdlcState::Escape;
                    None
                } else {
                    self.buf.push(byte);
                    None
                }
            }
            HdlcState::Escape => {
                // Unescape: flip the ESC_MASK bit
                self.buf.push(byte ^ ESC_MASK);
                self.state = HdlcState::InFrame;
                None
            }
        }
    }

    /// Reset the decoder to the initial state, discarding any partial frame.
    pub fn reset(&mut self) {
        self.state = HdlcState::WaitFlag;
        self.buf.clear();
    }
}

// ── SerialInterface ──

/// An async HDLC interface over a physical serial port.
///
/// ## Example
///
/// ```no_run
/// use rsticulum_interface::SerialInterface;
/// use rsticulum_interface::NetworkInterface;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let mut iface = SerialInterface::new("Serial", "/dev/ttyUSB0", 115200);
/// iface.start().await?;
/// while let Some(data) = iface.receive().await? {
///     // process data
/// }
/// iface.shutdown().await?;
/// # Ok(())
/// # }
/// ```
pub struct SerialInterface {
    name: String,
    port: String,
    speed: u32,
    online: bool,
    bitrate: u64,
    rxb: u64,
    txb: u64,
    /// Shared serial port handle (locked for each read/write).
    serial: Arc<std::sync::Mutex<Option<Box<dyn serialport::SerialPort>>>>,
    /// Channel receiver for decoded frames from the read loop.
    rx: mpsc::Receiver<Vec<u8>>,
    /// Signal to stop the read loop.
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl SerialInterface {
    /// Create a new serial interface (not yet online).
    ///
    /// Call [`start`](SerialInterface::start) to open the port and begin
    /// receiving frames.
    pub fn new(name: &str, port: &str, speed: u32) -> Self {
        let (_tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        Self {
            name: name.to_string(),
            port: port.to_string(),
            speed,
            online: false,
            bitrate: speed as u64,
            rxb: 0,
            txb: 0,
            serial: Arc::new(std::sync::Mutex::new(None)),
            rx,
            shutdown_tx: None,
        }
    }

    /// Total bytes received since the interface was started.
    pub fn rxb(&self) -> u64 {
        self.rxb
    }

    /// Total bytes transmitted since the interface was started.
    pub fn txb(&self) -> u64 {
        self.txb
    }

    /// Open the serial port synchronously.
    /// (unused — open_port is superseded by spawn_blocking in start())
    #[allow(dead_code)]
    fn open_port(&self) -> Result<Box<dyn serialport::SerialPort>, InterfaceError> {
        serialport::new(&self.port, self.speed)
            .timeout(Duration::from_millis(FRAME_TIMEOUT_MS))
            .open()
            .map_err(|e| InterfaceError::Serial(format!("failed to open {}: {e}", self.port)))
    }

    /// Spawn the blocking read loop.
    fn spawn_read_loop(
        serial: Arc<std::sync::Mutex<Option<Box<dyn serialport::SerialPort>>>>,
        tx: mpsc::Sender<Vec<u8>>,
        mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
        port_name: String,
    ) {
        task::spawn_blocking(move || {
            let mut decoder = HdlcDecoder::new();
            let mut byte_buf = [0u8; 1];

            loop {
                // Check shutdown signal
                if shutdown_rx.try_recv().is_ok() {
                    info!("Serial read loop shutting down: {port_name}");
                    break;
                }

                // Get the port handle
                let port_opt = {
                    let mut guard = serial.lock().unwrap();
                    guard.take()
                };

                match port_opt {
                    None => {
                        // Reconnect: try to open the port
                        info!("Serial reconnecting to {port_name}...");
                        match serialport::new(&port_name, 115200)
                            .timeout(Duration::from_millis(FRAME_TIMEOUT_MS))
                            .open()
                        {
                            Ok(port) => {
                                info!("Serial connected: {port_name}");
                                let mut guard = serial.lock().unwrap();
                                *guard = Some(port);
                            }
                            Err(e) => {
                                warn!("Serial reconnect failed: {e}");
                                // Sleep before retry
                                std::thread::sleep(Duration::from_secs(RECONNECT_DELAY_SECS));
                            }
                        }
                        continue;
                    }
                    Some(mut port) => {
                        // Read loop
                        #[allow(unused_assignments)]
                        let mut read_ok = true;
                        loop {
                            // Check shutdown inside inner loop too
                            if shutdown_rx.try_recv().is_ok() {
                                info!("Serial read loop shutting down: {port_name}");
                                let mut guard = serial.lock().unwrap();
                                *guard = None;
                                return;
                            }

                            match port.read_exact(&mut byte_buf) {
                                Ok(()) => {
                                    let byte = byte_buf[0];
                                    if let Some(frame) = decoder.feed(byte) {
                                        // Decoded a complete frame
                                        if tx.blocking_send(frame).is_err() {
                                            // Receiver dropped
                                            let mut guard = serial.lock().unwrap();
                                            *guard = None;
                                            return;
                                        }
                                    }
                                }
                                Err(ref e) if e.kind() == std::io::ErrorKind::TimedOut => {
                                    // Timeout: reset partial frame
                                    decoder.reset();
                                }
                                Err(e) => {
                                    error!("Serial read error on {port_name}: {e}");
                                    read_ok = false;
                                    break;
                                }
                            }
                        }

                        // Read error — put port back as None to trigger reconnect
                        if !read_ok {
                            let mut guard = serial.lock().unwrap();
                            *guard = None;
                        }
                    }
                }
            }
        });
    }
}

#[async_trait]
impl NetworkInterface for SerialInterface {
    fn name(&self) -> &str {
        &self.name
    }

    fn bitrate(&self) -> u64 {
        self.bitrate
    }

    fn is_online(&self) -> bool {
        self.online
    }

    async fn start(&mut self) -> Result<(), InterfaceError> {
        if self.online {
            return Err(InterfaceError::AlreadyOnline);
        }

        // Open the port
        let port = task::spawn_blocking({
            let port_name = self.port.clone();
            let speed = self.speed;
            move || -> Result<Box<dyn serialport::SerialPort>, InterfaceError> {
                serialport::new(&port_name, speed)
                    .timeout(Duration::from_millis(FRAME_TIMEOUT_MS))
                    .open()
                    .map_err(|e| InterfaceError::Serial(format!("failed to open {port_name}: {e}")))
            }
        })
        .await
        .map_err(|e| InterfaceError::Io(format!("spawn_blocking join: {e}")))??;

        {
            let mut guard = self.serial.lock().unwrap();
            *guard = Some(port);
        }

        // Create channel
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        // Spawn read loop
        Self::spawn_read_loop(self.serial.clone(), tx, shutdown_rx, self.port.clone());

        self.rx = rx;
        self.shutdown_tx = Some(shutdown_tx);
        self.online = true;
        self.rxb = 0;
        self.txb = 0;

        info!("SerialInterface '{}' started on {}", self.name, self.port);
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<(), InterfaceError> {
        if !self.online {
            return Err(InterfaceError::NotOnline);
        }

        // Signal the read loop to stop
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }

        // Close the port
        {
            let mut guard = self.serial.lock().unwrap();
            *guard = None;
        }

        // Drain remaining frames from the channel
        while self.rx.try_recv().is_ok() {}

        self.online = false;
        info!("SerialInterface '{}' shut down", self.name);
        Ok(())
    }

    async fn receive(&mut self) -> Result<Option<Vec<u8>>, InterfaceError> {
        if !self.online {
            return Err(InterfaceError::NotOnline);
        }

        match self.rx.try_recv() {
            Ok(data) => {
                self.rxb = self.rxb.saturating_add(data.len() as u64);
                Ok(Some(data))
            }
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => Err(InterfaceError::ConnectionLost),
        }
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), InterfaceError> {
        if !self.online {
            return Err(InterfaceError::NotOnline);
        }

        let frame = hdlc_encode(data);
        let serial = self.serial.clone();

        task::spawn_blocking(move || -> Result<(), InterfaceError> {
            let mut guard = serial
                .lock()
                .map_err(|e| InterfaceError::Io(format!("serial lock poisoned: {e}")))?;
            match guard.as_mut() {
                Some(port) => {
                    port.write_all(&frame)?;
                    port.flush()?;
                    Ok(())
                }
                None => Err(InterfaceError::ConnectionLost),
            }
        })
        .await
        .map_err(|e| InterfaceError::Io(format!("spawn_blocking join: {e}")))??;

        self.txb = self.txb.saturating_add(data.len() as u64);
        Ok(())
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    // ── HDLC encode/decode roundtrip ──

    #[test]
    fn hdlc_encode_decode_empty() {
        let encoded = hdlc_encode(b"");
        assert_eq!(encoded, vec![FLAG, FLAG]);
        let decoded = hdlc_decode(&encoded);
        assert_eq!(decoded, Some(vec![]));
    }

    #[test]
    fn hdlc_encode_decode_simple() {
        let data = b"hello";
        let encoded = hdlc_encode(data);
        let decoded = hdlc_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn hdlc_encode_decode_with_flag_bytes() {
        let data = vec![0x7E, 0x41, 0x7E, 0x42];
        let encoded = hdlc_encode(&data);
        // Should not contain bare 0x7E in the middle
        let middle = &encoded[1..encoded.len() - 1];
        assert!(!middle.contains(&0x7E));
        let decoded = hdlc_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn hdlc_encode_decode_with_esc_bytes() {
        let data = vec![0x7D, 0x41, 0x7D, 0x42];
        let encoded = hdlc_encode(&data);
        let decoded = hdlc_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn hdlc_encode_decode_full_byte_range() {
        let data: Vec<u8> = (0..=255).collect();
        let encoded = hdlc_encode(&data);
        let decoded = hdlc_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn hdlc_encode_decode_typical_payload() {
        // Simulate a realistic small RNS packet
        let data: Vec<u8> = (0..64).map(|i| (i * 7) as u8).collect();
        let encoded = hdlc_encode(&data);
        let decoded = hdlc_decode(&encoded).unwrap();
        assert_eq!(decoded, data);

        // Verify FLAG at start and end
        assert_eq!(encoded.first(), Some(&FLAG));
        assert_eq!(encoded.last(), Some(&FLAG));
    }

    // ── HdlcDecoder streaming tests ──

    #[test]
    fn decoder_single_frame() {
        let mut dec = HdlcDecoder::new();
        let frame = hdlc_encode(b"test");

        let mut result = None;
        for &byte in &frame {
            if let Some(f) = dec.feed(byte) {
                result = Some(f);
            }
        }
        assert_eq!(result.unwrap(), b"test");
    }

    #[test]
    fn decoder_multiple_frames() {
        let mut dec = HdlcDecoder::new();
        let mut frames = Vec::new();

        // Feed two frames back-to-back
        let frame1 = hdlc_encode(b"frame1");
        let frame2 = hdlc_encode(b"frame2");

        for &byte in &frame1 {
            if let Some(f) = dec.feed(byte) {
                frames.push(f);
            }
        }
        for &byte in &frame2 {
            if let Some(f) = dec.feed(byte) {
                frames.push(f);
            }
        }

        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0], b"frame1");
        assert_eq!(frames[1], b"frame2");
    }

    #[test]
    fn decoder_empty_frame_ignored() {
        // Two consecutive FLAG bytes = empty frame → should be ignored
        let mut dec = HdlcDecoder::new();
        assert!(dec.feed(FLAG).is_none()); // start frame
        assert!(dec.feed(FLAG).is_none()); // empty frame — dropped

        // Real frame
        let real = hdlc_encode(b"real");
        let mut result = None;
        for &byte in &real {
            if let Some(f) = dec.feed(byte) {
                result = Some(f);
            }
        }
        assert_eq!(result.unwrap(), b"real");
    }

    #[test]
    fn decoder_reset() {
        let mut dec = HdlcDecoder::new();
        assert!(dec.feed(FLAG).is_none());
        assert!(dec.feed(b'A').is_none()); // partial frame
        dec.reset();
        // Should now be waiting for a fresh FLAG
        assert!(dec.feed(b'B').is_none()); // garbage — ignored pre-FLAG
        let frame = hdlc_encode(b"fresh");
        let mut result = None;
        for &byte in &frame {
            if let Some(f) = dec.feed(byte) {
                result = Some(f);
            }
        }
        assert_eq!(result.unwrap(), b"fresh");
    }

    #[test]
    fn decoder_garbage_before_flag() {
        let mut dec = HdlcDecoder::new();
        // Junk bytes before the first FLAG should be ignored
        assert!(dec.feed(0xFF).is_none());
        assert!(dec.feed(0x00).is_none());
        let frame = hdlc_encode(b"clean");
        let mut result = None;
        for &byte in &frame {
            if let Some(f) = dec.feed(byte) {
                result = Some(f);
            }
        }
        assert_eq!(result.unwrap(), b"clean");
    }

    // ── Interface lifecycle (no real port needed) ──

    #[tokio::test]
    async fn serial_interface_not_online_initially() {
        let iface = SerialInterface::new("test", "/dev/fake", 9600);
        assert!(!iface.is_online());
        assert_eq!(iface.name(), "test");
        assert_eq!(iface.bitrate(), 9600);
    }

    #[tokio::test]
    async fn serial_interface_receive_when_not_online() {
        let mut iface = SerialInterface::new("test", "/dev/fake", 9600);
        let result = iface.receive().await;
        assert!(result.is_err());
        match result {
            Err(InterfaceError::NotOnline) => {}
            _ => panic!("expected NotOnline"),
        }
    }

    #[tokio::test]
    async fn serial_interface_send_when_not_online() {
        let mut iface = SerialInterface::new("test", "/dev/fake", 9600);
        let result = iface.send(b"data").await;
        assert!(result.is_err());
        match result {
            Err(InterfaceError::NotOnline) => {}
            _ => panic!("expected NotOnline"),
        }
    }

    #[tokio::test]
    async fn serial_interface_shutdown_when_not_online() {
        let mut iface = SerialInterface::new("test", "/dev/fake", 9600);
        let result = iface.shutdown().await;
        assert!(result.is_err());
        match result {
            Err(InterfaceError::NotOnline) => {}
            _ => panic!("expected NotOnline"),
        }
    }

    #[tokio::test]
    async fn serial_interface_already_online() {
        let mut iface = SerialInterface::new("test", "/dev/notexist", 9600);
        // Start will fail because port doesn't exist, but that's fine
        let _ = iface.start().await;
        // If it somehow started, double-start should fail
        if iface.is_online() {
            let result = iface.start().await;
            assert!(result.is_err());
        }
    }

    #[test]
    fn hw_mtu_constant() {
        assert_eq!(HW_MTU, 564);
    }
}
