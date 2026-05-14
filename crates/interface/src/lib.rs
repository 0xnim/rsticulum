//! Network interfaces — KISS, serial, TCP, I2P framing.
//!
//! Provides async I/O interfaces for Reticulum-compatible networking:
//! - [`SerialInterface`] — HDLC framing over serial ports.
//! - [`TcpClientInterface`] — KISS framing over TCP (outbound).
//! - [`TcpServerInterface`] — KISS framing over TCP (inbound, broadcast to clients).
//!
//! All interfaces implement [`NetworkInterface`], which exposes `start`,
//! `shutdown`, `receive`, and `send` via async methods and mpsc channels.

pub mod error;
pub mod hdlc;
pub mod kiss;
pub mod serial;
pub mod tcp;

use async_trait::async_trait;
pub use error::InterfaceError;
pub use hdlc::{
    HdlcDecoder, HdlcFrame, ESC as HDLC_ESC, ESC_MASK as HDLC_ESC_MASK, FLAG as HDLC_FLAG,
};
pub use kiss::{
    KissDecoder, KissFrame, KissFrameResult, CMD_DATA, CMD_FULLDUPLEX, CMD_P, CMD_READY,
    CMD_RETURN, CMD_SETHARDWARE, CMD_SLOTTIME, CMD_TXDELAY, CMD_TXTAIL, CMD_UNKNOWN, FEND, FESC,
    TFEND, TFESC,
};
pub use serial::SerialInterface;
pub use tcp::{TcpClientInterface, TcpServerInterface};

/// Common trait for all network interfaces.
///
/// Each interface manages its own I/O loop (serial port, TCP connections, etc.)
/// and delivers decoded frames through the [`receive`] method. Outgoing data is
/// encoded and sent through [`send`].
///
/// ## Lifecycle
///
/// 1. Create the interface via its constructor (e.g. [`SerialInterface::new`]).
/// 2. Call [`start`](NetworkInterface::start) to bring the interface online
///    (opens the port, spawns the read task, etc.).
/// 3. Poll [`receive`](NetworkInterface::receive) in a loop for incoming frames.
/// 4. Call [`send`](NetworkInterface::send) to encode and transmit frames.
/// 5. Call [`shutdown`](NetworkInterface::shutdown) to tear down I/O tasks.
#[async_trait]
pub trait NetworkInterface: Send + Sync {
    /// Human-readable name of this interface (e.g. `"Serial /dev/ttyUSB0"`).
    fn name(&self) -> &str;

    /// Physical or configured bitrate in bits per second.
    fn bitrate(&self) -> u64;

    /// Returns `true` if the interface is currently online.
    fn is_online(&self) -> bool;

    /// Bring the interface online.
    ///
    /// For serial: opens the port and spawns the read loop.
    /// For TCP client: connects to the remote host.
    /// For TCP server: binds the listener and begins accepting connections.
    ///
    /// Returns `Err(AlreadyOnline)` if already started.
    async fn start(&mut self) -> Result<(), InterfaceError>;

    /// Shut down the interface gracefully.
    ///
    /// Stops the read loop, closes the port/listener, and drains any
    /// in-flight sends. Returns `Err(NotOnline)` if not started.
    async fn shutdown(&mut self) -> Result<(), InterfaceError>;

    /// Receive the next decoded frame, if available.
    ///
    /// Returns `Ok(None)` if the channel is empty (non-blocking semantic).
    /// Returns `Ok(Some(data))` when a frame has been received and decoded
    /// (HDLC or KISS framing already stripped).
    /// Returns `Err(NotOnline)` if the interface is not running.
    async fn receive(&mut self) -> Result<Option<Vec<u8>>, InterfaceError>;

    /// Send raw payload data. The interface handles framing/encoding.
    ///
    /// Returns `Err(NotOnline)` if the interface is not running.
    async fn send(&mut self, data: &[u8]) -> Result<(), InterfaceError>;
}
