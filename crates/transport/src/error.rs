//! Transport layer errors.

use thiserror::Error;

/// Errors that can occur in the transport layer.
#[derive(Debug, Error)]
pub enum TransportError {
    /// The link is not established.
    #[error("link not established")]
    LinkNotEstablished,

    /// The link is already established.
    #[error("link already established")]
    LinkAlreadyEstablished,

    /// The link was closed.
    #[error("link closed")]
    LinkClosed,

    /// An invalid link state transition was attempted.
    #[error("invalid link state: {0}")]
    InvalidLinkState(String),

    /// Proof generation or verification failed.
    #[error("proof error: {0}")]
    ProofError(String),

    /// Signature verification failed.
    #[error("signature verification failed")]
    SignatureVerification,

    /// Packet serialization or deserialization error.
    #[error("packet error: {0}")]
    PacketError(#[from] rsticulum_packet::PacketError),

    /// A packet was received for an unknown resource.
    #[error("unknown resource: {0}")]
    UnknownResource(String),

    /// A resource transfer is already in progress.
    #[error("resource transfer already in progress: {0}")]
    ResourceInProgress(String),

    /// A resource segment is out of order.
    #[error("resource segment out of order: expected {expected}, got {got}")]
    ResourceSegmentOrder { expected: u32, got: u32 },

    /// Received an invalid chunk size.
    #[error("invalid chunk size: {0}")]
    InvalidChunkSize(usize),

    /// I/O error (for future network I/O).
    #[error("I/O error: {0}")]
    Io(String),

    /// Generic transport error.
    #[error("transport error: {0}")]
    Other(String),
}
