use crate::MeshError;
use async_trait::async_trait;
use rsticulum_identity::RnsAddress;

/// A physical transport medium the mesh sends/receives frames over.
#[async_trait]
pub trait Medium: Send + Sync + 'static {
    /// Human-readable name for this medium.
    fn name(&self) -> &str;

    /// Send a raw frame to a peer on this medium.
    async fn send(&self, to: RnsAddress, frame: &[u8]) -> Result<(), MeshError>;

    /// Receive the next frame. Returns `None` when the medium is closed.
    async fn recv(&self) -> Result<Option<(RnsAddress, Vec<u8>)>, MeshError>;

    /// Estimated one-way latency in microseconds to a peer, if known.
    fn peer_latency_us(&self, peer: &RnsAddress) -> Option<u64>;

    /// Shut down the medium. After this, `recv()` returns `None`.
    async fn shutdown(&self);
}
