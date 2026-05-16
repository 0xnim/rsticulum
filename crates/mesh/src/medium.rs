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

    /// Broadcast a raw frame to all known peers on this medium.
    /// Returns the number of peers the frame was sent to.
    async fn broadcast(&self, frame: &[u8]) -> Result<usize, MeshError> {
        // Default: no-op, returns 0. Mediums that support broadcast override this.
        let _ = frame;
        Ok(0)
    }

    /// Register a peer's transport address on this medium.
    /// This allows the medium to send frames to the peer without
    /// waiting for an incoming announce.
    async fn add_peer_endpoint(&self, addr: RnsAddress, endpoint: String) -> Result<(), MeshError> {
        // Default: no-op. Mediums that support outbound peer registration override this.
        let _ = (addr, endpoint);
        Ok(())
    }

    /// Receive the next frame. Returns `None` when the medium is closed.
    async fn recv(&self) -> Result<Option<(RnsAddress, Vec<u8>)>, MeshError>;

    /// Estimated one-way latency in microseconds to a peer, if known.
    fn peer_latency_us(&self, peer: &RnsAddress) -> Option<u64>;

    /// Shut down the medium. After this, `recv()` returns `None`.
    async fn shutdown(&self);
}
