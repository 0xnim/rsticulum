//! rsticulum-daemon — mesh networking + ICN forwarder.
//!
//! The daemon ties together:
//! - Identity management (keypair loading/generation/saving)
//! - Mesh routing (UDP medium, MeshRouter, link discovery)
//! - ICN forwarding (ContentStore, FIB/PIT, manifest serving)
//! - Local API (TCP socket for applications)
//!
//! ## Architecture
//! ```text
//! ┌─────────────────────────────────────┐
//! │           Local API (TCP)           │
//! │   express / publish / register      │
//! ├─────────────────────────────────────┤
//! │         ICN Forwarder               │
//! │   FIB / PIT / CS / Strategy         │
//! ├─────────────────────────────────────┤
//! │         Mesh Router                 │
//! │   routing table / link discovery    │
//! ├─────────────────────────────────────┤
//! │         Transport                   │
//! │   UDP medium / interfaces           │
//! └─────────────────────────────────────┘
//! ```

pub mod config;

use std::sync::Arc;

use rsticulum_identity::Keys;
use rsticulum_mesh::{Medium, MeshRouter, UdpMedium};

/// The daemon — holds all runtime state.
pub struct Daemon {
    /// Local identity keypair.
    pub keys: Keys,
    /// Mesh router for path discovery.
    pub router: MeshRouter,
    /// ICN forwarder for content-addressed networking.
    pub forwarder: rsticulum_icn::Forwarder,
    /// Active transport media.
    pub media: Vec<Arc<dyn Medium>>,
}

impl Daemon {
    /// Create a new daemon with the given keys.
    pub fn new(keys: Keys) -> Self {
        let router = MeshRouter::new(keys.rns_address());
        let forwarder = rsticulum_icn::Forwarder::new();
        Daemon {
            keys,
            router,
            forwarder,
            media: Vec::new(),
        }
    }

    /// Add a transport medium to the daemon.
    pub fn add_medium(&mut self, medium: Arc<dyn Medium>) {
        self.media.push(medium);
    }

    /// Start the daemon: run the mesh + ICN event loop.
    pub async fn run(&mut self) -> Result<(), DaemonError> {
        tracing::info!(
            "Daemon starting — local address: {}",
            self.keys.rns_address()
        );

        if self.media.is_empty() {
            tracing::warn!("No transport media configured — daemon has no network");
        }

        // Main event loop
        loop {
            // Receive from all media, collecting results before processing
            let mut frames = Vec::new();
            for medium in &self.media {
                match medium.recv().await {
                    Ok(Some((from, frame))) => {
                        frames.push((from, frame));
                    }
                    Ok(None) => {
                        tracing::info!("Medium {} closed", medium.name());
                    }
                    Err(e) => {
                        tracing::error!("Error receiving from {}: {}", medium.name(), e);
                    }
                }
            }

            // Process frames (self is free to borrow mutably now)
            for (from, frame) in frames {
                tracing::debug!("Received {} bytes from {}", frame.len(), from);
                self.handle_frame(from, frame).await?;
            }

            // Yield to avoid busy-looping
            tokio::task::yield_now().await;
        }
    }

    /// Handle an incoming frame from the mesh.
    async fn handle_frame(
        &mut self,
        from: rsticulum_identity::RnsAddress,
        frame: Vec<u8>,
    ) -> Result<(), DaemonError> {
        // Try to parse as an ICN Interest or Data packet
        // In a real daemon, the frame would be decrypted via Link first.
        // For now, try direct parsing.
        if let Ok(data) = rsticulum_icn::Data::from_bytes(&frame) {
            tracing::debug!("Received ICN Data: {}", data.name);
            self.forwarder.receive_data(data, 0).await?;
            return Ok(());
        }

        if let Ok(interest) = rsticulum_icn::Interest::from_bytes(&frame) {
            tracing::debug!("Received ICN Interest: {}", interest.name);
            // Express the Interest locally — forwarder will check CS, FIB, etc.
            // Use face ID 0 for "mesh face"
            if let Ok(Some(data)) = self.forwarder.express(interest, 0).await {
                // Send Data back to requester
                self.send_to(from, &data.to_bytes()).await?;
            }
            return Ok(());
        }

        // Unknown frame type — log and ignore
        tracing::debug!("Unknown frame type from {}: {} bytes", from, frame.len());
        Ok(())
    }

    /// Send raw bytes to a mesh destination.
    async fn send_to(
        &self,
        dest: rsticulum_identity::RnsAddress,
        data: &[u8],
    ) -> Result<(), DaemonError> {
        // Try each medium
        for medium in &self.media {
            match medium.send(dest, data).await {
                Ok(()) => return Ok(()),
                Err(e) => tracing::debug!("Failed to send via {}: {}", medium.name(), e),
            }
        }
        Err(DaemonError::NoRoute)
    }

    /// Publish content to the local ICN forwarder.
    pub fn publish(&mut self, data: rsticulum_icn::Data) -> Result<(), DaemonError> {
        // Verify and cache
        let name = data.name.clone();
        self.forwarder.cs_mut().insert(name, data);
        Ok(())
    }

    /// Add a FIB route for a producer prefix.
    pub fn add_route(&mut self, prefix: rsticulum_icn::Name, face_id: u64, cost: u8) {
        self.forwarder.add_route(prefix, face_id, cost);
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("no route to destination")]
    NoRoute,
    #[error("ICN error: {0}")]
    Icn(String),
    #[error("mesh error: {0}")]
    Mesh(#[from] rsticulum_mesh::MeshError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<String> for DaemonError {
    fn from(s: String) -> Self {
        DaemonError::Icn(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_daemon_creation() {
        let keys = Keys::generate();
        let daemon = Daemon::new(keys.clone());
        assert_eq!(daemon.keys.rns_address(), keys.rns_address());
        assert_eq!(daemon.router.local_addr(), &keys.rns_address());
        assert!(daemon.media.is_empty());
    }

    #[tokio::test]
    async fn test_daemon_with_medium() {
        let keys = Keys::generate();
        let mut daemon = Daemon::new(keys);

        // Create a local UDP medium
        let medium = UdpMedium::bind("test", "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        daemon.add_medium(Arc::new(medium));
        assert_eq!(daemon.media.len(), 1);
    }
}
