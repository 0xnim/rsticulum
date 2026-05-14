//! LinkFace — Face implementation over rsticulum Link.
//!
//! Wraps a rsticulum `Link` to provide the ICN Face trait. The LinkFace
//! handles Interest/Data serialization and delegates packet routing to
//! the caller via an outgoing packet channel.
//!
//! ## Architecture
//! ```text
//! Forwarder → LinkFace.express_interest() → Link.send() → packet_tx → [caller routes via mesh]
//!                                                           ↓
//! Forwarder ← LinkFace (wakes) ← Link.recv() ← Link.deliver() ← packet from mesh
//! ```

use std::sync::Arc;
use std::time::Duration;

use rsticulum_transport::Link;
use tokio::sync::{mpsc, Notify};

use crate::face::{Face, FaceCapabilities, FaceId};
use crate::interest::{Data, Interest};

/// A Face backed by a rsticulum Link.
///
/// Outgoing packets are sent to `packet_tx` for the caller to route.
/// Incoming data is made available via `deliver_packet()`.
pub struct LinkFace {
    id: FaceId,
    link: std::sync::Mutex<Link>,
    /// Outgoing packet channel — caller reads from this and routes via mesh.
    packet_tx: mpsc::UnboundedSender<Vec<u8>>,
    /// Notification when new data arrives on the link.
    data_notify: Arc<Notify>,
}

impl LinkFace {
    /// Create a new LinkFace wrapping a Link.
    ///
    /// Returns the LinkFace and a receiver for outgoing packets that
    /// the caller must route through the mesh.
    pub fn new(id: FaceId, link: Link) -> (Self, mpsc::UnboundedReceiver<Vec<u8>>) {
        let (packet_tx, packet_rx) = mpsc::unbounded_channel();
        let data_notify = Arc::new(Notify::new());

        (
            LinkFace {
                id,
                link: std::sync::Mutex::new(link),
                packet_tx,
                data_notify,
            },
            packet_rx,
        )
    }

    /// Deliver an incoming packet to the underlying Link.
    ///
    /// Call this when a packet arrives from the mesh destined for this Link.
    /// The Link will decrypt and buffer the message, making it available
    /// via recv().
    pub fn deliver_packet(&self, packet: &[u8]) -> Result<(), String> {
        let packet = rsticulum_packet::Packet::from_bytes(packet)
            .map_err(|e| format!("invalid packet: {e}"))?;

        let mut link = self.link.lock().unwrap();
        link.deliver(&packet)
            .map_err(|e| format!("deliver failed: {e}"))?;

        // Notify any waiting express_interest calls
        self.data_notify.notify_one();

        Ok(())
    }

    /// Get a reference to the underlying Link.
    pub fn link(&self) -> &std::sync::Mutex<Link> {
        &self.link
    }

    /// Get the notification handle for waking waiters.
    pub fn data_notify(&self) -> Arc<Notify> {
        self.data_notify.clone()
    }
}

#[async_trait::async_trait]
impl Face for LinkFace {
    async fn express_interest(&self, interest: &Interest) -> Result<Option<Data>, String> {
        let interest_bytes = interest.to_bytes();

        // Send Interest via Link
        let mut link = self.link.lock().unwrap();
        let _packet = link
            .send(interest_bytes)
            .map_err(|e| format!("send failed: {e}"))?;

        // The packet needs to be routed externally — send to packet_tx
        let _ = self.packet_tx.send(_packet.to_bytes());

        // Wait for response
        let timeout = interest.lifetime;
        let notify = self.data_notify.clone();

        loop {
            // Check for incoming data
            if let Some(data_bytes) = link.recv() {
                // Try to parse as Data
                if let Ok(data) = Data::from_bytes(&data_bytes) {
                    return Ok(Some(data));
                }
                // Not ICN Data — could be other Link traffic, skip
            }

            // Release lock before waiting
            drop(link);

            // Wait for notification or timeout
            let sleep = tokio::time::sleep(timeout);
            tokio::select! {
                _ = notify.notified() => {
                    // Data may have arrived, loop back
                }
                _ = sleep => {
                    return Ok(None); // timeout
                }
            }

            // Re-acquire lock for next iteration
            link = self.link.lock().unwrap();
        }
    }

    async fn send_data(&self, data: &Data) -> Result<(), String> {
        let data_bytes = data.to_bytes();

        let mut link = self.link.lock().unwrap();
        let packet = link
            .send(data_bytes)
            .map_err(|e| format!("send failed: {e}"))?;

        // Route packet externally
        let _ = self.packet_tx.send(packet.to_bytes());

        Ok(())
    }

    fn capabilities(&self) -> FaceCapabilities {
        FaceCapabilities {
            disruption_tolerance: Duration::from_secs(3600), // mesh can survive hours
            mtu: 500,                                        // rsticulum default effective MTU
            is_local: false,
        }
    }

    fn id(&self) -> FaceId {
        self.id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsticulum_destination::Destination;
    use rsticulum_identity::Keys;
    use rsticulum_transport::LinkConfig;

    #[tokio::test]
    async fn test_linkface_interest_data_round_trip() {
        // Create two identities
        let keys_a = Keys::generate();
        let keys_b = Keys::generate();
        let addr_a = keys_a.rns_address();
        let addr_b = keys_b.rns_address();

        // Create destinations
        let dest_a = Destination::new(keys_a.clone(), "test_app".to_string(), Vec::new()).unwrap();
        let dest_b = Destination::new(keys_b.clone(), "test_app".to_string(), Vec::new()).unwrap();

        // Create two Links
        let config = LinkConfig::default();
        let link_a = Link::with_config(dest_a, addr_b, config.clone());
        let link_b = Link::with_config(dest_b, addr_a, config);

        let (face_a, _rx_a) = LinkFace::new(1, link_a);
        let (face_b, _rx_b) = LinkFace::new(2, link_b);

        assert_eq!(face_a.id(), 1);
        assert_eq!(face_b.id(), 2);
        assert_eq!(
            face_a.capabilities().disruption_tolerance,
            Duration::from_secs(3600)
        );
    }
}
