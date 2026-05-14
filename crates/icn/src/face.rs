//! Face trait and TestFace mock.
//!
//! A Face is a communication endpoint — it can express Interests and
//! receive Data. Implementations include LinkFace (rsticulum transport)
//! and TestFace (in-memory channels for testing).

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

use crate::interest::{Data, Interest};

/// Unique identifier for a face within a forwarder.
pub type FaceId = u64;

/// Capabilities of a face — used by the forwarder for PIT timeout
/// and strategy decisions.
#[derive(Clone, Debug)]
pub struct FaceCapabilities {
    /// Expected maximum disruption duration (e.g., mesh = hours, backbone = minutes).
    pub disruption_tolerance: Duration,
    /// Maximum transmission unit in bytes.
    pub mtu: usize,
    /// Whether this face is local (e.g., loopback for testing).
    pub is_local: bool,
}

/// A face — an endpoint for Interest/Data exchange.
#[async_trait::async_trait]
pub trait Face: Send + Sync {
    /// Express an Interest on this face. Returns Some(Data) if satisfied,
    /// or None if the Interest timed out.
    async fn express_interest(&self, interest: &Interest) -> Result<Option<Data>, String>;

    /// Send Data on this face (in response to a previous Interest).
    async fn send_data(&self, data: &Data) -> Result<(), String>;

    /// Get this face's capabilities.
    fn capabilities(&self) -> FaceCapabilities;

    /// Unique identifier for this face.
    fn id(&self) -> FaceId;
}

// --- TestFace: in-memory face for integration testing ---

/// Internal channel type for TestFace communication.
pub struct TestFaceChannel {
    pub interest_tx: mpsc::UnboundedSender<Interest>,
    pub interest_rx: mpsc::UnboundedReceiver<Interest>,
    pub data_tx: mpsc::UnboundedSender<Data>,
    pub data_rx: mpsc::UnboundedReceiver<Data>,
}

impl TestFaceChannel {
    fn new() -> Self {
        let (interest_tx, interest_rx) = mpsc::unbounded_channel();
        let (data_tx, data_rx) = mpsc::unbounded_channel();
        TestFaceChannel {
            interest_tx,
            interest_rx,
            data_tx,
            data_rx,
        }
    }
}

/// A face for in-memory testing.
///
/// Uses tokio channels to simulate Interest/Data exchange between
/// forwarders in the same process.
pub struct TestFace {
    id: FaceId,
    /// Channel for receiving Interests (from the forwarder).
    interest_rx: std::sync::Mutex<mpsc::UnboundedReceiver<Interest>>,
    /// Channel for sending Data (back to the forwarder).
    data_tx: mpsc::UnboundedSender<Data>,
    /// Channel for sending Interests (to the other side).
    interest_tx: mpsc::UnboundedSender<Interest>,
    /// Channel for receiving Data (from the other side).
    data_rx: std::sync::Mutex<mpsc::UnboundedReceiver<Data>>,
    capabilities: FaceCapabilities,
}

impl TestFace {
    /// Create a TestFace with the given ID and channel pair.
    pub fn new(id: FaceId, channel: TestFaceChannel) -> Self {
        TestFace {
            id,
            interest_rx: std::sync::Mutex::new(channel.interest_rx),
            data_tx: channel.data_tx,
            interest_tx: channel.interest_tx,
            data_rx: std::sync::Mutex::new(channel.data_rx),
            capabilities: FaceCapabilities {
                disruption_tolerance: Duration::from_secs(5),
                mtu: 1500,
                is_local: true,
            },
        }
    }

    /// Send an Interest on the TestFace (to the connected peer).
    pub fn send_interest(&self, interest: Interest) {
        let _ = self.interest_tx.send(interest);
    }

    /// Receive an Interest from the connected peer.
    pub fn recv_interest(&self) -> Option<Interest> {
        self.interest_rx.lock().unwrap().try_recv().ok()
    }

    /// Receive Data from the connected peer.
    pub fn recv_data(&self) -> Option<Data> {
        self.data_rx.lock().unwrap().try_recv().ok()
    }
}

#[async_trait::async_trait]
impl Face for TestFace {
    async fn express_interest(&self, interest: &Interest) -> Result<Option<Data>, String> {
        // Send Interest to the other side
        let _ = self.interest_tx.send(interest.clone());

        // Wait for Data with timeout — must drop mutex guard before await
        let timeout = interest.lifetime;
        let mut rx = {
            // Lock, take receiver, unlock
            let mut guard = self.data_rx.lock().unwrap();
            std::mem::replace(&mut *guard, mpsc::unbounded_channel().1)
        };

        let result = tokio::time::timeout(timeout, rx.recv()).await;

        // Put the receiver back (may have remaining items)
        {
            let mut guard = self.data_rx.lock().unwrap();
            let _ = std::mem::replace(&mut *guard, rx);
        }

        match result {
            Ok(Some(data)) => Ok(Some(data)),
            Ok(None) => Ok(None),
            Err(_) => Ok(None), // timeout
        }
    }

    async fn send_data(&self, data: &Data) -> Result<(), String> {
        self.data_tx
            .send(data.clone())
            .map_err(|e| format!("failed to send Data: {e}"))
    }

    fn capabilities(&self) -> FaceCapabilities {
        self.capabilities.clone()
    }

    fn id(&self) -> FaceId {
        self.id
    }
}

impl std::fmt::Debug for TestFace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestFace").field("id", &self.id).finish()
    }
}

/// Create a pair of connected TestFaces for integration testing.
///
/// `a` and `b` are connected: Interests sent via `a` are received by `b`,
/// and Data sent by `b` is received by `a`.
pub fn test_face_pair() -> (Arc<TestFace>, Arc<TestFace>) {
    let ch_a = TestFaceChannel::new();
    let ch_b = TestFaceChannel::new();

    let face_a = TestFace {
        id: 1,
        interest_rx: std::sync::Mutex::new(ch_a.interest_rx),
        data_tx: ch_a.data_tx,
        interest_tx: ch_b.interest_tx,
        data_rx: std::sync::Mutex::new(ch_b.data_rx),
        capabilities: FaceCapabilities {
            disruption_tolerance: Duration::from_secs(5),
            mtu: 1500,
            is_local: true,
        },
    };

    let face_b = TestFace {
        id: 2,
        interest_rx: std::sync::Mutex::new(ch_b.interest_rx),
        data_tx: ch_b.data_tx,
        interest_tx: ch_a.interest_tx,
        data_rx: std::sync::Mutex::new(ch_a.data_rx),
        capabilities: FaceCapabilities {
            disruption_tolerance: Duration::from_secs(5),
            mtu: 1500,
            is_local: true,
        },
    };

    (Arc::new(face_a), Arc::new(face_b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hash(byte: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = byte;
        h
    }

    #[tokio::test]
    async fn test_testface_round_trip() {
        let (face_a, face_b) = test_face_pair();

        let name = crate::name::Name::new(make_hash(0x01), &[b"test"]);
        let interest = Interest::new(name.clone()).with_lifetime(Duration::from_millis(100));

        // Spawn a task to receive Interest and send Data back
        let b = face_b.clone();
        let response_name = name.clone();
        tokio::spawn(async move {
            // Receive Interest
            let recv_interest = b.recv_interest().expect("should receive interest");
            assert_eq!(recv_interest.name, response_name);

            // Send Data back
            let sig = rsticulum_transport::Proof::from_bytes(&vec![0u8; 96]).unwrap();
            let data = Data::new(response_name, b"hello".to_vec(), sig);
            b.send_data(&data).await.unwrap();
        });

        let result = face_a.express_interest(&interest).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().content, b"hello");
    }
}
