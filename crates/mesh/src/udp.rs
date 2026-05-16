use crate::{Medium, MeshError};
use async_trait::async_trait;
use rsticulum_identity::RnsAddress;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

/// UDP-based medium for local/network peering.
pub struct UdpMedium {
    name: String,
    socket: Arc<UdpSocket>,
    peer_addrs: RwLock<HashMap<RnsAddress, SocketAddr>>,
}

impl UdpMedium {
    pub async fn bind(name: impl Into<String>, bind_addr: SocketAddr) -> Result<Self, MeshError> {
        let socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| MeshError::Io(e.to_string()))?;
        Ok(Self {
            name: name.into(),
            socket: Arc::new(socket),
            peer_addrs: RwLock::new(HashMap::new()),
        })
    }

    /// Register a peer's UDP address.
    pub async fn add_peer(&self, addr: RnsAddress, socket_addr: SocketAddr) {
        self.peer_addrs.write().await.insert(addr, socket_addr);
    }

    /// Get the bound local address.
    pub fn local_addr(&self) -> Result<SocketAddr, MeshError> {
        self.socket
            .local_addr()
            .map_err(|e| MeshError::Io(e.to_string()))
    }
}

#[async_trait]
impl Medium for UdpMedium {
    fn name(&self) -> &str {
        &self.name
    }

    async fn send(&self, to: RnsAddress, frame: &[u8]) -> Result<(), MeshError> {
        let sa = {
            let peers = self.peer_addrs.read().await;
            peers
                .get(&to)
                .copied()
                .ok_or_else(|| MeshError::UnknownPeer(hex::encode(to.as_bytes())))?
        };
        self.socket
            .send_to(frame, sa)
            .await
            .map_err(|e| MeshError::Io(e.to_string()))?;
        Ok(())
    }

    async fn broadcast(&self, frame: &[u8]) -> Result<usize, MeshError> {
        let peers: Vec<SocketAddr> = {
            let addrs = self.peer_addrs.read().await;
            addrs.values().copied().collect()
        };
        let count = peers.len();
        for sa in &peers {
            if let Err(e) = self.socket.send_to(frame, sa).await {
                tracing::warn!("broadcast send to {sa} failed: {e}");
            }
        }
        Ok(count)
    }

    async fn add_peer_endpoint(&self, addr: RnsAddress, endpoint: String) -> Result<(), MeshError> {
        let sa: SocketAddr = endpoint
            .parse()
            .map_err(|e| MeshError::Io(format!("invalid endpoint '{endpoint}': {e}")))?;
        self.add_peer(addr, sa).await;
        tracing::info!("Registered peer {addr} at {sa} via API");
        Ok(())
    }

    async fn recv(&self) -> Result<Option<(RnsAddress, Vec<u8>)>, MeshError> {
        let mut buf = vec![0u8; 65535];
        let (n, from_addr) = self
            .socket
            .recv_from(&mut buf)
            .await
            .map_err(|e| MeshError::Io(e.to_string()))?;
        buf.truncate(n);

        // Try to look up existing peer by UDP address
        let addr = {
            let peers = self.peer_addrs.read().await;
            peers.iter().find(|(_, sa)| **sa == from_addr).map(|(a, _)| *a)
        };

        if let Some(addr) = addr {
            return Ok(Some((addr, buf)));
        }

        // Unknown peer: try to determine source address by parsing the packet.
        // For ANNOUNCE packets we can derive the sender's RNS address from the
        // identity key material in the packet data. Python RNS puts the full
        // 64-byte public key (X25519 || Ed25519) in the announce data, and
        // the identity hash is SHA-256(full_64_bytes)[:16].
        // For non-ANNOUNCE packets, we fall back to using the destination_hash
        // as the source. This may be wrong (e.g. for proofs the dest_hash is
        // the receiver), but the daemon's handle_proof can resolve the true
        // sender by matching transport_id against pending links.
        if let Ok(packet) = rsticulum_packet::Packet::from_bytes(&buf) {
            if packet.packet_type == rsticulum_packet::ANNOUNCE {
                if packet.data.len() >= 64 {
                    // Python RNS format: derive address from full 64-byte key
                    // SHA-256(X25519(32) || Ed25519(32))[:16]
                    let mut full_key = [0u8; 64];
                    full_key.copy_from_slice(&packet.data[..64]);
                    let addr = RnsAddress::from_full_key(&full_key);
                    tracing::info!(
                        "Auto-registered peer {addr} at {from_addr} via announce (64-byte key)"
                    );
                    self.add_peer(addr, from_addr).await;
                    return Ok(Some((addr, buf)));
                } else if packet.data.len() >= 32 {
                    // Rust-only format: SHA-256(Ed25519_32bytes)[:16]
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&packet.data[..32]);
                    let addr = RnsAddress::from_identity_key(&key);
                    tracing::info!(
                        "Auto-registered peer {addr} at {from_addr} via announce (32-byte key)"
                    );
                    self.add_peer(addr, from_addr).await;
                    return Ok(Some((addr, buf)));
                }
            }

            // For non-announce packets from unknown peers, use destination_hash
            // as a best-guess source address. The daemon can reconcile this with
            // transport_id matching for link proofs.
            if let Ok(dest) = packet.destination() {
                tracing::debug!(
                    "Using dest_hash {dest} as source for packet from unknown peer {from_addr}"
                );
                return Ok(Some((dest, buf)));
            }
        }

        tracing::warn!("UDP frame from unknown peer {from_addr}, dropping");
        Ok(None)
    }

    fn peer_latency_us(&self, _peer: &RnsAddress) -> Option<u64> {
        None
    }

    async fn shutdown(&self) { /* socket dropped naturally */
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsticulum_packet::Packet;

    fn test_addr(b: u8) -> RnsAddress {
        RnsAddress::from_identity_key(&[b; 32])
    }

    #[tokio::test]
    async fn two_nodes_exchange_data() {
        let a1 = test_addr(1);
        let a2 = test_addr(2);

        let m1 = UdpMedium::bind("test-1", "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let m2 = UdpMedium::bind("test-2", "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        let sa1 = m1.local_addr().unwrap();
        let sa2 = m2.local_addr().unwrap();
        m1.add_peer(a2, sa2).await;
        m2.add_peer(a1, sa1).await;

        let pkt = Packet::new_data(a2, b"hello, mesh!".to_vec());
        m1.send(a2, &pkt.to_bytes()).await.unwrap();

        let (src, data) = m2.recv().await.unwrap().unwrap();
        assert_eq!(src, a1);
        let recv_pkt = Packet::from_bytes(&data).unwrap();
        assert_eq!(recv_pkt.data, b"hello, mesh!");
    }
}
