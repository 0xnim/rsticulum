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

    async fn recv(&self) -> Result<Option<(RnsAddress, Vec<u8>)>, MeshError> {
        let mut buf = vec![0u8; 65535];
        let (n, from) = self
            .socket
            .recv_from(&mut buf)
            .await
            .map_err(|e| MeshError::Io(e.to_string()))?;
        buf.truncate(n);

        let addr = {
            let peers = self.peer_addrs.read().await;
            peers.iter().find(|(_, sa)| **sa == from).map(|(a, _)| *a)
        };

        match addr {
            Some(a) => Ok(Some((a, buf))),
            None => {
                tracing::warn!("UDP frame from unknown peer {from}, dropping");
                Ok(None)
            }
        }
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
