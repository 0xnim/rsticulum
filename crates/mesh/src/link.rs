use crate::Medium;
use rsticulum_identity::RnsAddress;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Measured link quality to a peer.
#[derive(Debug, Clone, Copy, Default)]
pub struct LinkQuality {
    pub rtt_us: f64,
    pub loss: f64,
    pub score: f64,
}

impl LinkQuality {
    pub fn recompute(&mut self) {
        let rtt_score = (1.0 - (self.rtt_us / 10_000_000.0)).clamp(0.0, 1.0);
        let loss_score = 1.0 - self.loss;
        self.score = (rtt_score * loss_score).sqrt();
    }
}

/// Information about a known peer.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub address: RnsAddress,
    pub medium_name: String,
    pub quality: LinkQuality,
    pub last_seen: Instant,
}

/// Configuration for the link layer.
#[derive(Debug, Clone)]
pub struct LinkConfig {
    pub heartbeat_interval: Duration,
    pub peer_timeout: Duration,
    pub smoothing_alpha: f64,
}

impl Default for LinkConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval: Duration::from_secs(5),
            peer_timeout: Duration::from_secs(30),
            smoothing_alpha: 0.2,
        }
    }
}

/// Manages peer discovery, heartbeats, and link quality.
pub struct LinkManager {
    config: LinkConfig,
    peers: HashMap<RnsAddress, PeerInfo>,
    medium: Arc<dyn Medium>,
}

impl LinkManager {
    pub fn new(medium: Arc<dyn Medium>, config: LinkConfig) -> Self {
        Self {
            config,
            peers: HashMap::new(),
            medium,
        }
    }

    pub fn peers(&self) -> Vec<&PeerInfo> {
        self.peers.values().collect()
    }

    /// Record a heartbeat from a peer, updating link quality via EWMA.
    pub fn record_heartbeat(&mut self, from: RnsAddress, rtt_us: f64) {
        let peer = self.peers.entry(from).or_insert_with(|| PeerInfo {
            address: from,
            medium_name: self.medium.name().to_string(),
            quality: LinkQuality::default(),
            last_seen: Instant::now(),
        });
        let alpha = self.config.smoothing_alpha;
        peer.quality.rtt_us = alpha * rtt_us + (1.0 - alpha) * peer.quality.rtt_us;
        peer.quality.recompute();
        peer.last_seen = Instant::now();
    }

    pub fn prune_stale(&mut self) {
        self.peers
            .retain(|_, info| info.last_seen.elapsed() < self.config.peer_timeout);
    }

    pub fn quality_to(&self, addr: &RnsAddress) -> Option<LinkQuality> {
        self.peers.get(addr).map(|p| p.quality)
    }

    pub fn peers_above(&self, min_score: f64) -> Vec<&PeerInfo> {
        self.peers
            .values()
            .filter(|p| p.quality.score >= min_score)
            .collect()
    }
}
