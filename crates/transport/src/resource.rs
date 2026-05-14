//! Resource segmented transfer — reliable delivery of large data blobs.
//!
//! Resources are transferred in segments over RNS links. This module
//! provides segment tracking, reassembly, and a Resource abstraction
//! that manages the full lifecycle of a resource transfer.

use crate::error::TransportError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Maximum segment size in bytes.
pub const DEFAULT_SEGMENT_SIZE: usize = 1024;

/// Configuration for a resource transfer.
#[derive(Debug, Clone)]
pub struct ResourceConfig {
    /// Size of each segment in bytes.
    pub segment_size: usize,
    /// Maximum number of concurrent resource transfers.
    pub max_concurrent: usize,
}

impl Default for ResourceConfig {
    fn default() -> Self {
        Self {
            segment_size: DEFAULT_SEGMENT_SIZE,
            max_concurrent: 16,
        }
    }
}

impl ResourceConfig {
    pub fn builder() -> ResourceConfigBuilder {
        ResourceConfigBuilder::default()
    }
}

/// Builder for [`ResourceConfig`].
#[derive(Debug, Default)]
pub struct ResourceConfigBuilder {
    segment_size: Option<usize>,
    max_concurrent: Option<usize>,
}

impl ResourceConfigBuilder {
    pub fn segment_size(mut self, size: usize) -> Self {
        self.segment_size = Some(size);
        self
    }

    pub fn max_concurrent(mut self, max: usize) -> Self {
        self.max_concurrent = Some(max);
        self
    }

    pub fn build(self) -> ResourceConfig {
        ResourceConfig {
            segment_size: self.segment_size.unwrap_or(DEFAULT_SEGMENT_SIZE),
            max_concurrent: self.max_concurrent.unwrap_or(16),
        }
    }
}

// ── Segment ──

/// A single segment of a resource transfer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Segment {
    /// Resource hash (identifies the resource).
    pub resource_hash: Vec<u8>,
    /// Zero-based segment index.
    pub index: u32,
    /// Total number of segments.
    pub total: u32,
    /// Segment payload.
    pub data: Vec<u8>,
    /// SHA-256 checksum of this segment's data (for integrity).
    pub checksum: Vec<u8>,
}

impl Segment {
    /// Create a new segment.
    pub fn new(resource_hash: Vec<u8>, index: u32, total: u32, data: Vec<u8>) -> Self {
        let checksum = Sha256::digest(&data).to_vec();
        Self {
            resource_hash,
            index,
            total,
            data,
            checksum,
        }
    }

    /// Verify the segment's checksum.
    pub fn verify_checksum(&self) -> bool {
        let expected = Sha256::digest(&self.data);
        self.checksum == expected.as_slice()
    }
}

// ── Segment Tracker ──

/// Tracks received segments for a resource transfer,
/// supporting out-of-order delivery and reassembly.
#[derive(Debug)]
pub struct SegmentTracker {
    /// Resource hash being tracked.
    resource_hash: Vec<u8>,
    /// Total number of expected segments.
    total: u32,
    /// Received segments, indexed by segment index.
    received: HashMap<u32, Segment>,
    /// Whether all segments have been received.
    complete: bool,
    /// Total bytes received so far.
    bytes_received: usize,
}

impl SegmentTracker {
    /// Create a new segment tracker for a resource with `total` segments.
    pub fn new(resource_hash: Vec<u8>, total: u32) -> Self {
        Self {
            resource_hash,
            total,
            received: HashMap::new(),
            complete: false,
            bytes_received: 0,
        }
    }

    /// Add a received segment to the tracker.
    ///
    /// Returns `Ok(true)` if the resource is now complete.
    /// Returns `Ok(false)` if more segments are needed.
    /// Returns `Err` if the segment is invalid (duplicate, wrong hash, bad checksum).
    pub fn add_segment(&mut self, segment: Segment) -> Result<bool, TransportError> {
        if segment.resource_hash != self.resource_hash {
            return Err(TransportError::UnknownResource(hex::encode(
                &segment.resource_hash,
            )));
        }

        if segment.index >= self.total {
            return Err(TransportError::ResourceSegmentOrder {
                expected: self.total,
                got: segment.index,
            });
        }

        if self.received.contains_key(&segment.index) {
            return Err(TransportError::Other(format!(
                "duplicate segment {}",
                segment.index
            )));
        }

        if !segment.verify_checksum() {
            return Err(TransportError::Other(format!(
                "checksum mismatch for segment {}",
                segment.index
            )));
        }

        self.bytes_received += segment.data.len();
        self.received.insert(segment.index, segment);

        if self.received.len() as u32 == self.total {
            self.complete = true;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Assemble the complete resource from all received segments.
    ///
    /// Returns `None` if not all segments have been received.
    pub fn assemble(&self) -> Option<Vec<u8>> {
        if !self.complete {
            return None;
        }

        let mut data = Vec::with_capacity(self.bytes_received);
        for i in 0..self.total {
            data.extend_from_slice(&self.received[&i].data);
        }
        Some(data)
    }

    /// The resource hash being tracked.
    pub fn resource_hash(&self) -> &[u8] {
        &self.resource_hash
    }

    /// Total expected segments.
    pub fn total(&self) -> u32 {
        self.total
    }

    /// Number of segments received so far.
    pub fn received_count(&self) -> usize {
        self.received.len()
    }

    /// Whether all segments have been received.
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Number of segments still missing.
    pub fn missing_count(&self) -> usize {
        self.total as usize - self.received.len()
    }

    /// Get the indices of missing segments.
    pub fn missing_indices(&self) -> Vec<u32> {
        (0..self.total)
            .filter(|i| !self.received.contains_key(i))
            .collect()
    }

    /// Progress as a fraction (0.0..=1.0).
    pub fn progress(&self) -> f64 {
        if self.total == 0 {
            return 1.0;
        }
        self.received.len() as f64 / self.total as f64
    }
}

// ── Resource ──

/// State of a resource transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceState {
    /// Waiting to begin transfer.
    Pending,
    /// Segments are being transferred.
    Transferring,
    /// All segments received and verified.
    Complete,
    /// Transfer failed or was aborted.
    Failed,
}

/// A resource — a data blob being transferred over the network.
///
/// Manages segmentation, tracking, and reassembly of large data
/// over transport links.
#[derive(Debug)]
pub struct Resource {
    /// Content hash for identification.
    hash: Vec<u8>,
    /// Total size of the resource in bytes.
    total_size: usize,
    /// Resource data (populated on assembly).
    data: Option<Vec<u8>>,
    /// Transfer state.
    state: ResourceState,
    /// Segment tracker.
    tracker: SegmentTracker,
    /// Resource configuration.
    #[allow(dead_code)]
    config: ResourceConfig,
    /// Segments prepared for sending.
    segments: Vec<Segment>,
}

impl Resource {
    /// Create a new resource from raw data for sending.
    ///
    /// The data is segmented according to the configuration.
    pub fn new_for_sending(data: Vec<u8>, config: ResourceConfig) -> Self {
        let hash = Sha256::digest(&data).to_vec();
        let segment_size = config.segment_size;
        let total = ((data.len() + segment_size - 1) / segment_size) as u32;

        let mut segments = Vec::with_capacity(total as usize);
        for (i, chunk) in data.chunks(segment_size).enumerate() {
            segments.push(Segment::new(hash.clone(), i as u32, total, chunk.to_vec()));
        }

        let tracker = SegmentTracker::new(hash.clone(), total);

        Self {
            hash,
            total_size: data.len(),
            data: Some(data),
            state: ResourceState::Pending,
            tracker,
            config,
            segments,
        }
    }

    /// Create a new resource for receiving, given the hash and total size.
    pub fn new_for_receiving(
        hash: Vec<u8>,
        total_size: usize,
        total_segments: u32,
        config: ResourceConfig,
    ) -> Self {
        let tracker = SegmentTracker::new(hash.clone(), total_segments);

        Self {
            hash,
            total_size,
            data: None,
            state: ResourceState::Pending,
            tracker,
            config,
            segments: Vec::new(),
        }
    }

    // ── Accessors ──

    /// Resource content hash (SHA-256).
    pub fn hash(&self) -> &[u8] {
        &self.hash
    }

    /// Total size of the resource in bytes.
    pub fn total_size(&self) -> usize {
        self.total_size
    }

    /// Current transfer state.
    pub fn state(&self) -> ResourceState {
        self.state
    }

    /// Number of segments.
    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    /// Get the assembled resource data.
    pub fn data(&self) -> Option<&[u8]> {
        self.data.as_deref()
    }

    /// Progress of the transfer (0.0..=1.0).
    pub fn progress(&self) -> f64 {
        self.tracker.progress()
    }

    // ── Sender methods ──

    /// Get the next segment to send, if any.
    pub fn next_segment(&mut self, index: u32) -> Option<&Segment> {
        self.state = ResourceState::Transferring;
        self.segments.get(index as usize)
    }

    /// Get all segments.
    pub fn all_segments(&self) -> &[Segment] {
        &self.segments
    }

    // ── Receiver methods ──

    /// Process a received segment.
    ///
    /// Returns `Ok(true)` if the resource is now complete.
    pub fn receive_segment(&mut self, segment: Segment) -> Result<bool, TransportError> {
        self.state = ResourceState::Transferring;

        let complete = self.tracker.add_segment(segment)?;
        if complete {
            self.state = ResourceState::Complete;
            self.data = self.tracker.assemble();
        }
        Ok(complete)
    }

    /// Mark the transfer as failed.
    pub fn fail(&mut self) {
        self.state = ResourceState::Failed;
    }

    /// Whether the resource transfer is complete.
    pub fn is_complete(&self) -> bool {
        self.state == ResourceState::Complete
    }

    /// Missing segment indices.
    pub fn missing_segments(&self) -> Vec<u32> {
        self.tracker.missing_indices()
    }

    /// Total segments expected.
    pub fn total_segments(&self) -> u32 {
        self.tracker.total()
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_checksum_verification() {
        let data = b"hello segment".to_vec();
        let seg = Segment::new(b"hash".to_vec(), 0, 1, data);
        assert!(seg.verify_checksum());
    }

    #[test]
    fn segment_tampered_data_fails_checksum() {
        let data = b"hello segment".to_vec();
        let mut seg = Segment::new(b"hash".to_vec(), 0, 1, data);
        seg.data[0] ^= 0xFF;
        assert!(!seg.verify_checksum());
    }

    #[test]
    fn segment_tracker_add_and_assemble() {
        let hash = b"resource-hash-001".to_vec();
        let mut tracker = SegmentTracker::new(hash.clone(), 3);

        let s0 = Segment::new(hash.clone(), 0, 3, b"AAA".to_vec());
        let s1 = Segment::new(hash.clone(), 1, 3, b"BBB".to_vec());
        let s2 = Segment::new(hash.clone(), 2, 3, b"CCC".to_vec());

        assert!(!tracker.add_segment(s0).unwrap());
        assert_eq!(tracker.received_count(), 1);
        assert_eq!(tracker.progress(), 1.0 / 3.0);

        assert!(!tracker.add_segment(s2).unwrap()); // out of order
        assert_eq!(tracker.received_count(), 2);

        assert!(tracker.add_segment(s1).unwrap()); // completes
        assert!(tracker.is_complete());

        let assembled = tracker.assemble().unwrap();
        assert_eq!(assembled, b"AAABBBCCC");
    }

    #[test]
    fn segment_tracker_rejects_wrong_hash() {
        let mut tracker = SegmentTracker::new(b"hash-a".to_vec(), 1);
        let seg = Segment::new(b"hash-b".to_vec(), 0, 1, b"data".to_vec());
        let err = tracker.add_segment(seg).unwrap_err();
        assert!(matches!(err, TransportError::UnknownResource(_)));
    }

    #[test]
    fn segment_tracker_rejects_duplicate() {
        let hash = b"dup-hash".to_vec();
        let mut tracker = SegmentTracker::new(hash.clone(), 1);
        let seg = Segment::new(hash.clone(), 0, 1, b"data".to_vec());
        tracker.add_segment(seg.clone()).unwrap();
        let err = tracker.add_segment(seg).unwrap_err();
        assert!(matches!(err, TransportError::Other(_)));
    }

    #[test]
    fn segment_tracker_missing_indices() {
        let hash = b"missing-test".to_vec();
        let mut tracker = SegmentTracker::new(hash.clone(), 5);
        tracker
            .add_segment(Segment::new(hash.clone(), 0, 5, b"A".to_vec()))
            .unwrap();
        tracker
            .add_segment(Segment::new(hash.clone(), 2, 5, b"C".to_vec()))
            .unwrap();
        tracker
            .add_segment(Segment::new(hash.clone(), 4, 5, b"E".to_vec()))
            .unwrap();

        let missing = tracker.missing_indices();
        assert_eq!(missing, vec![1, 3]);
    }

    #[test]
    fn resource_new_for_sending_segments_data() {
        let data = vec![0x42; 3000];
        let config = ResourceConfig {
            segment_size: 1024,
            ..Default::default()
        };
        let resource = Resource::new_for_sending(data.clone(), config);

        assert_eq!(resource.total_size(), 3000);
        assert_eq!(resource.segment_count(), 3); // ceil(3000/1024) = 3
        assert!(resource.data().is_some());

        // Verify each segment
        for seg in resource.all_segments() {
            assert!(seg.verify_checksum());
            assert_eq!(seg.total, 3);
        }
    }

    #[test]
    fn resource_receive_and_assemble() {
        let data = vec![0xAB; 2500];
        let config = ResourceConfig::default();
        let send_resource = Resource::new_for_sending(data.clone(), config.clone());

        let hash = send_resource.hash().to_vec();
        let total = send_resource.total_segments();
        let total_size = send_resource.total_size();

        let mut recv_resource = Resource::new_for_receiving(hash, total_size, total, config);

        for seg in send_resource.all_segments() {
            let complete = recv_resource.receive_segment(seg.clone()).unwrap();
            if seg.index + 1 == total {
                assert!(complete);
            } else {
                assert!(!complete);
            }
        }

        assert!(recv_resource.is_complete());
        assert_eq!(recv_resource.data().unwrap(), data.as_slice());
    }

    #[test]
    fn resource_segment_count_small_data() {
        let data = b"tiny".to_vec();
        let resource = Resource::new_for_sending(data, ResourceConfig::default());
        assert_eq!(resource.segment_count(), 1);
    }

    #[test]
    fn resource_state_transitions() {
        let data = vec![0u8; 100];
        let config = ResourceConfig::default();
        let resource = Resource::new_for_sending(data, config);
        assert_eq!(resource.state(), ResourceState::Pending);
        assert_eq!(resource.progress(), 0.0);
    }

    #[test]
    fn resource_config_builder() {
        let config = ResourceConfig::builder()
            .segment_size(2048)
            .max_concurrent(8)
            .build();
        assert_eq!(config.segment_size, 2048);
        assert_eq!(config.max_concurrent, 8);
    }

    #[test]
    fn resource_config_defaults() {
        let config = ResourceConfig::default();
        assert_eq!(config.segment_size, DEFAULT_SEGMENT_SIZE);
        assert_eq!(config.max_concurrent, 16);
    }

    #[test]
    fn segment_tracker_not_complete_until_all_received() {
        let hash = b"partial".to_vec();
        let mut tracker = SegmentTracker::new(hash.clone(), 3);
        tracker
            .add_segment(Segment::new(hash.clone(), 0, 3, b"x".to_vec()))
            .unwrap();
        assert!(!tracker.is_complete());
        assert_eq!(tracker.missing_count(), 2);
    }
}
