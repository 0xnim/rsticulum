//! Pending Interest Table — aggregation + reverse-path.

use crate::face::FaceId;
use crate::interest::Interest;
use std::time::Instant;

pub struct PitEntry {
    pub interest: Interest,
    pub in_faces: Vec<FaceId>,
    pub out_face: Option<FaceId>,
    pub expires_at: Instant,
    pub satisfied: bool,
}

pub enum PitOp {
    Inserted,
    Aggregated,
}

pub struct Pit {
    _private: (),
}

impl Pit {
    pub fn new() -> Self {
        Pit { _private: () }
    }
}
