//! Forwarding Information Base — prefix → faces.

use crate::face::FaceId;
use crate::name::Name;

pub struct FibEntry {
    pub prefix: Name,
    pub faces: Vec<(FaceId, u8)>,
}

pub struct Fib {
    _private: (),
}

impl Fib {
    pub fn new() -> Self {
        Fib { _private: () }
    }
}
