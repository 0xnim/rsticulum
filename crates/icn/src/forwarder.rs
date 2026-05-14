//! ICN Forwarder — ties FIB/PIT/CS/Strategy together.

use std::collections::HashMap;
use std::sync::Arc;

use crate::cs::ContentStore;
use crate::face::{Face, FaceId};
use crate::fib::Fib;
use crate::interest::{Data, Interest};
use crate::pit::Pit;
use crate::strategy::Strategy;

pub struct Forwarder {
    cs: ContentStore,
    fib: Fib,
    pit: Pit,
    _strategy: Box<dyn Strategy>,
    _faces: HashMap<FaceId, Arc<dyn Face>>,
}

impl Forwarder {
    pub fn new(strategy: Box<dyn Strategy>) -> Self {
        Forwarder {
            cs: ContentStore::new(1000),
            fib: Fib::new(),
            pit: Pit::new(),
            _strategy: strategy,
            _faces: HashMap::new(),
        }
    }

    pub fn register_face(&mut self, _face: Arc<dyn Face>) {}
    pub fn unregister_face(&mut self, _face_id: FaceId) {}

    pub async fn express(
        &mut self,
        _interest: Interest,
        _in_face: FaceId,
    ) -> Result<Option<Data>, String> {
        Ok(None)
    }

    pub async fn receive_data(&mut self, _data: Data, _in_face: FaceId) -> Result<(), String> {
        Ok(())
    }
}
