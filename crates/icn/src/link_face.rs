//! LinkFace — Face implementation over rsticulum Link.
//! Stub — implemented in Phase 5

use std::time::Duration;

use crate::face::{Face, FaceCapabilities, FaceId};
use crate::interest::{Data, Interest};

pub struct LinkFace {
    id: FaceId,
}

impl LinkFace {
    pub fn new(id: FaceId) -> Self {
        LinkFace { id }
    }
}

#[async_trait::async_trait]
impl Face for LinkFace {
    async fn express_interest(&self, _interest: &Interest) -> Result<Option<Data>, String> {
        Ok(None)
    }
    async fn send_data(&self, _data: &Data) -> Result<(), String> {
        Ok(())
    }
    fn capabilities(&self) -> FaceCapabilities {
        FaceCapabilities {
            disruption_tolerance: Duration::from_secs(3600),
            mtu: 500,
            is_local: false,
        }
    }
    fn id(&self) -> FaceId {
        self.id
    }
}
