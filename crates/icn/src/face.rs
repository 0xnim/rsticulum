//! Face trait and TestFace mock.

use std::time::Duration;

use crate::interest::{Data, Interest};

pub type FaceId = u64;

#[derive(Clone, Debug)]
pub struct FaceCapabilities {
    pub disruption_tolerance: Duration,
    pub mtu: usize,
    pub is_local: bool,
}

#[async_trait::async_trait]
pub trait Face: Send + Sync {
    async fn express_interest(&self, _interest: &Interest) -> Result<Option<Data>, String>;
    async fn send_data(&self, _data: &Data) -> Result<(), String>;
    fn capabilities(&self) -> FaceCapabilities;
    fn id(&self) -> FaceId;
}

pub struct TestFace;

impl TestFace {
    pub fn new(_id: FaceId) -> Self {
        TestFace
    }
}

#[async_trait::async_trait]
impl Face for TestFace {
    async fn express_interest(&self, _interest: &Interest) -> Result<Option<Data>, String> {
        Ok(None)
    }
    async fn send_data(&self, _data: &Data) -> Result<(), String> {
        Ok(())
    }
    fn capabilities(&self) -> FaceCapabilities {
        FaceCapabilities {
            disruption_tolerance: Duration::from_secs(0),
            mtu: 1500,
            is_local: true,
        }
    }
    fn id(&self) -> FaceId {
        0
    }
}

pub fn test_face_pair() -> (TestFace, TestFace) {
    (TestFace, TestFace)
}
