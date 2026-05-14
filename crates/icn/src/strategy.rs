//! Strategy trait and BestRoute implementation.

use crate::face::FaceId;
use crate::interest::{Data, Interest};
use crate::pit::PitEntry;

pub enum StrategyDecision {
    ForwardTo(FaceId),
    Multicast(Vec<FaceId>),
    SuppressAggregate,
    ServeFromCache,
    NoRoute,
}

#[async_trait::async_trait]
pub trait Strategy: Send + Sync {
    async fn decide(
        &self,
        _interest: &Interest,
        _fib_faces: &[(FaceId, u8)],
        _pit_hit: Option<&PitEntry>,
        _cs_hit: Option<&Data>,
    ) -> StrategyDecision;
}

pub struct BestRoute;

#[async_trait::async_trait]
impl Strategy for BestRoute {
    async fn decide(
        &self,
        _interest: &Interest,
        _fib_faces: &[(FaceId, u8)],
        _pit_hit: Option<&PitEntry>,
        _cs_hit: Option<&Data>,
    ) -> StrategyDecision {
        StrategyDecision::NoRoute
    }
}
