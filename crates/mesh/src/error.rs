use std::fmt;

#[derive(Debug, Clone)]
pub enum MeshError {
    Io(String),
    UnknownPeer(String),
    Serde(String),
    TtlExpired,
    InvalidPacket(&'static str),
}

impl fmt::Display for MeshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO error: {e}"),
            Self::UnknownPeer(a) => write!(f, "unknown peer: {a}"),
            Self::Serde(e) => write!(f, "serialization: {e}"),
            Self::TtlExpired => write!(f, "packet TTL expired"),
            Self::InvalidPacket(r) => write!(f, "invalid packet: {r}"),
        }
    }
}

impl std::error::Error for MeshError {}
