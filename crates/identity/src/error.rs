use std::fmt;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum IdentityError {
    InvalidLength {
        name: &'static str,
        expected: usize,
        got: usize,
    },
    SignatureMismatch,
    ClockDrift {
        delta_secs: i64,
        threshold_secs: u64,
    },
    Serde(String),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength {
                name,
                expected,
                got,
            } => write!(
                f,
                "invalid length for {name}: expected {expected}, got {got}"
            ),
            Self::SignatureMismatch => write!(f, "signature verification failed"),
            Self::ClockDrift {
                delta_secs,
                threshold_secs,
            } => write!(f, "clock drift {delta_secs}s exceeds {threshold_secs}s"),
            Self::Serde(e) => write!(f, "serialization: {e}"),
        }
    }
}

impl std::error::Error for IdentityError {}
