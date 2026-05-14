use thiserror::Error;

#[derive(Debug, Error)]
pub enum InterfaceError {
    #[error("I/O error: {0}")]
    Io(String),
    #[error("serial port error: {0}")]
    Serial(String),
    #[error("connection lost")]
    ConnectionLost,
    #[error("decode error: {0}")]
    DecodeError(String),
    #[error("operation timed out")]
    Timeout,
    #[error("interface already online")]
    AlreadyOnline,
    #[error("interface not online")]
    NotOnline,
    #[error("invalid configuration: {0}")]
    Config(String),
}

impl From<std::io::Error> for InterfaceError {
    fn from(e: std::io::Error) -> Self {
        InterfaceError::Io(e.to_string())
    }
}
