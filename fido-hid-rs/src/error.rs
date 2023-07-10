use thiserror::Error;

pub type Result<T> = std::result::Result<T, HidError>;

#[derive(Debug, Error, PartialEq, Eq, PartialOrd, Ord)]
pub enum HidError {
    #[error("I/O error communicating with device: {0}")]
    IoError(String),
    #[error("internal error, likely library bug")]
    Internal,
    #[error("attempted to communicate with a closed device")]
    Closed,
    #[error("device sent an unexpected message length")]
    InvalidMessageLength,
    #[error("could not send data to device")]
    SendError,
    #[error("permission denied")]
    PermissionDenied,
}

impl From<std::io::Error> for HidError {
    fn from(v: std::io::Error) -> Self {
        Self::IoError(v.to_string())
    }
}
