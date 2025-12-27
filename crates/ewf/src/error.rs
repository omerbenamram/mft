use std::io;

/// Result type used by this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Error type for EWF parsing and IO.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),

    #[error("unsupported: {0}")]
    Unsupported(String),

    #[error("invalid EWF data: {0}")]
    Invalid(String),

    #[error("corrupt EWF data: {0}")]
    Corrupt(String),
}
