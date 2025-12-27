use std::io;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

/// Errors returned by the `aff` crate.
#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error")]
    Io(#[from] io::Error),

    #[error("Invalid AFF container: {message}")]
    InvalidFormat { message: &'static str },

    #[error("Invalid AFF data: {message}")]
    InvalidData { message: String },

    #[error("Unsupported: {what}")]
    Unsupported { what: String },
}
