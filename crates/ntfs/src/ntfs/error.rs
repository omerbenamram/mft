use crate::parse::ParseError;
use std::io;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error")]
    Io(#[from] io::Error),

    #[error("{0}")]
    Parse(#[from] ParseError),

    #[error("MFT parser error")]
    Mft(#[from] mft::err::Error),

    #[error("Invalid NTFS boot sector: {message}")]
    InvalidBootSector { message: &'static str },

    #[error("Invalid filesystem data: {message}")]
    InvalidData { message: String },

    #[error("Not found: {what}")]
    NotFound { what: String },

    #[error("Unsupported: {what}")]
    Unsupported { what: String },
}
