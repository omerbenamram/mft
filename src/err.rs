use snafu::Snafu;
use std::path::PathBuf;
use std::{io, result};

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("An I/O error has occurred: {}", "source"))]
    IoError { source: std::io::Error },
    #[snafu(display("Failed to open file {}: {}", path.display(), source))]
    FailedToOpenFile {
        path: PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("Error while decoding name in filename attribute"))]
    InvalidFilename,
    #[snafu(display("Bad signature: {:04X}", bad_sig))]
    InvalidEntrySignature { bad_sig: u32 },
    #[snafu(display("Unhandled resident flag: {} (offset: {})", flag, offset))]
    UnhandledResidentFlag { flag: u8, offset: u64 },
    #[snafu(display("Expected usa_offset `{}` to equal 48", offset))]
    InvalidUsaOffset { offset: u16 },
    #[snafu(display("An unexpected error has occurred: {}", detail))]
    Any { detail: String },
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::IoError { source: err }
    }
}
