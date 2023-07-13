use std::path::{Path, PathBuf};
use thiserror::Error;

pub type Result<T> = ::std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("An I/O error has occurred")]
    IoError {
        #[from]
        source: std::io::Error,
    },
    #[error("Failed to open file {}", path.display())]
    FailedToOpenFile {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("Error while decoding name in filename attribute")]
    InvalidFilename,
    #[error(
        "Bad signature: {:x?}, expected one of [b\"FILE\", b\"BAAD\", b\"0000\"]",
        bad_sig
    )]
    InvalidEntrySignature { bad_sig: Vec<u8> },
    #[error("Unknown `AttributeType`: {:04X}", attribute_type)]
    UnknownAttributeType { attribute_type: u32 },
    #[error("Unknown collation type {}", collation_type)]
    UnknownCollationType { collation_type: u32 },
    #[error("Unknown filename namespace {}", namespace)]
    UnknownNamespace { namespace: u8 },
    #[error("Unhandled resident flag: {} (offset: {})", flag, offset)]
    UnhandledResidentFlag { flag: u8, offset: u64 },
    #[error(
        "Fixup bytes do not match bytes at end of stride {} {:x?}: {:x?}",
        stride_number,
        end_of_sector_bytes,
        fixup_bytes
    )]
    FailedToApplyFixup {
        stride_number: usize,
        end_of_sector_bytes: Vec<u8>,
        fixup_bytes: Vec<u8>,
    },
    #[error("Failed to read MftReference")]
    FailedToReadMftReference { source: winstructs::err::Error },
    #[error("Failed to read WindowsTime")]
    FailedToReadWindowsTime { source: winstructs::err::Error },
    #[error("Failed to read GUID")]
    FailedToReadGuid { source: winstructs::err::Error },
    #[error("Failed to decode data runs")]
    FailedToDecodeDataRuns { bad_data_runs: Vec<u8> },
    #[error("Failed to determine entry size")]
    FailedToReadEntrySize { },
    #[error("An unexpected error has occurred: {}", detail)]
    Any { detail: String },
}

impl Error {
    pub fn failed_to_read_windows_time(source: winstructs::err::Error) -> Error {
        Error::FailedToReadWindowsTime { source }
    }

    pub fn failed_to_read_mft_reference(source: winstructs::err::Error) -> Error {
        Error::FailedToReadMftReference { source }
    }

    pub fn failed_to_read_guid(source: winstructs::err::Error) -> Error {
        Error::FailedToReadGuid { source }
    }

    pub fn failed_to_open_file(path: impl AsRef<Path>, source: std::io::Error) -> Error {
        Error::FailedToOpenFile {
            path: path.as_ref().to_path_buf(),
            source,
        }
    }
}
