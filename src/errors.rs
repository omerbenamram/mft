use std::fmt;
use std::fmt::Display;
use std::io;

#[derive(Debug)]
pub enum ErrorKind {
    IoError,
    InvalidFileSignature,
    InvalidEntrySignature,
    Utf16Error,
}

#[derive(Debug)]
pub struct MftError {
    /// Formated error message
    pub message: String,
    /// The type of error
    pub kind: ErrorKind,
    /// Any additional information passed along, such as the argument name that caused the error
    pub info: Option<Vec<String>>,
}

impl MftError {
    #[allow(dead_code)]
    pub fn invalid_file_signature(err: String) -> Self {
        MftError {
            message: format!("{}", err),
            kind: ErrorKind::InvalidFileSignature,
            info: Some(vec![]),
        }
    }
    #[allow(dead_code)]
    pub fn invalid_entry_signature(err: String) -> Self {
        MftError {
            message: format!("{}", err),
            kind: ErrorKind::InvalidFileSignature,
            info: Some(vec![]),
        }
    }
    #[allow(dead_code)]
    pub fn decode_error(err: String) -> Self {
        MftError {
            message: format!("{}", err),
            kind: ErrorKind::Utf16Error,
            info: Some(vec![]),
        }
    }
}

impl From<io::Error> for MftError {
    fn from(err: io::Error) -> Self {
        MftError {
            message: format!("{}", err),
            kind: ErrorKind::IoError,
            info: Some(vec![]),
        }
    }
}

impl Display for MftError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "{}", self.message)
    }
}
