//! Shared parsing utilities for NTFS structures.

mod error;
mod hexdump;
mod reader;

pub use error::{ParseError, Result};
pub use reader::Reader;
