#![forbid(unsafe_code)]
#![deny(unused_must_use)]
// Don't allow dbg! prints in release.
#![cfg_attr(not(debug_assertions), deny(clippy::dbg_macro))]

#[macro_use]
extern crate num_derive;

pub use attribute::MftAttribute;
pub use attribute::x10::StandardInfoAttr;
pub use attribute::x30::FileNameAttr;
pub use jiff::Timestamp;

pub use crate::mft::MftParser;
pub use entry::{EntryHeader, MftEntry};

pub mod attribute;
pub mod csv;
pub mod entry;
pub mod err;
pub mod mft;
pub mod ntfs;
pub mod utf16;

pub(crate) mod macros;
pub(crate) mod utils;

// Public utilities (used by `mft_dump` and helpful for library consumers).
pub use utils::{
    serialize_option_timestamp_chrono_compat, serialize_timestamp_chrono_compat,
    windows_filetime_to_timestamp,
};

pub use utf16::Utf16LeStr;

#[cfg(test)]
pub(crate) mod tests;
