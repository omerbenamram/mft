#![deny(unused_must_use)]
// Don't allow dbg! prints in release.
#![cfg_attr(not(debug_assertions), deny(clippy::dbg_macro))]

#[macro_use]
extern crate num_derive;

pub use attribute::MftAttribute;
pub use attribute::x10::StandardInfoAttr;
pub use attribute::x30::FileNameAttr;

pub use crate::mft::MftParser;
pub use entry::{EntryHeader, MftEntry};

pub mod attribute;
pub mod csv;
pub mod entry;
pub mod err;
pub mod mft;

pub(crate) mod macros;
pub(crate) mod utils;

#[cfg(test)]
pub(crate) mod tests;
