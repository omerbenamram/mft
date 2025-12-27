#![forbid(unsafe_code)]
#![deny(unused_must_use)]
// Don't allow dbg! prints in release.
#![cfg_attr(not(debug_assertions), deny(clippy::dbg_macro))]

pub mod image;
pub mod ntfs;
pub mod parse;
pub mod tools;
