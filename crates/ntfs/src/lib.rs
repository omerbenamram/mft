#![forbid(unsafe_code)]
#![deny(unused_must_use)]
// Don't allow dbg! prints in release.
#![cfg_attr(not(debug_assertions), deny(clippy::dbg_macro))]
// Makes the Rust examples of README.md doc tests of this crate.
#![cfg_attr(doctest, doc = include_str!("../README.md"))]

pub mod image;
pub mod ntfs;
pub mod parse;
pub mod tools;
