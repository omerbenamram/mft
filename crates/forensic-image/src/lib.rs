//! Shared abstractions for reading from disk images.
//!
//! Many forensic formats provide a **logical** byte-addressable view of a disk (or partition)
//! even when the underlying container is segmented, compressed, sparse, or encrypted.
//! This crate defines a minimal random-access API (`ReadAt`) that higher-level parsers can
//! depend on without committing to a specific container format.
//!
//! ## Design goals
//!
//! - **Small API surface**: only what most parsers need (length + random reads).
//! - **No `unsafe`**: implementations can be fully safe Rust.
//! - **Format-agnostic**: no NTFS/EWF/AFF-specific behavior in this crate.
//!
//! ## Example
//!
//! ```no_run
//! use forensic_image::ReadAt;
//! use std::sync::Arc;
//!
//! # fn open_some_image() -> Arc<dyn ReadAt> { todo!() }
//! let img = open_some_image();
//! let mut sector0 = [0u8; 512];
//! img.read_exact_at(0, &mut sector0).unwrap();
//! ```

#![forbid(unsafe_code)]
#![deny(unused_must_use)]
#![cfg_attr(not(debug_assertions), deny(clippy::dbg_macro))]

use std::io;

/// Random-access reading over an image-like source.
///
/// Implementations should treat the image as a **logical byte array** of length `len()`.
/// Reads beyond `len()` must return `UnexpectedEof`.
pub trait ReadAt: Send + Sync {
    /// Returns the logical image size in bytes.
    fn len(&self) -> u64;

    /// Reads exactly `buf.len()` bytes starting at `offset`.
    ///
    /// Implementations must return `UnexpectedEof` if the requested range is out of bounds.
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()>;

    /// Returns `true` iff `len() == 0`.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
