//! Public “shape”/metadata types.
//!
//! The underlying formats expose a large metadata surface area (case data, device info, hashes,
//! etc.). This module provides a small, stable summary for callers who mostly care about
//! “what kind of image is this?” and “how big is it?”.

/// High-level EWF format identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EwfFormat {
    /// EnCase EWF1 (EVF) disk image.
    E01,
    /// SMART EWF1 (EVF) disk image.
    S01,
    /// EnCase EWF2 (EVF2) disk image.
    Ex01,
    /// EWF1 logical evidence.
    L01,
    /// EWF2 logical evidence.
    Lx01,
}

/// Compression algorithm identifier (not a guarantee every chunk is compressed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EwfCompression {
    None,
    Zlib,
    Bzip2,
    Unknown(u16),
}

/// Summary metadata for an EWF image set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EwfInfo {
    pub format: EwfFormat,
    pub media_size: u64,
    pub chunk_size: usize,
    pub chunk_count: u64,
    pub segment_count: usize,
    pub compression: EwfCompression,
}
