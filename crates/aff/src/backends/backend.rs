//! Backend abstraction shared by all container implementations.

use forensic_image::ReadAt;
use std::io;

/// Concrete container kind backing an [`crate::backends::AffImage`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerKind {
    /// AFF1 single-file (`.aff`).
    Aff1,
    /// AFM metadata file (`.afm`) + split-raw payload.
    Afm,
    /// AFD directory container.
    Afd,
}

/// Raw segment bytes as stored by the underlying container (no decryption, no signature checks).
///
/// Higher layers (crypto wrapper) may expose **decrypted** views in the future.
#[derive(Debug, Clone)]
pub struct Segment {
    /// Segment name (e.g. `pagesize`, `imagesize`, `page0`).
    pub name: String,
    /// Segment `arg` field (AFFLIB calls this `flag` in `af_segment_head`).
    pub arg: u32,
    /// Segment data bytes.
    pub data: Vec<u8>,
}

pub(crate) trait Backend: ReadAt {
    fn kind(&self) -> ContainerKind;
    fn page_size(&self) -> usize;

    /// Lists segment names present in the container.
    fn segment_names(&self) -> Vec<String>;

    /// Reads a segment by name.
    ///
    /// Returns `Ok(None)` if the segment does not exist.
    fn read_segment(&self, name: &str) -> io::Result<Option<Segment>>;
}


