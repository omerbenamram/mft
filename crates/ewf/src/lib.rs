//! Expert Witness Compression Format (EWF) reader/writer.
//!
//! This crate is a Rust implementation of the EWF family of formats (e.g. EnCase `.E01`, SMART
//! `.S01`, EnCase EWF2 `.Ex01`, and the logical evidence variants `.L01`/`.Lx01`).
//!
//! The implementation is intended to be **spec-driven** and **compatible with libewf** (see the
//! pinned libewf reference commit in `external/refs/repos/libyal__libewf.commit`).
//!
//! Note: The public API is stabilized as part of the crate extraction work. Expect additions as we
//! expand format coverage (EWF2, delta/shadow files, write resume, etc.).

mod error;
#[path = "reader/ewf1_volume.rs"]
mod ewf1_volume;
mod ewf2;
mod info;

pub mod delta;
pub mod metadata;
pub mod reader;
pub mod writer;

pub use delta::EwfDelta;
pub use error::{Error, Result};
pub use info::{EwfCompression, EwfFileFormat, EwfFormat, EwfInfo};
pub use reader::{EwfReader, LefEntry, LefExtent, LefReader, VerifyOptions};
pub use writer::{Ewf2CompressionMethod, Ewf2Writer, Ewf2WriterOptions, EwfWriter};
