//! EWF2 (Ex01/Lx01) format primitives.
//!
//! This module contains small, **spec-driven** building blocks shared by the reader and writer
//! implementations.
//!
//! Reference material:
//! - `external/libewf/documentation/Expert Witness Compression Format 2 (EWF2).asciidoc`

pub(crate) mod chunk;
pub(crate) mod file_header;
pub(crate) mod section;
