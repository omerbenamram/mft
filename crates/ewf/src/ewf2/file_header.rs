//! EWF2 segment file header (Ex01/Lx01).
//!
//! Every EWF2 segment starts with a fixed-size 32-byte header.
//!
//! ## Layout (EWF2 2.1)
//!
//! The file header is 32 bytes of size and consists of:
//!
//! - Offset `0x00..0x08` (`[u8; 8]`): signature (`EVF2\r\n\x81\x00` or `LEF2\r\n\x81\x00`)
//! - Offset `0x08` (`u8`): major version (expected `2`)
//! - Offset `0x09` (`u8`): minor version (commonly `1`)
//! - Offset `0x0a..0x0c` (`u16` LE): compression method (see “Compression methods” in spec)
//! - Offset `0x0c..0x10` (`u32` LE): segment file number (series)
//! - Offset `0x10..0x20` (`[u8; 16]`): segment file set identifier (little-endian GUID v4)
//!
//! Reference material:
//! - `external/libewf/documentation/Expert Witness Compression Format 2 (EWF2).asciidoc`
//!   - “Segment files” → “File header”

use crate::{Error, Result};
use binrw::{BinRead as _, BinWrite as _, binrw};
use std::io::Cursor;

pub(crate) const EWF2_FILE_HEADER_SIZE: usize = 32;

/// EWF2-Ex01 signature (`EVF2\r\n\x81\x00`).
pub(crate) const EWF2_EVF_SIGNATURE: [u8; 8] = [0x45, 0x56, 0x46, 0x32, 0x0d, 0x0a, 0x81, 0x00];

/// EWF2-Lx01 signature (`LEF2\r\n\x81\x00`).
pub(crate) const EWF2_LEF_SIGNATURE: [u8; 8] = [0x4c, 0x45, 0x46, 0x32, 0x0d, 0x0a, 0x81, 0x00];

const EWF2_VERSION_MAJOR: u8 = 2;
const EWF2_VERSION_MINOR: u8 = 1;

/// EWF2 container kind (Ex01 vs Lx01).
///
/// The kind is encoded in the file header signature.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ewf2Kind {
    /// EWF2-Ex01 (`EVF2\r\n\x81\x00`)
    #[brw(magic = b"EVF2\r\n\x81\0")]
    Ex01,
    /// EWF2-Lx01 (`LEF2\r\n\x81\x00`)
    #[brw(magic = b"LEF2\r\n\x81\0")]
    Lx01,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ewf2FileHeader {
    pub(crate) kind: Ewf2Kind,
    #[br(assert(
        major == EWF2_VERSION_MAJOR,
        "unsupported EWF2 major version: {}",
        major
    ))]
    pub(crate) major: u8,
    pub(crate) minor: u8,
    pub(crate) compression_method: u16,
    pub(crate) segment_number: u32,
    pub(crate) set_id: [u8; 16],
}

impl Ewf2FileHeader {
    pub(crate) fn new(
        kind: Ewf2Kind,
        compression_method: u16,
        segment_number: u32,
        set_id: [u8; 16],
    ) -> Self {
        Self {
            kind,
            major: EWF2_VERSION_MAJOR,
            minor: EWF2_VERSION_MINOR,
            compression_method,
            segment_number,
            set_id,
        }
    }

    pub(crate) fn parse(bytes: &[u8; EWF2_FILE_HEADER_SIZE]) -> Result<Self> {
        let mut cur = Cursor::new(bytes.as_slice());
        let hdr = Self::read(&mut cur).map_err(|e| {
            // Most failures here are signature/version mismatches, which callers expect as “invalid”.
            Error::Invalid(format!("invalid EWF2 segment file header: {e}"))
        })?;
        Ok(hdr)
    }

    pub(crate) fn to_bytes(self) -> [u8; EWF2_FILE_HEADER_SIZE] {
        let mut out = [0u8; EWF2_FILE_HEADER_SIZE];
        self.write(&mut Cursor::new(&mut out[..]))
            .expect("in-memory write cannot fail");
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_ex01_bytes() {
        let hdr = Ewf2FileHeader::new(Ewf2Kind::Ex01, 1, 7, [0x11; 16]);
        let bytes = hdr.to_bytes();
        let parsed = Ewf2FileHeader::parse(&bytes).unwrap();
        assert_eq!(parsed, hdr);
    }

    #[test]
    fn test_roundtrip_lx01_bytes() {
        let hdr = Ewf2FileHeader::new(Ewf2Kind::Lx01, 0, 1, [0x22; 16]);
        let bytes = hdr.to_bytes();
        let parsed = Ewf2FileHeader::parse(&bytes).unwrap();
        assert_eq!(parsed, hdr);
    }

    #[test]
    fn test_parse_rejects_unknown_signature() {
        let mut bytes = [0u8; EWF2_FILE_HEADER_SIZE];
        bytes[0..8].copy_from_slice(b"NOTEVF2!");
        let err = Ewf2FileHeader::parse(&bytes).unwrap_err();
        assert!(matches!(err, Error::Invalid(_)));
    }
}
