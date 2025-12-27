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

pub(crate) const EWF2_FILE_HEADER_SIZE: usize = 32;

/// EWF2-Ex01 signature (`EVF2\r\n\x81\x00`).
pub(crate) const EWF2_EVF_SIGNATURE: [u8; 8] = [0x45, 0x56, 0x46, 0x32, 0x0d, 0x0a, 0x81, 0x00];

/// EWF2-Lx01 signature (`LEF2\r\n\x81\x00`).
pub(crate) const EWF2_LEF_SIGNATURE: [u8; 8] = [0x4c, 0x45, 0x46, 0x32, 0x0d, 0x0a, 0x81, 0x00];

const EWF2_VERSION_MAJOR: u8 = 2;
const EWF2_VERSION_MINOR: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ewf2Kind {
    Ex01,
    Lx01,
}

impl Ewf2Kind {
    pub(crate) fn signature(self) -> [u8; 8] {
        match self {
            Self::Ex01 => EWF2_EVF_SIGNATURE,
            Self::Lx01 => EWF2_LEF_SIGNATURE,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ewf2FileHeader {
    pub(crate) kind: Ewf2Kind,
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
        let signature: [u8; 8] = bytes[0..8].try_into().expect("len=8");
        let kind = if signature == EWF2_EVF_SIGNATURE {
            Ewf2Kind::Ex01
        } else if signature == EWF2_LEF_SIGNATURE {
            Ewf2Kind::Lx01
        } else {
            return Err(Error::Invalid("not an EWF2 segment file".to_string()));
        };

        let major = bytes[8];
        let minor = bytes[9];
        if major != EWF2_VERSION_MAJOR {
            return Err(Error::Invalid(format!(
                "unsupported EWF2 major version: {major}"
            )));
        }

        let compression_method = u16::from_le_bytes(bytes[10..12].try_into().expect("len=2"));
        let segment_number = u32::from_le_bytes(bytes[12..16].try_into().expect("len=4"));
        let set_id: [u8; 16] = bytes[16..32].try_into().expect("len=16");

        Ok(Self {
            kind,
            major,
            minor,
            compression_method,
            segment_number,
            set_id,
        })
    }

    pub(crate) fn to_bytes(self) -> [u8; EWF2_FILE_HEADER_SIZE] {
        let mut out = [0u8; EWF2_FILE_HEADER_SIZE];
        out[0..8].copy_from_slice(&self.kind.signature());
        out[8] = self.major;
        out[9] = self.minor;
        out[10..12].copy_from_slice(&self.compression_method.to_le_bytes());
        out[12..16].copy_from_slice(&self.segment_number.to_le_bytes());
        out[16..32].copy_from_slice(&self.set_id);
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
