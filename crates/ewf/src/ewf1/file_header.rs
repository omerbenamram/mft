//! EWF1 segment file header (E01/S01/L01).
//!
//! Every EWF1 segment starts with a small fixed-size header:
//!
//! - Offset `0x00..0x08` (`[u8; 8]`): signature (`EVF\t\r\n\xff\x00` or `LVF\t\r\n\xff\x00`)
//! - Offset `0x08` (`u8`): start-of-fields marker (`0x01`)
//! - Offset `0x09..0x0b` (`u16` LE): segment number
//! - Offset `0x0b..0x0d` (`u16` LE): end-of-fields marker (`0x0000`)
//!
//! References:
//! - `external/libewf/documentation/Expert Witness Compression Format (EWF).asciidoc`
//! - libewf implementation:
//!   - `external/libewf/libewf/libewf_file_header.c`
//!
//! This module uses `binrw` to keep the on-disk layout declarative and symmetric (read+write).

use crate::{Error, Result};
use binrw::{BinRead as _, BinWrite as _, binrw};
use std::io::Cursor;

use super::{EWF1_EVF_SIGNATURE, EWF1_FILE_HEADER_SIZE, EWF1_LVF_SIGNATURE};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ewf1Signature {
    Evf,
    Lvf,
}

impl Ewf1Signature {
    pub(crate) fn bytes(self) -> [u8; 8] {
        match self {
            Self::Evf => EWF1_EVF_SIGNATURE,
            Self::Lvf => EWF1_LVF_SIGNATURE,
        }
    }

    pub(crate) fn from_bytes(signature: [u8; 8]) -> Result<Self> {
        if signature == EWF1_EVF_SIGNATURE {
            Ok(Self::Evf)
        } else if signature == EWF1_LVF_SIGNATURE {
            Ok(Self::Lvf)
        } else {
            Err(Error::Invalid("unsupported EWF1 signature".to_string()))
        }
    }
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ewf1FileHeader {
    #[br(try_map = Ewf1Signature::from_bytes)]
    #[bw(map = |sig| sig.bytes())]
    pub(crate) signature: Ewf1Signature,
    #[br(assert(start_of_fields == 0x01))]
    start_of_fields: u8,
    pub(crate) segment_number: u16,
    #[br(assert(end_of_fields == 0))]
    end_of_fields: u16,
}

impl Ewf1FileHeader {
    pub(crate) fn new(signature: Ewf1Signature, segment_number: u16) -> Self {
        Self {
            signature,
            start_of_fields: 0x01,
            segment_number,
            end_of_fields: 0,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn parse(bytes: &[u8; EWF1_FILE_HEADER_SIZE]) -> Result<Self> {
        let mut cur = Cursor::new(bytes.as_slice());
        let hdr = Self::read(&mut cur)
            .map_err(|e| Error::Invalid(format!("invalid EWF1 segment file header: {e}")))?;
        Ok(hdr)
    }

    pub(crate) fn to_bytes(self) -> [u8; EWF1_FILE_HEADER_SIZE] {
        let mut out = [0u8; EWF1_FILE_HEADER_SIZE];
        self.write(&mut Cursor::new(&mut out[..]))
            .expect("in-memory write cannot fail");
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_evf_bytes() {
        let hdr = Ewf1FileHeader::new(Ewf1Signature::Evf, 7);
        let bytes = hdr.to_bytes();
        let parsed = Ewf1FileHeader::parse(&bytes).unwrap();
        assert_eq!(parsed, hdr);
        assert_eq!(parsed.signature.bytes(), EWF1_EVF_SIGNATURE);
    }

    #[test]
    fn test_roundtrip_lvf_bytes() {
        let hdr = Ewf1FileHeader::new(Ewf1Signature::Lvf, 1);
        let bytes = hdr.to_bytes();
        let parsed = Ewf1FileHeader::parse(&bytes).unwrap();
        assert_eq!(parsed, hdr);
        assert_eq!(parsed.signature.bytes(), EWF1_LVF_SIGNATURE);
    }

    #[test]
    fn test_parse_rejects_unknown_signature() {
        let mut bytes = [0u8; EWF1_FILE_HEADER_SIZE];
        bytes[0..8].copy_from_slice(b"NOTEVF1!");
        let err = Ewf1FileHeader::parse(&bytes).unwrap_err();
        assert!(matches!(err, Error::Invalid(_)));
    }
}
