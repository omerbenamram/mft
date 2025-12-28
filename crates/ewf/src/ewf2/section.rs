//! EWF2 section descriptor parsing.
//!
//! EWF2 stores each section as:
//!
//! - the section **data** (possibly compressed / encrypted),
//! - followed by a fixed-size **section descriptor** (64 bytes) *at the end of the section*.
//!
//! Section descriptors are chained backwards through the `previous_offset` field, so readers can
//! find all sections by starting at the last descriptor (at end-of-file) and walking backwards.
//!
//! References:
//! - `external/libewf/documentation/Expert Witness Compression Format 2 (EWF2).asciidoc`
//! - libewf implementation:
//!   - `external/libewf/libewf/libewf_section_descriptor.c`

use std::fs::File;
use std::io::Cursor;

use crate::ewf2::file_header::EWF2_FILE_HEADER_SIZE;
use crate::util::{adler32_rfc1950, read_exact_at};
use crate::{Error, Result};
use binrw::{BinRead as _, BinWrite as _, binrw};
use bitflags::bitflags;

/// EWF2 section descriptor size (64 bytes).
pub(crate) const EWF2_SECTION_DESCRIPTOR_SIZE: usize = 64;

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy)]
struct RawEwf2SectionDescriptor {
    section_type: u32,
    data_flags: u32,
    previous_offset: u64,
    data_size: u64,
    descriptor_size: u32,
    padding_size: u32,
    data_integrity_hash: [u8; 16],
    reserved: [u8; 12],
    checksum: u32,
}

/// EWF2 section type identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ewf2SectionType {
    DeviceInformation,
    CaseData,
    SectorData,
    SectorTable,
    Md5Hash,
    Sha1Hash,
    Next,
    Done,
    SingleFilesData,
    Unknown(u32),
}

impl Ewf2SectionType {
    pub(crate) fn from_u32(v: u32) -> Self {
        match v {
            0x0000_0001 => Self::DeviceInformation,
            0x0000_0002 => Self::CaseData,
            0x0000_0003 => Self::SectorData,
            0x0000_0004 => Self::SectorTable,
            0x0000_0008 => Self::Md5Hash,
            0x0000_0009 => Self::Sha1Hash,
            0x0000_000d => Self::Next,
            0x0000_000f => Self::Done,
            0x0000_0020 => Self::SingleFilesData,
            other => Self::Unknown(other),
        }
    }

    pub(crate) fn as_u32(self) -> u32 {
        match self {
            Self::DeviceInformation => 0x0000_0001,
            Self::CaseData => 0x0000_0002,
            Self::SectorData => 0x0000_0003,
            Self::SectorTable => 0x0000_0004,
            Self::Md5Hash => 0x0000_0008,
            Self::Sha1Hash => 0x0000_0009,
            Self::Next => 0x0000_000d,
            Self::Done => 0x0000_000f,
            Self::SingleFilesData => 0x0000_0020,
            Self::Unknown(v) => v,
        }
    }
}

bitflags! {
    /// EWF2 section data flags.
    ///
    /// Unknown bits are preserved (see [`Ewf2SectionDataFlags::new`]).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct Ewf2SectionDataFlags: u32 {
        const MD5_HASHED = 0x0000_0001;
        const ENCRYPTED   = 0x0000_0002;
    }
}

impl Ewf2SectionDataFlags {
    /// Constructs flags from the raw on-disk bitmask, preserving unknown bits.
    pub(crate) fn new(raw: u32) -> Self {
        Self::from_bits_retain(raw)
    }

    pub(crate) fn raw(self) -> u32 {
        self.bits()
    }

    pub(crate) fn has_md5_integrity_hash(self) -> bool {
        self.contains(Self::MD5_HASHED)
    }

    pub(crate) fn is_encrypted(self) -> bool {
        self.contains(Self::ENCRYPTED)
    }
}

/// An EWF2 section descriptor plus derived section range information.
#[derive(Debug, Clone)]
pub(crate) struct Ewf2Section {
    pub(crate) section_type: Ewf2SectionType,
    pub(crate) data_flags: Ewf2SectionDataFlags,
    pub(crate) previous_offset: u64,

    #[allow(dead_code)]
    pub(crate) data_size: u64,
    #[allow(dead_code)]
    pub(crate) descriptor_size: u32,
    pub(crate) padding_size: u32,
    #[allow(dead_code)]
    pub(crate) data_integrity_hash: [u8; 16],

    /// Offset of the section descriptor (the descriptor is stored *at the end* of the section).
    #[allow(dead_code)]
    pub(crate) descriptor_offset: u64,

    /// Start offset of the section data (relative to the start of the segment file).
    pub(crate) data_start: u64,

    /// Length of the section data that is considered valid by `data_size`.
    ///
    /// Some tools may append extra bytes beyond `data_size` (e.g., after abort/restart scenarios).
    pub(crate) data_len: u64,
}

impl Ewf2Section {
    /// Parse a section descriptor at an absolute file offset.
    pub(crate) fn parse_at(file: &File, file_len: u64, descriptor_offset: u64) -> Result<Self> {
        // The caller ensures descriptor_offset points to a valid descriptor location.
        let _ = file_len;

        let mut buf = [0u8; EWF2_SECTION_DESCRIPTOR_SIZE];
        read_exact_at(file, descriptor_offset, &mut buf)?;

        let stored = u32::from_le_bytes(buf[60..64].try_into().expect("len=4"));
        let calculated = adler32_rfc1950(&buf[0..60]);
        if stored != calculated {
            return Err(Error::Corrupt(
                "EWF2 section descriptor checksum mismatch".to_string(),
            ));
        }

        let raw = RawEwf2SectionDescriptor::read(&mut Cursor::new(&buf[..])).map_err(|e| {
            Error::Invalid(format!("invalid EWF2 section descriptor encoding: {e}"))
        })?;

        let section_type = Ewf2SectionType::from_u32(raw.section_type);
        let data_flags = Ewf2SectionDataFlags::new(raw.data_flags);
        let previous_offset = raw.previous_offset;
        let data_size = raw.data_size;
        let descriptor_size = raw.descriptor_size;
        let padding_size = raw.padding_size;
        let data_integrity_hash = raw.data_integrity_hash;

        if descriptor_size as usize != EWF2_SECTION_DESCRIPTOR_SIZE {
            return Err(Error::Invalid(format!(
                "unsupported EWF2 section descriptor size: {descriptor_size}"
            )));
        }

        // The descriptor links to the previous section descriptor (by offset). The section data begins
        // after the previous descriptor (or after the file header for the first section).
        let data_start = if previous_offset == 0 {
            EWF2_FILE_HEADER_SIZE as u64
        } else {
            previous_offset.saturating_add(descriptor_size as u64)
        };

        if data_start > descriptor_offset {
            return Err(Error::Invalid(
                "EWF2 section data start offset out of bounds".to_string(),
            ));
        }

        // `data_size` is the amount of data considered part of the section (including any padding
        // described by `padding_size`). If tools appended extra bytes between sections, we ignore them.
        let max_len = descriptor_offset.saturating_sub(data_start);
        let data_len = data_size.min(max_len);

        Ok(Self {
            section_type,
            data_flags,
            previous_offset,
            data_size,
            descriptor_size,
            padding_size,
            data_integrity_hash,
            descriptor_offset,
            data_start,
            data_len,
        })
    }

    /// Scan all section descriptors for a segment file.
    pub(crate) fn scan(file: &File, file_len: u64) -> Result<Vec<Self>> {
        let min_len =
            (EWF2_FILE_HEADER_SIZE as u64).saturating_add(EWF2_SECTION_DESCRIPTOR_SIZE as u64);
        if file_len < min_len {
            return Err(Error::Invalid("file too small for EWF2".to_string()));
        }

        let mut sections_rev: Vec<Self> = Vec::new();
        let mut desc_off = file_len
            .checked_sub(EWF2_SECTION_DESCRIPTOR_SIZE as u64)
            .ok_or_else(|| Error::Invalid("file too small for EWF2".to_string()))?;

        // Hard guard against loops on corrupt inputs.
        for _ in 0..1_000_000u32 {
            let section = Self::parse_at(file, file_len, desc_off)?;
            let prev = section.previous_offset;
            sections_rev.push(section);

            if prev == 0 {
                break;
            }
            if prev >= desc_off {
                return Err(Error::Invalid(
                    "EWF2 previous section offset does not move backwards".to_string(),
                ));
            }
            desc_off = prev;
        }

        if sections_rev.is_empty() {
            return Err(Error::Invalid("no EWF2 sections found".to_string()));
        }

        sections_rev.reverse();
        Ok(sections_rev)
    }
}

/// Writes a canonical EWF2 section descriptor to bytes.
///
/// This is used by the writer; the reader parses the same format via [`Ewf2Section::parse_at`].
pub(crate) fn make_ewf2_section_descriptor(
    section_type: Ewf2SectionType,
    data_flags: Ewf2SectionDataFlags,
    previous_offset: u64,
    data_size: u64,
    padding_size: u32,
    data_integrity_hash: [u8; 16],
) -> [u8; EWF2_SECTION_DESCRIPTOR_SIZE] {
    // This is intentionally infallible: we write into an in-memory buffer of fixed size.
    let desc = RawEwf2SectionDescriptor {
        section_type: section_type.as_u32(),
        data_flags: data_flags.raw(),
        previous_offset,
        data_size,
        descriptor_size: EWF2_SECTION_DESCRIPTOR_SIZE as u32,
        padding_size,
        data_integrity_hash,
        reserved: [0u8; 12],
        checksum: 0,
    };

    let mut raw = [0u8; EWF2_SECTION_DESCRIPTOR_SIZE];
    desc.write(&mut Cursor::new(&mut raw[..]))
        .expect("in-memory write cannot fail");

    let checksum = adler32_rfc1950(&raw[..EWF2_SECTION_DESCRIPTOR_SIZE - 4]);
    raw[EWF2_SECTION_DESCRIPTOR_SIZE - 4..].copy_from_slice(&checksum.to_le_bytes());
    raw
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn test_make_ewf2_section_descriptor_roundtrips_raw_fields_and_checksum() {
        let section_type = Ewf2SectionType::SectorData;
        let data_flags = Ewf2SectionDataFlags::MD5_HASHED;
        let previous_offset = 0x1122_3344_5566_7788;
        let data_size = 0x99aa_bbcc_ddee_ff00;
        let padding_size = 0x1234_5678;
        let data_integrity_hash: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        let bytes = make_ewf2_section_descriptor(
            section_type,
            data_flags,
            previous_offset,
            data_size,
            padding_size,
            data_integrity_hash,
        );

        let stored = u32::from_le_bytes(bytes[60..64].try_into().expect("len=4"));
        let calculated = adler32_rfc1950(&bytes[0..60]);
        assert_eq!(stored, calculated);

        let raw =
            RawEwf2SectionDescriptor::read(&mut Cursor::new(&bytes[..])).expect("parse succeeds");
        assert_eq!(raw.section_type, section_type.as_u32());
        assert_eq!(raw.data_flags, data_flags.raw());
        assert_eq!(raw.previous_offset, previous_offset);
        assert_eq!(raw.data_size, data_size);
        assert_eq!(raw.descriptor_size, EWF2_SECTION_DESCRIPTOR_SIZE as u32);
        assert_eq!(raw.padding_size, padding_size);
        assert_eq!(raw.data_integrity_hash, data_integrity_hash);
        assert_eq!(raw.reserved, [0u8; 12]);
        assert_eq!(raw.checksum, stored);
    }

    #[test]
    fn test_parse_at_rejects_checksum_mismatch() {
        let good = make_ewf2_section_descriptor(
            Ewf2SectionType::Done,
            Ewf2SectionDataFlags::new(0),
            0,
            0,
            0,
            [0u8; 16],
        );

        let mut bad = good;
        bad[0] ^= 0x01;

        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        tmp.write_all(&vec![0u8; EWF2_FILE_HEADER_SIZE])
            .expect("write header");
        let descriptor_offset = EWF2_FILE_HEADER_SIZE as u64;
        tmp.write_all(&bad).expect("write descriptor");

        let file = std::fs::File::open(tmp.path()).expect("open");
        let file_len = file.metadata().expect("metadata").len();

        let err = Ewf2Section::parse_at(&file, file_len, descriptor_offset).unwrap_err();
        assert!(matches!(err, Error::Corrupt(msg) if msg.contains("checksum mismatch")));
    }

    #[test]
    fn test_section_data_flags_preserves_unknown_bits() {
        let raw = 0x8000_0000u32 | Ewf2SectionDataFlags::MD5_HASHED.bits();
        let flags = Ewf2SectionDataFlags::new(raw);
        assert_eq!(flags.raw(), raw);
        assert!(flags.has_md5_integrity_hash());
        assert!(!flags.is_encrypted());
    }
}
