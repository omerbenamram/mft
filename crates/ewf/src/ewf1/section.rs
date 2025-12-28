//! EWF1 section descriptor parsing.
//!
//! EWF1 stores each section as:
//!
//! - a 76-byte **section descriptor** (type string, offsets, size, Adler-32),
//! - followed by the section **body** (raw bytes, possibly zlib-compressed depending on section),
//! - and then the next section descriptor begins (unless this is the last section).
//!
//! The section descriptor's `size` field is the total section size **including** the descriptor.
//! Some writers (notably for the `next`/`done` sections) set `size = 0` and rely on `next_offset`
//! instead; libewf infers the size from `next_offset` in that case.
//!
//! References:
//! - `external/libewf/documentation/Expert Witness Compression Format (EWF).asciidoc`
//! - libewf implementation:
//!   - `external/libewf/libewf/libewf_section_descriptor.c`

use std::fs::File;
use std::io;

use crate::util::{adler32_rfc1950, parse_ascii_nul_terminated, read_exact_at};
use crate::{Error, Result};
use binrw::{BinRead as _, BinWrite as _, binrw};
use std::io::Cursor;

use super::{EWF1_SECTION_DESCRIPTOR_SIZE, EWF1_TABLE_HEADER_SIZE};

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy)]
struct RawEwf1SectionDescriptor {
    type_bytes: [u8; 16],
    next_offset: u64,
    size: u64,
    #[brw(pad_after = 40)]
    _reserved: (),
    checksum: u32,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy)]
struct RawEwf1TableHeader {
    number_of_entries: u32,
    #[brw(pad_after = 4)]
    _reserved0: (),
    base_offset: u64,
    #[brw(pad_after = 4)]
    _reserved1: (),
    checksum: u32,
}

/// Known EWF1 section type strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Ewf1SectionType {
    Header,
    Header2,
    Volume,
    Disk,
    Data,
    Sectors,
    Sector,
    Table,
    Table2,
    Digest,
    Hash,
    Session,
    Error2,
    LTree,
    XHeader,
    XHash,
    Next,
    Done,
    Unknown(String),
}

impl Ewf1SectionType {
    pub(crate) fn parse(value: &str) -> Self {
        match value {
            "header" => Self::Header,
            "header2" => Self::Header2,
            "volume" => Self::Volume,
            "disk" => Self::Disk,
            "data" => Self::Data,
            "sectors" => Self::Sectors,
            "sector" => Self::Sector,
            "table" => Self::Table,
            "table2" => Self::Table2,
            "digest" => Self::Digest,
            "hash" => Self::Hash,
            "session" => Self::Session,
            "error2" => Self::Error2,
            "ltree" => Self::LTree,
            "xheader" => Self::XHeader,
            "xhash" => Self::XHash,
            "next" => Self::Next,
            "done" => Self::Done,
            other => Self::Unknown(other.to_string()),
        }
    }

    pub(crate) fn as_str(&self) -> &str {
        match self {
            Self::Header => "header",
            Self::Header2 => "header2",
            Self::Volume => "volume",
            Self::Disk => "disk",
            Self::Data => "data",
            Self::Sectors => "sectors",
            Self::Sector => "sector",
            Self::Table => "table",
            Self::Table2 => "table2",
            Self::Digest => "digest",
            Self::Hash => "hash",
            Self::Session => "session",
            Self::Error2 => "error2",
            Self::LTree => "ltree",
            Self::XHeader => "xheader",
            Self::XHash => "xhash",
            Self::Next => "next",
            Self::Done => "done",
            Self::Unknown(s) => s,
        }
    }

    pub(crate) fn is_terminal(&self) -> bool {
        matches!(self, Self::Next | Self::Done)
    }
}

/// An EWF1 section descriptor.
#[derive(Debug, Clone)]
pub(crate) struct Ewf1SectionDescriptor {
    /// Offset of the section descriptor (relative to the start of the segment file).
    pub(crate) start_offset: u64,
    /// Parsed section type.
    pub(crate) section_type: Ewf1SectionType,
    /// Total section size in bytes, including the descriptor.
    pub(crate) size: u64,
}

impl Ewf1SectionDescriptor {
    /// Parse a section descriptor at an absolute file offset.
    pub(crate) fn parse_at(file: &File, file_len: u64, start_offset: u64) -> Result<Self> {
        if start_offset >= file_len {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }

        let mut raw = [0u8; EWF1_SECTION_DESCRIPTOR_SIZE];
        read_exact_at(file, start_offset, &mut raw)?;

        let stored = u32::from_le_bytes(
            raw[EWF1_SECTION_DESCRIPTOR_SIZE - 4..]
                .try_into()
                .expect("len=4"),
        );
        let calculated = adler32_rfc1950(&raw[..EWF1_SECTION_DESCRIPTOR_SIZE - 4]);
        if stored != calculated {
            return Err(Error::Corrupt(
                "section descriptor checksum mismatch".to_string(),
            ));
        }

        let raw_desc = RawEwf1SectionDescriptor::read(&mut Cursor::new(&raw[..])).map_err(|e| {
            Error::Invalid(format!("invalid EWF1 section descriptor encoding: {e}"))
        })?;

        let type_string = parse_ascii_nul_terminated(&raw_desc.type_bytes);
        let section_type = Ewf1SectionType::parse(&type_string);

        let next_offset = raw_desc.next_offset;
        let mut size = raw_desc.size;

        // libewf behavior: some writers leave `size = 0`, but set `next_offset`; infer size from that.
        if size == 0 && next_offset != start_offset && next_offset >= start_offset {
            size = next_offset - start_offset;
        }

        Ok(Self {
            start_offset,
            section_type,
            size,
        })
    }

    /// Returns the byte range containing the section body (`[start, end)`).
    pub(crate) fn data_range(&self) -> Result<(u64, u64)> {
        let start = self
            .start_offset
            .checked_add(EWF1_SECTION_DESCRIPTOR_SIZE as u64)
            .ok_or_else(|| Error::Invalid("section range overflow".to_string()))?;
        let end = self
            .start_offset
            .checked_add(self.size)
            .ok_or_else(|| Error::Invalid("section range overflow".to_string()))?;
        Ok((start, end))
    }

    /// Returns how far the scanning cursor should advance after this descriptor.
    pub(crate) fn advance_len(&self) -> Result<u64> {
        let advance = if self.size != 0 {
            self.size
        } else {
            // libewf: for last sections (`next`/`done`) some writers set size=0; advance by descriptor size.
            EWF1_SECTION_DESCRIPTOR_SIZE as u64
        };

        if advance == 0 {
            return Err(Error::Invalid(
                "zero advance while scanning sections".to_string(),
            ));
        }
        Ok(advance)
    }

    /// Scan section descriptors from `first_section_offset` until the terminal section.
    pub(crate) fn scan(file: &File, file_len: u64, first_section_offset: u64) -> Result<Vec<Self>> {
        let mut sections = Vec::new();
        let mut offset = first_section_offset;

        // Hard safety cap: avoid pathological scans on corrupted inputs.
        for _ in 0..100_000 {
            if offset == 0 || offset >= file_len {
                break;
            }

            let desc = Self::parse_at(file, file_len, offset)?;
            let is_last = desc.section_type.is_terminal();
            let advance = desc.advance_len()?;

            sections.push(desc);
            if is_last {
                break;
            }

            offset = offset.saturating_add(advance);
        }

        if sections.is_empty() {
            return Err(Error::Invalid("no EWF sections found".to_string()));
        }

        Ok(sections)
    }
}

/// Writes a canonical EWF1 section descriptor to bytes.
///
/// This is shared by the writer (to construct descriptors) and tests/tools. The `start_offset`
/// argument is accepted for API parity with libewf-like helpers, but is not encoded in the
/// descriptor itself.
pub(crate) fn make_ewf1_section_descriptor(
    type_string: &str,
    _start_offset: u64,
    next_offset: u64,
    size: u64,
) -> [u8; EWF1_SECTION_DESCRIPTOR_SIZE] {
    let mut type_bytes = [0u8; 16];
    let src = type_string.as_bytes();
    let copy_len = src.len().min(type_bytes.len().saturating_sub(1));
    type_bytes[..copy_len].copy_from_slice(&src[..copy_len]);

    let desc = RawEwf1SectionDescriptor {
        type_bytes,
        next_offset,
        size,
        _reserved: (),
        checksum: 0,
    };

    let mut raw = [0u8; EWF1_SECTION_DESCRIPTOR_SIZE];
    desc.write(&mut Cursor::new(&mut raw[..]))
        .expect("in-memory write cannot fail");

    let checksum = adler32_rfc1950(&raw[..EWF1_SECTION_DESCRIPTOR_SIZE - 4]);
    raw[EWF1_SECTION_DESCRIPTOR_SIZE - 4..].copy_from_slice(&checksum.to_le_bytes());
    raw
}

/// Writes a canonical EWF1 chunk table header to bytes.
///
/// This is used by both EWF-E01 (`table`/`table2`) and EWF-S01 (`table`) table sections.
pub(crate) fn make_ewf1_table_header(
    number_of_entries: u32,
    base_offset: u64,
) -> [u8; EWF1_TABLE_HEADER_SIZE] {
    let hdr = RawEwf1TableHeader {
        number_of_entries,
        _reserved0: (),
        base_offset,
        _reserved1: (),
        checksum: 0,
    };

    let mut out = [0u8; EWF1_TABLE_HEADER_SIZE];
    hdr.write(&mut Cursor::new(&mut out[..]))
        .expect("in-memory write cannot fail");

    let checksum = adler32_rfc1950(&out[..EWF1_TABLE_HEADER_SIZE - 4]);
    out[EWF1_TABLE_HEADER_SIZE - 4..].copy_from_slice(&checksum.to_le_bytes());
    out
}
