//! USN change journal (`$Extend\\$UsnJrnl:$J`) support.
//!
//! ## Supported record versions
//! - **Supported**: `USN_RECORD_V2` (`major_version == 2`)
//! - **Unsupported (strict error)**: any other major version (future work)
//!
//! This module is **strict by default**: unsupported versions, invalid sizes, and invalid UTF-16LE
//! file names are hard errors (no silent skipping).

pub mod journal;

use crate::ntfs::{Error, Result};
use crate::parse::Reader;
use bitflags::bitflags;
use mft::attribute::FileAttributeFlags;
use std::char::decode_utf16;

pub use journal::{
    DEFAULT_USN_JOURNAL_BLOCK_SIZE, MIN_USN_RECORD_SIZE, UsnChangeJournal, UsnRawRecord,
};

bitflags! {
    /// USN update reason flags (`USN_REASON_*`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct UsnReasonFlags: u32 {
        const DATA_OVERWRITE              = 0x0000_0001;
        const DATA_EXTEND                 = 0x0000_0002;
        const DATA_TRUNCATION             = 0x0000_0004;

        const NAMED_DATA_OVERWRITE        = 0x0000_0010;
        const NAMED_DATA_EXTEND           = 0x0000_0020;
        const NAMED_DATA_TRUNCATION       = 0x0000_0040;

        const FILE_CREATE                 = 0x0000_0100;
        const FILE_DELETE                 = 0x0000_0200;
        const EXTENDED_ATTRIBUTE_CHANGE   = 0x0000_0400;
        const SECURITY_CHANGE             = 0x0000_0800;
        const RENAME_OLD_NAME             = 0x0000_1000;
        const RENAME_NEW_NAME             = 0x0000_2000;
        const INDEXABLE_CHANGE            = 0x0000_4000;
        const BASIC_INFO_CHANGE           = 0x0000_8000;
        const HARD_LINK_CHANGE            = 0x0001_0000;
        const COMPRESSION_CHANGE          = 0x0002_0000;
        const ENCRYPTION_CHANGE           = 0x0004_0000;
        const OBJECT_IDENTIFIER_CHANGE    = 0x0008_0000;
        const REPARSE_POINT_CHANGE        = 0x0010_0000;
        const STREAM_CHANGE               = 0x0020_0000;
        const TRANSACTED_CHANGE           = 0x0040_0000;

        const CLOSE                       = 0x8000_0000;
    }
}

bitflags! {
    /// USN update source flags (`USN_SOURCE_*`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct UsnSourceFlags: u32 {
        const DATA_MANAGEMENT            = 0x0000_0001;
        const AUXILIARY_DATA             = 0x0000_0002;
        const REPLICATION_MANAGEMENT     = 0x0000_0004;
    }
}

/// Parsed USN record as stored in `$UsnJrnl:$J`.
#[derive(Debug, Clone, PartialEq)]
pub enum UsnRecord {
    V2(UsnRecordV2),
}

impl UsnRecord {
    /// Parse a USN record from an on-disk byte buffer (strict).
    ///
    /// `base_offset` is used only for parse error reporting.
    pub fn parse(buf: &[u8], base_offset: u64) -> Result<Self> {
        if buf.len() < MIN_USN_RECORD_SIZE {
            return Err(Error::InvalidData {
                message: format!(
                    "USN record buffer too small: len={} (min {MIN_USN_RECORD_SIZE})",
                    buf.len()
                ),
            });
        }

        // Peek the major version for dispatch.
        let mut r = Reader::with_base_offset(buf, base_offset);
        let record_len = r.u32_le("usn.record_length")? as usize;
        if record_len != buf.len() {
            return Err(Error::InvalidData {
                message: format!(
                    "USN record length mismatch: header={} actual={}",
                    record_len,
                    buf.len()
                ),
            });
        }
        let major = r.u16_le("usn.major_version")?;

        match major {
            2 => Ok(Self::V2(UsnRecordV2::parse(buf, base_offset)?)),
            other => Err(Error::Unsupported {
                what: format!("USN record major version {other} (supported: 2)"),
            }),
        }
    }
}

/// Parsed `USN_RECORD_V2` (major version 2).
///
/// Layout reference (Windows): `USN_RECORD_V2`.
#[derive(Debug, Clone, PartialEq)]
pub struct UsnRecordV2 {
    pub major_version: u16,
    pub minor_version: u16,
    pub file_reference: u64,
    pub parent_file_reference: u64,
    pub usn: u64,
    /// Windows FILETIME (100ns since 1601-01-01 UTC).
    pub timestamp_filetime: u64,
    pub reason: UsnReasonFlags,
    pub source_info: UsnSourceFlags,
    pub security_id: u32,
    pub file_attributes: FileAttributeFlags,
    pub name: String,
}

impl UsnRecordV2 {
    /// Parse a USN record from an on-disk byte buffer.
    ///
    /// `base_offset` is used only for parse error reporting.
    pub fn parse(buf: &[u8], base_offset: u64) -> Result<Self> {
        let mut r = Reader::with_base_offset(buf, base_offset);

        let record_len = r.u32_le("usn.record_length")? as usize;
        if record_len != buf.len() {
            return Err(Error::InvalidData {
                message: format!(
                    "USN record length mismatch: header={} actual={}",
                    record_len,
                    buf.len()
                ),
            });
        }

        let major = r.u16_le("usn.major_version")?;
        let minor = r.u16_le("usn.minor_version")?;
        if major != 2 {
            return Err(Error::Unsupported {
                what: format!("USN record major version {major} (expected 2)"),
            });
        }

        let file_reference = r.u64_le("usn.file_reference")?;
        let parent_file_reference = r.u64_le("usn.parent_file_reference")?;
        let usn = r.u64_le("usn.usn")?;
        let timestamp_filetime = r.u64_le("usn.timestamp")?;
        let reason_raw = r.u32_le("usn.reason")?;
        let source_raw = r.u32_le("usn.source_info")?;
        let security_id = r.u32_le("usn.security_id")?;
        let file_attributes_raw = r.u32_le("usn.file_attributes")?;
        let name_len = r.u16_le("usn.file_name_length")? as usize;
        let name_off = r.u16_le("usn.file_name_offset")? as usize;

        if name_off > buf.len() || name_len > buf.len().saturating_sub(name_off) {
            return Err(Error::InvalidData {
                message: format!(
                    "USN record name out of bounds: off={} len={} buf_len={}",
                    name_off,
                    name_len,
                    buf.len()
                ),
            });
        }
        if !name_len.is_multiple_of(2) {
            return Err(Error::InvalidData {
                message: format!("USN record name length is not UTF-16LE: len={name_len}"),
            });
        }

        let name_bytes = &buf[name_off..name_off + name_len];

        let reason = UsnReasonFlags::from_bits(reason_raw).ok_or_else(|| Error::Unsupported {
            what: format!("unsupported USN reason flags: 0x{reason_raw:08x} (unknown bits set)"),
        })?;
        let source_info =
            UsnSourceFlags::from_bits(source_raw).ok_or_else(|| Error::Unsupported {
                what: format!(
                    "unsupported USN source flags: 0x{source_raw:08x} (unknown bits set)"
                ),
            })?;
        let file_attributes =
            FileAttributeFlags::from_bits(file_attributes_raw).ok_or_else(|| Error::Unsupported {
                what: format!(
                    "unsupported USN file attributes: 0x{file_attributes_raw:08x} (unknown bits set)"
                ),
            })?;

        let name = decode_utf16le_strict(name_bytes, base_offset + name_off as u64)?;

        Ok(Self {
            major_version: major,
            minor_version: minor,
            file_reference,
            parent_file_reference,
            usn,
            timestamp_filetime,
            reason,
            source_info,
            security_id,
            file_attributes,
            name,
        })
    }
}

fn decode_utf16le_strict(bytes: &[u8], base_offset: u64) -> Result<String> {
    debug_assert!(bytes.len().is_multiple_of(2), "validated by caller");
    let mut u16s = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks_exact(2) {
        u16s.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }

    // Strict: treat invalid surrogate pairs as invalid data.
    let mut out = String::new();
    for ch in decode_utf16(u16s.into_iter()) {
        let ch = ch.map_err(|_| Error::InvalidData {
            message: format!("invalid UTF-16LE in USN record name at offset 0x{base_offset:x}"),
        })?;
        out.push(ch);
    }
    Ok(out)
}

/// Returns the names of set `USN_REASON_*` flags, matching upstream spelling.
pub fn reason_flag_names(flags: UsnReasonFlags) -> impl Iterator<Item = &'static str> {
    const MAP: &[(UsnReasonFlags, &str)] = &[
        (UsnReasonFlags::DATA_OVERWRITE, "USN_REASON_DATA_OVERWRITE"),
        (UsnReasonFlags::DATA_EXTEND, "USN_REASON_DATA_EXTEND"),
        (
            UsnReasonFlags::DATA_TRUNCATION,
            "USN_REASON_DATA_TRUNCATION",
        ),
        (
            UsnReasonFlags::NAMED_DATA_OVERWRITE,
            "USN_REASON_NAMED_DATA_OVERWRITE",
        ),
        (
            UsnReasonFlags::NAMED_DATA_EXTEND,
            "USN_REASON_NAMED_DATA_EXTEND",
        ),
        (
            UsnReasonFlags::NAMED_DATA_TRUNCATION,
            "USN_REASON_NAMED_DATA_TRUNCATION",
        ),
        (UsnReasonFlags::FILE_CREATE, "USN_REASON_FILE_CREATE"),
        (UsnReasonFlags::FILE_DELETE, "USN_REASON_FILE_DELETE"),
        (
            UsnReasonFlags::EXTENDED_ATTRIBUTE_CHANGE,
            "USN_REASON_EA_CHANGE",
        ),
        (
            UsnReasonFlags::SECURITY_CHANGE,
            "USN_REASON_SECURITY_CHANGE",
        ),
        (
            UsnReasonFlags::RENAME_OLD_NAME,
            "USN_REASON_RENAME_OLD_NAME",
        ),
        (
            UsnReasonFlags::RENAME_NEW_NAME,
            "USN_REASON_RENAME_NEW_NAME",
        ),
        (
            UsnReasonFlags::INDEXABLE_CHANGE,
            "USN_REASON_INDEXABLE_CHANGE",
        ),
        (
            UsnReasonFlags::BASIC_INFO_CHANGE,
            "USN_REASON_BASIC_INFO_CHANGE",
        ),
        (
            UsnReasonFlags::HARD_LINK_CHANGE,
            "USN_REASON_HARD_LINK_CHANGE",
        ),
        (
            UsnReasonFlags::COMPRESSION_CHANGE,
            "USN_REASON_COMPRESSION_CHANGE",
        ),
        (
            UsnReasonFlags::ENCRYPTION_CHANGE,
            "USN_REASON_ENCRYPTION_CHANGE",
        ),
        (
            UsnReasonFlags::OBJECT_IDENTIFIER_CHANGE,
            "USN_REASON_OBJECT_IDENTIFIER_CHANGE",
        ),
        (
            UsnReasonFlags::REPARSE_POINT_CHANGE,
            "USN_REASON_REPARSE_POINT_CHANGE",
        ),
        (UsnReasonFlags::STREAM_CHANGE, "USN_REASON_STREAM_CHANGE"),
        (
            UsnReasonFlags::TRANSACTED_CHANGE,
            "USN_REASON_TRANSACTED_CHANGE",
        ),
        (UsnReasonFlags::CLOSE, "USN_REASON_CLOSE"),
    ];

    MAP.iter().filter_map(move |(flag, name)| {
        if flags.contains(*flag) {
            Some(*name)
        } else {
            None
        }
    })
}

/// Returns the names of set `USN_SOURCE_*` flags, matching upstream spelling.
pub fn source_flag_names(flags: UsnSourceFlags) -> impl Iterator<Item = &'static str> {
    const MAP: &[(UsnSourceFlags, &str)] = &[
        (
            UsnSourceFlags::DATA_MANAGEMENT,
            "USN_SOURCE_DATA_MANAGEMENT",
        ),
        (UsnSourceFlags::AUXILIARY_DATA, "USN_SOURCE_AUXILIARY_DATA"),
        (
            UsnSourceFlags::REPLICATION_MANAGEMENT,
            "USN_SOURCE_REPLICATION_MANAGEMENT",
        ),
    ];
    MAP.iter().filter_map(move |(flag, name)| {
        if flags.contains(*flag) {
            Some(*name)
        } else {
            None
        }
    })
}

/// Returns the names of set `FILE_ATTRIBUTE_*` flags, matching upstream spelling.
pub fn file_attribute_flag_names(flags: FileAttributeFlags) -> impl Iterator<Item = &'static str> {
    // Keep these aligned with `mft::attribute::FileAttributeFlags` / Windows constants.
    const MAP: &[(u32, &str)] = &[
        (0x0000_0001, "FILE_ATTRIBUTE_READ_ONLY"),
        (0x0000_0002, "FILE_ATTRIBUTE_HIDDEN"),
        (0x0000_0004, "FILE_ATTRIBUTE_SYSTEM"),
        (0x0000_0010, "FILE_ATTRIBUTE_DIRECTORY"),
        (0x0000_0020, "FILE_ATTRIBUTE_ARCHIVE"),
        (0x0000_0040, "FILE_ATTRIBUTE_DEVICE"),
        (0x0000_0080, "FILE_ATTRIBUTE_NORMAL"),
        (0x0000_0100, "FILE_ATTRIBUTE_TEMPORARY"),
        (0x0000_0200, "FILE_ATTRIBUTE_SPARSE_FILE"),
        (0x0000_0400, "FILE_ATTRIBUTE_REPARSE_POINT"),
        (0x0000_0800, "FILE_ATTRIBUTE_COMPRESSED"),
        (0x0000_1000, "FILE_ATTRIBUTE_OFFLINE"),
        (0x0000_2000, "FILE_ATTRIBUTE_NOT_CONTENT_INDEXED"),
        (0x0000_4000, "FILE_ATTRIBUTE_ENCRYPTED"),
        (0x0001_0000, "FILE_ATTRIBUTE_VIRTUAL"),
    ];
    let bits = flags.bits();
    MAP.iter().filter_map(move |(mask, name)| {
        if (bits & mask) != 0 {
            Some(*name)
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect::<Vec<_>>()
    }

    #[test]
    fn parse_usn_record_v2_roundtrip_minimal() {
        let name = utf16le("test.txt");
        let record_len = 60 + name.len();
        let name_offset = 60u16;
        let name_len = name.len() as u16;
        let reason = (UsnReasonFlags::FILE_CREATE | UsnReasonFlags::CLOSE).bits();
        let source = UsnSourceFlags::DATA_MANAGEMENT.bits();

        let mut buf = vec![0u8; record_len];
        buf[0..4].copy_from_slice(&(record_len as u32).to_le_bytes());
        buf[4..6].copy_from_slice(&2u16.to_le_bytes()); // major
        buf[6..8].copy_from_slice(&0u16.to_le_bytes()); // minor
        buf[8..16].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes()); // file ref
        buf[16..24].copy_from_slice(&0x8877_6655_4433_2211u64.to_le_bytes()); // parent ref
        buf[24..32].copy_from_slice(&123u64.to_le_bytes()); // usn
        buf[32..40].copy_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes()); // timestamp
        buf[40..44].copy_from_slice(&reason.to_le_bytes());
        buf[44..48].copy_from_slice(&source.to_le_bytes());
        buf[48..52].copy_from_slice(&0x99u32.to_le_bytes()); // security id
        buf[52..56].copy_from_slice(&0x20u32.to_le_bytes()); // file attrs
        buf[56..58].copy_from_slice(&name_len.to_le_bytes());
        buf[58..60].copy_from_slice(&name_offset.to_le_bytes());
        buf[60..60 + name.len()].copy_from_slice(&name);

        let rec = UsnRecordV2::parse(&buf, 0).unwrap();
        assert_eq!(rec.major_version, 2);
        assert_eq!(rec.minor_version, 0);
        assert_eq!(rec.file_reference, 0x1122_3344_5566_7788);
        assert_eq!(rec.parent_file_reference, 0x8877_6655_4433_2211);
        assert_eq!(rec.usn, 123);
        assert_eq!(rec.timestamp_filetime, 0x0102_0304_0506_0708);
        assert_eq!(rec.reason.bits(), reason);
        assert_eq!(rec.source_info.bits(), source);
        assert_eq!(rec.security_id, 0x99);
        assert_eq!(
            rec.file_attributes,
            FileAttributeFlags::FILE_ATTRIBUTE_ARCHIVE
        );
        assert_eq!(rec.name, "test.txt");
    }

    #[test]
    fn parse_usn_record_v2_rejects_length_mismatch() {
        let mut buf = vec![0u8; 60];
        buf[0..4].copy_from_slice(&61u32.to_le_bytes()); // bogus length
        buf[4..6].copy_from_slice(&2u16.to_le_bytes());
        buf[6..8].copy_from_slice(&0u16.to_le_bytes());

        let err = UsnRecordV2::parse(&buf, 0).unwrap_err();
        assert!(matches!(err, Error::InvalidData { .. }));
    }
}
