//! The USN change journal, `$Extend\$UsnJrnl:$J`.
//!
//! Each change to a file appends a record to `$J`: `USN_RECORD_V2` (Windows 2000 and later) or
//! `USN_RECORD_V3` (128-bit file ids, Windows 8 and later). With range tracking on, `USN_RECORD_V4`
//! records follow a v3 record and list the byte ranges of the file that changed.
//!
//! [`UsnJournal`] reads an extracted `$J` stream, skipping the zeros that pad the end of each
//! page and fill the sparse start of the stream, and yields one [`UsnRecord`] at a time.
//! [`UsnRecord::from_slice`] parses one record.
//!
//! <https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v2>

use std::io::{self, Read};
use std::path::PathBuf;

use bitflags::bitflags;
use jiff::Timestamp;
use serde::Serialize;

use crate::attribute::FileAttributeFlags;
use crate::err::{Error, Result};
use crate::impl_serialize_for_bitflags;
use crate::utf16::Utf16LeStr;
use crate::utils::{read_u16, read_u32, read_u64, windows_filetime_to_timestamp_saturating};
use crate::{MftReference, serialize_timestamp};

/// Windows writes USN records in pages of this size, and a record never crosses a page.
pub const USN_PAGE_SIZE: usize = 0x1000;

/// The size of a `USN_RECORD_V2` with an empty name.
const V2_HEADER_SIZE: usize = 60;
/// The size of a `USN_RECORD_V3` with an empty name.
const V3_HEADER_SIZE: usize = 76;
/// The size of a `USN_RECORD_V4` with no extents.
const V4_HEADER_SIZE: usize = 64;
/// The size of a `USN_RECORD_EXTENT`.
const EXTENT_SIZE: usize = 16;

bitflags! {
    /// Why the file changed (`USN_REASON_*`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct UsnReasonFlags: u32 {
        const USN_REASON_DATA_OVERWRITE = 0x0000_0001;
        const USN_REASON_DATA_EXTEND = 0x0000_0002;
        const USN_REASON_DATA_TRUNCATION = 0x0000_0004;
        const USN_REASON_NAMED_DATA_OVERWRITE = 0x0000_0010;
        const USN_REASON_NAMED_DATA_EXTEND = 0x0000_0020;
        const USN_REASON_NAMED_DATA_TRUNCATION = 0x0000_0040;
        const USN_REASON_FILE_CREATE = 0x0000_0100;
        const USN_REASON_FILE_DELETE = 0x0000_0200;
        const USN_REASON_EA_CHANGE = 0x0000_0400;
        const USN_REASON_SECURITY_CHANGE = 0x0000_0800;
        const USN_REASON_RENAME_OLD_NAME = 0x0000_1000;
        const USN_REASON_RENAME_NEW_NAME = 0x0000_2000;
        const USN_REASON_INDEXABLE_CHANGE = 0x0000_4000;
        const USN_REASON_BASIC_INFO_CHANGE = 0x0000_8000;
        const USN_REASON_HARD_LINK_CHANGE = 0x0001_0000;
        const USN_REASON_COMPRESSION_CHANGE = 0x0002_0000;
        const USN_REASON_ENCRYPTION_CHANGE = 0x0004_0000;
        const USN_REASON_OBJECT_ID_CHANGE = 0x0008_0000;
        const USN_REASON_REPARSE_POINT_CHANGE = 0x0010_0000;
        const USN_REASON_STREAM_CHANGE = 0x0020_0000;
        const USN_REASON_TRANSACTED_CHANGE = 0x0040_0000;
        const USN_REASON_INTEGRITY_CHANGE = 0x0080_0000;
        const USN_REASON_DESIRED_STORAGE_CLASS_CHANGE = 0x0100_0000;
        const USN_REASON_CLOSE = 0x8000_0000;
        const _ = !0;
    }
}

impl_serialize_for_bitflags! {UsnReasonFlags}

bitflags! {
    /// Who made the change (`USN_SOURCE_*`). Empty for changes made by applications.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct UsnSourceFlags: u32 {
        const USN_SOURCE_DATA_MANAGEMENT = 0x0000_0001;
        const USN_SOURCE_AUXILIARY_DATA = 0x0000_0002;
        const USN_SOURCE_REPLICATION_MANAGEMENT = 0x0000_0004;
        const USN_SOURCE_CLIENT_REPLICATION_MANAGEMENT = 0x0000_0008;
        const _ = !0;
    }
}

impl_serialize_for_bitflags! {UsnSourceFlags}

/// One USN record.
#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct UsnRecord {
    /// Where the record starts in the input, in bytes.
    pub offset: u64,
    pub major_version: u16,
    pub minor_version: u16,
    /// The file that changed. A v3 or v4 record's 128-bit file id is cut to its low 64 bits,
    /// which on NTFS hold the whole reference.
    pub file_reference: MftReference,
    /// The directory the file was in.
    pub parent_reference: MftReference,
    /// The high 64 bits of a v3 or v4 record's file ids, when either isn't zero (ReFS). NTFS
    /// writes zeros there.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_id_high: Option<FileIdHigh>,
    /// The update sequence number: the record's offset in the `$J` stream.
    pub usn: i64,
    pub reason: UsnReasonFlags,
    pub source_info: UsnSourceFlags,
    #[serde(flatten)]
    pub details: UsnRecordDetails,
}

/// The high 64 bits of a v3 or v4 record's 128-bit file ids.
#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileIdHigh {
    pub file: u64,
    pub parent: u64,
}

/// The fields that differ between change records (v2 and v3) and range records (v4).
#[derive(Serialize, Debug, Clone, PartialEq)]
#[serde(untagged)]
pub enum UsnRecordDetails {
    /// A v2 or v3 record.
    Change {
        #[serde(serialize_with = "serialize_timestamp")]
        timestamp: Timestamp,
        /// The file's id in `$Secure`.
        security_id: u32,
        file_attributes: FileAttributeFlags,
        /// The file's name, without its directory.
        name: String,
    },
    /// A v4 record: the byte ranges of the file that changed.
    Range {
        /// How many more extents follow in later v4 records for the same change.
        remaining_extents: u32,
        extents: Vec<UsnExtent>,
    },
}

/// A byte range of a file that a change touched (`USN_RECORD_EXTENT`).
#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsnExtent {
    pub offset: i64,
    pub length: i64,
}

impl UsnRecord {
    /// The file's name, for a v2 or v3 record.
    pub fn name(&self) -> Option<&str> {
        match &self.details {
            UsnRecordDetails::Change { name, .. } => Some(name),
            UsnRecordDetails::Range { .. } => None,
        }
    }

    /// When the change was recorded, for a v2 or v3 record.
    pub fn timestamp(&self) -> Option<Timestamp> {
        match &self.details {
            UsnRecordDetails::Change { timestamp, .. } => Some(*timestamp),
            UsnRecordDetails::Range { .. } => None,
        }
    }

    /// Parses the record at the start of `buf`, which must hold at least its `RecordLength`
    /// bytes. `offset` is the record's offset in the input, for the record and its errors.
    pub fn from_slice(buf: &[u8], offset: u64) -> Result<UsnRecord> {
        let invalid = |detail: String| Error::InvalidUsnRecord { offset, detail };

        let (Some(record_length), Some(major_version), Some(minor_version)) =
            (read_u32(buf, 0), read_u16(buf, 4), read_u16(buf, 6))
        else {
            return Err(invalid(format!("only {} bytes", buf.len())));
        };
        let record_length = record_length as usize;
        let min_length = match major_version {
            2 => V2_HEADER_SIZE,
            3 => V3_HEADER_SIZE,
            4 => V4_HEADER_SIZE,
            _ => return Err(invalid(format!("unknown major version {major_version}"))),
        };
        if record_length < min_length || record_length > USN_PAGE_SIZE {
            return Err(invalid(format!(
                "record length {record_length} out of range for a v{major_version} record"
            )));
        }
        let Some(buf) = buf.get(..record_length) else {
            return Err(invalid(format!(
                "record length {record_length}, but only {} bytes",
                buf.len()
            )));
        };
        // Every field below is inside the header length checked above.
        let u16_at = |o| read_u16(buf, o).expect("in header");
        let u32_at = |o| read_u32(buf, o).expect("in header");
        let u64_at = |o| read_u64(buf, o).expect("in header");

        let (file_reference, parent_reference, file_id_high, fields) = if major_version == 2 {
            (u64_at(8), u64_at(16), None, 24)
        } else {
            let high = FileIdHigh {
                file: u64_at(16),
                parent: u64_at(32),
            };
            let high = (high.file != 0 || high.parent != 0).then_some(high);
            (u64_at(8), u64_at(24), high, 40)
        };
        let usn = u64_at(fields) as i64;

        let (reason, source_info, details) = if major_version == 4 {
            let reason = u32_at(48);
            let source_info = u32_at(52);
            let remaining_extents = u32_at(56);
            let number_of_extents = usize::from(u16_at(60));
            let extent_size = usize::from(u16_at(62));
            if extent_size != EXTENT_SIZE && number_of_extents != 0 {
                return Err(invalid(format!("extent size {extent_size}")));
            }
            let extents_end = V4_HEADER_SIZE + number_of_extents * EXTENT_SIZE;
            let Some(raw_extents) = buf.get(V4_HEADER_SIZE..extents_end) else {
                return Err(invalid(format!(
                    "{number_of_extents} extents don't fit in {record_length} bytes"
                )));
            };
            let extents = raw_extents
                .as_chunks::<EXTENT_SIZE>()
                .0
                .iter()
                .map(|e| UsnExtent {
                    offset: read_u64(e, 0).expect("16 bytes") as i64,
                    length: read_u64(e, 8).expect("16 bytes") as i64,
                })
                .collect();
            let details = UsnRecordDetails::Range {
                remaining_extents,
                extents,
            };
            (reason, source_info, details)
        } else {
            let f = fields + 8;
            let filetime = u64_at(f);
            let reason = u32_at(f + 8);
            let source_info = u32_at(f + 12);
            let security_id = u32_at(f + 16);
            let file_attributes = u32_at(f + 20);
            let name_length = usize::from(u16_at(f + 24));
            let name_offset = usize::from(u16_at(f + 26));

            if name_offset < min_length || name_length % 2 != 0 {
                return Err(invalid(format!(
                    "name at offset {name_offset} with length {name_length}"
                )));
            }
            let Some(raw_name) = buf.get(name_offset..name_offset + name_length) else {
                return Err(invalid(format!(
                    "name at offset {name_offset} with length {name_length} doesn't fit in \
                     {record_length} bytes"
                )));
            };

            let details = UsnRecordDetails::Change {
                // A time past what `Timestamp` holds keeps the record, like the `$MFT` parsers.
                timestamp: windows_filetime_to_timestamp_saturating(filetime),
                security_id,
                file_attributes: FileAttributeFlags::from_bits_retain(file_attributes),
                name: Utf16LeStr::from_utf16le_bytes(raw_name).to_utf8_string(),
            };
            (reason, source_info, details)
        };

        Ok(UsnRecord {
            offset,
            major_version,
            minor_version,
            file_reference: MftReference::from(file_reference),
            parent_reference: MftReference::from(parent_reference),
            file_id_high,
            usn,
            reason: UsnReasonFlags::from_bits_retain(reason),
            source_info: UsnSourceFlags::from_bits_retain(source_info),
            details,
        })
    }
}

/// A USN record as one CSV row, with the file's full path when it is known.
#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct FlatUsnRecord {
    pub offset: u64,
    pub usn: i64,
    #[serde(serialize_with = "crate::utils::serialize_option_timestamp")]
    pub timestamp: Option<Timestamp>,
    pub name: Option<String>,
    #[serde(serialize_with = "crate::utils::serialize_option_windows_path")]
    pub full_path: Option<PathBuf>,
    pub entry_id: u64,
    pub sequence: u16,
    pub parent_entry_id: u64,
    pub parent_sequence: u16,
    /// The high 64 bits of a v3 or v4 record's file ids, when they aren't zero (ReFS): then
    /// `EntryId` and `Sequence` are only the low 64 bits.
    pub file_id_high: Option<u64>,
    pub parent_id_high: Option<u64>,
    pub reason: UsnReasonFlags,
    pub source_info: UsnSourceFlags,
    pub file_attributes: Option<FileAttributeFlags>,
    pub security_id: Option<u32>,
    pub major_version: u16,
    pub minor_version: u16,
    /// A v4 record's extents, as `offset+length` joined by `|`.
    pub extents: Option<String>,
}

impl FlatUsnRecord {
    pub fn from_record(record: UsnRecord, full_path: Option<PathBuf>) -> Self {
        let (timestamp, name, file_attributes, security_id, extents) = match record.details {
            UsnRecordDetails::Change {
                timestamp,
                security_id,
                file_attributes,
                name,
            } => (
                Some(timestamp),
                Some(name),
                Some(file_attributes),
                Some(security_id),
                None,
            ),
            UsnRecordDetails::Range { extents, .. } => {
                let extents = extents
                    .iter()
                    .map(|e| format!("{}+{}", e.offset, e.length))
                    .collect::<Vec<_>>()
                    .join("|");
                (None, None, None, None, Some(extents))
            }
        };
        FlatUsnRecord {
            offset: record.offset,
            usn: record.usn,
            timestamp,
            name,
            full_path,
            entry_id: record.file_reference.entry,
            sequence: record.file_reference.sequence,
            parent_entry_id: record.parent_reference.entry,
            parent_sequence: record.parent_reference.sequence,
            file_id_high: record.file_id_high.map(|high| high.file),
            parent_id_high: record.file_id_high.map(|high| high.parent),
            reason: record.reason,
            source_info: record.source_info,
            file_attributes,
            security_id,
            major_version: record.major_version,
            minor_version: record.minor_version,
            extents,
        }
    }
}

/// How many bytes [`UsnJournal`] reads at a time.
const READ_SIZE: usize = 1 << 20;

/// Reads the records of an extracted `$J` stream in order.
///
/// Records start on 8-byte boundaries. Zeros between them (the padding at the end of each page,
/// or the sparse start of the stream) are skipped. Bytes that aren't zero and don't parse as a
/// record, such as a page Windows only partly overwrote, give one error for each run of them, and
/// reading carries on at the next record found after them.
///
/// # Example
///
/// ```no_run
/// # fn main() -> mft::err::Result<()> {
/// use mft::usn::UsnJournal;
///
/// let journal = UsnJournal::new(std::fs::File::open("$J")?);
/// for record in journal {
///     let record = record?;
///     println!("{} {:?} {}", record.usn, record.name(), record.reason);
/// }
/// # Ok(())
/// # }
/// ```
pub struct UsnJournal<R: Read> {
    reader: R,
    buf: Vec<u8>,
    /// The position of the next record to try in `buf`, always on an 8-byte boundary of the input.
    pos: usize,
    /// The input offset of `buf[0]`.
    buf_offset: u64,
    eof: bool,
    /// Whether the bytes at `pos` follow ones that didn't parse, which already gave an error.
    in_garbage: bool,
}

impl<R: Read> UsnJournal<R> {
    /// Reads records from the start of `reader`, which should be the start of the `$J` stream or
    /// of a part of it cut on a page boundary.
    pub fn new(reader: R) -> Self {
        UsnJournal {
            reader,
            buf: Vec::with_capacity(READ_SIZE + USN_PAGE_SIZE),
            pos: 0,
            buf_offset: 0,
            eof: false,
            in_garbage: false,
        }
    }

    /// Makes sure `buf` holds at least `n` bytes from `pos`, unless the input ends first.
    fn fill(&mut self, n: usize) -> io::Result<()> {
        if self.buf.len() - self.pos >= n || self.eof {
            return Ok(());
        }
        self.buf.drain(..self.pos);
        self.buf_offset += self.pos as u64;
        self.pos = 0;
        while self.buf.len() < n && !self.eof {
            let read = (&mut self.reader)
                .take(READ_SIZE as u64)
                .read_to_end(&mut self.buf)?;
            self.eof = read == 0;
        }
        Ok(())
    }

    /// Ends reading after a read error: without the rest of the input there is nothing more to
    /// read.
    fn stop(&mut self, e: io::Error) -> Error {
        self.eof = true;
        self.buf.clear();
        self.pos = 0;
        e.into()
    }

    /// A cheap check of the header at `pos`, which holds at least 8 bytes: whether a record of a
    /// known version and of `length` bytes could start there.
    fn looks_like_a_record(&self, length: usize, left_in_page: usize) -> bool {
        let major_version = read_u16(&self.buf, self.pos + 4).expect("8 bytes");
        (2..=4).contains(&major_version) && (V2_HEADER_SIZE..=left_in_page).contains(&length)
    }

    /// Moves `pos` past the zero words in `buf`, stopping at the first word that isn't zero or at
    /// the last whole word.
    fn skip_zeros(&mut self) {
        let words = self.buf[self.pos..].as_chunks::<8>().0;
        let zeros = words
            .iter()
            .position(|word| *word != [0; 8])
            .unwrap_or(words.len());
        if zeros > 0 {
            self.in_garbage = false;
        }
        self.pos += zeros * 8;
    }
}

impl<R: Read> Iterator for UsnJournal<R> {
    type Item = Result<UsnRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Err(e) = self.fill(8) {
                return Some(Err(self.stop(e)));
            }
            if self.buf.len() - self.pos < 8 {
                return None;
            }
            self.skip_zeros();
            if self.buf.len() - self.pos < 8 {
                continue;
            }

            let offset = self.buf_offset + self.pos as u64;
            // A record ends before the next page, so it is never longer than what is left of it.
            let left_in_page = USN_PAGE_SIZE - (offset as usize % USN_PAGE_SIZE);
            let length = read_u32(&self.buf, self.pos).expect("8 bytes") as usize;
            if self.in_garbage && !self.looks_like_a_record(length, left_in_page) {
                // Still garbage: skip it without building an error that won't be returned.
                self.pos += 8;
                continue;
            }
            let record = if length <= left_in_page {
                if let Err(e) = self.fill(length) {
                    return Some(Err(self.stop(e)));
                }
                UsnRecord::from_slice(&self.buf[self.pos..], offset)
            } else {
                Err(Error::InvalidUsnRecord {
                    offset,
                    detail: format!(
                        "record length {length} crosses the page boundary {left_in_page} bytes on"
                    ),
                })
            };

            match record {
                Ok(record) => {
                    // The input can end right after the record, before its padding.
                    self.pos = (self.pos + length.next_multiple_of(8)).min(self.buf.len());
                    self.in_garbage = false;
                    return Some(Ok(record));
                }
                Err(e) => {
                    self.pos += 8;
                    if !self.in_garbage {
                        self.in_garbage = true;
                        return Some(Err(e));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    /// A v2 record for `name`, padded to 8 bytes.
    fn v2(usn: u64, name: &str) -> Vec<u8> {
        let name = utf16(name);
        let length = V2_HEADER_SIZE + name.len();
        let mut r = vec![0u8; length.next_multiple_of(8)];
        r[0..4].copy_from_slice(&(length as u32).to_le_bytes());
        r[4..6].copy_from_slice(&2u16.to_le_bytes());
        r[8..16].copy_from_slice(&0x0002_0000_0000_0040u64.to_le_bytes());
        r[16..24].copy_from_slice(&0x0005_0000_0000_0005u64.to_le_bytes());
        r[24..32].copy_from_slice(&usn.to_le_bytes());
        r[32..40].copy_from_slice(&132_000_000_000_000_000u64.to_le_bytes());
        r[40..44].copy_from_slice(&0x8000_0100u32.to_le_bytes());
        r[48..52].copy_from_slice(&0x105u32.to_le_bytes());
        r[52..56].copy_from_slice(&0x20u32.to_le_bytes());
        r[56..58].copy_from_slice(&(name.len() as u16).to_le_bytes());
        r[58..60].copy_from_slice(&(V2_HEADER_SIZE as u16).to_le_bytes());
        r[60..60 + name.len()].copy_from_slice(&name);
        r
    }

    #[test]
    fn parses_v2() {
        let record = UsnRecord::from_slice(&v2(4096, "a.txt"), 7).unwrap();
        assert_eq!(record.offset, 7);
        assert_eq!(record.file_reference, MftReference::new(0x40, 2));
        assert_eq!(record.parent_reference, MftReference::new(5, 5));
        assert_eq!(record.usn, 4096);
        assert_eq!(
            record.reason,
            UsnReasonFlags::USN_REASON_FILE_CREATE | UsnReasonFlags::USN_REASON_CLOSE
        );
        assert_eq!(record.name(), Some("a.txt"));
        assert_eq!(
            record.timestamp().unwrap().to_string(),
            "2019-04-17T18:40:00Z"
        );
        let UsnRecordDetails::Change {
            security_id,
            file_attributes,
            ..
        } = record.details
        else {
            panic!("a v2 record is a change record");
        };
        assert_eq!(security_id, 0x105);
        assert_eq!(file_attributes, FileAttributeFlags::FILE_ATTRIBUTE_ARCHIVE);
    }

    #[test]
    fn parses_v3() {
        let name = utf16("b");
        let length = V3_HEADER_SIZE + name.len();
        let mut r = vec![0u8; length.next_multiple_of(8)];
        r[0..4].copy_from_slice(&(length as u32).to_le_bytes());
        r[4..6].copy_from_slice(&3u16.to_le_bytes());
        r[8..16].copy_from_slice(&0x0003_0000_0000_0041u64.to_le_bytes());
        r[24..32].copy_from_slice(&0x0001_0000_0000_0010u64.to_le_bytes());
        r[40..48].copy_from_slice(&8u64.to_le_bytes());
        r[56..60].copy_from_slice(&0x2u32.to_le_bytes());
        r[72..74].copy_from_slice(&(name.len() as u16).to_le_bytes());
        r[74..76].copy_from_slice(&(V3_HEADER_SIZE as u16).to_le_bytes());
        r[76..78].copy_from_slice(&name);

        let record = UsnRecord::from_slice(&r, 0).unwrap();
        assert_eq!(record.file_reference, MftReference::new(0x41, 3));
        assert_eq!(record.parent_reference, MftReference::new(0x10, 1));
        assert_eq!(record.file_id_high, None);
        assert_eq!(record.usn, 8);
        assert_eq!(record.reason, UsnReasonFlags::USN_REASON_DATA_EXTEND);
        assert_eq!(record.name(), Some("b"));

        r[16] = 1;
        let record = UsnRecord::from_slice(&r, 0).unwrap();
        assert_eq!(record.file_id_high, Some(FileIdHigh { file: 1, parent: 0 }));
    }

    #[test]
    fn parses_v4() {
        let length = V4_HEADER_SIZE + 2 * EXTENT_SIZE;
        let mut r = vec![0u8; length];
        r[0..4].copy_from_slice(&(length as u32).to_le_bytes());
        r[4..6].copy_from_slice(&4u16.to_le_bytes());
        r[8..16].copy_from_slice(&0x0003_0000_0000_0041u64.to_le_bytes());
        r[40..48].copy_from_slice(&16u64.to_le_bytes());
        r[48..52].copy_from_slice(&0x1u32.to_le_bytes());
        r[56..60].copy_from_slice(&3u32.to_le_bytes());
        r[60..62].copy_from_slice(&2u16.to_le_bytes());
        r[62..64].copy_from_slice(&16u16.to_le_bytes());
        r[64..72].copy_from_slice(&4096i64.to_le_bytes());
        r[72..80].copy_from_slice(&512i64.to_le_bytes());
        r[80..88].copy_from_slice(&0i64.to_le_bytes());
        r[88..96].copy_from_slice(&8i64.to_le_bytes());

        let record = UsnRecord::from_slice(&r, 0).unwrap();
        assert_eq!(record.name(), None);
        assert_eq!(
            record.details,
            UsnRecordDetails::Range {
                remaining_extents: 3,
                extents: vec![
                    UsnExtent {
                        offset: 4096,
                        length: 512
                    },
                    UsnExtent {
                        offset: 0,
                        length: 8
                    },
                ],
            }
        );

        // The extents must fit in the record.
        r[60..62].copy_from_slice(&3u16.to_le_bytes());
        assert!(UsnRecord::from_slice(&r, 0).is_err());
    }

    #[test]
    fn rejects_bad_records() {
        let mut r = v2(0, "a");
        r[4] = 9;
        assert!(UsnRecord::from_slice(&r, 0).is_err(), "unknown version");

        let mut r = v2(0, "a");
        r[56..58].copy_from_slice(&40u16.to_le_bytes());
        assert!(UsnRecord::from_slice(&r, 0).is_err(), "name past the end");

        let r = v2(0, "a");
        assert!(UsnRecord::from_slice(&r[..40], 0).is_err(), "cut short");
    }

    #[test]
    fn journal_skips_zeros_and_garbage() {
        let mut j = vec![0u8; 3 * USN_PAGE_SIZE];
        let first = v2(USN_PAGE_SIZE as u64, "first");
        j[USN_PAGE_SIZE..USN_PAGE_SIZE + first.len()].copy_from_slice(&first);
        let at = USN_PAGE_SIZE + first.len();
        let second = v2(at as u64, "second");
        j[at..at + second.len()].copy_from_slice(&second);
        // Two words of garbage, then a record in the next page.
        j[2 * USN_PAGE_SIZE - 16..2 * USN_PAGE_SIZE].fill(0xAB);
        let third = v2(2 * USN_PAGE_SIZE as u64, "third");
        j[2 * USN_PAGE_SIZE..2 * USN_PAGE_SIZE + third.len()].copy_from_slice(&third);

        let results: Vec<_> = UsnJournal::new(Cursor::new(j)).collect();
        assert_eq!(results.len(), 4);
        let names: Vec<_> = results
            .iter()
            .filter_map(|r| r.as_ref().ok())
            .map(|r| (r.offset, r.usn, r.name().unwrap().to_string()))
            .collect();
        assert_eq!(
            names,
            [
                (4096, 4096, "first".to_string()),
                (at as u64, at as i64, "second".to_string()),
                (8192, 8192, "third".to_string()),
            ]
        );
        assert!(matches!(
            results[2],
            Err(Error::InvalidUsnRecord { offset: 8176, .. })
        ));
    }

    #[test]
    fn keeps_a_record_with_a_time_past_the_supported_range() {
        let mut r = v2(0, "a");
        r[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
        let record = UsnRecord::from_slice(&r, 0).unwrap();
        assert_eq!(record.timestamp(), Some(Timestamp::MAX));
        assert_eq!(record.name(), Some("a"));
    }

    #[test]
    fn journal_ends_after_a_last_record_without_padding() {
        // One record of 62 bytes, and the input ends there rather than at its 8-byte padding.
        let mut j = v2(0, "a");
        j.truncate(V2_HEADER_SIZE + 2);
        let results: Vec<_> = UsnJournal::new(Cursor::new(j)).collect();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].as_ref().unwrap().name(), Some("a"));
    }

    #[test]
    fn journal_gives_one_error_for_a_run_of_garbage() {
        // A page of garbage, including words that pass the cheap header check but don't parse,
        // then a record.
        let mut j = vec![0x41u8; USN_PAGE_SIZE];
        j[64..72].copy_from_slice(&[64, 0, 0, 0, 2, 0, 0, 0]);
        j.extend_from_slice(&v2(USN_PAGE_SIZE as u64, "a"));
        let results: Vec<_> = UsnJournal::new(Cursor::new(j)).collect();
        assert_eq!(results.len(), 2);
        assert!(matches!(
            results[0],
            Err(Error::InvalidUsnRecord { offset: 0, .. })
        ));
        assert_eq!(results[1].as_ref().unwrap().offset, USN_PAGE_SIZE as u64);
    }

    #[test]
    fn journal_reads_across_buffer_refills() {
        // More records than one read holds.
        let mut j = Vec::new();
        let mut expected = 0;
        while j.len() < READ_SIZE * 2 + 100 {
            let r = v2(j.len() as u64, "file-name.txt");
            if j.len() % USN_PAGE_SIZE + r.len() > USN_PAGE_SIZE {
                j.resize(j.len().next_multiple_of(USN_PAGE_SIZE), 0);
                continue;
            }
            j.extend_from_slice(&r);
            expected += 1;
        }
        let mut count = 0;
        for record in UsnJournal::new(Cursor::new(&j)) {
            let record = record.unwrap();
            assert_eq!(record.usn as u64, record.offset);
            count += 1;
        }
        assert_eq!(count, expected);
    }
}
