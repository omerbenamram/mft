//! Index records (`INDX`), the nodes of a large index kept in `$INDEX_ALLOCATION`.
//!
//! A directory's `$I30` index starts in its `$INDEX_ROOT` attribute; once it outgrows the entry,
//! the rest lives in `INDX` records in the directory's `$INDEX_ALLOCATION` stream. Each record
//! holds sorted `$FILE_NAME` entries. When entries move or files are deleted, the old entries are
//! left behind the record's last entry, in its slack space, until something overwrites them. Those
//! slack entries are evidence of deleted and renamed files.
//!
//! [`IndxRecord::from_buffer`] parses one record, and [`IndxRecord::entries`] gives its entries
//! and [`IndxRecord::slack_entries`] the ones recovered from its slack. [`IndxFile`] reads the
//! records of an extracted `$INDEX_ALLOCATION:$I30` stream.
//!
//! <https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc#index-entry>

use std::io::{self, Read};
use std::path::PathBuf;

use jiff::Timestamp;
use serde::Serialize;

use crate::MftReference;
use crate::attribute::FileAttributeFlags;
use crate::attribute::x30::{FileNameAttr, FileNamespace};
use crate::attribute::x90::IndexEntryFlags;
use crate::err::{Error, Result};
use crate::impl_serialize_for_bitflags;
use crate::utils::{read_u16, read_u32, read_u64};
use bitflags::bitflags;

/// The size of an index record when the input doesn't say otherwise.
pub const DEFAULT_INDX_RECORD_SIZE: usize = 4096;

/// Where the index node header starts in a record.
const NODE_HEADER_OFFSET: usize = 0x18;
/// The size of an index entry's header, before its `$FILE_NAME`.
const ENTRY_HEADER_SIZE: usize = 0x10;
/// The size of a `$FILE_NAME` with an empty name.
const FILE_NAME_HEADER_SIZE: usize = 0x42;

bitflags! {
    /// The index node's flags.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct IndexNodeFlags: u32 {
        /// The node's entries point at child nodes.
        const HAS_CHILDREN = 0x01;
        const _ = !0;
    }
}

impl_serialize_for_bitflags! {IndexNodeFlags}

/// One `INDX` record, with its update sequence fixups applied.
#[derive(Debug, Clone)]
pub struct IndxRecord {
    /// Where the record starts in the input, in bytes.
    pub offset: u64,
    /// The `$LogFile` sequence number of the record's last change.
    pub lsn: u64,
    /// The record's virtual cluster number in the index.
    pub vcn: u64,
    pub flags: IndexNodeFlags,
    /// Whether every sector of the record ended with the update sequence number. A record that
    /// doesn't was torn by an interrupted write, so its entries may be partly stale.
    pub valid_fixup: bool,
    /// Where the node's first entry starts in the record.
    entries_start: usize,
    /// Where the node's entries end in the record, and its slack starts.
    entries_end: usize,
    /// Where the node's allocated space ends in the record.
    allocated_end: usize,
    data: Vec<u8>,
}

/// One `$FILE_NAME` entry of an index record.
#[derive(Serialize, Debug, Clone)]
pub struct IndxEntry<'a> {
    /// Where the entry starts in the input, in bytes.
    pub offset: u64,
    /// Whether the entry was recovered from the record's slack space, rather than being one of
    /// the index's current entries.
    pub from_slack: bool,
    /// The file the entry names. A slack entry whose header was overwritten has only its
    /// `$FILE_NAME`, so no reference.
    pub mft_reference: Option<MftReference>,
    pub flags: Option<IndexEntryFlags>,
    pub file_name: FileNameAttr<'a>,
}

impl IndxRecord {
    /// Parses the record in `data`, which must be the whole record. `offset` is the record's
    /// offset in the input, for the record and its errors.
    pub fn from_buffer(mut data: Vec<u8>, offset: u64) -> Result<IndxRecord> {
        let invalid = |detail: String| Error::InvalidIndexRecord { offset, detail };
        if data.get(..4) != Some(b"INDX") {
            return Err(invalid(format!(
                "signature {:02x?} isn't INDX",
                data.get(..4).unwrap_or(&data)
            )));
        }
        let header = |at| read_u32(&data, at).map(|v| v as usize);
        let (Some(usa_offset), Some(usa_count), Some(lsn), Some(vcn)) = (
            read_u16(&data, 4),
            read_u16(&data, 6),
            read_u64(&data, 8),
            read_u64(&data, 16),
        ) else {
            return Err(invalid("record header cut short".to_string()));
        };
        let (Some(entries_offset), Some(used), Some(allocated), Some(flags)) = (
            header(NODE_HEADER_OFFSET),
            header(NODE_HEADER_OFFSET + 4),
            header(NODE_HEADER_OFFSET + 8),
            read_u32(&data, NODE_HEADER_OFFSET + 12),
        ) else {
            return Err(invalid("node header cut short".to_string()));
        };

        let valid_fixup = crate::ntfs::apply_update_sequence_array_fixups_in_place_with(
            &mut data,
            usa_offset,
            usa_count,
            |_| {},
        )
        .map_err(|e| invalid(format!("update sequence array: {e}")))?;

        let entries_start = NODE_HEADER_OFFSET + entries_offset;
        let entries_end = NODE_HEADER_OFFSET + used;
        let allocated_end = NODE_HEADER_OFFSET + allocated;
        if entries_start > entries_end || entries_end > allocated_end || allocated_end > data.len()
        {
            return Err(invalid(format!(
                "node entries at {entries_start}..{entries_end}, allocated up to {allocated_end}, \
                 in a record of {} bytes",
                data.len()
            )));
        }

        Ok(IndxRecord {
            offset,
            lsn,
            vcn,
            flags: IndexNodeFlags::from_bits_retain(flags & 0xFF),
            valid_fixup,
            entries_start,
            entries_end,
            allocated_end,
            data,
        })
    }

    /// The node's current entries, up to its end entry.
    pub fn entries(&self) -> Result<Vec<IndxEntry<'_>>> {
        let mut entries = Vec::new();
        let mut at = self.entries_start;
        while at + ENTRY_HEADER_SIZE <= self.entries_end {
            let length = usize::from(read_u16(&self.data, at + 8).expect("in the node"));
            let flags = IndexEntryFlags::from_bits_retain(u32::from(
                read_u16(&self.data, at + 12).expect("in the node"),
            ));
            if flags.contains(IndexEntryFlags::INDEX_ENTRY_END) {
                break;
            }
            if length < ENTRY_HEADER_SIZE + FILE_NAME_HEADER_SIZE || at + length > self.entries_end
            {
                return Err(Error::InvalidIndexRecord {
                    offset: self.offset,
                    detail: format!("entry at {at} has length {length}"),
                });
            }
            let file_name =
                FileNameAttr::from_slice(&self.data[at + ENTRY_HEADER_SIZE..at + length])?;
            entries.push(IndxEntry {
                offset: self.offset + at as u64,
                from_slack: false,
                mft_reference: Some(MftReference::from(
                    read_u64(&self.data, at).expect("in the node"),
                )),
                flags: Some(flags),
                file_name,
            });
            at += length;
        }
        Ok(entries)
    }

    /// The entries found in the node's slack space: the bytes after its end entry, up to the end
    /// of its allocation. Each 8-byte boundary is tried as the start of an entry, and then as the
    /// start of a bare `$FILE_NAME`, for an entry whose header was overwritten. Only names that
    /// look whole are kept: a known namespace, a name without control characters, and timestamps
    /// from 1980 to 2100.
    pub fn slack_entries(&self) -> Vec<IndxEntry<'_>> {
        let slack_start = match self.end_entry_end() {
            Some(end) => end.next_multiple_of(8),
            None => self.entries_end.next_multiple_of(8),
        };
        let slack = &self.data[..self.allocated_end];
        let mut entries = Vec::new();
        let mut at = slack_start;
        while at + FILE_NAME_HEADER_SIZE <= slack.len() {
            if let Some((entry, length)) = self.slack_entry_at(slack, at) {
                entries.push(entry);
                at += length.next_multiple_of(8);
            } else {
                at += 8;
            }
        }
        entries
    }

    /// Where the node's end entry ends: the start of its slack space.
    fn end_entry_end(&self) -> Option<usize> {
        let mut at = self.entries_start;
        while at + ENTRY_HEADER_SIZE <= self.entries_end {
            let length = usize::from(read_u16(&self.data, at + 8)?);
            let flags = read_u16(&self.data, at + 12)?;
            if u32::from(flags) & IndexEntryFlags::INDEX_ENTRY_END.bits() != 0 {
                return Some(at + length.max(ENTRY_HEADER_SIZE));
            }
            if length == 0 {
                return None;
            }
            at += length;
        }
        None
    }

    fn slack_entry_at<'a>(&'a self, slack: &'a [u8], at: usize) -> Option<(IndxEntry<'a>, usize)> {
        // A whole entry: its header, then its `$FILE_NAME`.
        if let Some(file_name) = slack
            .get(at + ENTRY_HEADER_SIZE..)
            .and_then(plausible_file_name)
        {
            let length = usize::from(read_u16(slack, at + 8)?);
            let file_name_length = usize::from(read_u16(slack, at + 10)?);
            let flags = read_u16(slack, at + 12)?;
            let needed = FILE_NAME_HEADER_SIZE + 2 * usize::from(file_name.name_length);
            let reference = MftReference::from(read_u64(slack, at)?);
            if file_name_length == needed
                && length >= ENTRY_HEADER_SIZE + needed
                && length % 8 == 0
                && flags & !0x3 == 0
                && reference.entry != 0
                && reference.entry < 1 << 32
                && reference.sequence != 0
            {
                return Some((
                    IndxEntry {
                        offset: self.offset + at as u64,
                        from_slack: true,
                        mft_reference: Some(reference),
                        flags: Some(IndexEntryFlags::from_bits_retain(u32::from(flags))),
                        file_name,
                    },
                    length.min(slack.len() - at),
                ));
            }
        }
        // A `$FILE_NAME` whose entry header was overwritten.
        let file_name = plausible_file_name(&slack[at..])?;
        let length = FILE_NAME_HEADER_SIZE + 2 * usize::from(file_name.name_length);
        Some((
            IndxEntry {
                offset: self.offset + at as u64,
                from_slack: true,
                mft_reference: None,
                flags: None,
                file_name,
            },
            length,
        ))
    }
}

/// Parses a `$FILE_NAME` at the start of `buf` if it looks like a real one.
fn plausible_file_name(buf: &[u8]) -> Option<FileNameAttr<'_>> {
    // The parent's sequence number, the namespace, and a name length that isn't zero.
    if buf.len() < FILE_NAME_HEADER_SIZE || buf[0x40] == 0 || buf[0x41] > 3 {
        return None;
    }
    if read_u16(buf, 6)? == 0 && read_u64(buf, 0)? != 0 {
        return None;
    }
    let file_name = FileNameAttr::from_slice(buf).ok()?;
    let earliest = Timestamp::new(315_532_800, 0).expect("1980"); // 1980-01-01
    let latest = Timestamp::new(4_102_444_800, 0).expect("2100"); // 2100-01-01
    let times = [
        file_name.created,
        file_name.modified,
        file_name.mft_modified,
        file_name.accessed,
    ];
    if times.iter().any(|t| *t < earliest || *t > latest)
        || file_name.parent.entry == 0
        || file_name.physical_size < file_name.logical_size && file_name.physical_size != 0
    {
        return None;
    }
    let mut name_ok = true;
    file_name.name.with_utf8(|name| {
        name_ok = !name.chars().any(|c| c.is_control() || c == '\u{FFFD}');
    });
    name_ok.then_some(file_name)
}

/// Reads the `INDX` records of an extracted `$INDEX_ALLOCATION` stream, such as a directory's
/// `$I30`, in order. Records that are all zeros (allocated but never used) are skipped.
///
/// The record size comes from the first record's update sequence array: one fixup per 512-byte
/// sector, which is 4096 bytes on most volumes.
///
/// # Example
///
/// ```no_run
/// # fn main() -> mft::err::Result<()> {
/// use mft::indx::IndxFile;
///
/// for record in IndxFile::new(std::fs::File::open("$I30")?) {
///     let record = record?;
///     for entry in record.entries()?.iter().chain(&record.slack_entries()) {
///         println!("{} {}", entry.from_slack, entry.file_name.name);
///     }
/// }
/// # Ok(())
/// # }
/// ```
pub struct IndxFile<R: Read> {
    reader: R,
    record_size: Option<usize>,
    offset: u64,
    done: bool,
}

impl<R: Read> IndxFile<R> {
    pub fn new(reader: R) -> Self {
        IndxFile {
            reader,
            record_size: None,
            offset: 0,
            done: false,
        }
    }

    /// Reads up to `buf.len()` bytes, fewer only at the end of the input.
    fn read_full(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut read = 0;
        while read < buf.len() {
            match self.reader.read(&mut buf[read..]) {
                Ok(0) => break,
                Ok(n) => read += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(read)
    }

    fn next_record(&mut self) -> Result<Option<IndxRecord>> {
        let mut first = vec![0u8; 512];
        let read = self.read_full(&mut first)?;
        if read == 0 {
            return Ok(None);
        }
        let record_size = *self.record_size.get_or_insert_with(|| {
            match (&first[..4] == b"INDX", read_u16(&first, 6)) {
                (true, Some(usa_count)) if usa_count >= 2 => (usize::from(usa_count) - 1) * 512,
                _ => DEFAULT_INDX_RECORD_SIZE,
            }
        });
        let mut data = first;
        data.resize(record_size.max(512), 0);
        let read = read + self.read_full(&mut data[512.min(record_size)..])?;
        data.truncate(read);
        let offset = self.offset;
        self.offset += read as u64;
        if data.iter().all(|&b| b == 0) {
            return Ok(Some(IndxRecord::empty(offset)));
        }
        IndxRecord::from_buffer(data, offset).map(Some)
    }
}

impl IndxRecord {
    /// A stand-in for a record that is all zeros, which [`IndxFile`] skips.
    fn empty(offset: u64) -> IndxRecord {
        IndxRecord {
            offset,
            lsn: 0,
            vcn: 0,
            flags: IndexNodeFlags::empty(),
            valid_fixup: true,
            entries_start: 0,
            entries_end: 0,
            allocated_end: 0,
            data: Vec::new(),
        }
    }
}

impl<R: Read> Iterator for IndxFile<R> {
    type Item = Result<IndxRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.done {
            match self.next_record() {
                Ok(Some(record)) if record.data.is_empty() => continue,
                Ok(Some(record)) => return Some(Ok(record)),
                Ok(None) => self.done = true,
                Err(e @ Error::IoError { .. }) => {
                    self.done = true;
                    return Some(Err(e));
                }
                Err(e) => return Some(Err(e)),
            }
        }
        None
    }
}

/// An index entry as one CSV row, with the file's full path when it is known.
#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct FlatIndxEntry {
    pub offset: u64,
    pub record_vcn: u64,
    pub from_slack: bool,
    pub entry_id: Option<u64>,
    pub sequence: Option<u16>,
    pub parent_entry_id: u64,
    pub parent_sequence: u16,
    pub name: String,
    pub namespace: FileNamespace,
    #[serde(serialize_with = "crate::utils::serialize_option_windows_path")]
    pub full_path: Option<PathBuf>,
    #[serde(serialize_with = "crate::utils::serialize_timestamp")]
    pub created: Timestamp,
    #[serde(serialize_with = "crate::utils::serialize_timestamp")]
    pub modified: Timestamp,
    #[serde(serialize_with = "crate::utils::serialize_timestamp")]
    pub mft_modified: Timestamp,
    #[serde(serialize_with = "crate::utils::serialize_timestamp")]
    pub accessed: Timestamp,
    pub logical_size: u64,
    pub physical_size: u64,
    pub file_flags: FileAttributeFlags,
}

impl FlatIndxEntry {
    pub fn from_entry(
        record: &IndxRecord,
        entry: &IndxEntry<'_>,
        full_path: Option<PathBuf>,
    ) -> Self {
        let f = &entry.file_name;
        FlatIndxEntry {
            offset: entry.offset,
            record_vcn: record.vcn,
            from_slack: entry.from_slack,
            entry_id: entry.mft_reference.map(|r| r.entry),
            sequence: entry.mft_reference.map(|r| r.sequence),
            parent_entry_id: f.parent.entry,
            parent_sequence: f.parent.sequence,
            name: f.name.to_utf8_string(),
            namespace: f.namespace,
            full_path,
            created: f.created,
            modified: f.modified,
            mft_modified: f.mft_modified,
            accessed: f.accessed,
            logical_size: f.logical_size,
            physical_size: f.physical_size,
            file_flags: f.flags.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A `$FILE_NAME` index entry for `name` in directory 5, created in 2019.
    fn entry(reference: u64, name: &str, flags: u16) -> Vec<u8> {
        let name: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let file_name_length = FILE_NAME_HEADER_SIZE + name.len();
        let length = (ENTRY_HEADER_SIZE + file_name_length).next_multiple_of(8);
        let mut e = vec![0u8; length];
        e[0..8].copy_from_slice(&reference.to_le_bytes());
        e[8..10].copy_from_slice(&(length as u16).to_le_bytes());
        e[10..12].copy_from_slice(&(file_name_length as u16).to_le_bytes());
        e[12..14].copy_from_slice(&flags.to_le_bytes());
        let f = &mut e[ENTRY_HEADER_SIZE..];
        f[0..8].copy_from_slice(&0x0005_0000_0000_0005u64.to_le_bytes());
        for t in 0..4 {
            f[8 + 8 * t..16 + 8 * t].copy_from_slice(&132_000_000_000_000_000u64.to_le_bytes());
        }
        f[0x40] = (name.len() / 2) as u8;
        f[0x41] = 1;
        f[0x42..0x42 + name.len()].copy_from_slice(&name);
        e
    }

    fn end_entry() -> Vec<u8> {
        let mut e = vec![0u8; 16];
        e[8] = 16;
        e[12] = IndexEntryFlags::INDEX_ENTRY_END.bits() as u8;
        e
    }

    /// A 4096-byte record holding `live` entries, then `slack` bytes after the end entry.
    fn record(live: &[Vec<u8>], slack: &[u8]) -> Vec<u8> {
        let mut r = vec![0u8; 4096];
        r[0..4].copy_from_slice(b"INDX");
        r[4..6].copy_from_slice(&0x28u16.to_le_bytes());
        r[6..8].copy_from_slice(&9u16.to_le_bytes());
        r[16..24].copy_from_slice(&3u64.to_le_bytes());
        let mut at = 0x40;
        for e in live.iter().chain(std::iter::once(&end_entry())) {
            r[at..at + e.len()].copy_from_slice(e);
            at += e.len();
        }
        r[at..at + slack.len()].copy_from_slice(slack);
        r[0x18..0x1C].copy_from_slice(&(0x40u32 - 0x18).to_le_bytes());
        r[0x1C..0x20].copy_from_slice(&((at - 0x18) as u32).to_le_bytes());
        r[0x20..0x24].copy_from_slice(&(4096u32 - 0x18).to_le_bytes());
        // Update sequence 0x0001: each sector's last two bytes move to the array.
        r[0x28..0x2A].copy_from_slice(&1u16.to_le_bytes());
        for sector in 0..8 {
            let end = (sector + 1) * 512 - 2;
            let (a, b) = (r[end], r[end + 1]);
            r[0x2A + 2 * sector] = a;
            r[0x2B + 2 * sector] = b;
            r[end..end + 2].copy_from_slice(&1u16.to_le_bytes());
        }
        r
    }

    #[test]
    fn reads_entries_and_slack() {
        let live = [entry(0x0001_0000_0000_0040, "live.txt", 0)];
        let mut slack = entry(0x0002_0000_0000_0041, "deleted.txt", 0);
        // A second slack entry whose header was overwritten.
        let mut torn = entry(0x0001_0000_0000_0042, "torn.doc", 0);
        torn[..16].fill(0xEE);
        slack.extend_from_slice(&torn);

        let record = IndxRecord::from_buffer(record(&live, &slack), 4096).unwrap();
        assert!(record.valid_fixup);
        assert_eq!(record.vcn, 3);

        let entries = record.entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].file_name.name.to_utf8_string(), "live.txt");
        assert_eq!(entries[0].mft_reference, Some(MftReference::new(0x40, 1)));

        let slack = record.slack_entries();
        let names: Vec<_> = slack
            .iter()
            .map(|e| (e.file_name.name.to_utf8_string(), e.mft_reference))
            .collect();
        assert_eq!(
            names,
            [
                ("deleted.txt".to_string(), Some(MftReference::new(0x41, 2))),
                ("torn.doc".to_string(), None),
            ]
        );
        assert!(slack.iter().all(|e| e.from_slack));
    }

    #[test]
    fn file_skips_empty_records() {
        let mut input = vec![0u8; 4096];
        input.extend(record(&[entry(0x0001_0000_0000_0040, "a", 0)], &[]));
        let records: Vec<_> = IndxFile::new(Cursor::new(input))
            .collect::<Result<_>>()
            .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].offset, 4096);
        assert_eq!(records[0].entries().unwrap().len(), 1);
    }

    #[test]
    fn rejects_bad_records() {
        assert!(IndxRecord::from_buffer(vec![0; 4096], 0).is_err());
        let mut r = record(&[], &[]);
        r[0x1C..0x20].copy_from_slice(&5000u32.to_le_bytes());
        assert!(IndxRecord::from_buffer(r, 0).is_err());
    }
}
