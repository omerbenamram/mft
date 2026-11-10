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

        let entries_start = NODE_HEADER_OFFSET.saturating_add(entries_offset);
        let entries_end = NODE_HEADER_OFFSET.saturating_add(used);
        let allocated_end = NODE_HEADER_OFFSET.saturating_add(allocated);
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
        match self.entries_until_error() {
            (entries, None) => Ok(entries),
            (_, Some(error)) => Err(error),
        }
    }

    /// Like [`IndxRecord::entries`], but on a damaged entry gives the entries before it along
    /// with the error, rather than only the error.
    pub fn entries_until_error(&self) -> (Vec<IndxEntry<'_>>, Option<Error>) {
        let walk = self.walk_live();
        (walk.entries, walk.error)
    }

    /// The entries found in the node's slack space: the bytes after its end entry, up to the end
    /// of its allocation. When an entry before the end entry is damaged, the scan starts at that
    /// entry instead, so the intact entries after it are still found. Each 8-byte boundary is
    /// tried as the start of an entry, and then as the start of a bare `$FILE_NAME`, for an entry
    /// whose header was overwritten. Only names that look whole are kept: a known namespace, a
    /// name without control characters, and timestamps from 1980 to 2100.
    pub fn slack_entries(&self) -> Vec<IndxEntry<'_>> {
        let node = &self.data[..self.allocated_end];
        let mut entries = Vec::new();
        let mut at = self.walk_live().slack_start.next_multiple_of(8);
        while at + FILE_NAME_HEADER_SIZE <= node.len() {
            if let Some((entry, length)) = self.slack_entry_at(node, at) {
                entries.push(entry);
                at += length.next_multiple_of(8);
            } else {
                at += 8;
            }
        }
        entries
    }

    /// Walks the node's current entries up to its end entry, or up to the first damaged one.
    fn walk_live(&self) -> LiveWalk<'_> {
        let invalid = |detail: String| Error::InvalidIndexRecord {
            offset: self.offset,
            detail,
        };
        let mut entries = Vec::new();
        let mut at = self.entries_start;
        while at + ENTRY_HEADER_SIZE <= self.entries_end {
            let length = usize::from(read_u16(&self.data, at + 8).expect("in the node"));
            let flags = IndexEntryFlags::from_bits_retain(u32::from(
                read_u16(&self.data, at + 12).expect("in the node"),
            ));
            if flags.contains(IndexEntryFlags::INDEX_ENTRY_END) {
                // A bogus length here mustn't push the slack past the node's entries.
                let slack_start = (at + length.max(ENTRY_HEADER_SIZE)).min(self.entries_end);
                return LiveWalk {
                    entries,
                    error: None,
                    slack_start,
                };
            }
            let parsed = if length < ENTRY_HEADER_SIZE + FILE_NAME_HEADER_SIZE
                || at + length > self.entries_end
            {
                Err(invalid(format!("entry at {at} has length {length}")))
            } else {
                FileNameAttr::from_slice(&self.data[at + ENTRY_HEADER_SIZE..at + length])
                    .map_err(|e| invalid(format!("entry at {at}: {e}")))
            };
            let file_name = match parsed {
                Ok(file_name) => file_name,
                // The rest of the node is scanned like slack, from the damaged entry on.
                Err(error) => {
                    return LiveWalk {
                        entries,
                        error: Some(error),
                        slack_start: at,
                    };
                }
            };
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
        // No end entry: whatever is left of the node is scanned like slack.
        LiveWalk {
            entries,
            error: None,
            slack_start: at,
        }
    }

    fn slack_entry_at<'a>(&'a self, node: &'a [u8], at: usize) -> Option<(IndxEntry<'a>, usize)> {
        if let Some(found) = self.slack_entry_with_header_at(node, at) {
            return Some(found);
        }
        // A `$FILE_NAME` whose entry header was overwritten.
        let file_name = plausible_file_name(&node[at..])?;
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

    /// A whole entry at `at`: its header, then its `$FILE_NAME`.
    fn slack_entry_with_header_at<'a>(
        &'a self,
        node: &'a [u8],
        at: usize,
    ) -> Option<(IndxEntry<'a>, usize)> {
        let length = usize::from(read_u16(node, at + 8)?);
        let file_name_length = usize::from(read_u16(node, at + 10)?);
        let flags = read_u16(node, at + 12)?;
        let reference = MftReference::from(read_u64(node, at)?);
        if length % 8 != 0
            || flags & !0x3 != 0
            || reference.entry == 0
            || reference.entry >= 1 << 32
            || reference.sequence == 0
        {
            return None;
        }
        let file_name = plausible_file_name(node.get(at + ENTRY_HEADER_SIZE..)?)?;
        let needed = FILE_NAME_HEADER_SIZE + 2 * usize::from(file_name.name_length);
        if file_name_length != needed || length < ENTRY_HEADER_SIZE + needed {
            return None;
        }
        let flags = IndexEntryFlags::from_bits_retain(u32::from(flags));
        // A stale length can be longer than the entry; going by it could skip entries after it.
        // An entry is at most its name rounded up to 8 bytes, plus a child node's VCN.
        let child_vcn = if flags.contains(IndexEntryFlags::INDEX_ENTRY_NODE) {
            8
        } else {
            0
        };
        let longest = (ENTRY_HEADER_SIZE + needed).next_multiple_of(8) + child_vcn;
        Some((
            IndxEntry {
                offset: self.offset + at as u64,
                from_slack: true,
                mft_reference: Some(reference),
                flags: Some(flags),
                file_name,
            },
            length.min(longest).min(node.len() - at),
        ))
    }
}

/// The node's current entries, as [`IndxRecord::walk_live`] found them.
struct LiveWalk<'a> {
    entries: Vec<IndxEntry<'a>>,
    /// The damaged entry that stopped the walk early.
    error: Option<Error>,
    /// Where the node's slack starts: after its end entry, or at the damaged entry.
    slack_start: usize,
}

/// The `FILETIME` of 1980-01-01 and 2100-01-01: a `$FILE_NAME` timestamp outside them is garbage.
const EARLIEST_FILETIME: u64 = 119_600_064_000_000_000;
const LATEST_FILETIME: u64 = 157_469_184_000_000_000;
/// Sizes past 2^56 bytes (64 PiB) are larger than any NTFS volume.
const LARGEST_SIZE: u64 = 1 << 56;

/// Parses a `$FILE_NAME` at the start of `buf` if it looks like a real one.
fn plausible_file_name(buf: &[u8]) -> Option<FileNameAttr<'_>> {
    // A name length that isn't zero, and a known namespace.
    if buf.len() < FILE_NAME_HEADER_SIZE || buf[0x40] == 0 || buf[0x41] > 3 {
        return None;
    }
    // The parent's record number and sequence number aren't zero. The logical size can be
    // larger than the allocated one, for a compressed or sparse file.
    let parent = MftReference::from(read_u64(buf, 0)?);
    let times_ok = (0..4).all(|i| {
        read_u64(buf, 8 + 8 * i).is_some_and(|t| (EARLIEST_FILETIME..=LATEST_FILETIME).contains(&t))
    });
    if parent.entry == 0
        || parent.sequence == 0
        || !times_ok
        || read_u64(buf, 0x28)? >= LARGEST_SIZE
        || read_u64(buf, 0x30)? >= LARGEST_SIZE
    {
        return None;
    }
    let file_name = FileNameAttr::from_slice(buf).ok()?;
    let name_ok = file_name
        .name
        .with_utf8(|name| !name.chars().any(|c| c.is_control() || c == '\u{FFFD}'));
    name_ok.then_some(file_name)
}

/// Reads the `INDX` records of an extracted `$INDEX_ALLOCATION` stream, such as a directory's
/// `$I30`, in order. Records that are all zeros (allocated but never used) are skipped.
///
/// The record size comes from the first record's update sequence array: one fixup per 512-byte
/// sector, which is 4096 bytes on most volumes. When that array's size is damaged (not a power of
/// two from 512 to 65536 bytes), records are read as 4096 bytes.
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

    /// Appends up to `n` bytes to `buf`, fewer only at the end of the input.
    fn read_up_to(&mut self, buf: &mut Vec<u8>, n: usize) -> io::Result<()> {
        (&mut self.reader).take(n as u64).read_to_end(buf)?;
        Ok(())
    }

    /// Reads the next record that isn't all zeros.
    fn next_record(&mut self) -> Result<Option<IndxRecord>> {
        loop {
            let mut data = Vec::with_capacity(self.record_size.unwrap_or(DEFAULT_INDX_RECORD_SIZE));
            self.read_up_to(&mut data, 512)?;
            if data.is_empty() {
                return Ok(None);
            }
            let record_size = match self.record_size {
                Some(record_size) => record_size,
                // Until the first record, skip zeros a sector at a time, so the size comes from
                // a real record.
                None if data.iter().all(|&b| b == 0) => {
                    self.offset += data.len() as u64;
                    continue;
                }
                None => *self.record_size.insert(record_size_from_header(&data)),
            };
            if data.len() == 512 {
                self.read_up_to(&mut data, record_size.saturating_sub(512))?;
            }
            let offset = self.offset;
            self.offset += data.len() as u64;
            if data.iter().any(|&b| b != 0) {
                return IndxRecord::from_buffer(data, offset).map(Some);
            }
        }
    }
}

/// The record size the update sequence array of the record in `header` gives: one fixup per
/// 512-byte sector, plus the update sequence number. A size that isn't a power of two from 512
/// to 65536 bytes is damage, so [`DEFAULT_INDX_RECORD_SIZE`] is used instead.
fn record_size_from_header(header: &[u8]) -> usize {
    match (header.starts_with(b"INDX"), read_u16(header, 6)) {
        (true, Some(usa_count)) => {
            let size = usize::from(usa_count).saturating_sub(1) * 512;
            if size.is_power_of_two() && (512..=65536).contains(&size) {
                size
            } else {
                DEFAULT_INDX_RECORD_SIZE
            }
        }
        _ => DEFAULT_INDX_RECORD_SIZE,
    }
}

impl<R: Read> Iterator for IndxFile<R> {
    type Item = Result<IndxRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.done {
            match self.next_record() {
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
    pub record_lsn: u64,
    /// `false` when the record was torn by an interrupted write, so its entries may be stale.
    pub record_valid_fixup: bool,
    pub from_slack: bool,
    /// The index entry's flags, unless the entry's header was overwritten.
    pub flags: Option<IndexEntryFlags>,
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
            record_lsn: record.lsn,
            record_valid_fixup: record.valid_fixup,
            from_slack: entry.from_slack,
            flags: entry.flags,
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

    fn slack_names(record: &IndxRecord) -> Vec<(String, Option<MftReference>)> {
        record
            .slack_entries()
            .iter()
            .map(|e| (e.file_name.name.to_utf8_string(), e.mft_reference))
            .collect()
    }

    #[test]
    fn keeps_slack_names_of_compressed_files() {
        // A compressed or sparse file's allocated size is smaller than its real size.
        let mut slack = entry(0x0002_0000_0000_0041, "packed.bin", 0);
        slack[ENTRY_HEADER_SIZE + 0x28..ENTRY_HEADER_SIZE + 0x30]
            .copy_from_slice(&4096u64.to_le_bytes());
        slack[ENTRY_HEADER_SIZE + 0x30..ENTRY_HEADER_SIZE + 0x38]
            .copy_from_slice(&65536u64.to_le_bytes());
        let record = IndxRecord::from_buffer(record(&[], &slack), 0).unwrap();
        assert_eq!(
            slack_names(&record),
            [("packed.bin".to_string(), Some(MftReference::new(0x41, 2)))]
        );
    }

    #[test]
    fn caps_stale_slack_entry_lengths() {
        // The first slack entry's length runs over the second one.
        let mut slack = entry(0x0002_0000_0000_0041, "a.txt", 0);
        slack[8..10].copy_from_slice(&0x200u16.to_le_bytes());
        slack.extend(entry(0x0003_0000_0000_0042, "b.txt", 0));
        let record = IndxRecord::from_buffer(record(&[], &slack), 0).unwrap();
        assert_eq!(
            slack_names(&record),
            [
                ("a.txt".to_string(), Some(MftReference::new(0x41, 2))),
                ("b.txt".to_string(), Some(MftReference::new(0x42, 3))),
            ]
        );
    }

    #[test]
    fn scans_from_a_damaged_live_entry() {
        let mut damaged = entry(0x0001_0000_0000_0040, "a.txt", 0);
        damaged[8..10].copy_from_slice(&8u16.to_le_bytes());
        let live = [damaged, entry(0x0001_0000_0000_0041, "b.txt", 0)];
        let record = IndxRecord::from_buffer(record(&live, &[]), 0).unwrap();
        let (entries, error) = record.entries_until_error();
        assert!(entries.is_empty());
        assert!(error.is_some());
        // `a.txt` lost its header's length, but its `$FILE_NAME` and `b.txt` are still there.
        assert_eq!(
            slack_names(&record),
            [
                ("a.txt".to_string(), None),
                ("b.txt".to_string(), Some(MftReference::new(0x41, 1))),
            ]
        );
    }

    #[test]
    fn ignores_a_bogus_end_entry_length() {
        let live = [entry(0x0001_0000_0000_0040, "a.txt", 0)];
        let slack = entry(0x0002_0000_0000_0041, "deleted.txt", 0);
        let mut r = record(&live, &slack);
        let end = 0x40 + live[0].len();
        r[end + 8..end + 10].copy_from_slice(&0xFFF0u16.to_le_bytes());
        let record = IndxRecord::from_buffer(r, 0).unwrap();
        assert_eq!(record.entries().unwrap().len(), 1);
        assert_eq!(
            slack_names(&record),
            [("deleted.txt".to_string(), Some(MftReference::new(0x41, 2)))]
        );
    }

    #[test]
    fn record_size_falls_back_on_a_damaged_header() {
        let size = |usa_count: u16| {
            let mut header = b"INDX".to_vec();
            header.extend(0x28u16.to_le_bytes());
            header.extend(usa_count.to_le_bytes());
            record_size_from_header(&header)
        };
        assert_eq!(size(9), 4096);
        assert_eq!(size(3), 1024);
        assert_eq!(size(129), 65536);
        for bogus in [0, 1, 4, 257, u16::MAX] {
            assert_eq!(size(bogus), DEFAULT_INDX_RECORD_SIZE, "{bogus}");
        }
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
