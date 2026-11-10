//! The NTFS transaction log, `$LogFile`.
//!
//! `$LogFile` starts with two restart pages (`RSTR`), copies of each other that Windows writes in
//! turn. Each has a restart area: the LSN of the last checkpoint, the size of the file, how many
//! bits of an LSN are its sequence number, and the log's clients (on NTFS, only `NTFS`). The rest
//! of the file is record pages (`RCRD`), which hold the log records in a circular buffer.
//!
//! [`LogFile`] reads the restart pages and the record pages of an extracted `$LogFile`, and maps
//! an LSN to where its record is in the file ([`LogFile::lsn_offset`]).
//!
//! <https://flatcap.github.io/linux-ntfs/ntfs/files/logfile.html>,
//! <https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc#metadata_file_logfile>

use std::ops::Range;

use bitflags::bitflags;
use serde::Serialize;

use crate::MftReference;
use crate::attribute::x30::FileNameAttr;
use crate::err::{Error, Result};
use crate::impl_serialize_for_bitflags;
use crate::utf16::Utf16LeStr;
use crate::utils::{read_u16, read_u32, read_u64};

/// The size of the record page header, before the update sequence array.
const RECORD_PAGE_HEADER_SIZE: usize = 0x28;
/// Restart pages are this size unless their header says otherwise.
const DEFAULT_PAGE_SIZE: usize = 0x1000;
/// How many pages after the restart pages can hold copies of the log's tail: 2 in version 1.x
/// of the log, 32 in version 2.0.
const TAIL_COPY_PAGES: usize = 32;
/// Where a version 2.0 tail copy has the offset of the page it is a copy of.
const TAIL_COPY_FILE_OFFSET: usize = 0x3C;

bitflags! {
    /// `RESTART_AREA` flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct RestartAreaFlags: u16 {
        const RESTART_SINGLE_PAGE_IO = 0x0001;
        /// The volume was dismounted cleanly: there is nothing in the log to replay.
        const CLEAN_DISMOUNT = 0x0002;
        const _ = !0;
    }
}

impl_serialize_for_bitflags! {RestartAreaFlags}

bitflags! {
    /// Record page flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct RecordPageFlags: u32 {
        /// A log record ends in this page.
        const LOG_RECORD_END = 0x0001;
        const _ = !0;
    }
}

impl_serialize_for_bitflags! {RecordPageFlags}

/// A restart page (`RSTR`).
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct RestartPage {
    /// The page's offset in the file.
    pub offset: u64,
    /// Set by `chkdsk` when it replays the log.
    pub chkdsk_lsn: u64,
    pub system_page_size: u32,
    /// The size of each record page.
    pub log_page_size: u32,
    pub minor_version: i16,
    pub major_version: i16,
    /// Whether the update sequence values matched at the end of every sector.
    pub valid_fixup: bool,
    pub restart_area: RestartArea,
}

/// The restart area of a restart page (`LFS_RESTART_AREA`).
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct RestartArea {
    /// The LSN of the client's last restart record, the newest checkpoint.
    pub current_lsn: u64,
    pub log_clients: u16,
    pub client_free_list: u16,
    pub client_in_use_list: u16,
    pub flags: RestartAreaFlags,
    /// How many of the high bits of an LSN count how often the log has wrapped around.
    pub seq_number_bits: u32,
    pub restart_area_length: u16,
    pub client_array_offset: u16,
    /// The size of `$LogFile`.
    pub file_size: u64,
    pub last_lsn_data_length: u32,
    pub log_record_header_length: u16,
    /// Where log records start in a record page.
    pub log_page_data_offset: u16,
    pub restart_log_open_count: u32,
    pub clients: Vec<LogClient>,
}

/// A client of the log (`LFS_CLIENT_RECORD`). NTFS is the only one.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct LogClient {
    /// The oldest LSN the client still needs.
    pub oldest_lsn: u64,
    /// The LSN of the client's restart record.
    pub client_restart_lsn: u64,
    pub prev_client: u16,
    pub next_client: u16,
    pub seq_number: u16,
    pub name: String,
}

/// The header of a record page (`RCRD`).
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct RecordPage {
    /// The page's offset in the file.
    pub offset: u64,
    /// The highest LSN of a record that starts in the page, or, in the two buffer pages that
    /// hold copies of the log's tail in version 1.x of the log, the file offset the page is a
    /// copy of.
    pub last_lsn: u64,
    pub flags: RecordPageFlags,
    pub page_count: u16,
    pub page_position: u16,
    /// Where the free space in the page starts.
    pub next_record_offset: u16,
    /// The LSN of the last record that ends in the page.
    pub last_end_lsn: u64,
    pub valid_fixup: bool,
}

/// An extracted `$LogFile`, with its update sequence fixups applied.
///
/// # Example
///
/// ```no_run
/// # fn main() -> mft::err::Result<()> {
/// use mft::logfile::LogFile;
///
/// let log = LogFile::from_buffer(std::fs::read("$LogFile")?)?;
/// let restart = log.restart_page();
/// println!("checkpoint at LSN {}", restart.restart_area.current_lsn);
/// for page in log.record_pages().iter().flatten() {
///     println!("{} {}", page.offset, page.last_end_lsn);
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct LogFile {
    data: Vec<u8>,
    /// The restart pages that parse, in file order.
    restart_pages: Vec<RestartPage>,
    /// The index in `restart_pages` of the newer one.
    current: usize,
    page_size: usize,
    /// Where the first record page starts, after the restart pages.
    record_pages_start: usize,
    /// The record pages that were written, in file order.
    record_pages: Vec<Result<RecordPage>>,
    /// The tail copies that are newer than the page they are a copy of, one for each such page.
    tail_copies: Vec<TailCopy>,
    /// For each page-sized slot from `record_pages_start` on, the index of the first slot at or
    /// after it that holds no record page: one that doesn't start with `RCRD` and has no newer
    /// tail copy. One entry more than there are slots.
    next_other_page: Vec<usize>,
}

/// A page among the first after the restart pages that holds a newer copy of a page further on.
///
/// Windows doesn't write a page that isn't full yet over the last version of it: it writes it to
/// one of the pages kept for that at the start of the log, with the offset the page belongs at in
/// its header, and to its own place only later. After a crash, the newest records can be in such
/// a copy only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TailCopy {
    /// Where the copy is in the file.
    offset: usize,
    /// Where the page it is a copy of is in the file.
    home: usize,
    /// The LSN of the last record that ends in the copy.
    lsn: u64,
}

impl LogFile {
    /// Reads `data`, the whole file, and applies the fixups of each page. Fails unless at least
    /// one of the restart pages is intact.
    pub fn from_buffer(mut data: Vec<u8>) -> Result<Self> {
        let mut restart_pages = Vec::new();
        let mut first_error = None;
        // The second restart page follows the first, which is a system page long. When the first
        // page's size is damaged, the second page is looked for at each page size it could be.
        let is_restart_page = |at: usize| matches!(data.get(at..at + 4), Some(b"RSTR" | b"CHKD"));
        let second = read_u32(&data, 0x10)
            .map(|size| size as usize)
            .filter(|&size| is_valid_page_size(size))
            .or_else(|| {
                (9..=16)
                    .map(|bits| 1usize << bits)
                    .find(|&size| is_restart_page(size))
            })
            .unwrap_or(DEFAULT_PAGE_SIZE);
        // Neither restart page may reach into the record pages that follow them.
        let restart_end = (2 * second).min(data.len());
        for offset in [0, second] {
            match RestartPage::from_page(&mut data[..restart_end], offset) {
                Ok(page) => restart_pages.push(page),
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        // A page torn by an interrupted write fails its fixups: prefer one that doesn't.
        let Some(current) = restart_pages
            .iter()
            .enumerate()
            .max_by_key(|(_, page)| (page.valid_fixup, page.restart_area.current_lsn))
            .map(|(index, _)| index)
        else {
            return Err(first_error.expect("a page failed"));
        };

        let page_size = restart_pages[current].log_page_size as usize;
        // A page that is all zeros or all `0xFF` was never written. A last page that is cut short
        // is an error.
        let record_pages = data[restart_end..]
            .chunks_mut(page_size)
            .enumerate()
            .filter(|(_, page)| {
                let first = page[0];
                !((first == 0 || first == 0xFF) && page.iter().all(|&b| b == first))
            })
            .map(|(i, page)| {
                let offset = (restart_end + i * page_size) as u64;
                if page.len() < page_size {
                    return Err(Error::InvalidLogFile {
                        offset,
                        detail: "record page cut short".to_string(),
                    });
                }
                RecordPage::from_page(page, offset)
            })
            .collect();
        let mut log = LogFile {
            data,
            restart_pages,
            current,
            page_size,
            record_pages_start: restart_end,
            record_pages,
            tail_copies: Vec::new(),
            next_other_page: Vec::new(),
        };
        log.tail_copies = log.find_tail_copies();
        log.next_other_page = log.find_other_pages();
        Ok(log)
    }

    /// The newer of the restart pages that parse: the one with the higher current LSN.
    pub fn restart_page(&self) -> &RestartPage {
        &self.restart_pages[self.current]
    }

    /// The restart pages that parse, in file order.
    pub fn restart_pages(&self) -> &[RestartPage] {
        &self.restart_pages
    }

    /// The size of a record page.
    pub fn page_size(&self) -> usize {
        self.page_size
    }

    /// The file, with the fixups of its pages applied.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Where in the file the record with this LSN starts: its low bits (the ones that aren't
    /// the sequence number) count 8-byte units from the start of the file. `None` when that is
    /// past the end of the file.
    pub fn lsn_offset(&self, lsn: u64) -> Option<u64> {
        let bits = self.restart_page().restart_area.seq_number_bits;
        if !(3..64).contains(&bits) {
            return None;
        }
        let offset = (lsn << bits) >> (bits - 3);
        (offset < self.data.len() as u64).then_some(offset)
    }

    /// The tail copies that are newer than the page they are a copy of.
    ///
    /// A tail copy says where it belongs: version 2.0 of the log at `TAIL_COPY_FILE_OFFSET` of
    /// any of the first 32 record pages, version 1.x in place of the last LSN of the first two.
    /// What it says is taken only when the last record that ends in the page is at that place.
    /// It is newer when that record's LSN is higher than the LSNs in the header of the page it
    /// belongs at. When that page isn't a record page with valid fixups, the copy stands in for
    /// it whatever its age.
    fn find_tail_copies(&self) -> Vec<TailCopy> {
        let (start, page_size) = (self.record_pages_start, self.page_size);
        // The LSN of the last record that ends in a page, for pages that say so.
        let last_end = |page: &RecordPage| {
            page.flags
                .contains(RecordPageFlags::LOG_RECORD_END)
                .then_some(page.last_end_lsn)
        };
        let mut tail_copies: Vec<TailCopy> = Vec::new();
        for slot in 0..TAIL_COPY_PAGES {
            let offset = start + slot * page_size;
            let Some(page) = self.valid_record_page(offset) else {
                continue;
            };
            let Some(lsn) = last_end(page) else {
                continue;
            };
            let belongs_at = |home: u64| {
                let home = usize::try_from(home).ok()?;
                let end = home.checked_add(page_size)?;
                (home >= start
                    && home != offset
                    && (home - start).is_multiple_of(page_size)
                    && end <= self.data.len()
                    && self
                        .lsn_offset(lsn)
                        .is_some_and(|at| (home as u64..end as u64).contains(&at)))
                .then_some(home)
            };
            // Both places are tried: with pages of 8 KiB or more the update sequence array
            // covers the version 2.0 one, which is then not zero in a version 1.x copy.
            let version_2 = read_u32(&self.data, offset + TAIL_COPY_FILE_OFFSET).map(u64::from);
            let version_1 = (slot < 2).then_some(page.last_lsn);
            let Some(home) = version_2
                .and_then(belongs_at)
                .or_else(|| version_1.and_then(belongs_at))
            else {
                continue;
            };
            // A page in the middle of a long record has no record that ends in it, but still
            // the LSN of that record.
            let newer = self.valid_record_page(home).is_none_or(|home_page| {
                lsn > last_end(home_page).unwrap_or(0).max(home_page.last_lsn)
            });
            if !newer {
                continue;
            }
            let copy = TailCopy { offset, home, lsn };
            // Of two copies of one page, the newer one has all the other has.
            match tail_copies.iter_mut().find(|other| other.home == home) {
                Some(other) if other.lsn < lsn => *other = copy,
                Some(_) => {}
                None => tail_copies.push(copy),
            }
        }
        tail_copies
    }

    /// The record page at `offset`, if it is one and its fixups were valid.
    fn valid_record_page(&self, offset: usize) -> Option<&RecordPage> {
        let at = self
            .record_pages
            .binary_search_by_key(&(offset as u64), |page| match page {
                Ok(page) => page.offset,
                Err(Error::InvalidLogFile { offset, .. }) => *offset,
                // Every error of a record page is an `InvalidLogFile`.
                Err(_) => u64::MAX,
            })
            .ok()?;
        self.record_pages[at]
            .as_ref()
            .ok()
            .filter(|page| page.valid_fixup)
    }

    /// Where to read the record page that belongs at `page_start`: at its newer tail copy, if
    /// it has one, or else where it is. `None` when what is there isn't a record page.
    fn record_page_source(&self, page_start: usize) -> Option<usize> {
        let source = self
            .tail_copies
            .iter()
            .find(|copy| copy.home == page_start)
            .map_or(page_start, |copy| copy.offset);
        (self.data.get(source..source + 4) == Some(b"RCRD")).then_some(source)
    }

    /// For each page-sized slot from `record_pages_start` on, the index of the first slot at or
    /// after it that holds no record page, with one entry more than there are slots.
    fn find_other_pages(&self) -> Vec<usize> {
        let start = self.record_pages_start;
        let slots = (self.data.len() - start).div_ceil(self.page_size);
        let mut next_other_page = vec![slots; slots + 1];
        for slot in (0..slots).rev() {
            let page_start = start + slot * self.page_size;
            next_other_page[slot] = match self.record_page_source(page_start) {
                Some(_) => next_other_page[slot + 1],
                None => slot,
            };
        }
        next_other_page
    }

    /// The record pages that were written, in file order: a page that is all zeros or all
    /// `0xFF` is left out, and one without the `RCRD` signature is an error.
    pub fn record_pages(&self) -> &[Result<RecordPage>] {
        &self.record_pages
    }
}

/// Whether `size` can be a `$LogFile` page size: a power of two from 512 bytes to 64 KiB.
fn is_valid_page_size(size: usize) -> bool {
    (512..=0x10000).contains(&size) && size.is_power_of_two()
}

/// Whether an update sequence array of `usa_count` entries has a value for every 512-byte sector
/// of `page`, so that none is left without its fixup.
fn covers_every_sector(page: &[u8], usa_count: u16) -> bool {
    usize::from(usa_count) == page.len() / 512 + 1
}

impl RestartPage {
    /// Parses the restart page at `offset` of `data`, applying its fixups in place.
    fn from_page(data: &mut [u8], offset: usize) -> Result<Self> {
        let invalid = |detail: String| Error::InvalidLogFile {
            offset: offset as u64,
            detail,
        };
        let header = data
            .get(offset..offset + 0x30)
            .ok_or_else(|| invalid("restart page cut short".to_string()))?;
        // `chkdsk` marks the restart pages it has worked on `CHKD`.
        if &header[..4] != b"RSTR" && &header[..4] != b"CHKD" {
            return Err(invalid(format!(
                "signature {:02x?} isn't RSTR or CHKD",
                &header[..4]
            )));
        }
        let field16 = |at| read_u16(header, at).unwrap_or_default();
        let (usa_offset, usa_count) = (field16(4), field16(6));
        let chkdsk_lsn = read_u64(header, 8).unwrap_or_default();
        let system_page_size = read_u32(header, 0x10).unwrap_or_default();
        let log_page_size = read_u32(header, 0x14).unwrap_or_default();
        let restart_offset = usize::from(field16(0x18));
        let minor_version = field16(0x1A) as i16;
        let major_version = field16(0x1C) as i16;

        let page_size = system_page_size as usize;
        if !is_valid_page_size(page_size) {
            return Err(invalid(format!("system page size {page_size}")));
        }
        if !is_valid_page_size(log_page_size as usize) {
            return Err(invalid(format!("log page size {log_page_size}")));
        }
        let page = data
            .get_mut(offset..offset + page_size)
            .ok_or_else(|| invalid("restart page cut short".to_string()))?;
        let valid_fixup = crate::ntfs::apply_update_sequence_array_fixups_in_place_with(
            page,
            usa_offset,
            usa_count,
            |_| {},
        )
        .map_err(|e| invalid(format!("update sequence array: {e}")))?
            && covers_every_sector(page, usa_count);

        let restart_area = RestartArea::from_slice(page, restart_offset)
            .ok_or_else(|| invalid(format!("restart area at {restart_offset} cut short")))?;
        Ok(RestartPage {
            offset: offset as u64,
            chkdsk_lsn,
            system_page_size,
            log_page_size,
            minor_version,
            major_version,
            valid_fixup,
            restart_area,
        })
    }
}

impl RestartArea {
    /// Parses the restart area at `offset` of a restart page.
    fn from_slice(page: &[u8], offset: usize) -> Option<Self> {
        let area = page.get(offset..offset + 0x30)?;
        let log_clients = read_u16(area, 8)?;
        let client_array_offset = read_u16(area, 0x16)?;
        let clients_start = offset + usize::from(client_array_offset);
        // Each client record is 0xA0 bytes. Clients that don't fit in the page are left out.
        let clients = (0..usize::from(log_clients))
            .map_while(|i| LogClient::from_slice(page.get(clients_start + i * 0xA0..)?))
            .collect();
        Some(RestartArea {
            current_lsn: read_u64(area, 0)?,
            log_clients,
            client_free_list: read_u16(area, 0x0A)?,
            client_in_use_list: read_u16(area, 0x0C)?,
            flags: RestartAreaFlags::from_bits_retain(read_u16(area, 0x0E)?),
            seq_number_bits: read_u32(area, 0x10)?,
            restart_area_length: read_u16(area, 0x14)?,
            client_array_offset,
            file_size: read_u64(area, 0x18)?,
            last_lsn_data_length: read_u32(area, 0x20)?,
            log_record_header_length: read_u16(area, 0x24)?,
            log_page_data_offset: read_u16(area, 0x26)?,
            restart_log_open_count: read_u32(area, 0x28)?,
            clients,
        })
    }
}

impl LogClient {
    fn from_slice(client: &[u8]) -> Option<Self> {
        let client = client.get(..0xA0)?;
        // The name is at most 64 UTF-16 code units.
        let name_length = (read_u32(client, 0x1C)? as usize).min(128) & !1;
        let name =
            Utf16LeStr::from_utf16le_bytes(&client[0x20..0x20 + name_length]).to_utf8_string();
        Some(LogClient {
            oldest_lsn: read_u64(client, 0)?,
            client_restart_lsn: read_u64(client, 8)?,
            prev_client: read_u16(client, 0x10)?,
            next_client: read_u16(client, 0x12)?,
            seq_number: read_u16(client, 0x14)?,
            name,
        })
    }
}

impl RecordPage {
    /// Parses a record page, `page` being exactly a page long, applying its fixups in place.
    fn from_page(page: &mut [u8], offset: u64) -> Result<Self> {
        let invalid = |detail: String| Error::InvalidLogFile { offset, detail };
        if page.len() < RECORD_PAGE_HEADER_SIZE {
            return Err(invalid("record page cut short".to_string()));
        }
        if &page[..4] != b"RCRD" {
            return Err(invalid(format!("signature {:02x?} isn't RCRD", &page[..4])));
        }
        let field16 = |page: &[u8], at| read_u16(page, at).unwrap_or_default();
        let (usa_offset, usa_count) = (field16(page, 4), field16(page, 6));
        // The header is in the first sector, before any bytes the fixups replace.
        let valid_fixup = crate::ntfs::apply_update_sequence_array_fixups_in_place_with(
            page,
            usa_offset,
            usa_count,
            |_| {},
        )
        .map_err(|e| invalid(format!("update sequence array: {e}")))?
            && covers_every_sector(page, usa_count);
        Ok(RecordPage {
            offset,
            last_lsn: read_u64(page, 8).unwrap_or_default(),
            flags: RecordPageFlags::from_bits_retain(read_u32(page, 0x10).unwrap_or_default()),
            page_count: field16(page, 0x14),
            page_position: field16(page, 0x16),
            next_record_offset: field16(page, 0x18),
            last_end_lsn: read_u64(page, 0x20).unwrap_or_default(),
            valid_fixup,
        })
    }
}

/// What of a log record's header says whether a record is there.
struct RecordHeader {
    lsn: u64,
    record_type: u32,
    client_data_length: u32,
}

/// The size of a log record's header (`LFS_RECORD_HEADER`), before its client data.
pub const LOG_RECORD_HEADER_SIZE: usize = 0x30;
/// The size of the NTFS client data header (`NTFS_LOG_RECORD_HEADER`), before its LCNs.
const NTFS_RECORD_HEADER_SIZE: usize = 0x20;

bitflags! {
    /// Log record flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct LogRecordFlags: u16 {
        /// The record continues in the next page.
        const MULTI_PAGE = 0x0001;
        const _ = !0;
    }
}

impl_serialize_for_bitflags! {LogRecordFlags}

/// One log record.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct LogRecord {
    /// Where the record starts in the file.
    pub offset: u64,
    pub lsn: u64,
    /// The client's previous record in the same transaction.
    pub client_previous_lsn: u64,
    /// The next record to undo, when the transaction is rolled back.
    pub client_undo_next_lsn: u64,
    pub client_data_length: u32,
    pub client_seq_number: u16,
    pub client_index: u16,
    /// 1 for a client record, 2 for a client restart record (a checkpoint).
    pub record_type: u32,
    pub transaction_id: u32,
    pub flags: LogRecordFlags,
    /// What NTFS logged, for a client record.
    pub ntfs: Option<NtfsLogRecord>,
}

/// The NTFS part of a client record (`NTFS_LOG_RECORD_HEADER`): how to redo the change, how to
/// undo it, and where it applies.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct NtfsLogRecord {
    pub redo_operation: u16,
    /// The name of the redo operation (for example `InitializeFileRecordSegment`).
    pub redo_operation_name: Option<&'static str>,
    pub undo_operation: u16,
    pub undo_operation_name: Option<&'static str>,
    /// The attribute the change applies to, as an index in the open attribute table.
    pub target_attribute: u16,
    /// The offset of the change in the target record (an MFT record or index buffer).
    pub record_offset: u16,
    /// The offset of the changed attribute in its MFT record, or of the changed entry in its
    /// index.
    pub attribute_offset: u16,
    /// Which 512-byte block of the target cluster the record starts at.
    pub cluster_block_offset: u16,
    pub target_vcn: u64,
    /// The clusters the change applies to.
    pub lcns: Vec<u64>,
    #[serde(serialize_with = "crate::attribute::raw::data_as_hex")]
    pub redo_data: Vec<u8>,
    #[serde(serialize_with = "crate::attribute::raw::data_as_hex")]
    pub undo_data: Vec<u8>,
    /// For an operation on an index entry (adding one to a directory, or removing one), the
    /// file the entry names.
    pub index_entry: Option<LoggedIndexEntry>,
}

/// The `$FILE_NAME` index entry that an index operation adds or removes.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct LoggedIndexEntry {
    pub file_reference: MftReference,
    pub parent: MftReference,
    pub name: String,
}

/// The names of the NTFS log operations.
/// <https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc#log-operation-types>
pub fn operation_name(operation: u16) -> Option<&'static str> {
    Some(match operation {
        0x00 => "Noop",
        0x01 => "CompensationLogRecord",
        0x02 => "InitializeFileRecordSegment",
        0x03 => "DeallocateFileRecordSegment",
        0x04 => "WriteEndOfFileRecordSegment",
        0x05 => "CreateAttribute",
        0x06 => "DeleteAttribute",
        0x07 => "UpdateResidentValue",
        0x08 => "UpdateNonresidentValue",
        0x09 => "UpdateMappingPairs",
        0x0A => "DeleteDirtyClusters",
        0x0B => "SetNewAttributeSizes",
        0x0C => "AddIndexEntryRoot",
        0x0D => "DeleteIndexEntryRoot",
        0x0E => "AddIndexEntryAllocation",
        0x0F => "DeleteIndexEntryAllocation",
        0x10 => "WriteEndOfIndexBuffer",
        0x11 => "SetIndexEntryVcnRoot",
        0x12 => "SetIndexEntryVcnAllocation",
        0x13 => "UpdateFileNameRoot",
        0x14 => "UpdateFileNameAllocation",
        0x15 => "SetBitsInNonresidentBitMap",
        0x16 => "ClearBitsInNonresidentBitMap",
        0x17 => "HotFix",
        0x18 => "EndTopLevelAction",
        0x19 => "PrepareTransaction",
        0x1A => "CommitTransaction",
        0x1B => "ForgetTransaction",
        0x1C => "OpenNonresidentAttribute",
        0x1D => "OpenAttributeTableDump",
        0x1E => "AttributeNamesDump",
        0x1F => "DirtyPageTableDump",
        0x20 => "TransactionTableDump",
        0x21 => "UpdateRecordDataRoot",
        0x22 => "UpdateRecordDataAllocation",
        0x23 => "UpdateRelativeDataInIndex",
        0x24 => "UpdateRelativeDataInIndex2",
        0x25 => "ZeroEndOfFileRecord",
        _ => return None,
    })
}

impl NtfsLogRecord {
    /// Parses the client data of an NTFS client record.
    pub fn from_slice(data: &[u8]) -> Option<Self> {
        Self::parse(data.len(), |range| Some(data[range].to_vec()))
    }

    /// Parses client data of `length` bytes, of which `read` gives the bytes of a range. It is
    /// asked only for ranges inside the data: the header, the LCNs, and the redo and undo data,
    /// so that a record with much more data than it uses costs no more than one with little.
    fn parse(length: usize, read: impl Fn(Range<usize>) -> Option<Vec<u8>>) -> Option<Self> {
        if length < NTFS_RECORD_HEADER_SIZE {
            return None;
        }
        let header = read(0..NTFS_RECORD_HEADER_SIZE)?;
        let data = header.as_slice();
        let field = |at| read_u16(data, at);
        let (redo_operation, undo_operation) = (field(0)?, field(2)?);
        // A part that isn't all inside the client data is left empty.
        let part = |offset: u16, part_length: u16| {
            let start = usize::from(offset);
            let range = start..start + usize::from(part_length);
            if range.is_empty() || range.end > length {
                return Some(Vec::new());
            }
            read(range)
        };
        let redo_data = part(field(4)?, field(6)?)?;
        let undo_data = part(field(8)?, field(0x0A)?)?;
        // As many of the LCNs as are whole inside the client data.
        let lcns_to_follow = usize::from(field(0x0E)?);
        let lcns_fit = (length - NTFS_RECORD_HEADER_SIZE) / 8;
        let lcns_end = NTFS_RECORD_HEADER_SIZE + 8 * lcns_to_follow.min(lcns_fit);
        let lcns = read(NTFS_RECORD_HEADER_SIZE..lcns_end)?
            .as_chunks::<8>()
            .0
            .iter()
            .map(|lcn| u64::from_le_bytes(*lcn))
            .collect();

        // Adding an entry logs it to redo, removing one logs it to undo.
        let index_entry = match (redo_operation, undo_operation) {
            (0x0C | 0x0E, _) => LoggedIndexEntry::from_slice(&redo_data),
            (_, 0x0C | 0x0E) => LoggedIndexEntry::from_slice(&undo_data),
            _ => None,
        };

        Some(NtfsLogRecord {
            redo_operation,
            redo_operation_name: operation_name(redo_operation),
            undo_operation,
            undo_operation_name: operation_name(undo_operation),
            target_attribute: field(0x0C)?,
            record_offset: field(0x10)?,
            attribute_offset: field(0x12)?,
            cluster_block_offset: field(0x14)?,
            target_vcn: read_u64(data, 0x18)?,
            lcns,
            redo_data,
            undo_data,
            index_entry,
        })
    }
}

impl LoggedIndexEntry {
    /// Parses a `$FILE_NAME` index entry: the file reference, the entry's and the key's
    /// lengths, flags, then the key.
    fn from_slice(entry: &[u8]) -> Option<Self> {
        let file_reference = MftReference::from(read_u64(entry, 0)?);
        let key_length = usize::from(read_u16(entry, 0x0A)?);
        let key = entry.get(0x10..0x10 + key_length)?;
        let file_name = FileNameAttr::from_slice(key).ok()?;
        Some(LoggedIndexEntry {
            file_reference,
            parent: file_name.parent,
            name: file_name.name.to_utf8_string(),
        })
    }
}

impl LogFile {
    /// The log records in the record pages, in file order. That is LSN order from the oldest
    /// page to the newest one, then the older records that the newest pages haven't written
    /// over yet.
    ///
    /// Each page is scanned on every 8-byte boundary for a record header whose LSN gives its own
    /// offset ([`LogFile::lsn_offset`]), so a record is found even when the records before it
    /// are damaged, and the copies of the log's tail in the buffer pages (whose LSNs give the
    /// offset of the original) aren't found twice. A record that continues past the end of the
    /// file is left out.
    ///
    /// A tail copy that is newer than the page it is a copy of, as after a crash, is read as that
    /// page: the records in it that the page doesn't have are given too, with the `offset` they
    /// have in the copy (so [`LogFile::lsn_offset`] of their LSN is another offset), and a record
    /// that continues into the page continues in the copy.
    pub fn records(&self) -> impl Iterator<Item = LogRecord> + '_ {
        let page_size = self.page_size;
        let data_offset = usize::from(self.restart_page().restart_area.log_page_data_offset)
            .clamp(RECORD_PAGE_HEADER_SIZE, page_size);
        self.record_pages
            .iter()
            .flatten()
            .flat_map(move |page| {
                let start = page.offset as usize;
                // Whether the page is a newer tail copy is the same for all that is in it.
                let copy = self.tail_copies.iter().find(|copy| copy.offset == start);
                // LSNs count 8-byte units, so a record starts on an 8-byte boundary.
                ((start + data_offset).next_multiple_of(8)
                    ..start + page_size - LOG_RECORD_HEADER_SIZE + 1)
                    .step_by(8)
                    .map(move |offset| (offset, copy))
            })
            .filter_map(move |(offset, copy)| {
                self.record_at(offset, offset, data_offset).or_else(|| {
                    // A record the copy has and the page it belongs at doesn't.
                    let home = copy?.home + (offset - copy?.offset);
                    let lsn = self.record_header_at(offset, home, data_offset)?.lsn;
                    let at_home = self.record_header_at(home, home, data_offset);
                    if at_home.is_some_and(|at_home| at_home.lsn == lsn) {
                        return None;
                    }
                    self.record_at(offset, home, data_offset)
                })
            })
    }

    /// The fields of the record header at `offset` that say whether a record is there, if one
    /// is: one whose LSN gives `home`, where the header belongs (another offset than `offset`
    /// for a record in a tail copy), and whose client data is all in record pages.
    fn record_header_at(
        &self,
        offset: usize,
        home: usize,
        data_offset: usize,
    ) -> Option<RecordHeader> {
        let header = self.data.get(offset..offset + LOG_RECORD_HEADER_SIZE)?;
        let lsn = read_u64(header, 0)?;
        let record_type = read_u32(header, 0x20)?;
        let client_data_length = read_u32(header, 0x18)?;
        let data_start = home + LOG_RECORD_HEADER_SIZE;
        (lsn != 0
            && self.lsn_offset(lsn) == Some(home as u64)
            && (1..=2).contains(&record_type)
            && client_data_length as usize <= self.data.len() - data_start
            && self.client_data_fits(data_start, client_data_length as usize, data_offset))
        .then_some(RecordHeader {
            lsn,
            record_type,
            client_data_length,
        })
    }

    /// The record whose header starts at `offset` and belongs at `home`, if there is one.
    fn record_at(&self, offset: usize, home: usize, data_offset: usize) -> Option<LogRecord> {
        let RecordHeader {
            lsn,
            record_type,
            client_data_length,
        } = self.record_header_at(offset, home, data_offset)?;
        let header = self.data.get(offset..offset + LOG_RECORD_HEADER_SIZE)?;
        let data_start = home + LOG_RECORD_HEADER_SIZE;
        // The data in the header's page is read where the header is.
        let source = offset + LOG_RECORD_HEADER_SIZE;
        // Only an NTFS client record's data is parsed, and only the parts its header points at
        // are copied: copying all of it for every record takes quadratic time on a log whose
        // every record claims the rest of the file.
        let ntfs = if record_type == 1 {
            NtfsLogRecord::parse(client_data_length as usize, |range| {
                self.client_data(source, data_start, range, data_offset)
            })
        } else {
            None
        };
        Some(LogRecord {
            offset: offset as u64,
            lsn,
            client_previous_lsn: read_u64(header, 8)?,
            client_undo_next_lsn: read_u64(header, 0x10)?,
            client_data_length,
            client_seq_number: read_u16(header, 0x1C)?,
            client_index: read_u16(header, 0x1E)?,
            record_type,
            transaction_id: read_u32(header, 0x24)?,
            flags: LogRecordFlags::from_bits_retain(read_u16(header, 0x28)?),
            ntfs,
        })
    }

    /// Whether `length` bytes of client data from `offset` on are all in the file, in record
    /// pages: whether [`Self::client_data`] gives them. Takes the same time whatever the length.
    fn client_data_fits(&self, offset: usize, length: usize, data_offset: usize) -> bool {
        if length == 0 {
            return true;
        }
        let slot = (offset - self.record_pages_start) / self.page_size;
        let page_start = self.record_pages_start + slot * self.page_size;
        // A record whose header ends a page starts its data in the next one.
        if offset == page_start && self.next_other_page[slot] == slot {
            return false;
        }
        let offset = offset.max(page_start + data_offset);
        let in_first_page = (page_start + self.page_size - offset).min(length);
        if offset + in_first_page > self.data.len() {
            return false;
        }
        let left = length - in_first_page;
        if left == 0 {
            return true;
        }
        let in_each_page = self.page_size - data_offset;
        if in_each_page == 0 {
            return false;
        }
        // Every page the data continues into must be a record page, and the last one must hold
        // what is left for it.
        let more_pages = left.div_ceil(in_each_page);
        let last_slot = slot + more_pages;
        let in_last_page = left - (more_pages - 1) * in_each_page;
        let last_page_start = self.record_pages_start + last_slot * self.page_size;
        self.next_other_page[slot + 1] > last_slot
            && last_page_start + data_offset + in_last_page <= self.data.len()
    }

    /// The bytes `range` of the client data that belongs at `offset` on, which continues past
    /// the end of a page at the data of the next one. `source` is where the data is when it
    /// starts inside a page: `offset`, or the same place in the page's tail copy. Each page the
    /// data continues into is read at its newer tail copy, if it has one.
    fn client_data(
        &self,
        mut source: usize,
        mut offset: usize,
        range: Range<usize>,
        data_offset: usize,
    ) -> Option<Vec<u8>> {
        let mut client_data = Vec::with_capacity(range.len());
        // How much of the client data is before `offset`.
        let mut passed = 0;
        while passed < range.end {
            // A record whose header ends a page continues after the next page's header.
            // Record pages follow the restart pages, which needn't be a record page long.
            let page_start = offset - (offset - self.record_pages_start) % self.page_size;
            // A page the record continues into must be a record page: a page that was never
            // written, or that holds something else, isn't the rest of this record.
            if offset == page_start {
                source = self.record_page_source(page_start)?;
            }
            let skipped = (page_start + data_offset).saturating_sub(offset);
            offset += skipped;
            source += skipped;
            let page_end = page_start + self.page_size;
            let n = (page_end - offset).min(range.end - passed);
            let before = range.start.saturating_sub(passed).min(n);
            client_data.extend_from_slice(self.data.get(source + before..source + n)?);
            passed += n;
            offset = page_end;
        }
        #[cfg(test)]
        tests::BYTES_COPIED.with(|copied| copied.set(copied.get() + client_data.len()));
        Some(client_data)
    }
}

/// A [`LogRecord`] flattened to one CSV row.
#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct FlatLogRecord {
    pub offset: u64,
    pub lsn: u64,
    pub previous_lsn: u64,
    pub undo_next_lsn: u64,
    pub transaction_id: u32,
    pub record_type: u32,
    pub redo_operation: Option<String>,
    pub undo_operation: Option<String>,
    pub target_attribute: Option<u16>,
    pub target_vcn: Option<u64>,
    pub cluster_block_offset: Option<u16>,
    pub record_offset: Option<u16>,
    pub attribute_offset: Option<u16>,
    /// `|`-separated.
    pub lcns: Option<String>,
    pub redo_length: Option<usize>,
    pub undo_length: Option<usize>,
    pub file_reference: Option<u64>,
    pub file_sequence: Option<u16>,
    pub parent_reference: Option<u64>,
    pub parent_sequence: Option<u16>,
    pub file_name: Option<String>,
}

impl FlatLogRecord {
    pub fn from_record(record: &LogRecord) -> Self {
        let ntfs = record.ntfs.as_ref();
        let name = |operation: u16, name: Option<&str>| match name {
            Some(name) => name.to_string(),
            None => format!("0x{operation:02x}"),
        };
        let entry = ntfs.and_then(|ntfs| ntfs.index_entry.as_ref());
        FlatLogRecord {
            offset: record.offset,
            lsn: record.lsn,
            previous_lsn: record.client_previous_lsn,
            undo_next_lsn: record.client_undo_next_lsn,
            transaction_id: record.transaction_id,
            record_type: record.record_type,
            redo_operation: ntfs.map(|n| name(n.redo_operation, n.redo_operation_name)),
            undo_operation: ntfs.map(|n| name(n.undo_operation, n.undo_operation_name)),
            target_attribute: ntfs.map(|n| n.target_attribute),
            target_vcn: ntfs.map(|n| n.target_vcn),
            cluster_block_offset: ntfs.map(|n| n.cluster_block_offset),
            record_offset: ntfs.map(|n| n.record_offset),
            attribute_offset: ntfs.map(|n| n.attribute_offset),
            lcns: ntfs.map(|n| {
                n.lcns
                    .iter()
                    .map(u64::to_string)
                    .collect::<Vec<_>>()
                    .join("|")
            }),
            redo_length: ntfs.map(|n| n.redo_data.len()),
            undo_length: ntfs.map(|n| n.undo_data.len()),
            file_reference: entry.map(|e| e.file_reference.entry),
            file_sequence: entry.map(|e| e.file_reference.sequence),
            parent_reference: entry.map(|e| e.parent.entry),
            parent_sequence: entry.map(|e| e.parent.sequence),
            file_name: entry.map(|e| e.name.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    thread_local! {
        /// How many bytes of client data `LogFile::client_data` has copied on this thread.
        pub(super) static BYTES_COPIED: Cell<usize> = const { Cell::new(0) };
    }

    /// A restart page of `size` bytes with an `NTFS` client and the given current LSN.
    fn restart_page(size: usize, current_lsn: u64) -> Vec<u8> {
        let mut page = vec![0u8; size];
        page[..4].copy_from_slice(b"RSTR");
        page[4..6].copy_from_slice(&0x1Eu16.to_le_bytes());
        let usa_count = (size / 512 + 1) as u16;
        page[6..8].copy_from_slice(&usa_count.to_le_bytes());
        page[0x10..0x14].copy_from_slice(&(size as u32).to_le_bytes());
        page[0x14..0x18].copy_from_slice(&0x1000u32.to_le_bytes());
        page[0x18..0x1A].copy_from_slice(&0x30u16.to_le_bytes());
        page[0x1A..0x1C].copy_from_slice(&1u16.to_le_bytes());
        page[0x1C..0x1E].copy_from_slice(&1u16.to_le_bytes());
        // The update sequence value is 1, and the sectors' last bytes are already 1.
        page[0x1E..0x20].copy_from_slice(&1u16.to_le_bytes());
        for sector in 0..size / 512 {
            page[sector * 512 + 510..sector * 512 + 512].copy_from_slice(&1u16.to_le_bytes());
        }
        let area = &mut page[0x30..];
        area[..8].copy_from_slice(&current_lsn.to_le_bytes());
        area[8..10].copy_from_slice(&1u16.to_le_bytes());
        area[0x0E..0x10].copy_from_slice(&2u16.to_le_bytes());
        area[0x10..0x14].copy_from_slice(&44u32.to_le_bytes());
        area[0x16..0x18].copy_from_slice(&0x40u16.to_le_bytes());
        area[0x26..0x28].copy_from_slice(&0x40u16.to_le_bytes());
        let client = &mut area[0x40..];
        client[0x1C..0x20].copy_from_slice(&8u32.to_le_bytes());
        for (i, unit) in "NTFS".encode_utf16().enumerate() {
            client[0x20 + 2 * i..0x22 + 2 * i].copy_from_slice(&unit.to_le_bytes());
        }
        page
    }

    #[test]
    fn the_newer_restart_page_is_current() {
        let mut data = restart_page(0x1000, 10);
        data.extend(restart_page(0x1000, 20));
        data.resize(0x4000, 0);
        let log = LogFile::from_buffer(data).unwrap();
        assert_eq!(log.restart_pages().len(), 2);
        assert_eq!(log.restart_page().offset, 0x1000);
        let area = &log.restart_page().restart_area;
        assert_eq!(area.current_lsn, 20);
        assert_eq!(area.flags, RestartAreaFlags::CLEAN_DISMOUNT);
        assert_eq!(area.clients[0].name, "NTFS");
        assert!(log.restart_page().valid_fixup);
    }

    #[test]
    fn one_damaged_restart_page_is_enough() {
        let mut data = vec![0u8; 0x1000];
        data.extend(restart_page(0x1000, 20));
        data.resize(0x4000, 0);
        assert_eq!(
            LogFile::from_buffer(data).unwrap().restart_page().offset,
            0x1000
        );
        assert!(LogFile::from_buffer(vec![0u8; 0x4000]).is_err());
    }

    #[test]
    fn the_second_restart_page_is_found_past_a_damaged_first_one() {
        let mut data = vec![0u8; 0x2000];
        data.extend(restart_page(0x2000, 20));
        data.resize(0x8000, 0);
        assert_eq!(
            LogFile::from_buffer(data).unwrap().restart_page().offset,
            0x2000
        );
    }

    #[test]
    fn a_torn_restart_page_is_not_current() {
        let mut data = restart_page(0x1000, 10);
        let mut torn = restart_page(0x1000, 20);
        torn[0x3FE] = 7;
        data.extend(torn);
        data.resize(0x4000, 0);
        let log = LogFile::from_buffer(data).unwrap();
        assert_eq!(log.restart_pages().len(), 2);
        assert_eq!(log.restart_page().restart_area.current_lsn, 10);
    }

    /// Makes `page` (4 KiB) a record page: the signature and the update sequence array, with the
    /// last two bytes of each sector moved into it.
    fn seal_record_page(page: &mut [u8]) {
        page[..4].copy_from_slice(b"RCRD");
        page[4..6].copy_from_slice(&0x28u16.to_le_bytes());
        page[6..8].copy_from_slice(&9u16.to_le_bytes());
        page[0x28..0x2A].copy_from_slice(&1u16.to_le_bytes());
        for sector in 0..8 {
            let end = (sector + 1) * 512;
            page.copy_within(end - 2..end, 0x2A + 2 * sector);
            page[end - 2..end].copy_from_slice(&1u16.to_le_bytes());
        }
    }

    /// Writes a client record header at `offset` whose LSN gives that offset.
    fn put_record_header(data: &mut [u8], offset: usize, client_data_length: u32) {
        put_record_header_for(data, offset, offset, client_data_length);
    }

    /// Writes a client record header at `offset` whose LSN gives the offset `home`.
    fn put_record_header_for(data: &mut [u8], offset: usize, home: usize, client_data_length: u32) {
        let header = &mut data[offset..offset + LOG_RECORD_HEADER_SIZE];
        header[..8].copy_from_slice(&(home as u64 / 8).to_le_bytes());
        header[0x18..0x1C].copy_from_slice(&client_data_length.to_le_bytes());
        header[0x20..0x24].copy_from_slice(&1u32.to_le_bytes());
    }

    /// A log of `size` bytes: two restart pages, then record pages with nothing in them.
    fn empty_log(size: usize) -> Vec<u8> {
        let mut data = restart_page(0x1000, 0);
        data.extend(restart_page(0x1000, 0));
        data.resize(size, 0);
        data
    }

    #[test]
    fn records_that_each_claim_the_rest_of_the_file_take_linear_time() {
        // A record header every 0x30 bytes of every page, each with as much client data as is
        // left of the file. Copying each record's data made this take a minute for 8 MiB.
        let size = 8 << 20;
        let mut data = empty_log(size);
        for page_start in (0x2000..size).step_by(0x1000) {
            for offset in (page_start + 0x40..=page_start + 0x1000 - 0x30).step_by(0x30) {
                let rest = (size - offset - LOG_RECORD_HEADER_SIZE) as u32;
                put_record_header(&mut data, offset, rest);
            }
            seal_record_page(&mut data[page_start..page_start + 0x1000]);
        }
        let log = LogFile::from_buffer(data).unwrap();
        BYTES_COPIED.set(0);
        let records: Vec<_> = log.records().collect();
        // The page headers on the way leave room for the claimed data only from the last page.
        assert_eq!(records.len(), 84);
        assert!(records.iter().all(|r| r.offset >= size as u64 - 0x1000));
        // No more is copied than the NTFS header of each of them.
        assert!(BYTES_COPIED.get() <= 84 * NTFS_RECORD_HEADER_SIZE);
    }

    #[test]
    fn only_the_data_a_record_gives_is_copied() {
        // A record header every 0x30 bytes again, each with 128 KiB of client data. The client
        // data of a record starts at the header after it, whose LSN and previous LSN are made
        // to read as an NTFS header with 0xFFFF bytes of redo and of undo data at 0xFFFF.
        let size = 1 << 20;
        let mut data = empty_log(size);
        for page_start in (0x2000..size).step_by(0x1000) {
            for offset in (page_start + 0x40..=page_start + 0x1000 - 0x30).step_by(0x30) {
                put_record_header(&mut data, offset, 0x20000);
                // The high half of the LSN is its sequence number, which can be anything.
                data[offset + 4..offset + 12].fill(0xFF);
            }
            seal_record_page(&mut data[page_start..page_start + 0x1000]);
        }
        let log = LogFile::from_buffer(data).unwrap();
        BYTES_COPIED.set(0);
        let records: Vec<_> = log.records().collect();
        let returned: usize = records
            .iter()
            .filter_map(|r| r.ntfs.as_ref())
            .map(|n| NTFS_RECORD_HEADER_SIZE + n.redo_data.len() + n.undo_data.len())
            .sum();
        assert!(records.len() > 10_000);
        assert!(returned > records.len() * 0x1FFFE);
        // Each byte is copied once, into the record that gives it.
        assert_eq!(BYTES_COPIED.get(), returned);
    }

    /// Whether client data fits is worked out, not read: both must agree.
    fn assert_fits_agrees_with_reading(
        log: &LogFile,
        offset: usize,
        lengths: impl Iterator<Item = usize>,
    ) {
        for length in lengths {
            assert_eq!(
                log.client_data_fits(offset, length, 0x40),
                log.client_data(offset, offset, 0..length, 0x40).is_some(),
                "{length:#x} bytes at {offset:#x}"
            );
        }
    }

    #[test]
    fn long_records_parse_as_before() {
        // A record with a redo part four pages on, in a log whose page 6 was never written.
        let size = 0xA000;
        let mut data = empty_log(size);
        let record = 0x2040;
        let in_each_page = 0x1000 - 0x40;
        let redo_offset = 0x28 + 3 * in_each_page as u16;
        let client = record + LOG_RECORD_HEADER_SIZE;
        data[client..client + 2].copy_from_slice(&2u16.to_le_bytes());
        data[client + 4..client + 6].copy_from_slice(&redo_offset.to_le_bytes());
        data[client + 6..client + 8].copy_from_slice(&8u16.to_le_bytes());
        // The first page holds 0x30 bytes less than the others, for the record's header.
        let redo = 0x5040 + 0x30 + 0x28;
        data[redo..redo + 8].copy_from_slice(b"redodata");
        for page_start in (0x2000..size).step_by(0x1000) {
            if page_start != 0x8000 {
                seal_record_page(&mut data[page_start..page_start + 0x1000]);
            }
        }

        let with_length = |length: u32| {
            let mut data = data.clone();
            // Sealing moved the last two bytes of the sector, not the header.
            put_record_header(&mut data, record, length);
            LogFile::from_buffer(data).unwrap()
        };
        let whole = u32::from(redo_offset) + 8;
        let log = with_length(whole);
        let records: Vec<_> = log.records().collect();
        assert_eq!(records.len(), 1);
        let ntfs = records[0].ntfs.as_ref().unwrap();
        assert_eq!(
            ntfs.redo_operation_name,
            Some("InitializeFileRecordSegment")
        );
        assert_eq!(ntfs.redo_data, b"redodata");

        // Whether a record's data fits is worked out, not walked: both must agree, up to and
        // past the page that was never written and the end of the file.
        let log = with_length(0);
        let lengths = (0..0x8000).step_by(8).chain([1, 0xFBF, 0xFC1, 0x10_0000]);
        for offset in [client, 0x3000, 0x3F00, 0x7000, 0x7FF8, 0x9000, 0x9FF8] {
            assert_fits_agrees_with_reading(&log, offset, lengths.clone());
        }
    }

    /// A log with a record in page 0x23000 and, in the page before it, one whose last 16 bytes
    /// of data continue into it. Page 0x7000 holds a later version of page 0x23000, with a
    /// second record, as a version 2.0 tail copy. Returns the log before its pages are sealed.
    fn log_with_a_tail_copy() -> Vec<u8> {
        let mut data = empty_log(0x30000);
        let (copy, home) = (0x7000, 0x23000);
        // The record before the page: 0x20 bytes of NTFS header, then 16 bytes of redo data.
        let spanning = home - 0x50;
        put_record_header(&mut data, spanning, 0x30);
        let client = spanning + LOG_RECORD_HEADER_SIZE;
        data[client + 4..client + 6].copy_from_slice(&0x20u16.to_le_bytes());
        data[client + 6..client + 8].copy_from_slice(&0x10u16.to_le_bytes());
        data[home - 0x1000 + 0x10] = 1;

        for (page, records) in [(home, 1), (copy, 2)] {
            data[page + 0x40..page + 0x50].copy_from_slice(b"the redo data...");
            let mut last_lsn = 0u64;
            for record in 0..records {
                let offset = home + 0x50 + record * 0x30;
                last_lsn = offset as u64 / 8;
                put_record_header_for(&mut data, page + offset - home, offset, 0);
            }
            data[page + 0x10] = 1;
            data[page + 0x20..page + 0x28].copy_from_slice(&last_lsn.to_le_bytes());
        }
        data[copy + 0x3C..copy + 0x40].copy_from_slice(&(home as u32).to_le_bytes());
        data
    }

    fn sealed(mut data: Vec<u8>) -> LogFile {
        for page_start in (0x2000..data.len()).step_by(0x1000) {
            let page = &data[page_start..page_start + 0x1000];
            if page.iter().any(|&b| b != 0) && page.iter().any(|&b| b != 0xFF) {
                seal_record_page(&mut data[page_start..page_start + 0x1000]);
            }
        }
        LogFile::from_buffer(data).unwrap()
    }

    #[test]
    fn a_newer_tail_copy_gives_the_records_its_page_lacks() {
        let log = sealed(log_with_a_tail_copy());
        let records: Vec<_> = log.records().map(|r| (r.offset, r.lsn)).collect();
        // The second record is only in the copy, and is found there.
        assert_eq!(
            records,
            [
                (0x7080, 0x23080 / 8),
                (0x22FB0, 0x22FB0 / 8),
                (0x23050, 0x23050 / 8),
            ]
        );
    }

    #[test]
    fn a_tail_copy_stands_in_for_a_page_that_was_never_written() {
        let mut data = log_with_a_tail_copy();
        data[0x23000..0x24000].fill(0xFF);
        let log = sealed(data);
        let records: Vec<_> = log.records().collect();
        let offsets: Vec<_> = records.iter().map(|r| r.offset).collect();
        assert_eq!(offsets, [0x7050, 0x7080, 0x22FB0]);
        // The record that continues into the page continues in the copy.
        let ntfs = records[2].ntfs.as_ref().unwrap();
        assert_eq!(ntfs.redo_data, b"the redo data...");

        // Whether data fits is worked out with the copy in the page's place too.
        for offset in [0x22FE0, 0x23000, 0x23800, 0x24000] {
            assert_fits_agrees_with_reading(&log, offset, (0..0x3000).step_by(0x100));
        }
    }

    #[test]
    fn a_tail_copy_does_not_replace_the_middle_of_a_newer_long_record() {
        // The page is now in the middle of a record that started after the copy was written:
        // no record ends in it, and its header has that record's LSN.
        let mut data = log_with_a_tail_copy();
        let home = 0x23000;
        data[home + 0x10] = 0;
        data[home + 8..home + 0x10].copy_from_slice(&0x10_0000u64.to_le_bytes());
        let log = sealed(data);
        let offsets: Vec<_> = log.records().map(|r| r.offset).collect();
        assert_eq!(offsets, [0x22FB0, 0x23050]);

        // With an older LSN there, the copy is the newer one.
        let mut data = log_with_a_tail_copy();
        data[home + 0x10] = 0;
        data[home + 8..home + 0x10].copy_from_slice(&(0x23050u64 / 8).to_le_bytes());
        let log = sealed(data);
        let offsets: Vec<_> = log.records().map(|r| r.offset).collect();
        assert_eq!(offsets, [0x7080, 0x22FB0, 0x23050]);
    }

    #[test]
    fn a_version_1_tail_copy_is_found_whatever_is_at_the_version_2_place() {
        // The copy is in the first record page and names its page where the last LSN is. With
        // large pages the update sequence array is where version 2.0 names it.
        let mut data = log_with_a_tail_copy();
        let (copy, home) = (0x2000, 0x23000usize);
        data.copy_within(0x7000..0x8000, copy);
        data[0x7000..0x8000].fill(0);
        data[copy + 8..copy + 0x10].copy_from_slice(&(home as u64).to_le_bytes());
        for at_version_2_place in [0u32, 0xDEAD_BEEF, 0x24000] {
            let mut data = data.clone();
            data[copy + 0x3C..copy + 0x40].copy_from_slice(&at_version_2_place.to_le_bytes());
            let log = sealed(data);
            let offsets: Vec<_> = log.records().map(|r| r.offset).collect();
            assert_eq!(
                offsets,
                [0x2080, 0x22FB0, 0x23050],
                "{at_version_2_place:#x}"
            );
        }
    }

    #[test]
    fn an_older_tail_copy_gives_nothing() {
        // The page has the two records, the copy only the first.
        let mut data = log_with_a_tail_copy();
        let (copy, home) = (0x7000, 0x23000);
        data.copy_within(copy + 0x80..copy + 0xB0, home + 0x80);
        data.copy_within(copy + 0x20..copy + 0x28, home + 0x20);
        data[copy + 0x80..copy + 0xB0].fill(0);
        data[copy + 0x20..copy + 0x28].copy_from_slice(&(0x23050u64 / 8).to_le_bytes());
        let log = sealed(data);
        let offsets: Vec<_> = log.records().map(|r| r.offset).collect();
        assert_eq!(offsets, [0x22FB0, 0x23050, 0x23080]);

        // As old as the page, as on a volume that was dismounted cleanly.
        let mut data = log_with_a_tail_copy();
        data.copy_within(copy..copy + 0x1000, home);
        data[home + 0x3C..home + 0x40].fill(0);
        let log = sealed(data);
        let offsets: Vec<_> = log.records().map(|r| r.offset).collect();
        assert_eq!(offsets, [0x22FB0, 0x23050, 0x23080]);
    }

    #[test]
    fn lsn_offsets_drop_the_sequence_number() {
        let mut data = restart_page(0x1000, 0);
        data.extend(restart_page(0x1000, 0));
        data.resize(0x10_0000, 0);
        let log = LogFile::from_buffer(data).unwrap();
        // 44 sequence bits leave 20 bits of 8-byte units.
        assert_eq!(log.lsn_offset((7 << 20) | 0x1234), Some(0x1234 * 8));
        assert_eq!(log.lsn_offset(0x2_0000), None);
    }
}
