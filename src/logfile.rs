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
use byteorder::{ByteOrder, LittleEndian};
use serde::Serialize;

use crate::MftReference;
use crate::attribute::x30::NameInParent;
use crate::err::{Error, Result};
use crate::impl_serialize_for_bitflags;
use crate::indx::ENTRY_HEADER_SIZE;
use crate::ntfs::{UPDATE_SEQUENCE_STRIDE_BYTES, is_valid_page_size};
use crate::utf16::Utf16LeStr;
use crate::utils::{read_u16, read_u32, read_u64};

/// The size of the restart page header, before the update sequence array.
const RESTART_PAGE_HEADER_SIZE: usize = 0x30;
/// The size of the fixed part of a restart area, before its clients.
const RESTART_AREA_SIZE: usize = 0x30;
/// The size of a client record (`LFS_CLIENT_RECORD`).
const CLIENT_RECORD_SIZE: usize = 0xA0;
/// A client's name is at most 64 UTF-16 code units.
const CLIENT_NAME_MAX_BYTES: usize = 128;
/// Ends a chain of clients (`LFS_NO_CLIENT`).
const NO_CLIENT: u16 = 0xFFFF;
/// The size of the record page header, before the update sequence array.
const RECORD_PAGE_HEADER_SIZE: usize = 0x28;
/// Restart pages are this size unless their header says otherwise.
const DEFAULT_PAGE_SIZE: usize = 0x1000;
/// How many pages after the restart pages hold copies of the log's tail in version 1.x of the
/// log, which names the page a copy belongs at in place of its last LSN.
const TAIL_COPY_PAGES_V1: usize = 2;
/// How many pages after the restart pages hold copies of the log's tail in version 2.0, which
/// names the page a copy belongs at in the field at `TAIL_COPY_FILE_OFFSET`.
const TAIL_COPY_PAGES_V2: usize = 32;
/// Where a version 2.0 tail copy has the offset of the page it is a copy of.
const TAIL_COPY_FILE_OFFSET: usize = 0x3C;
/// The sequence number bits a restart area can have. Windows uses 44; fewer than 20 would leave
/// LSNs able to address more than 128 TiB of log.
const SEQ_NUMBER_BITS: std::ops::RangeInclusive<u32> = 20..=60;

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
    /// Whether the update sequence array covers every sector of the page and its values matched
    /// at the end of each.
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
    /// The clients in use, following the chain from `client_in_use_list`.
    pub clients: Vec<LogClient>,
    /// Whether the chain of clients in use ended where it should. `false` when it loops, names a
    /// slot past `log_clients`, or reaches a client that runs off the page: `clients` then holds
    /// the ones before that.
    pub client_chain_intact: bool,
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
    /// Whether the update sequence array covers every sector of the page and its values matched
    /// at the end of each.
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
    /// The index in `restart_pages` of the one in use.
    current: usize,
    /// The record pages that were written, in file order.
    record_pages: Vec<Result<RecordPage>>,
    /// For each page-sized slot from the first record page on, what records are read from:
    /// `None` when there is neither a record page whose fixups all matched nor a newer tail copy
    /// of one.
    slots: Vec<Option<Slot>>,
}

/// A page-sized slot of the record pages, as [`LogFile::from_buffer`] found it.
///
/// Windows doesn't write a page that isn't full yet over the last version of it: it writes it to
/// one of the pages kept for that at the start of the log (the tail copies), with the offset the
/// page belongs at in its header, and to its own place only later. After a crash, the newest
/// records can be in such a copy only. A copy that is newer than the page it belongs at stands
/// in for that page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Slot {
    /// What [`LogFile::continues_record`] looks at: the last LSN and last end LSN of the record
    /// page, or for a page a copy stands in for, the copy's last end LSN (twice). A record that
    /// continues into the page and ends there can't be newer than that, and one that went on
    /// past the page would leave no record ending in the copy.
    lsns: [u64; 2],
    /// Where the page is read: its own offset, or the newer tail copy that stands in for it.
    source: usize,
    /// Whether the record page at the slot's own offset parsed and its fixups all matched.
    intact: bool,
    /// For a tail copy that stands in for a page, the offset of that page.
    copy_of: Option<usize>,
}

impl Slot {
    /// The slots of a log whose record pages start at `start`, given its record pages.
    ///
    /// A tail copy says where it belongs: version 2.0 of the log at `TAIL_COPY_FILE_OFFSET` of
    /// any of its first 32 record pages, version 1.x in place of the last LSN of its first two;
    /// the restart page's major version says which. What it says is taken only for a page past
    /// the copies, which the last record that ends in the copy can reach: it starts no later
    /// than that page, and no further before it than a record's longest client data spans.
    /// A copy is newer when that record's LSN is higher than the LSNs in the header of the page
    /// it belongs at. When that page isn't a record page with valid fixups, the copy stands in
    /// for it whatever its age. Of two copies of one page, the newer one has all the other has.
    fn table(
        data: &[u8],
        record_pages: &[Result<RecordPage>],
        start: usize,
        restart: &RestartPage,
    ) -> Vec<Option<Slot>> {
        let page_size = restart.log_page_size as usize;
        let data_offset = usize::from(restart.restart_area.log_page_data_offset);
        let count = (data.len() - start).div_ceil(page_size);
        let slot_of = |offset: usize| (offset - start) / page_size;
        let mut pages: Vec<Option<&RecordPage>> = vec![None; count];
        for page in record_pages
            .iter()
            .flatten()
            .filter(|page| page.valid_fixup)
        {
            pages[slot_of(page.offset as usize)] = Some(page);
        }
        let mut slots: Vec<_> = pages
            .iter()
            .map(|page| {
                page.map(|page| Slot {
                    lsns: [page.last_lsn, page.last_end_lsn],
                    source: page.offset as usize,
                    intact: true,
                    copy_of: None,
                })
            })
            .collect();

        // The LSN of the last record that ends in a page, for pages that say so.
        let last_end = |page: &RecordPage| {
            page.flags
                .contains(RecordPageFlags::LOG_RECORD_END)
                .then_some(page.last_end_lsn)
        };
        let version_2 = restart.major_version >= 2;
        let copies = if version_2 {
            TAIL_COPY_PAGES_V2
        } else {
            TAIL_COPY_PAGES_V1
        };
        // How far before the page it ends in a record can start.
        let longest_span =
            (MAX_CLIENT_DATA_LENGTH.div_ceil(page_size - data_offset) + 1) * page_size;
        for slot in 0..copies.min(count) {
            let Some(page) = pages[slot] else {
                continue;
            };
            let Some(lsn) = last_end(page) else {
                continue;
            };
            let named = if version_2 {
                read_u32(data, page.offset as usize + TAIL_COPY_FILE_OFFSET).map(u64::from)
            } else {
                Some(page.last_lsn)
            };
            let belongs_at = |home: u64| {
                let home = usize::try_from(home).ok()?;
                let end = home.checked_add(page_size)?;
                let at = lsn_file_offset(restart, data.len(), lsn)? as usize;
                (home >= start + copies * page_size
                    && (home - start).is_multiple_of(page_size)
                    && end <= data.len()
                    && at < end
                    && at + longest_span >= home)
                    .then_some(home)
            };
            let Some(home) = named.and_then(belongs_at) else {
                continue;
            };
            let home_slot = slot_of(home);
            // A page in the middle of a long record has no record that ends in it, but still
            // the LSN of that record.
            let newer = pages[home_slot].is_none_or(|home_page| {
                lsn > last_end(home_page).unwrap_or(0).max(home_page.last_lsn)
            });
            let newest =
                slots[home_slot].is_none_or(|other| other.source == home || other.lsns[0] < lsn);
            if newer && newest {
                slots[home_slot] = Some(Slot {
                    lsns: [lsn; 2],
                    source: page.offset as usize,
                    intact: pages[home_slot].is_some(),
                    copy_of: None,
                });
            }
        }
        // Each copy that stands in for a page knows which.
        for home_slot in copies.min(count)..count {
            let home = start + home_slot * page_size;
            if let Some(Slot { source, .. }) = slots[home_slot]
                && source != home
                && let Some(copy) = slots[slot_of(source)].as_mut()
            {
                copy.copy_of = Some(home);
            }
        }
        slots
    }
}

impl LogFile {
    /// Reads `data`, the whole file, and applies the fixups of each page. Fails unless at least
    /// one of the restart pages parses.
    pub fn from_buffer(mut data: Vec<u8>) -> Result<Self> {
        let second = second_restart_page(&data);
        // Neither restart page may reach into the record pages that follow them.
        let bound = (2 * second).min(data.len());
        let (restart_pages, sectors_match): (Vec<_>, Vec<_>) =
            match [0, second].map(|offset| RestartPage::from_page(&mut data[..bound], offset)) {
                [Err(error), Err(_)] => return Err(error),
                results => results.into_iter().flatten().unzip(),
            };
        // A page torn by an interrupted write fails its fixups: prefer one whose sectors all
        // match, then the newer one.
        let current = restart_pages
            .iter()
            .zip(&sectors_match)
            .enumerate()
            .max_by_key(|(_, (page, matched))| (**matched, page.restart_area.current_lsn))
            .map_or(0, |(index, _)| index);

        // The record pages start after the two restart pages of the page in use.
        let chosen = &restart_pages[current];
        let restart_end = (2 * chosen.system_page_size as usize).min(data.len());
        let page_size = chosen.log_page_size as usize;
        let record_pages = data[restart_end..]
            .chunks_mut(page_size)
            .enumerate()
            .filter_map(|(i, page)| {
                let offset = (restart_end + i * page_size) as u64;
                // A last page that is cut short is an error, whatever it holds.
                if page.len() < page_size {
                    return Some(Err(Error::InvalidLogFile {
                        offset,
                        detail: "record page cut short".to_string(),
                    }));
                }
                // A page that is all zeros or all `0xFF` was never written.
                let first = page[0];
                if (first == 0 || first == 0xFF) && page.iter().all(|&b| b == first) {
                    return None;
                }
                Some(RecordPage::from_page(page, offset))
            })
            .collect::<Vec<_>>();
        let slots = Slot::table(&data, &record_pages, restart_end, chosen);
        Ok(LogFile {
            data,
            restart_pages,
            current,
            record_pages,
            slots,
        })
    }

    /// The slot of the page that `offset` is in, which is at or past the first record page.
    fn slot(&self, offset: usize) -> Option<Slot> {
        let slot = (offset - self.record_pages_start()) / self.page_size();
        self.slots.get(slot).copied().flatten()
    }

    /// How many of a file's first bytes [`LogFile::looks_like`] looks at: up to the signature of
    /// a second restart page after a first one of 64 KiB, the largest there is.
    pub const LOOKS_LIKE_PREFIX: usize = 0x10000 + 4;

    /// Whether a file that starts with `start` has a restart page where [`LogFile::from_buffer`]
    /// looks for one: at its start or, with that page damaged, a page on.
    pub fn looks_like(start: &[u8]) -> bool {
        has_restart_signature(start)
            || start
                .get(second_restart_page(start)..)
                .is_some_and(has_restart_signature)
    }

    /// The restart page in use. Of the restart pages that parse, those whose update sequence
    /// values match at the end of every sector the array covers are preferred (a torn write
    /// leaves one that doesn't), and of those, the one with the higher current LSN.
    pub fn restart_page(&self) -> &RestartPage {
        &self.restart_pages[self.current]
    }

    /// The restart pages that parse, in file order.
    pub fn restart_pages(&self) -> &[RestartPage] {
        &self.restart_pages
    }

    /// The size of a record page, from the restart page in use.
    pub fn page_size(&self) -> usize {
        self.restart_page().log_page_size as usize
    }

    /// Where the first record page starts: after the two restart pages, each a system page
    /// long, of the restart page in use.
    fn record_pages_start(&self) -> usize {
        (2 * self.restart_page().system_page_size as usize).min(self.data.len())
    }

    /// The file, with the fixups of its pages applied.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Where in the file the record with this LSN would be: its low bits (the ones that aren't
    /// the sequence number) count 8-byte units from the start of the file.
    ///
    /// `None` for LSN 0, which is no record, and when the offset falls outside the record pages
    /// (in the restart pages or past the end of the file).
    ///
    /// The sequence number (how often the log had wrapped around when the record was written)
    /// isn't checked. A page is only rewritten when the log reaches it again, so the file can
    /// hold records from passes long before the checkpoint's: in the Narcos sample the
    /// checkpoint is in pass 24, but most records still in its pages are from pass 2. That also
    /// means the page at this offset may now hold a record of another pass, so callers must
    /// compare the LSN in the record header there with the one they asked for.
    ///
    /// This is the record's place in the circular log. The pages after the restart pages hold
    /// copies of the log's tail, which can be newer than the page at that offset when Windows
    /// stopped before writing it back; they aren't consulted here ([`LogFile::records`] reads
    /// them).
    pub fn lsn_offset(&self, lsn: u64) -> Option<u64> {
        lsn_file_offset(self.restart_page(), self.data.len(), lsn)
    }

    /// The record pages that were written, in file order: a page that is all zeros or all
    /// `0xFF` is left out, and one without the `RCRD` signature, or cut short at the end of the
    /// file, is an error.
    pub fn record_pages(&self) -> &[Result<RecordPage>] {
        &self.record_pages
    }
}

/// [`LogFile::lsn_offset`] for a log of `file_len` bytes whose restart page in use is `restart`.
fn lsn_file_offset(restart: &RestartPage, file_len: usize, lsn: u64) -> Option<u64> {
    if lsn == 0 {
        return None;
    }
    // A restart area that parses has its sequence number bits in `SEQ_NUMBER_BITS`.
    let bits = restart.restart_area.seq_number_bits;
    let offset = (lsn << bits) >> (bits - 3);
    let record_pages = 2 * u64::from(restart.system_page_size)..file_len as u64;
    record_pages.contains(&offset).then_some(offset)
}

/// Whether `page` starts with a restart page signature: `RSTR`, or `CHKD` once `chkdsk` has
/// worked on it.
fn has_restart_signature(page: &[u8]) -> bool {
    matches!(page.get(..4), Some(b"RSTR" | b"CHKD"))
}

/// Where the second restart page of the log in `data` starts: after the first, which is a system
/// page long. When the first page's size is damaged, or there is no restart page where it says,
/// the second page is looked for at each size a page can be.
fn second_restart_page(data: &[u8]) -> usize {
    let first_size = read_u32(data, 0x10)
        .map(|size| size as usize)
        .filter(|&size| is_valid_page_size(size));
    first_size
        .into_iter()
        .chain((9..=16).map(|bits| 1usize << bits))
        .find(|&size| data.get(size..).is_some_and(has_restart_signature))
        .or(first_size)
        .unwrap_or(DEFAULT_PAGE_SIZE)
}

/// The outcome of applying a page's update sequence fixups.
struct Fixups {
    /// The update sequence value matched at the end of every sector the array covers.
    sectors_match: bool,
    /// They matched, and the array covers every sector of the page.
    valid: bool,
}

/// Applies the update sequence fixups of `page`, the page at `offset`, in place. Its header
/// starts like every multi-sector structure's: the signature, then the array's offset and count.
fn apply_fixups(page: &mut [u8], offset: u64) -> Result<Fixups> {
    let usa_offset = LittleEndian::read_u16(&page[4..]);
    let usa_count = LittleEndian::read_u16(&page[6..]);
    let sectors_match =
        crate::ntfs::apply_update_sequence_array_fixups_in_place(page, usa_offset, usa_count)
            .map_err(|e| Error::InvalidLogFile {
                offset,
                detail: format!("update sequence array: {e}"),
            })?;
    let covers_every_sector =
        usize::from(usa_count) == page.len() / UPDATE_SEQUENCE_STRIDE_BYTES + 1;
    Ok(Fixups {
        sectors_match,
        valid: sectors_match && covers_every_sector,
    })
}

impl RestartPage {
    /// Parses the restart page at `offset` of `data`, applying its fixups in place. The `bool`
    /// says whether the update sequence values matched in every sector the array covers.
    fn from_page(data: &mut [u8], offset: usize) -> Result<(Self, bool)> {
        let invalid = |detail: String| Error::InvalidLogFile {
            offset: offset as u64,
            detail,
        };
        let header = data
            .get(offset..offset + RESTART_PAGE_HEADER_SIZE)
            .ok_or_else(|| invalid("restart page cut short".to_string()))?;
        if !has_restart_signature(header) {
            return Err(invalid(format!(
                "signature {:02x?} isn't RSTR or CHKD",
                &header[..4]
            )));
        }
        let chkdsk_lsn = LittleEndian::read_u64(&header[8..]);
        let system_page_size = LittleEndian::read_u32(&header[0x10..]);
        let log_page_size = LittleEndian::read_u32(&header[0x14..]);
        let restart_offset = usize::from(LittleEndian::read_u16(&header[0x18..]));
        let minor_version = LittleEndian::read_i16(&header[0x1A..]);
        let major_version = LittleEndian::read_i16(&header[0x1C..]);

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
        let fixups = apply_fixups(page, offset as u64)?;
        let restart_area = RestartArea::from_slice(page, restart_offset, log_page_size as usize)
            .map_err(|detail| invalid(format!("restart area at {restart_offset}: {detail}")))?;
        let page = RestartPage {
            offset: offset as u64,
            chkdsk_lsn,
            system_page_size,
            log_page_size,
            minor_version,
            major_version,
            valid_fixup: fixups.valid,
            restart_area,
        };
        Ok((page, fixups.sectors_match))
    }
}

impl RestartArea {
    /// Parses the restart area at `offset` of a restart page, failing when it is cut short or
    /// its fields can't be those of a log with record pages of `log_page_size`.
    fn from_slice(
        page: &[u8],
        offset: usize,
        log_page_size: usize,
    ) -> std::result::Result<Self, String> {
        let area = page
            .get(offset..offset + RESTART_AREA_SIZE)
            .ok_or("cut short")?;
        let field16 = |at: usize| LittleEndian::read_u16(&area[at..]);
        let log_clients = field16(8);
        let client_in_use_list = field16(0x0C);
        let seq_number_bits = LittleEndian::read_u32(&area[0x10..]);
        let restart_area_length = field16(0x14);
        let client_array_offset = field16(0x16);
        let file_size = LittleEndian::read_u64(&area[0x18..]);
        let log_page_data_offset = field16(0x26);

        if !SEQ_NUMBER_BITS.contains(&seq_number_bits) {
            return Err(format!("{seq_number_bits} sequence number bits"));
        }
        let length = usize::from(restart_area_length);
        if length < RESTART_AREA_SIZE || offset + length > page.len() {
            return Err(format!("length {restart_area_length}"));
        }
        // The file holds both restart pages, and an LSN's low bits can address all of it.
        let max_file_size = 8u64 << (64 - seq_number_bits);
        if file_size < 2 * page.len() as u64 || file_size > max_file_size {
            return Err(format!("file size {file_size}"));
        }
        if !(RECORD_PAGE_HEADER_SIZE..log_page_size).contains(&usize::from(log_page_data_offset)) {
            return Err(format!("log page data offset {log_page_data_offset}"));
        }

        let clients_start = offset + usize::from(client_array_offset);
        let (clients, client_chain_intact) =
            LogClient::read_chain(page, clients_start, log_clients, client_in_use_list);
        Ok(RestartArea {
            current_lsn: LittleEndian::read_u64(area),
            log_clients,
            client_free_list: field16(0x0A),
            client_in_use_list,
            flags: RestartAreaFlags::from_bits_retain(field16(0x0E)),
            seq_number_bits,
            restart_area_length,
            client_array_offset,
            file_size,
            last_lsn_data_length: LittleEndian::read_u32(&area[0x20..]),
            log_record_header_length: field16(0x24),
            log_page_data_offset,
            restart_log_open_count: LittleEndian::read_u32(&area[0x28..]),
            clients,
            client_chain_intact,
        })
    }
}

impl LogClient {
    /// Reads the chain of clients that starts with slot `first` of the `log_clients` slots at
    /// `start` of `page`, each linked to the next by `next_client`. The `bool` says whether the
    /// chain ended with [`NO_CLIENT`] rather than looping, naming a slot that doesn't exist, or
    /// reaching a client that runs off the page.
    fn read_chain(page: &[u8], start: usize, log_clients: u16, first: u16) -> (Vec<Self>, bool) {
        let mut clients = Vec::new();
        let mut next = first;
        while next != NO_CLIENT {
            // A chain longer than there are slots goes round a loop.
            if next >= log_clients || clients.len() >= usize::from(log_clients) {
                return (clients, false);
            }
            let slot = start + usize::from(next) * CLIENT_RECORD_SIZE;
            let Some(client) = page.get(slot..).and_then(LogClient::from_slice) else {
                return (clients, false);
            };
            next = client.next_client;
            clients.push(client);
        }
        (clients, true)
    }

    fn from_slice(client: &[u8]) -> Option<Self> {
        let client = client.get(..CLIENT_RECORD_SIZE)?;
        let name_length = (read_u32(client, 0x1C)? as usize).min(CLIENT_NAME_MAX_BYTES) & !1;
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
        if &page[..4] != b"RCRD" {
            return Err(Error::InvalidLogFile {
                offset,
                detail: format!("signature {:02x?} isn't RCRD", &page[..4]),
            });
        }
        // The header is in the first sector, before any bytes the fixups replace.
        let valid_fixup = apply_fixups(page, offset)?.valid;
        let header = &page[..RECORD_PAGE_HEADER_SIZE];
        let field16 = |at: usize| LittleEndian::read_u16(&header[at..]);
        Ok(RecordPage {
            offset,
            last_lsn: LittleEndian::read_u64(&header[8..]),
            flags: RecordPageFlags::from_bits_retain(LittleEndian::read_u32(&header[0x10..])),
            page_count: field16(0x14),
            page_position: field16(0x16),
            next_record_offset: field16(0x18),
            last_end_lsn: LittleEndian::read_u64(&header[0x20..]),
            valid_fixup,
        })
    }
}

/// A log record's header, with the fields that say whether a record is there.
struct RecordHeader<'a> {
    bytes: &'a [u8],
    lsn: u64,
    record_type: u32,
    client_data_length: u32,
}

/// The size of a log record's header (`LFS_RECORD_HEADER`), before its client data.
pub const LOG_RECORD_HEADER_SIZE: usize = 0x30;
/// The size of the NTFS client data header (`NTFS_LOG_RECORD_HEADER`), before its LCNs.
const NTFS_RECORD_HEADER_SIZE: usize = 0x20;
/// The most client data a record is taken to have. NTFS's largest records, the table dumps
/// that go with a checkpoint, are tens of KiB on a busy volume; a length beyond this is damage,
/// not a record, and isn't worth assembling from the pages that follow.
pub const MAX_CLIENT_DATA_LENGTH: usize = 4 << 20;
/// The most LCNs an NTFS record lists: the clusters of the record or index buffer it changes,
/// which is at most 64 KiB, over clusters of at least 512 bytes.
const MAX_LCNS: usize = 128;

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
    /// [`CLIENT_RECORD`] for a client record, [`CLIENT_RESTART_RECORD`] for a client restart
    /// record (a checkpoint).
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
    /// Whether the LCNs, the redo data or the undo data run past where they can end (the LCNs
    /// into the redo or undo data, the data past the end of the client data). They then hold
    /// only what fits, which tells a damaged record from one with nothing to redo or undo.
    pub truncated: bool,
    /// For an operation on an index entry (adding one to a directory, or removing one), the
    /// file the entry names.
    ///
    /// The record doesn't say which index the entry is in, and only a `$FILE_NAME` key is
    /// read: an entry of another index (`$O`, `$Q`, `$R`, `$SII`, `$SDH`) is left out unless
    /// its key happens to parse as one.
    pub index_entry: Option<LoggedIndexEntry>,
}

/// The `$FILE_NAME` index entry that an index operation adds or removes.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct LoggedIndexEntry {
    pub file_reference: MftReference,
    pub parent: MftReference,
    pub name: String,
}

/// The record type of a client record, one that logs a change.
pub const CLIENT_RECORD: u32 = 1;
/// The record type of a client restart record, a checkpoint.
pub const CLIENT_RESTART_RECORD: u32 = 2;

/// The operation that adds an entry to an index root (`$INDEX_ROOT`).
pub const ADD_INDEX_ENTRY_ROOT: u16 = 0x0C;
/// The operation that adds an entry to an index buffer (`$INDEX_ALLOCATION`).
pub const ADD_INDEX_ENTRY_ALLOCATION: u16 = 0x0E;

/// The operation that zeroes the end of an MFT record. Its redo length is how many bytes to
/// zero, with no data logged.
pub const ZERO_END_OF_FILE_RECORD: u16 = 0x25;

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
        ADD_INDEX_ENTRY_ROOT => "AddIndexEntryRoot",
        0x0D => "DeleteIndexEntryRoot",
        ADD_INDEX_ENTRY_ALLOCATION => "AddIndexEntryAllocation",
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
        ZERO_END_OF_FILE_RECORD => "ZeroEndOfFileRecord",
        _ => return None,
    })
}

impl NtfsLogRecord {
    /// Parses the client data of an NTFS client record.
    pub fn from_slice(data: &[u8]) -> Option<Self> {
        Self::parse(data.len(), |range| Some(data[range].to_vec()))
    }

    /// Parses client data of `length` bytes, of which `read` gives the bytes of a range. It is
    /// asked only for ranges inside the data: the header, the LCNs, and what fits of the redo
    /// and undo data, so that a record with much more data than it uses costs no more than one
    /// with little.
    fn parse(length: usize, read: impl Fn(Range<usize>) -> Option<Vec<u8>>) -> Option<Self> {
        if length < NTFS_RECORD_HEADER_SIZE {
            return None;
        }
        let header = read(0..NTFS_RECORD_HEADER_SIZE)?;
        let data = header.as_slice();
        let field = |at| read_u16(data, at);
        let (redo_operation, undo_operation) = (field(0)?, field(2)?);
        let (redo_offset, redo_length) = (usize::from(field(4)?), usize::from(field(6)?));
        let (undo_offset, undo_length) = (usize::from(field(8)?), usize::from(field(0x0A)?));
        let lcns_to_follow = usize::from(field(0x0E)?);
        let target_vcn = read_u64(data, 0x18)?;

        // The redo and undo data, or what of them fits in the client data.
        let part = |offset: usize, part_length: usize| {
            let end = (offset + part_length).min(length);
            let fits = read(offset.min(end)..end)?;
            let cut = fits.len() < part_length;
            Some((fits, cut))
        };
        let (redo_data, redo_cut) = part(redo_offset, redo_length)?;
        let (undo_data, undo_cut) = part(undo_offset, undo_length)?;

        // The LCNs follow the header and end before the redo and undo data.
        let lcns_end = [
            (redo_offset, redo_data.len()),
            (undo_offset, undo_data.len()),
        ]
        .into_iter()
        .filter(|&(_, length)| length > 0)
        .map(|(offset, _)| offset)
        .fold(length, usize::min);
        let lcns_fit = (lcns_end.saturating_sub(NTFS_RECORD_HEADER_SIZE) / 8).min(MAX_LCNS);
        let lcns_read = NTFS_RECORD_HEADER_SIZE + 8 * lcns_to_follow.min(lcns_fit);
        let lcns = read(NTFS_RECORD_HEADER_SIZE..lcns_read)?
            .as_chunks::<8>()
            .0
            .iter()
            .map(|lcn| u64::from_le_bytes(*lcn))
            .collect();

        // Adding an entry logs it to redo, removing one logs it to undo.
        let is_add =
            |operation| matches!(operation, ADD_INDEX_ENTRY_ROOT | ADD_INDEX_ENTRY_ALLOCATION);
        let index_entry = if is_add(redo_operation) {
            LoggedIndexEntry::from_slice(&redo_data)
        } else if is_add(undo_operation) {
            LoggedIndexEntry::from_slice(&undo_data)
        } else {
            None
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
            target_vcn,
            lcns,
            redo_data,
            undo_data,
            truncated: (redo_cut && redo_operation != ZERO_END_OF_FILE_RECORD)
                || undo_cut
                || lcns_to_follow > lcns_fit,
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
        let key = entry.get(ENTRY_HEADER_SIZE..ENTRY_HEADER_SIZE + key_length)?;
        let name = NameInParent::from_slice(key)?;
        Some(LoggedIndexEntry {
            file_reference,
            parent: name.parent,
            name: name.name.to_utf8_string(),
        })
    }
}

impl LogFile {
    /// The log records in the record pages, in file order. That is LSN order from the oldest
    /// page to the newest one, then the older records that the newest pages haven't written
    /// over yet.
    ///
    /// Each page is scanned on every 8-byte boundary for a record header whose LSN gives its own
    /// offset ([`LogFile::lsn_offset`], whatever its pass: pages from passes long before the
    /// checkpoint's survive where the log hasn't reached since), so a record is found even when
    /// the records before it are damaged, and the copies of the log's tail in the buffer pages
    /// (whose LSNs give the offset of the original) aren't found twice.
    ///
    /// A record that continues into the next page is left out unless that page is a record
    /// page whose fixups all matched and that was written in the same pass of the log, no
    /// earlier than the record; and so is one with more than [`MAX_CLIENT_DATA_LENGTH`] bytes
    /// of client data.
    ///
    /// A tail copy that is newer than the page it is a copy of, as after a crash, is read as that
    /// page: the records in it that the page doesn't have are given too, with the `offset` they
    /// have in the copy (so [`LogFile::lsn_offset`] of their LSN is another offset), and a record
    /// that continues into the page continues in the copy. When the page itself isn't intact
    /// (it didn't parse, or its fixups didn't all match), all its records are read from the
    /// copy and none from the page.
    ///
    /// Not handled: a record that continues past the end of the file into the first record
    /// page, where the log wraps around.
    pub fn records(&self) -> impl Iterator<Item = LogRecord> + '_ {
        let page_size = self.page_size();
        let data_offset = self.log_page_data_offset();
        self.record_pages
            .iter()
            .flatten()
            .flat_map(move |page| {
                let start = page.offset as usize;
                let slot = self.slot(start);
                // A page that isn't intact, with a copy that stands in for it, is read there.
                let stood_in = slot.is_some_and(|slot| slot.source != start && !slot.intact);
                // For a copy that stands in for a page: that page, and whether it is read too.
                let home = slot.and_then(|slot| slot.copy_of).map(|home| {
                    let home_read = self.slot(home).is_some_and(|slot| slot.intact);
                    (home - start, home_read)
                });
                // LSNs count 8-byte units, so a record starts on an 8-byte boundary.
                let first = (start + data_offset).next_multiple_of(8);
                let end = if stood_in {
                    first
                } else {
                    start + page_size - LOG_RECORD_HEADER_SIZE + 1
                };
                (first..end).step_by(8).map(move |offset| (offset, home))
            })
            .filter_map(move |(offset, home)| {
                if let Some(record) = self.record_at(offset, offset) {
                    return Some(record);
                }
                // A record the copy has and the page it belongs at doesn't, or all the copy
                // has when that page isn't read.
                let (distance, home_read) = home?;
                let home = offset + distance;
                let header = self.record_header_at(offset, home)?;
                if home_read
                    && self
                        .record_header_at(home, home)
                        .is_some_and(|at_home| at_home.lsn == header.lsn)
                {
                    return None;
                }
                self.record_from_header(offset, home, header)
            })
    }

    /// Where log records start in a record page, from the restart page in use.
    fn log_page_data_offset(&self) -> usize {
        // A restart area that parses has it after the page header and inside the page.
        usize::from(self.restart_page().restart_area.log_page_data_offset)
    }

    /// The fields of the record header at `offset` that say whether a record is there, if one
    /// is: one whose LSN gives `home`, where the header belongs (another offset than `offset`
    /// for a record in a tail copy), and whose client data is all there.
    fn record_header_at(&self, offset: usize, home: usize) -> Option<RecordHeader<'_>> {
        let header = self.data.get(offset..offset + LOG_RECORD_HEADER_SIZE)?;
        let lsn = read_u64(header, 0)?;
        let record_type = read_u32(header, 0x20)?;
        let client_data_length = read_u32(header, 0x18)?;
        let length = client_data_length as usize;
        let data_start = home + LOG_RECORD_HEADER_SIZE;
        (self.lsn_offset(lsn) == Some(home as u64)
            && matches!(record_type, CLIENT_RECORD | CLIENT_RESTART_RECORD)
            && length <= MAX_CLIENT_DATA_LENGTH
            && length <= self.data.len() - data_start
            && self.client_data_fits(lsn, data_start, length))
        .then_some(RecordHeader {
            bytes: header,
            lsn,
            record_type,
            client_data_length,
        })
    }

    /// The record whose header starts at `offset` and belongs at `home`, if there is one.
    fn record_at(&self, offset: usize, home: usize) -> Option<LogRecord> {
        let header = self.record_header_at(offset, home)?;
        self.record_from_header(offset, home, header)
    }

    /// The record of `header`, which [`Self::record_header_at`] found at `offset`, belonging at
    /// `home`.
    fn record_from_header(
        &self,
        offset: usize,
        home: usize,
        header: RecordHeader<'_>,
    ) -> Option<LogRecord> {
        let RecordHeader {
            bytes: header,
            lsn,
            record_type,
            client_data_length,
        } = header;
        let data_start = home + LOG_RECORD_HEADER_SIZE;
        // The data in the header's page is read where the header is.
        let source = offset + LOG_RECORD_HEADER_SIZE;
        // Only an NTFS client record's data is parsed, and only the parts its header points at
        // are copied: copying all of it for every record takes quadratic time on a log whose
        // every record claims much of the file.
        let ntfs = match record_type {
            CLIENT_RECORD => NtfsLogRecord::parse(client_data_length as usize, |range| {
                self.client_data(source, data_start, range)
            }),
            _ => None,
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

    /// Whether the `length` bytes of client data of the record `lsn`, from `offset` on, are all
    /// there: the rest of the page the header is in, then the data of each page the record
    /// continues into. `false` when the record continues into a page that isn't the rest of it.
    fn client_data_fits(&self, lsn: u64, offset: usize, length: usize) -> bool {
        let page_size = self.page_size();
        let data_offset = self.log_page_data_offset();
        // The end of the page the header ends in. Record pages follow the restart pages,
        // which needn't be a record page long.
        let pages_start = self.record_pages_start();
        let mut page = pages_start + ((offset - 1 - pages_start) / page_size + 1) * page_size;
        let first = (page - offset).min(length);
        if offset + first > self.data.len() {
            return false;
        }
        let mut left = length - first;
        while left > 0 {
            let n = (page_size - data_offset).min(left);
            if !self.continues_record(page, lsn) || page + data_offset + n > self.data.len() {
                return false;
            }
            left -= n;
            page += page_size;
        }
        true
    }

    /// The bytes `range` of the client data that belongs at `offset` on and continues past the
    /// end of a page at the data of the next one, which [`Self::client_data_fits`] has checked.
    /// `source` is where the data is when it starts inside a page: `offset`, or the same place
    /// in the page's tail copy. Each page the data continues into is read at its newer tail
    /// copy, if it has one.
    fn client_data(
        &self,
        mut source: usize,
        mut offset: usize,
        range: Range<usize>,
    ) -> Option<Vec<u8>> {
        let page_size = self.page_size();
        let data_offset = self.log_page_data_offset();
        let pages_start = self.record_pages_start();
        let mut client_data = Vec::with_capacity(range.len());
        // How much of the client data is before `offset`.
        let mut passed = 0;
        while passed < range.end {
            // A record whose header ends a page continues after the next page's header.
            let page_start = offset - (offset - pages_start) % page_size;
            if offset == page_start {
                source = self.slot(page_start).map_or(page_start, |slot| slot.source);
            }
            let skipped = (page_start + data_offset).saturating_sub(offset);
            offset += skipped;
            source += skipped;
            let page_end = page_start + page_size;
            let n = (page_end - offset).min(range.end - passed);
            let before = range.start.saturating_sub(passed).min(n);
            client_data.extend_from_slice(self.data.get(source + before..source + n)?);
            passed += n;
            offset = page_end;
        }
        Some(client_data)
    }

    /// Whether the page at `offset` can hold the rest of the record `lsn`: a record page whose
    /// fixups all matched, written in the same pass of the log as the record and no earlier.
    /// A page that was never written, holds something else, or was written over in a later
    /// pass isn't the rest of this record.
    fn continues_record(&self, offset: usize, lsn: u64) -> bool {
        let Some(Slot {
            lsns: page_lsns, ..
        }) = self.slot(offset)
        else {
            return false;
        };
        let bits = self.restart_page().restart_area.seq_number_bits;
        let sequence = |lsn: u64| lsn >> (64 - bits);
        // The page's last LSN is the newest record that starts in it, and its last end LSN the
        // newest that ends in it: the record or one after it does one or the other.
        page_lsns
            .iter()
            .any(|&page_lsn| page_lsn >= lsn && sequence(page_lsn) == sequence(lsn))
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
    pub truncated: Option<bool>,
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
            truncated: ntfs.map(|n| n.truncated),
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

    /// How many bytes of client data [`NtfsLogRecord::parse`] asks for to parse `records`, as
    /// [`LogFile::records`] parses them. Each must come out the same as `records` has it.
    fn bytes_requested(log: &LogFile, records: &[LogRecord]) -> usize {
        let requested = Cell::new(0);
        for record in records {
            let source = record.offset as usize + LOG_RECORD_HEADER_SIZE;
            let data_start = log.lsn_offset(record.lsn).unwrap() as usize + LOG_RECORD_HEADER_SIZE;
            let length = record.client_data_length as usize;
            let ntfs = NtfsLogRecord::parse(length, |range| {
                requested.set(requested.get() + range.len());
                log.client_data(source, data_start, range)
            });
            assert_eq!(ntfs, record.ntfs);
        }
        requested.get()
    }

    /// A restart page of 4 KiB, of version 2.0 of the log, for record pages of 4 KiB with their
    /// data at 0x40 and 44 sequence number bits, and an `NTFS` client.
    fn restart_page() -> Vec<u8> {
        let mut page = vec![0u8; 0x1000];
        page[..4].copy_from_slice(b"RSTR");
        page[4..6].copy_from_slice(&0x1Eu16.to_le_bytes());
        page[6..8].copy_from_slice(&9u16.to_le_bytes());
        page[0x10..0x14].copy_from_slice(&0x1000u32.to_le_bytes());
        page[0x14..0x18].copy_from_slice(&0x1000u32.to_le_bytes());
        page[0x18..0x1A].copy_from_slice(&0x30u16.to_le_bytes());
        page[0x1C..0x1E].copy_from_slice(&2u16.to_le_bytes());
        // The update sequence value is 1, and the sectors' last bytes are already 1.
        page[0x1E..0x20].copy_from_slice(&1u16.to_le_bytes());
        for sector in 0..8 {
            page[sector * 512 + 510..sector * 512 + 512].copy_from_slice(&1u16.to_le_bytes());
        }
        let area = &mut page[0x30..];
        area[8..10].copy_from_slice(&1u16.to_le_bytes());
        area[0x0A..0x0C].copy_from_slice(&0xFFFFu16.to_le_bytes());
        area[0x10..0x14].copy_from_slice(&44u32.to_le_bytes());
        area[0x14..0x16].copy_from_slice(&0xE0u16.to_le_bytes());
        area[0x16..0x18].copy_from_slice(&0x40u16.to_le_bytes());
        area[0x18..0x20].copy_from_slice(&0x10_0000u64.to_le_bytes());
        area[0x26..0x28].copy_from_slice(&0x40u16.to_le_bytes());
        let client = &mut area[0x40..0xE0];
        client[0x10..0x14].copy_from_slice(&[0xFF; 4]);
        client[0x1C..0x20].copy_from_slice(&8u32.to_le_bytes());
        for (i, unit) in "NTFS".encode_utf16().enumerate() {
            client[0x20 + 2 * i..0x22 + 2 * i].copy_from_slice(&unit.to_le_bytes());
        }
        page
    }

    /// Makes `page` (4 KiB) a record page: the signature and the update sequence array, with
    /// the last two bytes of each sector moved into it.
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

    /// Makes `page` (4 KiB) a record page with `last_lsn` as its last LSN, so that it can
    /// continue the records of its pass up to that LSN.
    fn seal_record_page_with_lsn(page: &mut [u8], last_lsn: u64) {
        page[8..0x10].copy_from_slice(&last_lsn.to_le_bytes());
        seal_record_page(page);
    }

    /// The highest LSN of pass 0 of the log, so a page with it continues any record of pass 0.
    const LAST_LSN_OF_PASS_0: u64 = (1 << 20) - 1;

    /// Writes a client record header at `offset` whose LSN gives that offset, in pass 0.
    fn put_record_header(data: &mut [u8], offset: usize, client_data_length: u32) {
        put_record_header_for(data, offset, offset, client_data_length);
    }

    /// Writes a client record header at `offset` whose LSN gives the offset `home`, in pass 0.
    fn put_record_header_for(data: &mut [u8], offset: usize, home: usize, client_data_length: u32) {
        let header = &mut data[offset..offset + LOG_RECORD_HEADER_SIZE];
        header[..8].copy_from_slice(&(home as u64 / 8).to_le_bytes());
        header[0x18..0x1C].copy_from_slice(&client_data_length.to_le_bytes());
        header[0x20..0x24].copy_from_slice(&CLIENT_RECORD.to_le_bytes());
    }

    /// A log of `size` bytes: two restart pages, then record pages with nothing in them.
    fn empty_log(size: usize) -> Vec<u8> {
        let mut data = restart_page();
        data.extend(restart_page());
        data.resize(size, 0);
        data
    }

    #[test]
    fn records_that_each_claim_most_of_the_file_copy_only_their_ntfs_header() {
        // A record header every 0x30 bytes of every page, each with the most client data a
        // record can have, and every page continuing them. Copying all of each record's data
        // would copy 4 MiB for each of them; only the parts the NTFS header points at are
        // copied, so the bytes copied grow with the records, not with the data they claim.
        // (Whether the data is all there is still a walk over its pages, bounded by
        // MAX_CLIENT_DATA_LENGTH.)
        let size = 6 << 20;
        let mut data = empty_log(size);
        for page_start in (0x2000..size).step_by(0x1000) {
            for offset in (page_start + 0x40..=page_start + 0x1000 - 0x30).step_by(0x30) {
                put_record_header(&mut data, offset, MAX_CLIENT_DATA_LENGTH as u32);
            }
            seal_record_page_with_lsn(
                &mut data[page_start..page_start + 0x1000],
                LAST_LSN_OF_PASS_0,
            );
        }
        let log = LogFile::from_buffer(data).unwrap();
        let records: Vec<_> = log.records().collect();
        // Those whose data ends before the end of the file.
        assert!(records.len() > 30_000);
        // The client data of each starts with the next header, whose NTFS header points at no
        // redo or undo data and no LCNs: no more is copied than that header.
        assert!(
            records
                .iter()
                .all(|r| r.ntfs.as_ref().unwrap().lcns.is_empty())
        );
        assert_eq!(
            bytes_requested(&log, &records),
            records.len() * NTFS_RECORD_HEADER_SIZE
        );
    }

    #[test]
    fn only_the_data_a_record_gives_is_copied() {
        // A record header every 0x30 bytes again, each with 128 KiB of client data. The client
        // data of a record starts at the header after it, whose LSN and previous LSN are made
        // to read as an NTFS header with 0xFFFF bytes of redo and of undo data at 0xFFFF.
        let size = 1 << 20;
        let mut data = empty_log(size);
        // The high half of the LSN is mostly its sequence number, which can be anything.
        let pass = 0xFFFF_FFFF_0000_0000;
        for page_start in (0x2000..size).step_by(0x1000) {
            for offset in (page_start + 0x40..=page_start + 0x1000 - 0x30).step_by(0x30) {
                put_record_header(&mut data, offset, 0x20000);
                data[offset + 4..offset + 12].fill(0xFF);
            }
            let page = &mut data[page_start..page_start + 0x1000];
            seal_record_page_with_lsn(page, pass | LAST_LSN_OF_PASS_0);
        }
        let log = LogFile::from_buffer(data).unwrap();
        let records: Vec<_> = log.records().collect();
        let returned: usize = records
            .iter()
            .filter_map(|r| r.ntfs.as_ref())
            .map(|n| NTFS_RECORD_HEADER_SIZE + n.redo_data.len() + n.undo_data.len())
            .sum();
        assert!(records.len() > 10_000);
        assert!(returned > records.len() * 0x1FFFE);
        // Each byte is copied once, into the record that gives it.
        assert_eq!(bytes_requested(&log, &records), returned);
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
                let page = &mut data[page_start..page_start + 0x1000];
                seal_record_page_with_lsn(page, LAST_LSN_OF_PASS_0);
            }
        }

        let records = |length: usize| {
            let mut data = data.clone();
            // Sealing moved the last two bytes of the sector, not the header.
            put_record_header(&mut data, record, length as u32);
            LogFile::from_buffer(data)
                .unwrap()
                .records()
                .collect::<Vec<_>>()
        };
        let whole = usize::from(redo_offset) + 8;
        let found = records(whole);
        assert_eq!(found.len(), 1);
        let ntfs = found[0].ntfs.as_ref().unwrap();
        assert_eq!(
            ntfs.redo_operation_name,
            Some("InitializeFileRecordSegment")
        );
        assert_eq!(ntfs.redo_data, b"redodata");
        assert!(!ntfs.truncated);

        // The data can run up to the end of page 5, but not into page 6, which was never
        // written.
        let up_to_page_6 = (0x1000 - 0x70) + 5 * in_each_page;
        assert_eq!(records(up_to_page_6).len(), 1);
        assert!(records(up_to_page_6 + 1).is_empty());
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

    /// Seals each record page of `data` that isn't all zeros or all `0xFF`.
    fn seal_pages(data: &mut [u8]) {
        for page_start in (0x2000..data.len()).step_by(0x1000) {
            let page = &data[page_start..page_start + 0x1000];
            if page.iter().any(|&b| b != 0) && page.iter().any(|&b| b != 0xFF) {
                seal_record_page(&mut data[page_start..page_start + 0x1000]);
            }
        }
    }

    fn sealed(mut data: Vec<u8>) -> LogFile {
        seal_pages(&mut data);
        LogFile::from_buffer(data).unwrap()
    }

    /// The offsets of the records of `log_with_a_tail_copy()` when the page the copy belongs at
    /// is damaged by `damage` after sealing, and the redo data of the record that continues
    /// into that page.
    fn with_the_home_page_damaged(damage: impl Fn(&mut [u8])) -> (Vec<u64>, Vec<u8>) {
        let mut data = log_with_a_tail_copy();
        seal_pages(&mut data);
        damage(&mut data[0x23000..0x24000]);
        let log = LogFile::from_buffer(data).unwrap();
        let records: Vec<_> = log.records().collect();
        let spanning = records.iter().find(|r| r.offset == 0x22FB0).unwrap();
        let redo = spanning.ntfs.as_ref().unwrap().redo_data.clone();
        (records.iter().map(|r| r.offset).collect(), redo)
    }

    #[test]
    fn a_tail_copy_stands_in_for_a_page_that_did_not_parse() {
        // The record both have is read from the copy, not lost from both.
        let (offsets, redo) = with_the_home_page_damaged(|page| page[..4].copy_from_slice(b"XXXX"));
        assert_eq!(offsets, [0x7050, 0x7080, 0x22FB0]);
        assert_eq!(redo, b"the redo data...");
    }

    #[test]
    fn a_tail_copy_stands_in_for_a_torn_page() {
        // The page parses, but a sector's update sequence value doesn't match: its records are
        // read from the intact copy instead.
        let (offsets, redo) = with_the_home_page_damaged(|page| page[0x3FE] = 7);
        assert_eq!(offsets, [0x7050, 0x7080, 0x22FB0]);
        assert_eq!(redo, b"the redo data...");
    }

    #[test]
    fn a_tail_copy_whose_only_record_ending_in_it_started_a_page_before() {
        // The page the copy belongs at was written only to the copy, which holds just the end
        // of the record that started in the page before.
        let mut data = log_with_a_tail_copy();
        let (copy, home) = (0x7000, 0x23000);
        data[home..home + 0x1000].fill(0xFF);
        data[copy + 0x50..copy + 0xB0].fill(0);
        let spanning = (home - 0x50) as u64 / 8;
        data[copy + 0x20..copy + 0x28].copy_from_slice(&spanning.to_le_bytes());
        let log = sealed(data);
        let records: Vec<_> = log.records().collect();
        let offsets: Vec<_> = records.iter().map(|r| r.offset).collect();
        assert_eq!(offsets, [0x22FB0]);
        let ntfs = records[0].ntfs.as_ref().unwrap();
        assert_eq!(ntfs.redo_data, b"the redo data...");
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
        // large pages the update sequence array is where version 2.0 names it, so in a log of
        // version 1.1, as the restart pages say, that place isn't read.
        let mut data = log_with_a_tail_copy();
        for restart in [0, 0x1000] {
            data[restart + 0x1A..restart + 0x1E].copy_from_slice(&[1, 0, 1, 0]);
        }
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
    fn what_looks_like_a_log_is_what_can_be_opened() {
        let intact = || {
            let mut data = restart_page();
            data.extend(restart_page());
            data.resize(0x4000, 0);
            data
        };
        let agree = |data: Vec<u8>, is_log: bool| {
            let start = &data[..data.len().min(LogFile::LOOKS_LIKE_PREFIX)];
            assert_eq!(LogFile::looks_like(start), is_log);
            assert_eq!(LogFile::from_buffer(data).is_ok(), is_log);
        };
        agree(intact(), true);

        // The first page is no restart page, but has what reads as a page size where a restart
        // page has its own: the second page is still found, a real page on.
        let mut data = intact();
        data[..0x1000].fill(0xA5);
        data[0x10..0x14].copy_from_slice(&512u32.to_le_bytes());
        agree(data, true);

        // The second page is damaged.
        let mut data = intact();
        data[0x1000..0x2000].fill(0);
        agree(data, true);

        // Neither is a restart page.
        let mut data = intact();
        data[..0x2000].fill(0);
        data[0x2000..0x2004].copy_from_slice(b"RCRD");
        agree(data, false);
    }
}
