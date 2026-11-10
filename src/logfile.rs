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

use bitflags::bitflags;
use byteorder::{ByteOrder, LittleEndian};
use serde::Serialize;

use crate::MftReference;
use crate::attribute::x30::FileNameAttr;
use crate::err::{Error, Result};
use crate::impl_serialize_for_bitflags;
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
    /// The highest LSN of a record that starts in the page, or, in the buffer pages that hold
    /// copies of the log's tail, the file offset the page is a copy of.
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
}

impl LogFile {
    /// Reads `data`, the whole file, and applies the fixups of each page. Fails unless at least
    /// one of the restart pages parses.
    pub fn from_buffer(mut data: Vec<u8>) -> Result<Self> {
        // The second restart page follows the first, which is a system page long. When the first
        // page's size is damaged, or there is no restart page where it says, the second page is
        // looked for at each size a page can be.
        let first_size = read_u32(&data, 0x10)
            .map(|size| size as usize)
            .filter(|&size| is_valid_page_size(size));
        let second = first_size
            .into_iter()
            .chain((9..=16).map(|bits| 1usize << bits))
            .find(|&size| data.get(size..).is_some_and(has_restart_signature))
            .or(first_size)
            .unwrap_or(DEFAULT_PAGE_SIZE);
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
            .collect();
        Ok(LogFile {
            data,
            restart_pages,
            current,
            record_pages,
        })
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

    /// Where in the file the record with this LSN starts: its low bits (the ones that aren't
    /// the sequence number) count 8-byte units from the start of the file.
    ///
    /// `None` for LSN 0, which is no record; when the LSN's sequence number (how often the log
    /// had wrapped around when it was written) isn't within one of the current LSN's, since
    /// the file holds at most the pass the checkpoint is in and the ones either side of it; and
    /// when the offset is past the end of the file.
    ///
    /// This is the record's place in the circular log. The two pages after the restart pages
    /// hold copies of the log's tail, which can be newer than the page at that offset when
    /// Windows stopped before writing it back; they aren't consulted.
    pub fn lsn_offset(&self, lsn: u64) -> Option<u64> {
        let area = &self.restart_page().restart_area;
        // A restart area that parses has its sequence number bits in `SEQ_NUMBER_BITS`.
        let bits = area.seq_number_bits;
        let sequence = |lsn: u64| lsn >> (64 - bits);
        let current = sequence(area.current_lsn);
        if lsn == 0 || sequence(lsn) + 1 < current || sequence(lsn) > current + 1 {
            return None;
        }
        self.lsn_file_offset(lsn)
    }

    /// Where the record with this LSN would start, from its low bits alone, whatever its
    /// sequence number; `None` past the end of the file.
    fn lsn_file_offset(&self, lsn: u64) -> Option<u64> {
        // A restart area that parses has its sequence number bits in `SEQ_NUMBER_BITS`.
        let bits = self.restart_page().restart_area.seq_number_bits;
        let offset = (lsn << bits) >> (bits - 3);
        (offset < self.data.len() as u64).then_some(offset)
    }

    /// The record pages that were written, in file order: a page that is all zeros or all
    /// `0xFF` is left out, and one without the `RCRD` signature, or cut short at the end of the
    /// file, is an error.
    pub fn record_pages(&self) -> &[Result<RecordPage>] {
        &self.record_pages
    }
}

/// Whether `page` starts with a restart page signature: `RSTR`, or `CHKD` once `chkdsk` has
/// worked on it.
fn has_restart_signature(page: &[u8]) -> bool {
    matches!(page.get(..4), Some(b"RSTR" | b"CHKD"))
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
        let field = |at| read_u16(data, at);
        let (redo_operation, undo_operation) = (field(0)?, field(2)?);
        let part = |offset: u16, length: u16| {
            let start = usize::from(offset);
            data.get(start..start + usize::from(length))
                .unwrap_or_default()
                .to_vec()
        };
        let redo_data = part(field(4)?, field(6)?);
        let undo_data = part(field(8)?, field(0x0A)?);
        let lcns_to_follow = usize::from(field(0x0E)?);
        let lcns = (0..lcns_to_follow)
            .map_while(|i| read_u64(data, NTFS_RECORD_HEADER_SIZE + 8 * i))
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
    /// offset (its low bits, as in [`LogFile::lsn_offset`], but whatever its sequence number:
    /// pages from passes long before the checkpoint's survive where the log hasn't reached
    /// since), so a record is found even when the records before it are damaged, and the copies of the log's tail in the buffer pages (whose LSNs give the
    /// offset of the original) aren't found twice. A record that continues past the end of the
    /// file is left out.
    pub fn records(&self) -> impl Iterator<Item = LogRecord> + '_ {
        let page_size = self.page_size();
        let data_offset = usize::from(self.restart_page().restart_area.log_page_data_offset)
            .clamp(RECORD_PAGE_HEADER_SIZE, page_size);
        self.record_pages
            .iter()
            .flatten()
            .flat_map(move |page| {
                let start = page.offset as usize;
                // LSNs count 8-byte units, so a record starts on an 8-byte boundary.
                ((start + data_offset).next_multiple_of(8)
                    ..start + page_size - LOG_RECORD_HEADER_SIZE + 1)
                    .step_by(8)
            })
            .filter_map(move |offset| self.record_at(offset, data_offset))
    }

    /// The record whose header starts at `offset`, if there is one.
    fn record_at(&self, offset: usize, data_offset: usize) -> Option<LogRecord> {
        let header = self.data.get(offset..offset + LOG_RECORD_HEADER_SIZE)?;
        let lsn = read_u64(header, 0)?;
        let record_type = read_u32(header, 0x20)?;
        let client_data_length = read_u32(header, 0x18)?;
        if lsn == 0
            || self.lsn_file_offset(lsn) != Some(offset as u64)
            || !(1..=2).contains(&record_type)
            || client_data_length as usize > self.data.len() - offset - LOG_RECORD_HEADER_SIZE
        {
            return None;
        }
        let client_data = self.client_data(
            offset + LOG_RECORD_HEADER_SIZE,
            client_data_length as usize,
            data_offset,
        )?;
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
            ntfs: if record_type == 1 {
                NtfsLogRecord::from_slice(&client_data)
            } else {
                None
            },
        })
    }

    /// `length` bytes of client data from `offset` on, continuing past the end of a page at the
    /// data of the next one.
    fn client_data(&self, mut offset: usize, length: usize, data_offset: usize) -> Option<Vec<u8>> {
        let mut client_data = Vec::with_capacity(length);
        while client_data.len() < length {
            // A record whose header ends a page continues after the next page's header.
            // Record pages follow the restart pages, which needn't be a record page long.
            let page_start =
                offset - (offset - self.record_pages_start()) % self.page_size();
            // A page the record continues into must be a record page: a page that was never
            // written, or that holds something else, isn't the rest of this record.
            if offset == page_start && self.data.get(page_start..page_start + 4) != Some(b"RCRD") {
                return None;
            }
            offset = offset.max(page_start + data_offset);
            let page_end = page_start + self.page_size();
            let n = (page_end - offset).min(length - client_data.len());
            client_data.extend_from_slice(self.data.get(offset..offset + n)?);
            offset = page_end;
        }
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
