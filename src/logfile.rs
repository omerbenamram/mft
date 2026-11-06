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
        Ok(LogFile {
            data,
            restart_pages,
            current,
            page_size,
            record_pages_start: restart_end,
            record_pages,
        })
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
    /// offset ([`LogFile::lsn_offset`]), so a record is found even when the records before it
    /// are damaged, and the copies of the log's tail in the buffer pages (whose LSNs give the
    /// offset of the original) aren't found twice. A record that continues past the end of the
    /// file is left out.
    pub fn records(&self) -> impl Iterator<Item = LogRecord> + '_ {
        let page_size = self.page_size;
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
            || self.lsn_offset(lsn) != Some(offset as u64)
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
            let page_start = offset - (offset - self.record_pages_start) % self.page_size;
            // A page the record continues into must be a record page: a page that was never
            // written, or that holds something else, isn't the rest of this record.
            if offset == page_start && self.data.get(page_start..page_start + 4) != Some(b"RCRD") {
                return None;
            }
            offset = offset.max(page_start + data_offset);
            let page_end = page_start + self.page_size;
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

#[cfg(test)]
mod tests {
    use super::*;

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
