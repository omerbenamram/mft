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
/// for page in log.record_pages() {
///     let page = page.as_ref().map_err(|e| e.to_string()).unwrap();
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
    /// The record pages that were written, in file order.
    record_pages: Vec<Result<RecordPage>>,
}

impl LogFile {
    /// Reads `data`, the whole file, and applies the fixups of each page. Fails unless at least
    /// one of the restart pages is intact.
    pub fn from_buffer(mut data: Vec<u8>) -> Result<Self> {
        let mut restart_pages = Vec::new();
        let mut first_error = None;
        // The second restart page follows the first, which is a system page long.
        let second = read_u32(&data, 0x10)
            .map(|size| size as usize)
            .filter(|&size| is_valid_page_size(size))
            .unwrap_or(DEFAULT_PAGE_SIZE);
        for offset in [0, second] {
            match RestartPage::from_page(&mut data, offset) {
                Ok(page) => restart_pages.push(page),
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        let Some(current) = restart_pages
            .iter()
            .enumerate()
            .max_by_key(|(_, page)| page.restart_area.current_lsn)
            .map(|(index, _)| index)
        else {
            return Err(first_error.expect("a page failed"));
        };

        let page_size = restart_pages[current].log_page_size as usize;
        if !is_valid_page_size(page_size) {
            return Err(Error::InvalidLogFile {
                offset: restart_pages[current].offset,
                detail: format!("log page size {page_size}"),
            });
        }
        // A page that is all zeros or all `0xFF` was never written.
        let start = (2 * second).min(data.len());
        let record_pages = data[start..]
            .chunks_exact_mut(page_size)
            .enumerate()
            .filter(|(_, page)| !page.iter().all(|&b| b == 0) && !page.iter().all(|&b| b == 0xFF))
            .map(|(i, page)| RecordPage::from_page(page, (2 * second + i * page_size) as u64))
            .collect();
        Ok(LogFile {
            data,
            restart_pages,
            current,
            page_size,
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
        if &header[..4] != b"RSTR" {
            return Err(invalid(format!(
                "signature {:02x?} isn't RSTR",
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
        let page = data
            .get_mut(offset..offset + page_size)
            .ok_or_else(|| invalid("restart page cut short".to_string()))?;
        let valid_fixup = crate::ntfs::apply_update_sequence_array_fixups_in_place_with(
            page,
            usa_offset,
            usa_count,
            |_| {},
        )
        .map_err(|e| invalid(format!("update sequence array: {e}")))?;

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
        let field16 = |at| read_u16(page, at).unwrap_or_default();
        let (usa_offset, usa_count) = (field16(4), field16(6));
        let header = RecordPage {
            offset,
            last_lsn: read_u64(page, 8).unwrap_or_default(),
            flags: RecordPageFlags::from_bits_retain(read_u32(page, 0x10).unwrap_or_default()),
            page_count: field16(0x14),
            page_position: field16(0x16),
            next_record_offset: field16(0x18),
            last_end_lsn: read_u64(page, 0x20).unwrap_or_default(),
            valid_fixup: false,
        };
        let valid_fixup = crate::ntfs::apply_update_sequence_array_fixups_in_place_with(
            page,
            usa_offset,
            usa_count,
            |_| {},
        )
        .map_err(|e| invalid(format!("update sequence array: {e}")))?;
        Ok(RecordPage {
            valid_fixup,
            ..header
        })
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
