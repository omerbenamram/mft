mod fixtures;

use fixtures::*;
use mft::logfile::{LogFile, MAX_CLIENT_DATA_LENGTH, NtfsLogRecord, RestartAreaFlags};

fn sample() -> LogFile {
    let path = testdata_dir()
        .join("logfile")
        .join("narcos-sysreserved-head.LogFile");
    LogFile::from_buffer(std::fs::read(path).unwrap()).unwrap()
}

#[test]
fn it_reads_the_restart_pages() {
    let log = sample();
    assert_eq!(log.restart_pages().len(), 2);
    let restart = log.restart_page();
    assert_eq!((restart.major_version, restart.minor_version), (1, 1));
    assert_eq!(log.page_size(), 4096);

    let area = &restart.restart_area;
    assert_eq!(area.current_lsn, 25_184_410);
    assert_eq!(area.seq_number_bits, 44);
    assert_eq!(area.file_size, 4_325_376);
    assert!(area.flags.contains(RestartAreaFlags::CLEAN_DISMOUNT));
    assert_eq!(area.clients.len(), 1);
    assert_eq!(area.clients[0].name, "NTFS");
    assert_eq!(area.clients[0].client_restart_lsn, area.current_lsn);

    // The checkpoint record is where its LSN says.
    let offset = log.lsn_offset(area.current_lsn).unwrap() as usize;
    let this_lsn = u64::from_le_bytes(log.data()[offset..offset + 8].try_into().unwrap());
    assert_eq!(this_lsn, area.current_lsn);
}

#[test]
fn it_reads_the_record_pages() {
    let log = sample();
    let pages: Vec<_> = log
        .record_pages()
        .iter()
        .map(|page| page.as_ref().unwrap())
        .collect();
    assert_eq!(pages.len(), 27);
    assert!(pages.iter().all(|page| page.valid_fixup));
    // Two buffer pages with copies of the log's tail, then the log itself.
    assert_eq!(pages[0].offset, 0x2000);
    assert_eq!(pages[2].offset, 0x4000);
}

#[test]
fn it_reads_the_log_records() {
    let log = sample();
    let records: Vec<_> = log.records().collect();
    assert_eq!(records.len(), 422);
    // 15 checkpoints, the rest NTFS client records.
    assert_eq!(records.iter().filter(|r| r.record_type == 2).count(), 15);
    assert!(
        records
            .iter()
            .all(|r| (r.record_type == 1) == r.ntfs.is_some())
    );
    // The checkpoint the restart area names is one of them.
    let current = log.restart_page().restart_area.current_lsn;
    assert!(
        records
            .iter()
            .any(|r| r.lsn == current && r.record_type == 2)
    );

    // Each transaction's records chain back through records that were found.
    let lsns: std::collections::HashSet<u64> = records.iter().map(|r| r.lsn).collect();
    let previous: Vec<u64> = records
        .iter()
        .map(|r| r.client_previous_lsn)
        .filter(|&lsn| lsn != 0)
        .collect();
    let found = previous.iter().filter(|lsn| lsns.contains(lsn)).count();
    assert!(found + 2 >= previous.len(), "{found} of {}", previous.len());

    // Formatting the volume created the files of `$Extend` in its index.
    let names: Vec<&str> = records
        .iter()
        .filter_map(|r| r.ntfs.as_ref()?.index_entry.as_ref())
        .map(|entry| entry.name.as_str())
        .collect();
    for name in ["$Extend", "$Quota", "$ObjId", "$Reparse"] {
        assert!(names.contains(&name), "{names:?}");
    }
}

// Synthetic logs.

/// A restart page of `size` bytes, for record pages of 4 KiB and a file of 1 MiB, with an `NTFS`
/// client and the given current LSN.
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
    area[0x0A..0x0C].copy_from_slice(&0xFFFFu16.to_le_bytes());
    area[0x0E..0x10].copy_from_slice(&2u16.to_le_bytes());
    area[0x10..0x14].copy_from_slice(&44u32.to_le_bytes());
    area[0x14..0x16].copy_from_slice(&0xE0u16.to_le_bytes());
    area[0x16..0x18].copy_from_slice(&0x40u16.to_le_bytes());
    area[0x18..0x20].copy_from_slice(&0x10_0000u64.to_le_bytes());
    area[0x26..0x28].copy_from_slice(&0x40u16.to_le_bytes());
    set_client(&mut page, 0, 0xFFFF, "NTFS");
    page
}

/// Writes client slot `slot` of a page from [`restart_page`], linked to `next`.
fn set_client(page: &mut [u8], slot: usize, next: u16, name: &str) {
    let client = &mut page[0x70 + slot * 0xA0..][..0xA0];
    client[0x10..0x12].copy_from_slice(&0xFFFFu16.to_le_bytes());
    client[0x12..0x14].copy_from_slice(&next.to_le_bytes());
    client[0x1C..0x20].copy_from_slice(&(2 * name.len() as u32).to_le_bytes());
    for (i, unit) in name.encode_utf16().enumerate() {
        client[0x20 + 2 * i..0x22 + 2 * i].copy_from_slice(&unit.to_le_bytes());
    }
}

/// An `RCRD` page of 4 KiB with valid fixups.
fn record_page() -> Vec<u8> {
    let mut page = vec![0u8; 0x1000];
    page[..4].copy_from_slice(b"RCRD");
    page[4..6].copy_from_slice(&0x28u16.to_le_bytes());
    page[6..8].copy_from_slice(&9u16.to_le_bytes());
    page[0x28..0x2A].copy_from_slice(&1u16.to_le_bytes());
    for sector in 0..8 {
        page[sector * 512 + 510..sector * 512 + 512].copy_from_slice(&1u16.to_le_bytes());
    }
    page
}

fn two_restart_pages(first_lsn: u64, second_lsn: u64) -> Vec<u8> {
    let mut data = restart_page(0x1000, first_lsn);
    data.extend(restart_page(0x1000, second_lsn));
    data
}

#[test]
fn the_newer_restart_page_is_current() {
    let mut data = two_restart_pages(10, 20);
    data.resize(0x4000, 0);
    let log = LogFile::from_buffer(data).unwrap();
    assert_eq!(log.restart_pages().len(), 2);
    assert_eq!(log.restart_page().offset, 0x1000);
    let area = &log.restart_page().restart_area;
    assert_eq!(area.current_lsn, 20);
    assert_eq!(area.flags, RestartAreaFlags::CLEAN_DISMOUNT);
    assert_eq!(area.clients[0].name, "NTFS");
    assert!(area.client_chain_intact);
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

/// A torn first page whose size field reads as a plausible but wrong size: the second page is
/// still found where it is, and the record pages start after it.
#[test]
fn a_torn_first_page_with_a_wrong_size_does_not_hide_the_second() {
    let mut first = restart_page(0x1000, 30);
    first[0x10..0x14].copy_from_slice(&0x2000u32.to_le_bytes());
    first[0x1FE] = 7;
    let mut data = first;
    data.extend(restart_page(0x1000, 20));
    data.extend(record_page());
    data.resize(0x8000, 0);
    let log = LogFile::from_buffer(data).unwrap();
    assert_eq!(log.restart_page().offset, 0x1000);
    assert_eq!(log.restart_page().restart_area.current_lsn, 20);
    let pages = log.record_pages();
    assert_eq!(pages.len(), 1);
    assert_eq!(pages[0].as_ref().unwrap().offset, 0x2000);
}

/// The record pages start after the restart pages of the page in use, not where a damaged first
/// page's size says.
#[test]
fn the_restart_region_comes_from_the_page_in_use() {
    // The first page claims 512-byte pages, which its update sequence array runs past.
    let mut first = restart_page(0x1000, 5);
    first[0x10..0x14].copy_from_slice(&0x200u32.to_le_bytes());
    let mut data = first;
    data.extend(restart_page(0x1000, 20));
    data.extend(record_page());
    let log = LogFile::from_buffer(data).unwrap();
    assert_eq!(log.restart_page().offset, 0x1000);
    assert_eq!(log.page_size(), 0x1000);
    let pages = log.record_pages();
    assert_eq!(pages.len(), 1);
    assert_eq!(pages[0].as_ref().unwrap().offset, 0x2000);
}

/// An array that misses a sector doesn't make a page lose to an older one whose sectors match no
/// better.
#[test]
fn a_short_update_sequence_array_does_not_outrank_the_lsn() {
    let mut data = restart_page(0x1000, 10);
    let mut short = restart_page(0x1000, 20);
    short[6..8].copy_from_slice(&8u16.to_le_bytes());
    data.extend(short);
    data.resize(0x4000, 0);
    let log = LogFile::from_buffer(data).unwrap();
    assert_eq!(log.restart_page().restart_area.current_lsn, 20);
    assert!(!log.restart_page().valid_fixup);
}

#[test]
fn lsn_offsets_drop_the_sequence_number() {
    let lsn = |sequence: u64, units: u64| (sequence << 20) | units;
    let mut data = two_restart_pages(lsn(7, 0x100), lsn(7, 0x100));
    data.resize(0x10_0000, 0);
    let log = LogFile::from_buffer(data).unwrap();
    // 44 sequence bits leave 20 bits of 8-byte units.
    assert_eq!(log.lsn_offset(lsn(7, 0x1234)), Some(0x1234 * 8));
    assert_eq!(log.lsn_offset(lsn(7, 0x2_0000)), None);
}

#[test]
fn lsn_offsets_ignore_the_pass() {
    let lsn = |sequence: u64, units: u64| (sequence << 20) | units;
    let mut data = two_restart_pages(lsn(7, 0x100), lsn(7, 0x100));
    data.resize(0x10_0000, 0);
    let log = LogFile::from_buffer(data).unwrap();
    assert_eq!(log.lsn_offset(0), None);
    // Pages that weren't reached again still hold records of passes long before the current one.
    for sequence in [1, 5, 6, 8, 9] {
        assert_eq!(log.lsn_offset(lsn(sequence, 0x1234)), Some(0x1234 * 8));
    }
    // An offset in the restart pages, or past the end of the file, is no record.
    assert_eq!(log.lsn_offset(lsn(7, 0x100)), None);
    assert_eq!(log.lsn_offset(lsn(7, 0x2_0000)), None);
}

#[test]
fn clients_follow_the_in_use_chain() {
    let mut page = restart_page(0x1000, 20);
    // Three slots: the chain is 2 -> 0, and slot 1 is free.
    page[0x38..0x3A].copy_from_slice(&3u16.to_le_bytes());
    page[0x3C..0x3E].copy_from_slice(&2u16.to_le_bytes());
    page[0x44..0x46].copy_from_slice(&0x250u16.to_le_bytes());
    set_client(&mut page, 1, 0xFFFF, "FREE");
    set_client(&mut page, 2, 0, "SECOND");
    let mut data = page.clone();
    data.extend(page);
    data.resize(0x4000, 0);
    let area = LogFile::from_buffer(data)
        .unwrap()
        .restart_page()
        .restart_area
        .clone();
    let names: Vec<_> = area.clients.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, ["SECOND", "NTFS"]);
    assert!(area.client_chain_intact);
}

#[test]
fn a_looping_or_truncated_client_chain_is_flagged() {
    let mut looping = restart_page(0x1000, 20);
    set_client(&mut looping, 0, 0, "NTFS");
    let mut data = looping.clone();
    data.extend(looping);
    data.resize(0x4000, 0);
    let area = LogFile::from_buffer(data)
        .unwrap()
        .restart_page()
        .restart_area
        .clone();
    assert_eq!(area.clients.len(), 1);
    assert!(!area.client_chain_intact);

    // The client array starts too near the end of the page for a whole client.
    let mut off_page = restart_page(0x1000, 20);
    off_page[0x46..0x48].copy_from_slice(&0xF80u16.to_le_bytes());
    let mut data = off_page.clone();
    data.extend(off_page);
    data.resize(0x4000, 0);
    let area = LogFile::from_buffer(data)
        .unwrap()
        .restart_page()
        .restart_area
        .clone();
    assert!(area.clients.is_empty());
    assert!(!area.client_chain_intact);
}

#[test]
fn a_garbage_restart_area_is_not_current() {
    let corruptions: [(usize, &[u8]); 4] = [
        // Sequence number bits.
        (0x40, &200u32.to_le_bytes()),
        // Restart area length, past the end of the page.
        (0x44, &0xFFFFu16.to_le_bytes()),
        // File size, smaller than the restart pages.
        (0x48, &0x100u64.to_le_bytes()),
        // Log page data offset, past the end of a record page.
        (0x56, &0x2000u16.to_le_bytes()),
    ];
    for (at, bytes) in corruptions {
        let mut data = restart_page(0x1000, 10);
        let mut garbage = restart_page(0x1000, 20);
        garbage[at..at + bytes.len()].copy_from_slice(bytes);
        data.extend(garbage);
        data.resize(0x4000, 0);
        let log = LogFile::from_buffer(data).unwrap();
        assert_eq!(log.restart_pages().len(), 1, "corruption at {at:#x}");
        assert_eq!(log.restart_page().restart_area.current_lsn, 10);
    }
}

#[test]
fn a_cut_short_last_page_is_reported_even_if_blank() {
    let mut data = two_restart_pages(10, 20);
    data.extend(record_page());
    data.resize(0x3800, 0);
    let log = LogFile::from_buffer(data).unwrap();
    let pages = log.record_pages();
    assert_eq!(pages.len(), 2);
    assert!(pages[0].is_ok());
    assert!(pages[1].is_err());
}

// Synthetic log records, in record pages from 0x2000 on, with log page data at 0x40 and 44
// sequence number bits.

/// The LSN of a record at `offset` in pass `sequence` of the log.
fn lsn(sequence: u64, offset: usize) -> u64 {
    (sequence << 20) | (offset as u64 / 8)
}

/// Writes the header of a record of `record_type` at `offset` of `data`, with `client_data_length`
/// bytes of client data, and returns its LSN (in pass 1).
fn put_record(data: &mut [u8], offset: usize, record_type: u32, client_data_length: u32) -> u64 {
    let lsn = lsn(1, offset);
    let header = &mut data[offset..offset + 0x30];
    header[..8].copy_from_slice(&lsn.to_le_bytes());
    header[0x18..0x1C].copy_from_slice(&client_data_length.to_le_bytes());
    header[0x20..0x24].copy_from_slice(&record_type.to_le_bytes());
    lsn
}

/// An NTFS client data header: `InitializeFileRecordSegment`, with its redo data at
/// `redo_offset`, `redo_length` long, and `lcns` LCNs to follow.
fn ntfs_header(redo_offset: u16, redo_length: u16, lcns: u16) -> [u8; 0x20] {
    let mut header = [0u8; 0x20];
    header[..2].copy_from_slice(&2u16.to_le_bytes());
    header[4..6].copy_from_slice(&redo_offset.to_le_bytes());
    header[6..8].copy_from_slice(&redo_length.to_le_bytes());
    header[0x0E..0x10].copy_from_slice(&lcns.to_le_bytes());
    header
}

/// A log whose client record starts at the end of the record page at 0x2000 and continues
/// into the one at 0x3000, whose header gets `continuation_lsn` as its last end LSN. Returns
/// the log and the record's LSN.
fn spanning_record(continuation_lsn: impl Fn(u64) -> u64, tear: bool) -> (Vec<u8>, u64) {
    let mut data = two_restart_pages(10, 20);
    data.extend(record_page());
    data.extend(record_page());
    // The header ends 0x10 bytes before the end of the page: the first 0x10 bytes of the client
    // data are there, the other 0x30 after the next page's header.
    let lsn = put_record(&mut data, 0x2FC0, 1, 0x40);
    let header = ntfs_header(0x20, 0x20, 0);
    data[0x2FF0..0x2FFE].copy_from_slice(&header[..0x0E]);
    data[0x3040..0x3050].copy_from_slice(&header[0x10..]);
    data[0x3050..0x3070].fill(0xAB);
    data[0x3020..0x3028].copy_from_slice(&continuation_lsn(lsn).to_le_bytes());
    if tear {
        data[0x33FE] = 7;
    }
    (data, lsn)
}

#[test]
fn a_record_continues_into_the_next_page() {
    let (data, lsn) = spanning_record(|lsn| lsn, false);
    let log = LogFile::from_buffer(data).unwrap();
    let records: Vec<_> = log.records().collect();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].lsn, lsn);
    let ntfs = records[0].ntfs.as_ref().unwrap();
    assert_eq!(
        ntfs.redo_operation_name,
        Some("InitializeFileRecordSegment")
    );
    assert_eq!(ntfs.redo_data, [0xAB; 0x20]);
    assert!(!ntfs.truncated);
}

#[test]
fn a_record_does_not_continue_into_a_page_that_is_not_its_rest() {
    let older = |lsn: u64| lsn - 1;
    let later_pass = |lsn: u64| lsn + (1 << 20);
    for (what, continuation_lsn, tear) in [
        ("torn", (|lsn| lsn) as fn(u64) -> u64, true),
        ("older", older, false),
        ("from a later pass", later_pass, false),
    ] {
        let (data, _) = spanning_record(continuation_lsn, tear);
        let log = LogFile::from_buffer(data).unwrap();
        assert_eq!(log.records().count(), 0, "{what}");
    }

    // A page that was never written isn't the rest of the record either.
    let (mut data, _) = spanning_record(|lsn| lsn, false);
    data[0x3000..].fill(0);
    assert_eq!(LogFile::from_buffer(data).unwrap().records().count(), 0);
}

#[test]
fn client_data_is_capped() {
    // Enough record pages, each continuing the record, for the longest client data and more.
    let mut data = two_restart_pages(10, 20);
    let pages = MAX_CLIENT_DATA_LENGTH / (0x1000 - 0x40) + 2;
    let first = lsn(1, 0x2040);
    for _ in 0..pages {
        let mut page = record_page();
        page[0x20..0x28].copy_from_slice(&first.to_le_bytes());
        data.extend(page);
    }
    let length = MAX_CLIENT_DATA_LENGTH as u32;
    put_record(&mut data, 0x2040, 2, length);
    assert_eq!(
        LogFile::from_buffer(data.clone())
            .unwrap()
            .records()
            .count(),
        1
    );
    put_record(&mut data, 0x2040, 2, length + 8);
    assert_eq!(LogFile::from_buffer(data).unwrap().records().count(), 0);
}

/// A log with one client record in its first record page, with this client data.
fn one_record(client_data: &[u8]) -> NtfsLogRecord {
    let mut data = two_restart_pages(10, 20);
    data.extend(record_page());
    put_record(&mut data, 0x2040, 1, client_data.len() as u32);
    data[0x2070..0x2070 + client_data.len()].copy_from_slice(client_data);
    let log = LogFile::from_buffer(data).unwrap();
    let mut records: Vec<_> = log.records().collect();
    assert_eq!(records.len(), 1);
    records.remove(0).ntfs.unwrap()
}

#[test]
fn lcns_end_before_the_redo_data() {
    let mut client_data = ntfs_header(0x28, 8, 0xFFFF).to_vec();
    client_data.extend(7u64.to_le_bytes());
    client_data.extend([0xAB; 8]);
    let ntfs = one_record(&client_data);
    assert_eq!(ntfs.lcns, [7]);
    assert_eq!(ntfs.redo_data, [0xAB; 8]);
    assert!(ntfs.truncated);

    let mut client_data = ntfs_header(0x28, 8, 1).to_vec();
    client_data.extend(7u64.to_le_bytes());
    client_data.extend([0xAB; 8]);
    let ntfs = one_record(&client_data);
    assert_eq!(ntfs.lcns, [7]);
    assert!(!ntfs.truncated);
}

#[test]
fn redo_data_past_the_client_data_is_truncated() {
    let mut client_data = ntfs_header(0x20, 0x100, 0).to_vec();
    client_data.extend([0xAB; 0x10]);
    let ntfs = one_record(&client_data);
    assert_eq!(ntfs.redo_data, [0xAB; 0x10]);
    assert!(ntfs.truncated);

    // No redo data is not damage.
    let ntfs = one_record(&ntfs_header(0x20, 0, 0));
    assert!(ntfs.redo_data.is_empty());
    assert!(!ntfs.truncated);
}
