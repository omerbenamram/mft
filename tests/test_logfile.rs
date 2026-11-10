mod fixtures;

use fixtures::*;
use mft::logfile::{LogFile, RestartAreaFlags};

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
