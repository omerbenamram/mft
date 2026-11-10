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

/// Swaps the last two bytes of each sector of the page at `page` with its update sequence array,
/// which applies the page's fixups or, done again, takes them back.
fn swap_fixups(data: &mut [u8], page: usize) {
    for sector in 1..=8 {
        let (end, entry) = (page + sector * 512 - 2, page + 0x28 + 2 * sector);
        for i in 0..2 {
            data.swap(end + i, entry + i);
        }
    }
}

#[test]
fn it_reads_records_that_are_only_in_a_tail_copy() {
    let path = testdata_dir()
        .join("logfile")
        .join("narcos-sysreserved-head.LogFile");
    let clean = std::fs::read(path).unwrap();
    let lsns = |log: &LogFile| log.records().map(|r| r.lsn).collect::<Vec<_>>();
    let mut clean_lsns = lsns(&LogFile::from_buffer(clean.clone()).unwrap());
    clean_lsns.sort_unstable();

    // The two tail copies are of the page at 0x24000, which has the same 9 records.
    let home = 0x24000;
    assert_eq!(clean[0x2008..0x2010], (home as u64).to_le_bytes());

    // After a crash the page can be an older version of itself: here, one with its first 3
    // records, the third of which ends at 0x218.
    let mut older = clean.clone();
    swap_fixups(&mut older, home);
    let third_lsn = older[home + 0x150..home + 0x158].to_vec();
    assert_eq!(third_lsn, 25_184_298u64.to_le_bytes());
    older[home + 0x218..home + 0x1000].fill(0);
    older[home + 0x18..home + 0x1A].copy_from_slice(&0x218u16.to_le_bytes());
    older[home + 8..home + 0x10].copy_from_slice(&third_lsn);
    older[home + 0x20..home + 0x28].copy_from_slice(&third_lsn);
    swap_fixups(&mut older, home);

    // Or a page that was never written.
    let mut blank = clean.clone();
    blank[home..home + 0x1000].fill(0xFF);

    for (dirty, in_copy) in [(older, 6), (blank, 9)] {
        let log = LogFile::from_buffer(dirty).unwrap();
        let records: Vec<_> = log.records().collect();
        let mut dirty_lsns: Vec<_> = records.iter().map(|r| r.lsn).collect();
        dirty_lsns.sort_unstable();
        assert_eq!(dirty_lsns, clean_lsns);
        // The records the page lost are read from the first tail copy.
        let from_copy: Vec<_> = records
            .iter()
            .filter(|r| log.lsn_offset(r.lsn) != Some(r.offset))
            .collect();
        assert_eq!(from_copy.len(), in_copy);
        assert!(
            from_copy
                .iter()
                .all(|r| (0x2000..0x3000).contains(&r.offset))
        );
        let current = log.restart_page().restart_area.current_lsn;
        assert!(from_copy.iter().any(|r| r.lsn == current));
    }
}
