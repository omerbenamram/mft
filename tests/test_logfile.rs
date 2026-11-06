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
