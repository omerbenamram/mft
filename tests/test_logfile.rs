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
