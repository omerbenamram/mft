mod fixtures;

use fixtures::*;
use mft::MftEntry;
use mft::csv::{CsvRows, FlatMftEntryWithName};
use std::path::PathBuf;

fn win11_entry(entry_id: u64, name: &str) -> MftEntry {
    let data = std::fs::read(win11_sample(&format!("entry_{entry_id}_{name}"))).unwrap();
    MftEntry::from_buffer(data, entry_id).unwrap()
}

/// The rows of a single record, with `link_path` standing in for path resolution.
fn rows(entry: &MftEntry, rows: CsvRows) -> Vec<FlatMftEntryWithName> {
    FlatMftEntryWithName::rows_with_path(entry, &[], PathBuf::from("file"), rows, |name| {
        PathBuf::from(format!("{}\\{}", name.parent.entry, name.name))
    })
}

#[test]
fn hard_link_rows_add_a_row_per_other_long_name() {
    // `MMCEx.dll`, linked from `WinSxS` (directory 1614, a `POSIX` name) and the GAC (directory
    // 18333, the `Win32AndDos` name that the path is built from).
    let entry = win11_entry(45647, "hard_links");

    assert_eq!(rows(&entry, CsvRows::default()).len(), 1);

    let links = rows(
        &entry,
        CsvRows {
            hard_links: true,
            ..CsvRows::default()
        },
    );
    let paths: Vec<_> = links.iter().map(|row| row.full_path.clone()).collect();
    assert_eq!(
        paths,
        [PathBuf::from("file"), PathBuf::from("1614\\MMCEx.dll")]
    );
    for row in &links {
        assert_eq!(row.entry_id, 45647);
        assert_eq!(row.file_name.as_deref(), Some("MMCEx.dll"));
    }

    // A file's only long name gets no extra row.
    let single = win11_entry(358, "appexeclink");
    let hard_links = CsvRows {
        hard_links: true,
        ..CsvRows::default()
    };
    assert_eq!(rows(&single, hard_links).len(), 1);
}

#[test]
fn stream_rows_add_a_row_per_named_stream() {
    let entry = win11_entry(95063, "usn_journal");
    let streams = rows(
        &entry,
        CsvRows {
            streams: true,
            ..CsvRows::default()
        },
    );

    let summary: Vec<_> = streams
        .iter()
        .map(|row| (row.full_path.clone(), row.file_name.clone(), row.file_size))
        .collect();
    let file_size = streams[0].file_size;
    assert_eq!(
        summary,
        [
            (
                PathBuf::from("file"),
                Some("$UsnJrnl".to_string()),
                file_size
            ),
            (
                PathBuf::from("file:$J"),
                Some("$UsnJrnl:$J".to_string()),
                519_854_576
            ),
            (
                PathBuf::from("file:$Max"),
                Some("$UsnJrnl:$Max".to_string()),
                32
            ),
        ]
    );
}

#[test]
#[cfg(feature = "mft_dump")]
fn extra_rows_need_csv_output() {
    let dir = tempfile::tempdir().unwrap();
    let previous = dir.path().join("previous.json");
    std::fs::write(&previous, "earlier output").unwrap();

    let output = assert_cmd::cargo::cargo_bin_cmd!("mft_dump")
        .args([
            "-o",
            "json",
            "--stream-rows",
            "--no-confirm-overwrite",
            "-f",
        ])
        .arg(&previous)
        .arg(mft_sample())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("only apply to `-o csv`"));
    // The mistake is caught before the output file is truncated.
    assert_eq!(
        std::fs::read_to_string(&previous).unwrap(),
        "earlier output"
    );
}
