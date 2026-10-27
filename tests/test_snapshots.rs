//! Snapshot tests for the serialized output of selected sample entries.
//!
//! These guard the JSON and CSV output formats against accidental changes. When a change to the
//! output is intentional, review and accept the new snapshots with `cargo insta review`.
mod fixtures;

use fixtures::*;
use mft::csv::FlatMftEntryWithName;
use mft::mft::MftParser;

/// Entries chosen to cover different record shapes in `samples/MFT`.
const JSON_ENTRIES: &[(u64, &str)] = &[
    (0, "mft"),
    (3, "volume"),
    (5, "root_directory"),
    (9, "secure"),
    (462, "object_id"),
    (3498, "attribute_list"),
    (8671, "alternate_data_stream"),
    (11600, "deleted"),
];

/// Full paths are built with the platform's separator, so Windows output uses `\\`.
fn normalize_path_separators(s: &str) -> String {
    if cfg!(windows) {
        s.replace('\\', "/")
    } else {
        s.to_string()
    }
}

#[test]
fn test_json_output_snapshots() {
    ensure_env_logger_initialized();
    let mut parser = MftParser::from_path(mft_sample()).unwrap();

    for &(entry_id, name) in JSON_ENTRIES {
        let entry = parser.get_entry(entry_id).unwrap();
        let json = serde_json::to_string_pretty(&entry).unwrap();
        insta::assert_snapshot!(format!("json_entry_{entry_id}_{name}"), json);
    }
}

#[test]
fn test_csv_output_snapshot() {
    ensure_env_logger_initialized();
    let mut parser = MftParser::from_path(mft_sample()).unwrap();

    let entry_ids: Vec<u64> = (0..40)
        .chain(JSON_ENTRIES.iter().map(|(id, _)| *id))
        .collect();

    let mut writer = csv::Writer::from_writer(Vec::new());
    for entry_id in entry_ids {
        let entry = parser.get_entry(entry_id).unwrap();
        if !entry.header.is_valid() {
            continue;
        }
        let flat = FlatMftEntryWithName::from_entry(&entry, &mut parser);
        writer.serialize(flat).unwrap();
    }

    let csv = String::from_utf8(writer.into_inner().unwrap()).unwrap();
    insta::assert_snapshot!("csv_selected_entries", normalize_path_separators(&csv));
}

/// `mft_dump` uses a different JSON serializer for JSONL than the library's serde_json output, so
/// snapshot the CLI output too.
#[test]
#[cfg(feature = "mft_dump")]
fn test_cli_output_snapshots() {
    use assert_cmd::cargo::cargo_bin_cmd;

    let ranges = "0,3,5,9,462,3498,8671,11600";

    for format in ["jsonl", "csv"] {
        let mut cmd = cargo_bin_cmd!("mft_dump");
        cmd.arg("-o")
            .arg(format)
            .arg("-r")
            .arg(ranges)
            .arg(mft_sample());
        let output = cmd.output().unwrap();
        assert!(
            output.status.success(),
            "mft_dump failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let stdout = normalize_path_separators(&String::from_utf8(output.stdout).unwrap());
        insta::assert_snapshot!(format!("cli_{format}_selected_entries"), stdout);
    }
}
