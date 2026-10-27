//! Snapshot tests for the serialized output of selected sample entries.
//!
//! These guard the JSON and CSV output formats against accidental changes. When a change to the
//! output is intentional, review and accept the new snapshots with `cargo insta review`.
mod fixtures;

use fixtures::*;
use mft::mft::MftParser;
use std::collections::BTreeSet;

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

/// Formats an entry list as an `mft_dump --ranges` argument.
fn ranges_arg(ids: impl IntoIterator<Item = u64>) -> String {
    ids.into_iter()
        .map(|id| id.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// `mft_dump` uses a different JSON serializer for JSONL than the library's serde_json output, so
/// snapshot the CLI output too. CSV covers the first 40 records plus the JSON entries.
#[test]
#[cfg(feature = "mft_dump")]
fn test_cli_output_snapshots() {
    use assert_cmd::cargo::cargo_bin_cmd;

    let json_ids = || JSON_ENTRIES.iter().map(|&(id, _)| id);
    let csv_ids: BTreeSet<u64> = (0..40).chain(json_ids()).collect();

    // Both formats carry full paths, written with `\` on every platform.
    for (format, ids) in [
        ("jsonl", ranges_arg(json_ids())),
        ("csv", ranges_arg(csv_ids)),
    ] {
        let mut cmd = cargo_bin_cmd!("mft_dump");
        cmd.arg("-o")
            .arg(format)
            .arg("-r")
            .arg(ids)
            .arg(mft_sample());
        let output = cmd.output().unwrap();
        assert!(
            output.status.success(),
            "mft_dump failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let stdout = String::from_utf8(output.stdout).unwrap();
        insta::assert_snapshot!(format!("cli_{format}_selected_entries"), stdout);
    }
}
