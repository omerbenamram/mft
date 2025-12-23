mod fixtures;

use fixtures::*;
use mft::Timestamp;
use mft::attribute::header::ResidentialHeader;
use mft::attribute::x30::{FileNameAttr, FileNamespace};
use mft::attribute::x90::{IndexCollationRules, IndexEntryFlags, IndexEntryHeader};
use mft::attribute::{FileAttributeFlags, MftAttribute, MftAttributeType};
use mft::entry::MftEntry;
use mft::err::Error as MftError;
use mft::mft::MftParser;
use winstructs::ntfs::mft_reference::MftReference;

fn filetime_bytes_to_timestamp(bytes: [u8; 8]) -> Timestamp {
    // Windows FILETIME: 100ns intervals since 1601-01-01 UTC.
    // Match historical behavior (`winstructs::timestamp::WinTimestamp::to_datetime`):
    // truncate to microseconds.
    const WINDOWS_TO_UNIX_EPOCH_MICROS: i64 = 11_644_473_600_000_000;
    let filetime_100ns = u64::from_le_bytes(bytes);

    let micros_since_windows_epoch = (filetime_100ns / 10) as i64;
    let micros_since_unix_epoch = micros_since_windows_epoch - WINDOWS_TO_UNIX_EPOCH_MICROS;

    let seconds = micros_since_unix_epoch.div_euclid(1_000_000);
    let subsec_micros = micros_since_unix_epoch.rem_euclid(1_000_000);
    let subsec_nanos = (subsec_micros * 1_000) as i32;

    Timestamp::new(seconds, subsec_nanos).expect("valid FILETIME conversion")
}

#[test]
fn test_entry_invalid_fixup_value() {
    let mft_entry_buffer = include_bytes!("../samples/entry_102130_fixup_issue");

    let entry =
        MftEntry::from_buffer(mft_entry_buffer.to_vec(), 102130).expect("Failed to parse entry");

    assert_eq!(entry.valid_fixup, Some(false));

    let mft_json_value = serde_json::to_value(&entry).expect("Error serializing MftEntry");
    assert_eq!(
        mft_json_value["valid_fixup"],
        serde_json::value::Value::from(false)
    );
}

#[test]
fn test_entry_index_root() {
    let sample = mft_sample_name("entry_multiple_index_root_entries");
    let mut parser = MftParser::from_path(sample).unwrap();

    for record in parser.iter_entries().take(1).filter_map(|a| a.ok()) {
        let attributes: Vec<MftAttribute> =
            record.iter_attributes().filter_map(Result::ok).collect();
        for attribute in attributes {
            if attribute.header.type_code == MftAttributeType::IndexRoot {
                let index_root = attribute.data.into_index_root().unwrap();
                assert_eq!(
                    index_root.collation_rule,
                    IndexCollationRules::CollationFilename
                );
                let index_entries = index_root.index_entries.index_entries;
                assert_eq!(index_entries.len(), 4);

                let created =
                    filetime_bytes_to_timestamp([0x00, 0x00, 0xC1, 0x03, 0xDB, 0x6A, 0xC6, 0x01]);
                let mft_modified =
                    filetime_bytes_to_timestamp([0x76, 0x86, 0xF6, 0x8C, 0x04, 0x64, 0xCA, 0x01]);

                let index_entry_comp = IndexEntryHeader {
                    mft_reference: MftReference {
                        entry: 26399,
                        sequence: 1,
                    },
                    index_record_length: 136,
                    attr_fname_length: 110,
                    flags: IndexEntryFlags::INDEX_ENTRY_NODE,
                    fname_info: FileNameAttr {
                        parent: MftReference {
                            entry: 26359,
                            sequence: 1,
                        },
                        created,
                        modified: created,
                        mft_modified,
                        accessed: mft_modified,
                        logical_size: 4096,
                        physical_size: 1484,
                        flags: FileAttributeFlags::FILE_ATTRIBUTE_ARCHIVE,
                        reparse_value: 0,
                        name_length: 22,
                        namespace: FileNamespace::Win32,
                        name: "test_returnfuncptrs.py".to_string(),
                    },
                };
                let last_index_entry = &index_entries[3];
                assert_eq!(last_index_entry, &index_entry_comp);
            }
        }
    }
}

#[test]
fn test_out_of_range_filetime_is_error_not_panic() {
    // Start from a real on-disk entry buffer, then corrupt a FILETIME inside the
    // $STANDARD_INFORMATION (0x10) payload.
    let mut raw = include_bytes!("../samples/entry_single_file").to_vec();

    // First parse the entry to discover the exact on-disk offsets for the $STANDARD_INFORMATION
    // resident payload.
    let entry = MftEntry::from_buffer(raw.clone(), 0).expect("failed to parse entry fixture");
    let (attr_start, data_offset) = entry
        .iter_attributes()
        .filter_map(Result::ok)
        .find_map(|attr| {
            if attr.header.type_code != MftAttributeType::StandardInformation {
                return None;
            }
            match attr.header.residential_header {
                ResidentialHeader::Resident(resident) => {
                    Some((attr.header.start_offset, resident.data_offset))
                }
                ResidentialHeader::NonResident(_) => None,
            }
        })
        .expect("fixture should contain a resident $STANDARD_INFORMATION attribute");

    let data_start =
        usize::try_from(attr_start).expect("attr_start fits in usize") + usize::from(data_offset);
    assert!(data_start + 8 <= raw.len(), "corrupt offset is in-bounds");

    // Corrupt the first FILETIME (created) to an out-of-range value for `jiff::Timestamp`.
    raw[data_start..data_start + 8].copy_from_slice(&u64::MAX.to_le_bytes());

    // Re-parse and ensure we get a clean error (no panic), and the entry still serializes.
    let entry = MftEntry::from_buffer(raw, 0).expect("failed to parse corrupted entry");

    let mut saw_out_of_range = false;
    for res in entry.iter_attributes() {
        match res {
            Ok(_) => {}
            Err(MftError::FiletimeTimestampOutOfRange { filetime_100ns }) => {
                saw_out_of_range = true;
                assert_eq!(filetime_100ns, u64::MAX);
            }
            Err(_) => {}
        }
    }
    assert!(
        saw_out_of_range,
        "expected an out-of-range timestamp error while parsing attributes"
    );

    // `MftEntry` serialization drops attribute parse errors; it should never panic.
    serde_json::to_value(&entry).expect("entry should serialize");
}
