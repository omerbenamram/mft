mod fixtures;

use fixtures::*;
use mft::Timestamp;
use mft::attribute::MftAttributeType;
use mft::attribute::header::ResidentialHeader;
use mft::attribute::x30::FileNamespace;
use mft::attribute::x90::{IndexCollationRules, IndexEntryFlags, ViewIndexValue};
use mft::entry::MftEntry;
use mft::err::Error as MftError;
use mft::mft::MftParser;

fn filetime_bytes_to_timestamp(bytes: [u8; 8]) -> Timestamp {
    mft::windows_filetime_to_timestamp(u64::from_le_bytes(bytes))
        .expect("valid FILETIME conversion")
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
        let attributes: Vec<_> = record.iter_attributes().filter_map(Result::ok).collect();
        for attribute in attributes {
            if attribute.header.type_code == MftAttributeType::IndexRoot {
                let index_root = attribute.data.as_index_root().unwrap();
                assert_eq!(
                    index_root.collation_rule,
                    IndexCollationRules::CollationFilename
                );
                let index_entries = &index_root.index_entries.index_entries;
                assert_eq!(index_entries.len(), 4);

                let created =
                    filetime_bytes_to_timestamp([0x00, 0x00, 0xC1, 0x03, 0xDB, 0x6A, 0xC6, 0x01]);
                let mft_modified =
                    filetime_bytes_to_timestamp([0x76, 0x86, 0xF6, 0x8C, 0x04, 0x64, 0xCA, 0x01]);

                let last_index_entry = &index_entries[3];
                assert_eq!(last_index_entry.mft_reference.entry, 26399);
                assert_eq!(last_index_entry.mft_reference.sequence, 1);
                assert_eq!(last_index_entry.index_record_length, 136);
                assert_eq!(last_index_entry.attr_fname_length, 110);
                assert_eq!(last_index_entry.flags, IndexEntryFlags::INDEX_ENTRY_NODE);
                assert_eq!(last_index_entry.fname_info.parent.entry, 26359);
                assert_eq!(last_index_entry.fname_info.parent.sequence, 1);
                assert_eq!(last_index_entry.fname_info.created, created);
                assert_eq!(last_index_entry.fname_info.modified, created);
                assert_eq!(last_index_entry.fname_info.mft_modified, mft_modified);
                assert_eq!(last_index_entry.fname_info.accessed, mft_modified);
                assert_eq!(last_index_entry.fname_info.logical_size, 1484);
                assert_eq!(last_index_entry.fname_info.physical_size, 4096);
                assert_eq!(
                    last_index_entry.fname_info.flags,
                    mft::attribute::FileAttributeFlags::FILE_ATTRIBUTE_ARCHIVE
                );
                assert_eq!(last_index_entry.fname_info.reparse_value, 0);
                assert_eq!(last_index_entry.fname_info.name_length, 22);
                assert_eq!(last_index_entry.fname_info.namespace, FileNamespace::Win32);
                assert_eq!(
                    last_index_entry.fname_info.name.to_utf8_string(),
                    "test_returnfuncptrs.py"
                );
            }
        }
    }
}

/// Asserts the view index entries in the index roots of `entry`, by index name.
fn assert_view_entries(entry: &MftEntry, expected: &[(&str, Vec<ViewIndexValue>)]) {
    let attributes: Vec<_> = entry.iter_attributes().map(Result::unwrap).collect();
    let actual: Vec<_> = attributes
        .iter()
        .filter_map(|attribute| {
            let index_root = attribute.data.as_index_root()?;
            assert!(index_root.index_entries.index_entries.is_empty());
            let values = index_root.index_entries.view_entries.iter();
            Some((
                attribute.header.name.to_string(),
                values.map(|entry| entry.value.clone()).collect::<Vec<_>>(),
            ))
        })
        .collect();
    let expected: Vec<_> = expected
        .iter()
        .map(|(name, values)| (name.to_string(), values.clone()))
        .collect();
    assert_eq!(actual, expected);
}

#[test]
fn test_view_index_entries() {
    let mut parser = MftParser::from_path(mft_sample()).unwrap();
    let secure = |hash, security_id, sds_offset, sds_length| ViewIndexValue::SecurityDescriptor {
        hash,
        security_id,
        sds_offset,
        sds_length,
    };
    assert_view_entries(
        &parser.get_entry(9).unwrap(),
        &[
            ("$SDH", vec![secure(0x8048_FB19, 301, 9648, 236)]),
            ("$SII", vec![secure(0x63D4_6E04, 305, 10400, 140)]),
        ],
    );

    let mut parser = MftParser::from_path(win11_sample("system.MFT")).unwrap();
    let change_time = mft::windows_filetime_to_timestamp(0x01DA_0BF0_48AD_BEF4).unwrap();
    let admins = "S-1-5-32-544".to_string();
    let quota = |owner_id, sid| ViewIndexValue::Quota {
        owner_id,
        version: 2,
        quota_flags: 1,
        bytes_used: 0,
        change_time,
        warning_limit: -1,
        hard_limit: -1,
        exceeded_time: None,
        sid,
    };
    assert_view_entries(
        &parser.get_entry(24).unwrap(),
        &[
            (
                "$O",
                vec![ViewIndexValue::QuotaOwner {
                    sid: admins.clone(),
                    owner_id: 256,
                }],
            ),
            ("$Q", vec![quota(1, None), quota(256, Some(admins))]),
        ],
    );
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

    // `MftEntry` serialization reports attribute parse errors instead of panicking.
    let json = serde_json::to_value(&entry).expect("entry should serialize");
    let errors = json["errors"].as_array().expect("expected an errors field");
    assert!(
        errors.iter().any(|e| e
            .as_str()
            .is_some_and(|s| s.contains("out of range for jiff::Timestamp"))),
        "unexpected errors: {errors:?}"
    );
}

#[test]
fn test_json_lists_attribute_errors() {
    let mut parser = MftParser::from_path(mft_sample()).unwrap();
    let mut entry = parser.get_entry(0).unwrap();

    let clean: serde_json::Value = serde_json::to_value(&entry).unwrap();
    assert!(
        clean.get("errors").is_none(),
        "entries that parse cleanly should not carry an errors field"
    );

    // Corrupt the form code (byte 8 of the header) of the second attribute ($FILE_NAME) so its
    // header fails to parse.
    let second = entry
        .iter_attributes()
        .nth(1)
        .unwrap()
        .unwrap()
        .header
        .start_offset as usize;
    entry.data[second + 8] = 0x7F;

    let json: serde_json::Value = serde_json::to_value(&entry).unwrap();
    let errors = json["errors"].as_array().expect("expected an errors field");
    assert_eq!(errors.len(), 1);
    assert!(
        errors[0]
            .as_str()
            .unwrap()
            .contains("Unhandled resident flag: 127"),
        "unexpected error message: {}",
        errors[0]
    );
    // The attribute before the corrupt one is still emitted.
    let attributes = json["attributes"].as_array().unwrap();
    assert_eq!(attributes.len(), 1);
}

#[test]
fn test_bitflags_serialize_as_flag_names() {
    use mft::attribute::x90::IndexRootFlags;
    use mft::attribute::{AttributeDataFlags, FileAttributeFlags};
    use mft::entry::EntryFlags;

    let flags =
        FileAttributeFlags::FILE_ATTRIBUTE_HIDDEN | FileAttributeFlags::FILE_ATTRIBUTE_SYSTEM;
    assert_eq!(
        serde_json::to_string(&flags).unwrap(),
        r#""FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM""#
    );
    assert_eq!(
        serde_json::to_string(&EntryFlags::ALLOCATED).unwrap(),
        r#""ALLOCATED""#
    );
    assert_eq!(
        serde_json::to_string(&AttributeDataFlags::empty()).unwrap(),
        r#""(empty)""#
    );
    // A zero-valued flag names the empty set.
    assert_eq!(IndexRootFlags::empty().to_string(), "SMALL_INDEX");
    assert_eq!(IndexRootFlags::LARGE_INDEX.to_string(), "LARGE_INDEX");
}

#[test]
fn test_volume_attributes_are_parsed() {
    let mut parser = MftParser::from_path(mft_sample()).unwrap();
    let volume = parser.get_entry(3).unwrap();

    let name = volume
        .iter_attributes_matching(Some(vec![MftAttributeType::VolumeName]))
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(
        name.data.as_volume_name().unwrap().name.to_utf8_string(),
        ""
    );

    let info = volume
        .iter_attributes_matching(Some(vec![MftAttributeType::VolumeInformation]))
        .next()
        .unwrap()
        .unwrap();
    let info = info.data.as_volume_information().unwrap();
    assert_eq!((info.major_version, info.minor_version), (3, 1));
    assert!(info.flags.is_empty());
}
