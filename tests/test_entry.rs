mod fixtures;

use fixtures::*;
use mft::entry::MftEntry;
use mft::mft::MftParser;
use mft::attribute::{MftAttribute, MftAttributeType, FileAttributeFlags};
use mft::attribute::x90::{IndexEntryHeader, IndexEntryFlags, IndexCollationRules};
use mft::attribute::x30::{FileNameAttr, FileNamespace};
use winstructs::ntfs:: mft_reference::MftReference;
use winstructs::timestamp::WinTimestamp;
use serde_json;

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
        let attributes: Vec<MftAttribute> = record.iter_attributes().filter_map(Result::ok).collect();
        for attribute in attributes {
            if attribute.header.type_code == MftAttributeType::IndexRoot {
                let index_root = attribute.data.into_index_root().unwrap();
                assert_eq!(index_root.collation_rule, IndexCollationRules::CollationFilename);
                let index_entries = index_root.index_entries.index_entries;
                assert_eq!(index_entries.len(), 4);

                let created = WinTimestamp::new(&[0x00, 0x00, 0xC1, 0x03, 0xDB, 0x6A, 0xC6, 0x01]).unwrap().to_datetime();
                let mft_modified = WinTimestamp::new(&[0x76, 0x86, 0xF6, 0x8C, 0x04, 0x64, 0xCA, 0x01]).unwrap().to_datetime();

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
                        created: created,
                        modified: created,
                        mft_modified: mft_modified,
                        accessed: mft_modified,
                        logical_size: 4096,
                        physical_size: 1484,
                        flags: FileAttributeFlags::FILE_ATTRIBUTE_ARCHIVE,
                        reparse_value: 0,
                        name_length: 22,
                        namespace: FileNamespace::Win32,
                        name: "test_returnfuncptrs.py".to_string()
                    }
                };                
                let last_index_entry = &index_entries[3];
                assert_eq!(last_index_entry, &index_entry_comp);
            }
        }
    }
}
