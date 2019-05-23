use crate::attribute::x30::FileNamespace;
use crate::attribute::{FileAttributeFlags, MftAttributeContent, MftAttributeType};
use crate::entry::EntryFlags;
use crate::{MftAttribute, MftEntry, MftParser, ReadSeek};

use serde::Serialize;

use chrono::{DateTime, Utc};
use std::path::PathBuf;

/// Used for CSV output
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct FlatMftEntryWithName {
    pub signature: String,

    pub entry_id: u64,
    pub sequence: u16,

    pub base_entry_id: u64,
    pub base_entry_sequence: u16,

    pub hard_link_count: u16,
    pub flags: EntryFlags,

    /// The size of the file, in bytes.
    pub used_entry_size: u32,
    pub total_entry_size: u32,

    /// Indicates whether the record is a directory.
    pub is_a_directory: bool,

    /// Indicates whether the record has alternate data streams.
    pub has_alternate_data_streams: bool,

    /// All of these fields are present for entries that have an 0x10 attribute.
    pub standard_info_flags: Option<FileAttributeFlags>,
    pub standard_info_last_modified: Option<DateTime<Utc>>,
    pub standard_info_last_access: Option<DateTime<Utc>>,
    pub standard_info_created: Option<DateTime<Utc>>,
    /// All of these fields are present for entries that have an 0x30 attribute.
    pub file_name_flags: Option<FileAttributeFlags>,
    pub file_name_last_modified: Option<DateTime<Utc>>,
    pub file_name_last_access: Option<DateTime<Utc>>,
    pub file_name_created: Option<DateTime<Utc>>,

    pub full_path: PathBuf,
}

impl FlatMftEntryWithName {
    pub fn from_entry(
        entry: &MftEntry,
        parser: &mut MftParser<impl ReadSeek>,
    ) -> FlatMftEntryWithName {
        let entry_attributes: Vec<MftAttribute> = entry
            .iter_attributes_matching(Some(vec![
                MftAttributeType::FileName,
                MftAttributeType::StandardInformation,
                MftAttributeType::DATA,
            ]))
            .filter_map(Result::ok)
            .collect();

        let mut file_name = None;
        let mut standard_info = None;

        for attr in entry_attributes.iter() {
            if let MftAttributeContent::AttrX30(data) = &attr.data {
                if [FileNamespace::Win32, FileNamespace::Win32AndDos].contains(&data.namespace) {
                    file_name = Some(data.clone());
                    break;
                }
            }
        }
        for attr in entry_attributes.iter() {
            if let MftAttributeContent::AttrX10(data) = &attr.data {
                standard_info = Some(data.clone());
                break;
            }
        }

        let has_ads = entry_attributes
            .iter()
            .any(|a| a.header.type_code == MftAttributeType::DATA && a.header.name_size > 0);

        FlatMftEntryWithName {
            entry_id: entry.header.record_number,
            signature: String::from_utf8(entry.header.signature.to_ascii_uppercase())
                .expect("It should be either FILE or BAAD (valid utf-8)"),
            sequence: entry.header.sequence,
            hard_link_count: entry.header.hard_link_count,
            flags: entry.header.flags,
            used_entry_size: entry.header.used_entry_size,
            total_entry_size: entry.header.total_entry_size,
            base_entry_id: entry.header.base_reference.entry,
            base_entry_sequence: entry.header.base_reference.sequence,
            is_a_directory: entry.is_dir(),
            has_alternate_data_streams: has_ads,
            standard_info_flags: standard_info.as_ref().and_then(|i| Some(i.file_flags)),
            standard_info_last_modified: standard_info.as_ref().and_then(|i| Some(i.modified)),
            standard_info_last_access: standard_info.as_ref().and_then(|i| Some(i.accessed)),
            standard_info_created: standard_info.as_ref().and_then(|i| Some(i.created)),
            file_name_flags: file_name.as_ref().and_then(|i| Some(i.flags)),
            file_name_last_modified: file_name.as_ref().and_then(|i| Some(i.modified)),
            file_name_last_access: file_name.as_ref().and_then(|i| Some(i.accessed)),
            file_name_created: file_name.as_ref().and_then(|i| Some(i.created)),
            full_path: parser
                .get_full_path_for_entry(entry)
                .expect("I/O Err")
                .unwrap_or_default(),
        }
    }
}
