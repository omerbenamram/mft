use crate::attribute::header::ResidentialHeader;

use crate::attribute::{FileAttributeFlags, MftAttributeType};
use crate::entry::EntryFlags;
use crate::{MftAttribute, MftEntry, MftParser};

use serde::Serialize;

use chrono::{DateTime, Utc};
use std::io::{Read, Seek};

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

    /// The size of the file, if available, from the X80 attribute.
    /// Will be 0 if no $DATA attribute is found.
    pub file_size: u64,

    /// Indicates whether the record is a directory.
    pub is_a_directory: bool,
    /// Indicates whether the record has the `ALLOCATED` bit turned off.
    pub is_deleted: bool,

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

    pub full_path: String,
}

impl FlatMftEntryWithName {
    pub fn from_entry(
        entry: &MftEntry,
        parser: &mut MftParser<impl Read + Seek>,
    ) -> FlatMftEntryWithName {
        let entry_attributes: Vec<MftAttribute> = entry
            .iter_attributes_matching(Some(vec![
                MftAttributeType::FileName,
                MftAttributeType::StandardInformation,
                MftAttributeType::DATA,
            ]))
            .filter_map(Result::ok)
            .collect();

        let file_name = entry_attributes
            .iter()
            .find(|a| a.header.type_code == MftAttributeType::FileName)
            .and_then(|a| a.data.clone().into_file_name());

        let standard_info = entry_attributes
            .iter()
            .find(|a| a.header.type_code == MftAttributeType::StandardInformation)
            .and_then(|a| a.data.clone().into_standard_info());

        let data_attr = entry_attributes
            .iter()
            .find(|a| a.header.type_code == MftAttributeType::DATA);

        let file_size = match data_attr {
            Some(attr) => match &attr.header.residential_header {
                ResidentialHeader::Resident(r) => u64::from(r.data_size),
                ResidentialHeader::NonResident(nr) => nr.file_size,
            },
            _ => 0,
        };

        let has_ads = entry_attributes
            .iter()
            .any(|a| a.header.type_code == MftAttributeType::DATA && !a.header.name.is_empty());

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
            is_deleted: !entry.header.flags.contains(EntryFlags::ALLOCATED),
            has_alternate_data_streams: has_ads,
            standard_info_flags: standard_info.as_ref().map(|i| i.file_flags),
            standard_info_last_modified: standard_info.as_ref().map(|i| i.modified),
            standard_info_last_access: standard_info.as_ref().map(|i| i.accessed),
            standard_info_created: standard_info.as_ref().map(|i| i.created),
            file_name_flags: file_name.as_ref().map(|i| i.flags),
            file_name_last_modified: file_name.as_ref().map(|i| i.modified),
            file_name_last_access: file_name.as_ref().map(|i| i.accessed),
            file_name_created: file_name.as_ref().map(|i| i.created),
            file_size,
            full_path: parser
                .get_full_path_for_entry(entry)
                .expect("I/O Err")
                .unwrap_or_default(),
        }
    }
}
