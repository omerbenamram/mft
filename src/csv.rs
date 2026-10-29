use crate::attribute::{FileAttributeFlags, MftAttributeType};
use crate::entry::{EntryFlags, find_best_name_attribute_in};
use crate::{MftAttribute, MftEntry, MftParser};

use serde::Serialize;

use jiff::Timestamp;
use std::io::{Read, Seek};
use std::path::PathBuf;
use winstructs::guid::Guid;

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
    #[serde(serialize_with = "crate::utils::serialize_option_timestamp")]
    pub standard_info_last_modified: Option<Timestamp>,
    #[serde(serialize_with = "crate::utils::serialize_option_timestamp")]
    pub standard_info_last_access: Option<Timestamp>,
    #[serde(serialize_with = "crate::utils::serialize_option_timestamp")]
    pub standard_info_created: Option<Timestamp>,
    /// All of these fields are present for entries that have an 0x30 attribute. They come from the
    /// best name (`Win32` over `POSIX` over `Dos`), the same one the full path uses.
    pub file_name_flags: Option<FileAttributeFlags>,
    #[serde(serialize_with = "crate::utils::serialize_option_timestamp")]
    pub file_name_last_modified: Option<Timestamp>,
    #[serde(serialize_with = "crate::utils::serialize_option_timestamp")]
    pub file_name_last_access: Option<Timestamp>,
    #[serde(serialize_with = "crate::utils::serialize_option_timestamp")]
    pub file_name_created: Option<Timestamp>,

    /// Written with `\` separators on every platform.
    #[serde(serialize_with = "crate::utils::serialize_windows_path")]
    pub full_path: PathBuf,

    // These come after `FullPath` so the earlier columns keep their positions.
    #[serde(serialize_with = "crate::utils::serialize_option_timestamp")]
    pub standard_info_last_mft_modified: Option<Timestamp>,
    #[serde(serialize_with = "crate::utils::serialize_option_timestamp")]
    pub file_name_last_mft_modified: Option<Timestamp>,

    /// The best `$FILE_NAME` name, the last part of `FullPath`.
    pub file_name: Option<String>,
    /// The `$LogFile` sequence number of the record's last change.
    pub lsn: u64,
    /// The update sequence number of the file's last change in `$Extend\$UsnJrnl`, from
    /// `$STANDARD_INFORMATION`. 0 if the journal hasn't recorded the file.
    pub usn: Option<u64>,
    /// The file's security descriptor id in `$Secure`, from `$STANDARD_INFORMATION`.
    pub security_id: Option<u32>,
    /// The object id from `$OBJECT_ID`, if the file has one.
    pub object_id: Option<Guid>,
    /// The names of the named `$DATA` streams, separated by `|`.
    pub alternate_data_streams: String,
}

impl FlatMftEntryWithName {
    pub fn from_entry(
        entry: &MftEntry,
        parser: &mut MftParser<impl Read + Seek>,
    ) -> FlatMftEntryWithName {
        let full_path = parser
            .get_full_path_for_entry(entry)
            .expect("I/O Err")
            .unwrap_or_default();
        let extensions = parser.get_extension_entries(entry);
        Self::from_entry_with_path(entry, &extensions, full_path)
    }

    /// Same as [`FlatMftEntryWithName::from_entry`], for callers that already resolved the
    /// entry's full path and read its extension records (see
    /// [`MftParser::get_extension_entries`]).
    pub fn from_entry_with_path(
        entry: &MftEntry,
        extensions: &[MftEntry],
        full_path: PathBuf,
    ) -> FlatMftEntryWithName {
        let entry_attributes: Vec<MftAttribute> = std::iter::once(entry)
            .chain(extensions)
            .flat_map(|record| {
                record.iter_attributes_matching(Some(vec![
                    MftAttributeType::StandardInformation,
                    MftAttributeType::ObjectId,
                    MftAttributeType::DATA,
                ]))
            })
            .filter_map(Result::ok)
            .collect();

        let file_name = find_best_name_attribute_in(entry, extensions);

        let standard_info = entry_attributes
            .iter()
            .find(|a| a.header.type_code == MftAttributeType::StandardInformation)
            .and_then(|a| a.data.as_standard_info())
            .cloned();

        // The unnamed stream, or a named one if there is none. Records that continue a stream
        // started elsewhere don't hold its size.
        let file_size = entry_attributes
            .iter()
            .filter(|a| a.header.type_code == MftAttributeType::DATA && !a.header.is_continuation())
            .min_by_key(|a| !a.header.name.is_empty())
            .map_or(0, |a| a.header.value_size());

        let object_id = entry_attributes
            .iter()
            .find_map(|a| a.data.as_object_id())
            .map(|o| o.object_id.clone());

        // A stream spread over several records has a header in each, so keep its first.
        let mut streams: Vec<String> = Vec::new();
        for a in &entry_attributes {
            if a.header.type_code == MftAttributeType::DATA && !a.header.name.is_empty() {
                let name = a.header.name.to_string();
                if !streams.contains(&name) {
                    streams.push(name);
                }
            }
        }

        FlatMftEntryWithName {
            entry_id: entry.header.record_number,
            signature: String::from_utf8(entry.header.signature.to_ascii_uppercase())
                .expect("It should be either FILE or BAAD (valid utf-8)"),
            sequence: entry.header.sequence,
            hard_link_count: entry.header.hard_link_count,
            flags: entry.header.flags.clone(),
            used_entry_size: entry.header.used_entry_size,
            total_entry_size: entry.header.total_entry_size,
            base_entry_id: entry.header.base_reference.entry,
            base_entry_sequence: entry.header.base_reference.sequence,
            is_a_directory: entry.is_dir(),
            is_deleted: !entry.header.flags.contains(EntryFlags::ALLOCATED),
            has_alternate_data_streams: !streams.is_empty(),
            standard_info_flags: standard_info.as_ref().map(|i| i.file_flags.clone()),
            standard_info_last_modified: standard_info.as_ref().map(|i| i.modified),
            standard_info_last_access: standard_info.as_ref().map(|i| i.accessed),
            standard_info_created: standard_info.as_ref().map(|i| i.created),
            file_name_flags: file_name.as_ref().map(|i| i.flags.clone()),
            file_name_last_modified: file_name.as_ref().map(|i| i.modified),
            file_name_last_access: file_name.as_ref().map(|i| i.accessed),
            file_name_created: file_name.as_ref().map(|i| i.created),
            standard_info_last_mft_modified: standard_info.as_ref().map(|i| i.mft_modified),
            file_name_last_mft_modified: file_name.as_ref().map(|i| i.mft_modified),
            file_name: file_name.as_ref().map(|i| i.name.to_string()),
            lsn: entry.header.metadata_transaction_journal,
            usn: standard_info.as_ref().map(|i| i.usn),
            security_id: standard_info.as_ref().map(|i| i.security_id),
            object_id,
            alternate_data_streams: streams.join("|"),
            file_size,
            full_path,
        }
    }
}
