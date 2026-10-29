use crate::attribute::x10::StandardInfoAttr;
use crate::attribute::x30::FileNameAttr;
use crate::attribute::{FileAttributeFlags, MftAttributeType};
use crate::entry::{BestNames, EntryFlags, is_long_name};
use crate::{MftAttribute, MftEntry, MftParser};

use serde::Serialize;

use jiff::Timestamp;
use std::io::{Read, Seek};
use std::path::PathBuf;
use winstructs::guid::Guid;

/// Used for CSV output
#[derive(Serialize, Clone)]
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

    /// The best `$FILE_NAME` name, the last part of `FullPath`. Empty for extension records,
    /// which hold no name of their own.
    pub file_name: Option<String>,
    /// The `$LogFile` sequence number of the record's last change.
    pub lsn: u64,
    /// The update sequence number of the file's last change in `$Extend\$UsnJrnl`, from
    /// `$STANDARD_INFORMATION`. 0 if the journal hasn't recorded the file, and empty if the
    /// attribute predates NTFS 3.0 and has no USN.
    pub usn: Option<u64>,
    /// The file's security descriptor id in `$Secure`, from `$STANDARD_INFORMATION`. Empty if the
    /// attribute predates NTFS 3.0 and has no id.
    pub security_id: Option<u32>,
    /// The object id from `$OBJECT_ID`, if the file has one.
    pub object_id: Option<Guid>,
    /// The names of the named `$DATA` streams, separated by `|`, which Windows doesn't allow in
    /// names. These include the streams of NTFS metadata files, such as `$Secure:$SDS`.
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
        let (attributes, file_name) = Self::file_attributes(entry, extensions);
        Self::from_attributes(entry, &attributes, file_name.as_ref(), full_path)
    }

    /// The attributes of a file that its rows are built from, from its base record and its
    /// extension records, and its best name ([`crate::entry::find_best_name_attribute_in`]).
    fn file_attributes<'a>(
        entry: &'a MftEntry,
        extensions: &'a [MftEntry],
    ) -> (Vec<MftAttribute<'a>>, Option<FileNameAttr<'a>>) {
        let mut entry_attributes = Vec::new();
        // The name `find_best_name_attribute_in` picks, chosen in the same pass.
        let mut names = BestNames::default();
        let records = std::iter::once((entry, true)).chain(extensions.iter().map(|e| (e, false)));
        for (record, is_base) in records {
            for attribute in record
                .iter_attributes_matching(Some(vec![
                    MftAttributeType::StandardInformation,
                    MftAttributeType::FileName,
                    MftAttributeType::ObjectId,
                    MftAttributeType::DATA,
                ]))
                .filter_map(Result::ok)
            {
                if let Some(name) = attribute.data.as_file_name() {
                    names.offer(name, is_base);
                }
                entry_attributes.push(attribute);
            }
        }
        (entry_attributes, names.best())
    }

    fn from_attributes(
        entry: &MftEntry,
        entry_attributes: &[MftAttribute<'_>],
        file_name: Option<&FileNameAttr<'_>>,
        full_path: PathBuf,
    ) -> FlatMftEntryWithName {
        let standard_info_attribute = entry_attributes
            .iter()
            .find(|a| a.header.type_code == MftAttributeType::StandardInformation);
        let standard_info = standard_info_attribute.and_then(|a| a.data.as_standard_info());
        // Only the NTFS 3.0 layout has the security id and USN.
        let standard_info_v3 = standard_info_attribute
            .filter(|a| a.header.value_size() >= StandardInfoAttr::V3_SIZE as u64)
            .and_then(|a| a.data.as_standard_info());

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
        let mut alternate_data_streams = String::new();
        for a in entry_attributes {
            if a.header.type_code == MftAttributeType::DATA
                && !a.header.name.is_empty()
                && !a.header.is_continuation()
            {
                if !alternate_data_streams.is_empty() {
                    alternate_data_streams.push('|');
                }
                a.header
                    .name
                    .with_utf8(|name| alternate_data_streams.push_str(name));
            }
        }

        let mut row = FlatMftEntryWithName {
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
            has_alternate_data_streams: !alternate_data_streams.is_empty(),
            standard_info_flags: standard_info.map(|i| i.file_flags.clone()),
            standard_info_last_modified: standard_info.map(|i| i.modified),
            standard_info_last_access: standard_info.map(|i| i.accessed),
            standard_info_created: standard_info.map(|i| i.created),
            file_name_flags: None,
            file_name_last_modified: None,
            file_name_last_access: None,
            file_name_created: None,
            standard_info_last_mft_modified: standard_info.map(|i| i.mft_modified),
            file_name_last_mft_modified: None,
            file_name: None,
            lsn: entry.header.metadata_transaction_journal,
            usn: standard_info_v3.map(|i| i.usn),
            security_id: standard_info_v3.map(|i| i.security_id),
            object_id,
            alternate_data_streams,
            file_size,
            full_path,
        };
        row.set_file_name(file_name);
        row
    }

    /// The rows of an entry: its row from [`FlatMftEntryWithName::from_entry_with_path`], then
    /// the extra rows that `rows` asks for. `link_path` gives the full path of a file under one of
    /// its names (see [`MftParser::get_full_path_for_name`]).
    pub fn rows_with_path(
        entry: &MftEntry,
        extensions: &[MftEntry],
        full_path: PathBuf,
        rows: CsvRows,
        mut link_path: impl FnMut(&FileNameAttr<'_>) -> PathBuf,
    ) -> Vec<FlatMftEntryWithName> {
        let (attributes, best) = Self::file_attributes(entry, extensions);
        let row = Self::from_attributes(entry, &attributes, best.as_ref(), full_path);
        // An extension record isn't a file of its own.
        if !(rows.hard_links || rows.streams) || !entry.header.is_base_record() {
            return vec![row];
        }

        let mut extra = Vec::new();
        // A directory can't have hard links.
        if rows.hard_links && !entry.is_dir() {
            for name in attributes.iter().filter_map(|a| a.data.as_file_name()) {
                // The `Dos` name is another spelling of a long one, not a link. A copy of the best
                // name would only repeat the file's own row.
                if is_long_name(name) && Some(name) != best.as_ref() {
                    let mut link = row.clone();
                    link.set_file_name(Some(name));
                    link.full_path = link_path(name);
                    extra.push(link);
                }
            }
        }
        if rows.streams {
            for header in attributes.iter().map(|a| &a.header).filter(|h| {
                h.type_code == MftAttributeType::DATA && !h.name.is_empty() && !h.is_continuation()
            }) {
                let mut stream = row.clone();
                let suffix = format!(":{}", header.name.to_utf8_string());
                let mut path = stream.full_path.into_os_string();
                path.push(&suffix);
                stream.full_path = path.into();
                if let Some(file_name) = &mut stream.file_name {
                    file_name.push_str(&suffix);
                }
                stream.file_size = header.value_size();
                extra.push(stream);
            }
        }
        extra.insert(0, row);
        extra
    }

    /// Fills the `FileName*` columns from `name`.
    fn set_file_name(&mut self, name: Option<&FileNameAttr<'_>>) {
        self.file_name_flags = name.map(|i| i.flags.clone());
        self.file_name_last_modified = name.map(|i| i.modified);
        self.file_name_last_access = name.map(|i| i.accessed);
        self.file_name_created = name.map(|i| i.created);
        self.file_name_last_mft_modified = name.map(|i| i.mft_modified);
        self.file_name = name.map(|i| i.name.to_utf8_string());
    }
}

/// The extra CSV rows to write for each file, besides its own.
#[derive(Clone, Copy, Debug, Default)]
pub struct CsvRows {
    /// A row for each of the file's other long names (hard links), with that name's path and
    /// `FileName*` columns.
    pub hard_links: bool,
    /// A row for each named `$DATA` stream, with `:stream` appended to `FullPath` and `FileName`
    /// and the stream's size in `FileSize`. These use the file's own path, not its other links'.
    pub streams: bool,
}
