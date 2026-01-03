pub mod data_run;
pub mod header;
pub mod non_resident_attr;
pub mod raw;
pub mod x10;
pub mod x20;
pub mod x30;
pub mod x40;
pub mod x80;
pub mod x90;

use crate::err::Result;
use crate::impl_serialize_for_bitflags;

use std::io::Cursor;

use bitflags::bitflags;

use crate::attribute::raw::RawAttribute;
use crate::attribute::x10::StandardInfoAttr;
use crate::attribute::x20::AttributeListAttr;
use crate::attribute::x30::FileNameAttr;

use crate::attribute::data_run::decode_data_runs;
use crate::attribute::header::{MftAttributeHeader, ResidentialHeader};
use crate::attribute::non_resident_attr::NonResidentAttr;
use crate::attribute::x40::ObjectIdAttr;
use crate::attribute::x80::DataAttr;
use crate::attribute::x90::IndexRootAttr;
use serde::Serialize;

#[derive(Serialize, Clone, Debug)]
pub struct MftAttribute<'a> {
    pub header: MftAttributeHeader<'a>,
    pub data: MftAttributeContent<'a>,
}

impl<'a> MftAttributeContent<'a> {
    pub fn from_record(record: &'a [u8], header: &MftAttributeHeader<'a>) -> Result<Self> {
        match &header.residential_header {
            ResidentialHeader::Resident(resident) => {
                let data_offset = resident.data_offset as usize;
                let data_size = resident.data_size as usize;
                let end =
                    data_offset
                        .checked_add(data_size)
                        .ok_or_else(|| crate::err::Error::Any {
                            detail: "attribute resident data offset overflow".to_string(),
                        })?;
                let value = record
                    .get(data_offset..end)
                    .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?;

                match header.type_code {
                    MftAttributeType::StandardInformation => Ok(MftAttributeContent::AttrX10(
                        StandardInfoAttr::from_slice(value)?,
                    )),
                    MftAttributeType::AttributeList => Ok(MftAttributeContent::AttrX20(
                        AttributeListAttr::from_slice(value)?,
                    )),
                    MftAttributeType::FileName => Ok(MftAttributeContent::AttrX30(
                        FileNameAttr::from_slice(value)?,
                    )),
                    MftAttributeType::DATA => {
                        Ok(MftAttributeContent::AttrX80(DataAttr::from_slice(value)))
                    }
                    MftAttributeType::ObjectId => Ok(MftAttributeContent::AttrX40(
                        ObjectIdAttr::from_stream(&mut Cursor::new(value), value.len())?,
                    )),
                    MftAttributeType::IndexRoot => Ok(MftAttributeContent::AttrX90(
                        IndexRootAttr::from_slice(value)?,
                    )),
                    _ => Ok(MftAttributeContent::Raw(RawAttribute::from_slice(
                        header.type_code.clone(),
                        value,
                    ))),
                }
            }
            ResidentialHeader::NonResident(nonresident) => {
                let datarun_offset = nonresident.datarun_offset as usize;
                let runs = record
                    .get(datarun_offset..)
                    .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?;

                // The mapping pairs array is normally terminated by a 0 byte. However, older
                // versions of this crate accepted the edge-case where the mapping pairs section
                // is empty (`datarun_offset == record_length`), treating it as an empty runlist.
                // Preserve that behavior for compatibility with such records.
                let data_runs = if runs.is_empty() {
                    Vec::new()
                } else {
                    decode_data_runs(runs).ok_or_else(|| {
                        crate::err::Error::FailedToDecodeDataRuns {
                            bad_data_runs: runs.to_vec(),
                        }
                    })?
                };
                Ok(MftAttributeContent::DataRun(NonResidentAttr { data_runs }))
            }
        }
    }

    pub fn as_attribute_list(&self) -> Option<&AttributeListAttr<'a>> {
        match self {
            MftAttributeContent::AttrX20(content) => Some(content),
            _ => None,
        }
    }

    pub fn as_index_root(&self) -> Option<&IndexRootAttr<'a>> {
        match self {
            MftAttributeContent::AttrX90(content) => Some(content),
            _ => None,
        }
    }

    pub fn as_object_id(&self) -> Option<&ObjectIdAttr> {
        match self {
            MftAttributeContent::AttrX40(content) => Some(content),
            _ => None,
        }
    }

    pub fn as_standard_info(&self) -> Option<&StandardInfoAttr> {
        match self {
            MftAttributeContent::AttrX10(content) => Some(content),
            _ => None,
        }
    }

    pub fn as_data(&self) -> Option<&DataAttr<'a>> {
        match self {
            MftAttributeContent::AttrX80(content) => Some(content),
            _ => None,
        }
    }

    pub fn as_file_name(&self) -> Option<&FileNameAttr<'a>> {
        match self {
            MftAttributeContent::AttrX30(content) => Some(content),
            _ => None,
        }
    }

    pub fn as_data_runs(&self) -> Option<&NonResidentAttr> {
        match self {
            MftAttributeContent::DataRun(content) => Some(content),
            _ => None,
        }
    }
}

#[derive(Serialize, Clone, Debug)]
#[serde(untagged)]
pub enum MftAttributeContent<'a> {
    Raw(RawAttribute<'a>),
    AttrX10(StandardInfoAttr),
    AttrX20(AttributeListAttr<'a>),
    AttrX30(FileNameAttr<'a>),
    AttrX40(ObjectIdAttr),
    AttrX80(DataAttr<'a>),
    AttrX90(IndexRootAttr<'a>),
    DataRun(NonResidentAttr),
}

/// MFT Possible attribute types, from <https://docs.microsoft.com/en-us/windows/desktop/devnotes/attribute-list-entry>
#[derive(Serialize, Debug, Clone, FromPrimitive, ToPrimitive, PartialOrd, PartialEq)]
#[repr(u32)]
pub enum MftAttributeType {
    /// File attributes (such as read-only and archive), time stamps (such as file creation and last modified), and the hard link count.
    StandardInformation = 0x10_u32,
    /// A list of attributes that make up the file and the file reference of the MFT file record in which each attribute is located.
    AttributeList = 0x20_u32,
    /// The name of the file, in Unicode characters.
    FileName = 0x30_u32,
    /// An 16-byte object identifier assigned by the link-tracking service.
    ObjectId = 0x40_u32,
    /// File's access control list and security properties
    SecurityDescriptor = 0x50_u32,
    /// The volume label.
    /// Present in the $Volume file.
    VolumeName = 0x60_u32,
    /// The volume information.
    /// Present in the $Volume file.
    VolumeInformation = 0x70_u32,
    /// The contents of the file.
    DATA = 0x80_u32,
    /// Used to implement filename allocation for large directories.
    IndexRoot = 0x90_u32,
    /// Used to implement filename allocation for large directories.
    IndexAllocation = 0xA0_u32,
    /// A bitmap index for a large directory.
    BITMAP = 0xB0_u32,
    /// The reparse point data.
    ReparsePoint = 0xC0_u32,
    /// Used for backward compatibility with OS/2 applications (HPFS)
    EaInformation = 0xD0_u32,
    /// Used for backward compatibility with OS/2 applications (HPFS)
    EA = 0xE0_u32,
    /// Keys and other information about encrypted attributes (NTFS 3.0+; Windows 2000+)
    LoggedUtilityStream = 0x100_u32,
}

bitflags! {
    /// Flag sources:
    /// <https://github.com/EricZimmerman/MFT/blob/3bed2626ee85e9a96a6db70a17407d0c3696056a/MFT/Attributes/StandardInfo.cs#L10>
    /// <https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/ca28ec38-f155-4768-81d6-4bfeb8586fc9>
    /// <https://learn.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants>
    ///
    #[derive(Clone, Debug, PartialEq)]
    pub struct FileAttributeFlags: u32 {
        const FILE_ATTRIBUTE_READONLY             = 0x0000_0001;
        const FILE_ATTRIBUTE_HIDDEN               = 0x0000_0002;
        const FILE_ATTRIBUTE_SYSTEM               = 0x0000_0004;
        const FILE_ATTRIBUTE_DIRECTORY            = 0x0000_0010;
        const FILE_ATTRIBUTE_ARCHIVE              = 0x0000_0020;
        const FILE_ATTRIBUTE_DEVICE               = 0x0000_0040;
        const FILE_ATTRIBUTE_NORMAL               = 0x0000_0080;
        const FILE_ATTRIBUTE_TEMPORARY            = 0x0000_0100;
        const FILE_ATTRIBUTE_SPARSE_FILE          = 0x0000_0200;
        const FILE_ATTRIBUTE_REPARSE_POINT        = 0x0000_0400;
        const FILE_ATTRIBUTE_COMPRESSED           = 0x0000_0800;
        const FILE_ATTRIBUTE_OFFLINE              = 0x0000_1000;
        const FILE_ATTRIBUTE_NOT_CONTENT_INDEXED  = 0x0000_2000;
        const FILE_ATTRIBUTE_ENCRYPTED            = 0x0000_4000;
        const FILE_ATTRIBUTE_INTEGRITY_STREAM     = 0x0000_8000;
        const FILE_ATTRIBUTE_VIRTUAL              = 0x0001_0000;
        const FILE_ATTRIBUTE_NO_SCRUB_DATA        = 0x0002_0000;
        // Multiple names share the same bit; retain HAS_EA for backward compatibility.
        const FILE_ATTRIBUTE_EA                   = 0x0004_0000;
        const FILE_ATTRIBUTE_RECALL_ON_OPEN       = 0x0004_0000;
        const FILE_ATTRIBUTE_HAS_EA               = 0x0004_0000;
        const FILE_ATTRIBUTE_PINNED               = 0x0008_0000;
        const FILE_ATTRIBUTE_UNPINNED             = 0x0010_0000;
        const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x0040_0000;
        const FILE_ATTRIBUTE_IS_DIRECTORY         = 0x1000_0000;
        const FILE_ATTRIBUTE_INDEX_VIEW           = 0x2000_0000;
    }
}

impl_serialize_for_bitflags! {FileAttributeFlags}

bitflags! {
    #[derive(Default, Clone, Debug, PartialEq)]
    pub struct AttributeDataFlags: u16 {
        const IS_COMPRESSED     = 0x0001;
        const COMPRESSION_MASK  = 0x00FF;
        const ENCRYPTED         = 0x4000;
        const SPARSE            = 0x8000;
    }
}

impl_serialize_for_bitflags! {AttributeDataFlags}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attribute::header::MftAttributeHeader;

    #[test]
    fn nonresident_attribute_allows_empty_mapping_pairs_section() {
        // Regression test:
        // `NonResidentAttr::from_stream` historically treated `data_run_bytes_count == 0`
        // (i.e. `datarun_offset == record_length`) as a valid empty runlist.
        // The slice-based parser must preserve that behavior to avoid rejecting such records.
        let record_length: u32 = 64;
        let mut record = vec![0u8; record_length as usize];

        // Common attribute record header.
        record[0..4].copy_from_slice(&(MftAttributeType::DATA as u32).to_le_bytes());
        record[4..8].copy_from_slice(&record_length.to_le_bytes());
        record[8] = 1; // non-resident
        record[9] = 0; // name length
        record[10..12].copy_from_slice(&0u16.to_le_bytes()); // name offset (unused)
        record[12..14].copy_from_slice(&0u16.to_le_bytes()); // flags
        record[14..16].copy_from_slice(&0u16.to_le_bytes()); // instance

        // Non-resident header.
        // vnc_first (16..24) and vnc_last (24..32) are 0.
        record[32..34].copy_from_slice(&(record_length as u16).to_le_bytes()); // datarun_offset
        record[34..36].copy_from_slice(&0u16.to_le_bytes()); // compression unit size
        // padding (36..40) = 0
        // allocated_length (40..48) = 0
        // file_size (48..56) = 0
        // valid_data_length (56..64) = 0

        let header = MftAttributeHeader::from_slice(&record, 0)
            .expect("expected header parse to succeed")
            .expect("expected attribute type != $END");

        let content = MftAttributeContent::from_record(&record, &header)
            .expect("expected non-resident attribute to parse successfully");

        match content {
            MftAttributeContent::DataRun(nonresident) => {
                assert!(nonresident.data_runs.is_empty());
            }
            other => panic!("expected DataRun content, got {other:?}"),
        }
    }
}
