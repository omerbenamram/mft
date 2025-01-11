pub mod header;
pub mod raw;
pub mod x10;
pub mod x20;
pub mod x30;
pub mod x40;
pub mod x80;
pub mod x90;
pub mod non_resident_attr;
pub mod data_run;

use crate::err::Result;
use crate::impl_serialize_for_bitflags;

use std::io::{Cursor, Read, Seek};
use std::fmt;

use bitflags::bitflags;

use crate::attribute::raw::RawAttribute;
use crate::attribute::x10::StandardInfoAttr;
use crate::attribute::x20::AttributeListAttr;
use crate::attribute::x30::FileNameAttr;

use crate::attribute::header::{MftAttributeHeader, ResidentHeader, NonResidentHeader};
use crate::attribute::x40::ObjectIdAttr;
use crate::attribute::x80::DataAttr;
use crate::attribute::x90::IndexRootAttr;
use crate::attribute::non_resident_attr::NonResidentAttr;
use serde::Serialize;

#[derive(Serialize, Clone, Debug)]
pub struct MftAttribute {
    pub header: MftAttributeHeader,
    pub data: MftAttributeContent,
}

impl MftAttributeContent {    
    pub fn from_stream_non_resident<S: Read + Seek>(
        stream: &mut S,
        header: &MftAttributeHeader,
        resident: &NonResidentHeader,
    ) -> Result<Self> { 
        Ok(MftAttributeContent::DataRun(
            NonResidentAttr::from_stream(stream, header, resident)?,
        ))
    }

    pub fn from_stream_resident<S: Read + Seek>(
        stream: &mut S,
        header: &MftAttributeHeader,
        resident: &ResidentHeader,
    ) -> Result<Self> {
        match header.type_code {
            MftAttributeType::StandardInformation => Ok(MftAttributeContent::AttrX10(
                StandardInfoAttr::from_reader(stream)?,
            )),
            MftAttributeType::AttributeList => {
                // An attribute list is a buffer of attribute entries which are varying sizes if
                // the attributes contain names. Thus, we must know when to stop reading. To
                // do this, we will create a buffer of the attribute, and stop reading attribute
                // entries when we reach the end of the buffer.
                let content_size = resident.data_size;

                let mut attribute_buffer = vec![0; content_size as usize];
                stream.read_exact(&mut attribute_buffer)?;

                // Create a new stream that the attribute will read from.
                let mut new_stream = Cursor::new(attribute_buffer);

                let attr_list =
                    AttributeListAttr::from_stream(&mut new_stream, Some(content_size as u64))?;

                Ok(MftAttributeContent::AttrX20(attr_list))
            }
            MftAttributeType::FileName => Ok(MftAttributeContent::AttrX30(
                FileNameAttr::from_stream(stream)?,
            )),
            // Resident DATA
            MftAttributeType::DATA => Ok(MftAttributeContent::AttrX80(DataAttr::from_stream(
                stream,
                resident.data_size as usize,
            )?)),
            // Always Resident
            MftAttributeType::ObjectId => Ok(MftAttributeContent::AttrX40(
                ObjectIdAttr::from_stream(stream, resident.data_size as usize)?,
            )),
            // Always Resident
            MftAttributeType::IndexRoot => Ok(MftAttributeContent::AttrX90(
                IndexRootAttr::from_stream(stream)?,
            )),
            // An unparsed resident attribute
            _ => Ok(MftAttributeContent::Raw(RawAttribute::from_stream(
                stream,
                header.type_code.clone(),
                resident.data_size as usize,
            )?)),
        }
    }

    /// Converts the given attributes into a 'AttributeListAttr', consuming the object attribute object.
    pub fn into_attribute_list(self) -> Option<AttributeListAttr> {
        match self {
            MftAttributeContent::AttrX20(content) => Some(content),
            _ => None,
        }
    }

    /// Converts the given attributes into a `IndexRootAttr`, consuming the object attribute object.
    pub fn into_index_root(self) -> Option<IndexRootAttr> {
        match self {
            MftAttributeContent::AttrX90(content) => Some(content),
            _ => None,
        }
    }

    /// Converts the given attributes into a `ObjectIdAttr`, consuming the object attribute object.
    pub fn into_object_id(self) -> Option<ObjectIdAttr> {
        match self {
            MftAttributeContent::AttrX40(content) => Some(content),
            _ => None,
        }
    }
    /// Converts the given attributes into a `StandardInfoAttr`, consuming the object attribute object.
    pub fn into_standard_info(self) -> Option<StandardInfoAttr> {
        match self {
            MftAttributeContent::AttrX10(content) => Some(content),
            _ => None,
        }
    }
    
    /// Converts the given attributes into a `DataAttr`, consuming the object attribute object.
    pub fn into_data(self) -> Option<DataAttr> {
        match self {
            MftAttributeContent::AttrX80(content) => Some(content),
            _ => None,
        }
    }

    /// Converts the given attributes into a `FileNameAttr`, consuming the object attribute object.
    pub fn into_file_name(self) -> Option<FileNameAttr> {
        match self {
            MftAttributeContent::AttrX30(content) => Some(content),
            _ => None,
        }
    }

    /// Converts the given attributes into a `NonResidentAttr`, consuming the object attribute object.
    pub fn into_data_runs(self) -> Option<NonResidentAttr> {
        match self {
            MftAttributeContent::DataRun(content) => Some(content),
            _ => None,
        }
    }
}

#[derive(Serialize, Clone, Debug)]
#[serde(untagged)]
pub enum MftAttributeContent {
    Raw(RawAttribute),
    AttrX10(StandardInfoAttr),
    AttrX20(AttributeListAttr),
    AttrX30(FileNameAttr),
    AttrX40(ObjectIdAttr),
    AttrX80(DataAttr),
    AttrX90(IndexRootAttr),
    DataRun(NonResidentAttr),
    /// Empty - used when data is non resident.
    None,
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
    ///
    #[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Clone, Copy)]
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
        const FILE_ATTRIBUTE_NO_SCRUB_DATA        = 0x0002_0000;
        const FILE_ATTRIBUTE_HAS_EA               = 0x0004_0000;
        const FILE_ATTRIBUTE_IS_DIRECTORY         = 0x1000_0000;
        const FILE_ATTRIBUTE_INDEX_VIEW           = 0x2000_0000;
    }
}

impl fmt::Display for FileAttributeFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for flag in [
            FileAttributeFlags::FILE_ATTRIBUTE_READONLY,
            FileAttributeFlags::FILE_ATTRIBUTE_HIDDEN,
            FileAttributeFlags::FILE_ATTRIBUTE_SYSTEM,
            FileAttributeFlags::FILE_ATTRIBUTE_DIRECTORY,
            FileAttributeFlags::FILE_ATTRIBUTE_ARCHIVE,
            FileAttributeFlags::FILE_ATTRIBUTE_DEVICE,
            FileAttributeFlags::FILE_ATTRIBUTE_NORMAL,
            FileAttributeFlags::FILE_ATTRIBUTE_TEMPORARY,
            FileAttributeFlags::FILE_ATTRIBUTE_SPARSE_FILE,
            FileAttributeFlags::FILE_ATTRIBUTE_REPARSE_POINT,
            FileAttributeFlags::FILE_ATTRIBUTE_COMPRESSED,
            FileAttributeFlags::FILE_ATTRIBUTE_OFFLINE,
            FileAttributeFlags::FILE_ATTRIBUTE_NOT_CONTENT_INDEXED,
            FileAttributeFlags::FILE_ATTRIBUTE_ENCRYPTED,
            FileAttributeFlags::FILE_ATTRIBUTE_INTEGRITY_STREAM,
            FileAttributeFlags::FILE_ATTRIBUTE_NO_SCRUB_DATA,
            FileAttributeFlags::FILE_ATTRIBUTE_HAS_EA,
            FileAttributeFlags::FILE_ATTRIBUTE_IS_DIRECTORY,
            FileAttributeFlags::FILE_ATTRIBUTE_INDEX_VIEW,
            // Add other flags as needed
        ] {
            if self.contains(flag) {
                if !first {
                    write!(f, " | ")?;
                }
                let flag_str = format!("{:?}", flag);
                let flag_str = flag_str.strip_prefix("FileAttributeFlags(").unwrap_or(&flag_str);
                let flag_str = flag_str.strip_suffix(")").unwrap_or(&flag_str);
                write!(f, "{}", flag_str)?;
                first = false;
            }
        }
        Ok(())
    }
}

impl_serialize_for_bitflags! {FileAttributeFlags}

bitflags! {
    #[derive(Default, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Clone, Copy)]
    pub struct AttributeDataFlags: u16 {
        const IS_COMPRESSED     = 0x0001;
        const COMPRESSION_MASK  = 0x00FF;
        const ENCRYPTED         = 0x4000;
        const SPARSE            = 0x8000;
    }
}

impl fmt::Display for AttributeDataFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for flag in [
            AttributeDataFlags::IS_COMPRESSED,
            AttributeDataFlags::COMPRESSION_MASK,
            AttributeDataFlags::ENCRYPTED,
            AttributeDataFlags::SPARSE,
            // Add other flags as needed
        ] {
            if self.contains(flag) {
                if !first {
                    write!(f, " | ")?;
                }
                let flag_str = format!("{:?}", flag);
                let flag_str = flag_str.strip_prefix("AttributeDataFlags(").unwrap_or(&flag_str);
                let flag_str = flag_str.strip_suffix(")").unwrap_or(&flag_str);
                write!(f, "{}", flag_str)?;
                first = false;
            }
        }
        Ok(())
    }
}

impl_serialize_for_bitflags! {AttributeDataFlags}
