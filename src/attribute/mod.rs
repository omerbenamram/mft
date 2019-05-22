pub mod header;
pub mod raw;
pub mod x10;
pub mod x30;
pub mod x40;
pub mod x80;
pub mod x90;

use crate::err::Result;
use crate::{impl_serialize_for_bitflags, ReadSeek};

use bitflags::bitflags;

use crate::attribute::raw::RawAttribute;
use crate::attribute::x10::StandardInfoAttr;
use crate::attribute::x30::FileNameAttr;

use crate::attribute::header::{MftAttributeHeader, ResidentHeader};
use crate::attribute::x40::ObjectIdAttr;
use crate::attribute::x80::DataAttr;
use crate::attribute::x90::IndexRootAttr;
use serde::Serialize;

#[derive(Serialize, Clone, Debug)]
pub struct MftAttribute {
    pub header: MftAttributeHeader,
    pub data: MftAttributeContent,
}

impl MftAttributeContent {
    pub fn from_stream_resident<S: ReadSeek>(
        stream: &mut S,
        header: &MftAttributeHeader,
        resident: &ResidentHeader,
    ) -> Result<Self> {
        match header.type_code {
            MftAttributeType::StandardInformation => Ok(MftAttributeContent::AttrX10(
                StandardInfoAttr::from_reader(stream)?,
            )),
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
}

#[derive(Serialize, Clone, Debug)]
#[serde(untagged)]
pub enum MftAttributeContent {
    Raw(RawAttribute),
    AttrX80(DataAttr),
    AttrX10(StandardInfoAttr),
    AttrX30(FileNameAttr),
    AttrX40(ObjectIdAttr),
    AttrX90(IndexRootAttr),
    /// Empty - used when data is non resident.
    None,
}

/// MFT Possible attribute types, from https://docs.microsoft.com/en-us/windows/desktop/devnotes/attribute-list-entry
#[derive(Serialize, Debug, Clone, FromPrimitive, PartialOrd, PartialEq)]
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
}

bitflags! {
    pub struct FileAttributeFlags: u32 {
        const FILE_ATTRIBUTE_READONLY             = 0x0000_0001;
        const FILE_ATTRIBUTE_HIDDEN               = 0x0000_0002;
        const FILE_ATTRIBUTE_SYSTEM               = 0x0000_0004;
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
    }
}

impl_serialize_for_bitflags! {FileAttributeFlags}

bitflags! {
    #[derive(Default)]
    pub struct AttributeDataFlags: u16 {
        const IS_COMPRESSED     = 0x0001;
        const COMPRESSION_MASK  = 0x00FF;
        const ENCRYPTED         = 0x4000;
        const SPARSE            = 0x8000;
    }
}

impl_serialize_for_bitflags! {AttributeDataFlags}
