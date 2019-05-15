pub mod header;
pub mod raw;
pub mod x10;
pub mod x30;


use crate::impl_serialize_for_bitflags;

use bitflags::bitflags;
use num_traits::FromPrimitive;

use crate::attribute::raw::RawAttribute;
use crate::attribute::x10::StandardInfoAttr;
use crate::attribute::x30::FileNameAttr;

use crate::attribute::header::AttributeHeader;

use serde::{Serialize};


#[derive(Serialize, Clone, Debug)]
pub struct Attribute {
    pub header: AttributeHeader,
    pub data: MftAttributeContent,
}

#[derive(Serialize, Clone, Debug)]
#[serde(untagged)]
pub enum MftAttributeContent {
    Raw(RawAttribute),
    AttrX10(StandardInfoAttr),
    AttrX30(FileNameAttr),
    /// Empty - used when data is non resident.
    None,
}

/// MFT Possible attribute types, from https://docs.microsoft.com/en-us/windows/desktop/devnotes/attribute-list-entry
#[derive(Serialize, Debug, Clone, FromPrimitive, PartialOrd, PartialEq)]
#[repr(u32)]
pub enum AttributeType {
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
    #[derive(Default)]
    pub struct AttributeDataFlags: u16 {
        const IS_COMPRESSED     = 0x0001;
        const COMPRESSION_MASK  = 0x00FF;
        const ENCRYPTED         = 0x4000;
        const SPARSE            = 0x8000;
    }
}

impl_serialize_for_bitflags! {AttributeDataFlags}
