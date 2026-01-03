use crate::Utf16LeStr;
use crate::attribute::FileAttributeFlags;
use crate::err::{Error, Result};
use log::trace;

use byteorder::{LittleEndian, ReadBytesExt};
use jiff::Timestamp;
use num_traits::FromPrimitive;
use serde::Serialize;
use std::io::Cursor;

use winstructs::ntfs::mft_reference::MftReference;

#[derive(FromPrimitive, Serialize, Clone, Copy, Debug, PartialOrd, PartialEq)]
#[repr(u8)]
pub enum FileNamespace {
    POSIX = 0,
    Win32 = 1,
    DOS = 2,
    Win32AndDos = 3,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct FileNameAttr<'a> {
    pub parent: MftReference,
    #[serde(serialize_with = "crate::utils::serialize_timestamp_chrono_compat")]
    pub created: Timestamp,
    #[serde(serialize_with = "crate::utils::serialize_timestamp_chrono_compat")]
    pub modified: Timestamp,
    #[serde(serialize_with = "crate::utils::serialize_timestamp_chrono_compat")]
    pub mft_modified: Timestamp,
    #[serde(serialize_with = "crate::utils::serialize_timestamp_chrono_compat")]
    pub accessed: Timestamp,
    pub logical_size: u64,
    pub physical_size: u64,
    pub flags: FileAttributeFlags,
    pub reparse_value: u32,
    pub name_length: u8,
    pub namespace: FileNamespace,
    pub name: Utf16LeStr<'a>,
}

impl<'a> FileNameAttr<'a> {
    /// Parse a Filename attrbiute buffer.
    ///
    /// # Example
    ///
    /// Parse a raw buffer.
    ///
    /// ```
    /// use mft::attribute::x30::{FileNameAttr, FileNamespace};
    /// # use std::io::Cursor;
    /// let attribute_buffer: &[u8] = &[
    ///     0x05,0x00,0x00,0x00,0x00,0x00,0x05,0x00,0xD5,0x2D,0x48,0x58,0x43,0x5F,0xCE,0x01,
    ///     0xD5,0x2D,0x48,0x58,0x43,0x5F,0xCE,0x01,0xD5,0x2D,0x48,0x58,0x43,0x5F,0xCE,0x01,
    ///     0xD5,0x2D,0x48,0x58,0x43,0x5F,0xCE,0x01,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x00,
    ///     0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x00,0x06,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    ///     0x08,0x03,0x24,0x00,0x4C,0x00,0x6F,0x00,0x67,0x00,0x46,0x00,0x69,0x00,0x6C,0x00,
    ///     0x65,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    /// ];
    ///
    /// let attribute = FileNameAttr::from_slice(attribute_buffer).unwrap();
    ///
    /// assert_eq!(attribute.parent.entry, 5);
    /// assert_eq!(attribute.created.as_second(), 1370144608);
    /// assert_eq!(attribute.modified.as_second(), 1370144608);
    /// assert_eq!(attribute.mft_modified.as_second(), 1370144608);
    /// assert_eq!(attribute.accessed.as_second(), 1370144608);
    /// assert_eq!(attribute.logical_size, 67108864);
    /// assert_eq!(attribute.physical_size, 67108864);
    /// assert_eq!(attribute.flags.bits(), 6);
    /// assert_eq!(attribute.reparse_value, 0);
    /// assert_eq!(attribute.name_length, 8);
    /// assert_eq!(attribute.namespace, FileNamespace::Win32AndDos);
    /// assert_eq!(attribute.name.to_utf8_string(), "$LogFile");
    /// ```
    pub fn from_slice(value: &'a [u8]) -> Result<FileNameAttr<'a>> {
        let mut stream = Cursor::new(value);
        trace!("Offset {}: FilenameAttr", stream.position());

        let parent =
            MftReference::from_reader(&mut stream).map_err(Error::failed_to_read_mft_reference)?;
        // Timestamps are stored as Windows FILETIME (100ns since 1601-01-01 UTC).
        let created =
            crate::utils::windows_filetime_to_timestamp(stream.read_u64::<LittleEndian>()?)?;
        let modified =
            crate::utils::windows_filetime_to_timestamp(stream.read_u64::<LittleEndian>()?)?;
        let mft_modified =
            crate::utils::windows_filetime_to_timestamp(stream.read_u64::<LittleEndian>()?)?;
        let accessed =
            crate::utils::windows_filetime_to_timestamp(stream.read_u64::<LittleEndian>()?)?;

        let logical_size = stream.read_u64::<LittleEndian>()?;
        let physical_size = stream.read_u64::<LittleEndian>()?;
        let flags = FileAttributeFlags::from_bits_truncate(stream.read_u32::<LittleEndian>()?);
        let reparse_value = stream.read_u32::<LittleEndian>()?;
        let name_length = stream.read_u8()?;
        let namespace = stream.read_u8()?;
        let namespace =
            FileNamespace::from_u8(namespace).ok_or(Error::UnknownNamespace { namespace })?;

        let name_pos = stream.position() as usize;
        let name_len_bytes = name_length as usize * 2;
        let name_bytes = value
            .get(name_pos..name_pos + name_len_bytes)
            .ok_or(Error::InvalidFilename)?;
        let name = Utf16LeStr::from_utf16le_bytes(name_bytes);

        Ok(FileNameAttr {
            parent,
            created,
            modified,
            mft_modified,
            accessed,
            logical_size,
            physical_size,
            flags,
            reparse_value,
            name_length,
            namespace,
            name,
        })
    }
}
