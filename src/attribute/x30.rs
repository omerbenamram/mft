use std::io::{Read, Seek};

use crate::attribute::FileAttributeFlags;
use crate::err::{Error, Result};
use log::trace;

use byteorder::{LittleEndian, ReadBytesExt};
use encoding::all::UTF_16LE;
use encoding::{DecoderTrap, Encoding};

use chrono::{DateTime, Utc};
use num_traits::FromPrimitive;
use serde::Serialize;

use winstructs::ntfs::mft_reference::MftReference;
use winstructs::timestamp::WinTimestamp;

#[derive(FromPrimitive, Serialize, Clone, Debug, PartialOrd, PartialEq)]
#[repr(u8)]
pub enum FileNamespace {
    POSIX = 0,
    Win32 = 1,
    DOS = 2,
    Win32AndDos = 3,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct FileNameAttr {
    pub parent: MftReference,
    pub created: DateTime<Utc>,
    pub modified: DateTime<Utc>,
    pub mft_modified: DateTime<Utc>,
    pub accessed: DateTime<Utc>,
    pub logical_size: u64,
    pub physical_size: u64,
    pub flags: FileAttributeFlags,
    pub reparse_value: u32,
    pub name_length: u8,
    pub namespace: FileNamespace,
    pub name: String,
}

impl FileNameAttr {
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
    /// let attribute = FileNameAttr::from_stream(&mut Cursor::new(attribute_buffer)).unwrap();
    ///
    /// assert_eq!(attribute.parent.entry, 5);
    /// assert_eq!(attribute.created.timestamp(), 1370144608);
    /// assert_eq!(attribute.modified.timestamp(), 1370144608);
    /// assert_eq!(attribute.mft_modified.timestamp(), 1370144608);
    /// assert_eq!(attribute.accessed.timestamp(), 1370144608);
    /// assert_eq!(attribute.logical_size, 67108864);
    /// assert_eq!(attribute.physical_size, 67108864);
    /// assert_eq!(attribute.flags.bits(), 6);
    /// assert_eq!(attribute.reparse_value, 0);
    /// assert_eq!(attribute.name_length, 8);
    /// assert_eq!(attribute.namespace, FileNamespace::Win32AndDos);
    /// assert_eq!(attribute.name, "$LogFile");
    /// ```
    pub fn from_stream<S: Read + Seek>(stream: &mut S) -> Result<FileNameAttr> {
        trace!("Offset {}: FilenameAttr", stream.stream_position()?);
        let parent =
            MftReference::from_reader(stream).map_err(Error::failed_to_read_mft_reference)?;
        let created = WinTimestamp::from_reader(stream)
            .map_err(Error::failed_to_read_windows_time)?
            .to_datetime();
        let modified = WinTimestamp::from_reader(stream)
            .map_err(Error::failed_to_read_windows_time)?
            .to_datetime();
        let mft_modified = WinTimestamp::from_reader(stream)
            .map_err(Error::failed_to_read_windows_time)?
            .to_datetime();
        let accessed = WinTimestamp::from_reader(stream)
            .map_err(Error::failed_to_read_windows_time)?
            .to_datetime();

        let logical_size = stream.read_u64::<LittleEndian>()?;
        let physical_size = stream.read_u64::<LittleEndian>()?;
        let flags = FileAttributeFlags::from_bits_truncate(stream.read_u32::<LittleEndian>()?);
        let reparse_value = stream.read_u32::<LittleEndian>()?;
        let name_length = stream.read_u8()?;
        let namespace = stream.read_u8()?;
        let namespace =
            FileNamespace::from_u8(namespace).ok_or(Error::UnknownNamespace { namespace })?;

        let mut name_buffer = vec![0; name_length as usize * 2];
        stream.read_exact(&mut name_buffer)?;

        let name = match UTF_16LE.decode(&name_buffer, DecoderTrap::Ignore) {
            Ok(s) => s,
            Err(_e) => return Err(Error::InvalidFilename {}),
        };

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
