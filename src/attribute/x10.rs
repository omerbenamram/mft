use std::io::{Read, Seek};

use crate::attribute::FileAttributeFlags;
use crate::err::{Error, Result};

use byteorder::{LittleEndian, ReadBytesExt};
use chrono::{DateTime, Utc};
use log::trace;
use serde::Serialize;
use winstructs::timestamp::WinTimestamp;

#[derive(Serialize, Debug, Clone)]
pub struct StandardInfoAttr {
    pub created: DateTime<Utc>,
    pub modified: DateTime<Utc>,
    pub mft_modified: DateTime<Utc>,
    pub accessed: DateTime<Utc>,
    /// DOS File Permissions
    pub file_flags: FileAttributeFlags,
    pub max_version: u32,
    pub version: u32,
    pub class_id: u32,
    pub owner_id: u32,
    pub security_id: u32,
    pub quota: u64,
    pub usn: u64,
}

impl StandardInfoAttr {
    /// Parse a Standard Information attrbiute buffer.
    ///
    /// # Example
    ///
    /// Parse a raw buffer.
    ///
    /// ```
    /// use mft::attribute::x10::StandardInfoAttr;
    /// use mft::attribute::FileAttributeFlags;
    /// # use std::io::Cursor;
    /// let attribute_buffer: &[u8] = &[
    ///     0x2F,0x6D,0xB6,0x6F,0x0C,0x97,0xCE,0x01,0x56,0xCD,0x1A,0x75,0x73,0xB5,0xCE,0x01,
    ///     0x56,0xCD,0x1A,0x75,0x73,0xB5,0xCE,0x01,0x56,0xCD,0x1A,0x75,0x73,0xB5,0xCE,0x01,
    ///     0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    ///     0x00,0x00,0x00,0x00,0xB0,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    ///     0x68,0x58,0xA0,0x0A,0x02,0x00,0x00,0x00
    /// ];
    ///
    /// let attribute = StandardInfoAttr::from_reader(&mut Cursor::new(attribute_buffer)).unwrap();
    ///
    /// assert_eq!(attribute.created.timestamp(), 1376278290);
    /// assert_eq!(attribute.modified.timestamp(), 1379621073);
    /// assert_eq!(attribute.mft_modified.timestamp(), 1379621073);
    /// assert_eq!(attribute.accessed.timestamp(), 1379621073);
    /// assert_eq!(attribute.file_flags.bits(), 32);
    /// assert_eq!(attribute.max_version, 0);
    /// assert_eq!(attribute.version, 0);
    /// assert_eq!(attribute.class_id, 0);
    /// assert_eq!(attribute.security_id, 1456);
    /// assert_eq!(attribute.quota, 0);
    /// assert_eq!(attribute.usn, 8768215144);
    /// ```
    pub fn from_reader<S: Read + Seek>(reader: &mut S) -> Result<StandardInfoAttr> {
        trace!("Offset {}: StandardInfoAttr", reader.stream_position()?);
        let created = WinTimestamp::from_reader(reader)
            .map_err(Error::failed_to_read_windows_time)?
            .to_datetime();
        let modified = WinTimestamp::from_reader(reader)
            .map_err(Error::failed_to_read_windows_time)?
            .to_datetime();
        let mft_modified = WinTimestamp::from_reader(reader)
            .map_err(Error::failed_to_read_windows_time)?
            .to_datetime();
        let accessed = WinTimestamp::from_reader(reader)
            .map_err(Error::failed_to_read_windows_time)?
            .to_datetime();

        Ok(StandardInfoAttr {
            created,
            modified,
            mft_modified,
            accessed,
            file_flags: FileAttributeFlags::from_bits_truncate(reader.read_u32::<LittleEndian>()?),
            max_version: reader.read_u32::<LittleEndian>()?,
            version: reader.read_u32::<LittleEndian>()?,
            class_id: reader.read_u32::<LittleEndian>()?,
            owner_id: reader.read_u32::<LittleEndian>()?,
            security_id: reader.read_u32::<LittleEndian>()?,
            quota: reader.read_u64::<LittleEndian>()?,
            usn: reader.read_u64::<LittleEndian>()?,
        })
    }
}
