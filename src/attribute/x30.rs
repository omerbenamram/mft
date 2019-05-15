use crate::err::{self, Result};
use crate::{impl_serialize_for_bitflags, ReadSeek};
use log::trace;

use bitflags::bitflags;
use byteorder::{LittleEndian, ReadBytesExt};
use encoding::all::UTF_16LE;
use encoding::{DecoderTrap, Encoding};

use chrono::{DateTime, Utc};
use serde::Serialize;

use snafu::ResultExt;
use winstructs::ntfs::mft_reference::MftReference;
use winstructs::timestamp::WinTimestamp;

#[derive(Serialize, Clone, Debug)]
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
    pub namespace: u8,
    pub name: String,
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

impl FileNameAttr {
    /// Parse a Filename attrbiute buffer.
    ///
    /// # Example
    ///
    /// Parse a raw buffer.
    ///
    /// ```
    /// use mft::attribute::x30::FileNameAttr;
    /// # use std::io::Cursor;
    /// # fn test_filename_attribute() {
    /// let attribute_buffer: &[u8] = &[
    /// 	0x05,0x00,0x00,0x00,0x00,0x00,0x05,0x00,0xD5,0x2D,0x48,0x58,0x43,0x5F,0xCE,0x01,
    /// 	0xD5,0x2D,0x48,0x58,0x43,0x5F,0xCE,0x01,0xD5,0x2D,0x48,0x58,0x43,0x5F,0xCE,0x01,
    /// 	0xD5,0x2D,0x48,0x58,0x43,0x5F,0xCE,0x01,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x00,
    /// 	0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x00,0x06,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    /// 	0x08,0x03,0x24,0x00,0x4C,0x00,0x6F,0x00,0x67,0x00,0x46,0x00,0x69,0x00,0x6C,0x00,
    /// 	0x65,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    /// ];
    ///
    /// let attribute = FileNameAttr::from_stream(&mut Cursor::new(attribute_buffer)).unwrap();
    ///
    /// assert_eq!(attribute.parent.entry, 1407374883553285);
    /// assert_eq!(attribute.created.timestamp(), 130146182088895957);
    /// assert_eq!(attribute.modified.timestamp(), 130146182088895957);
    /// assert_eq!(attribute.mft_modified.timestamp(), 130146182088895957);
    /// assert_eq!(attribute.accessed.timestamp(), 130146182088895957);
    /// assert_eq!(attribute.logical_size, 67108864);
    /// assert_eq!(attribute.physical_size, 67108864);
    /// assert_eq!(attribute.flags, 6);
    /// assert_eq!(attribute.reparse_value, 0);
    /// assert_eq!(attribute.name_length, 8);
    /// assert_eq!(attribute.namespace, 3);
    /// assert_eq!(attribute.name, "$LogFile");
    /// # }
    /// ```
    pub fn from_stream<S: ReadSeek>(stream: &mut S) -> Result<FileNameAttr> {
        trace!("Offset {}: FilenameAttr", stream.tell()?);
        let parent = MftReference::from_reader(stream).context(err::FailedToReadMftReference)?;
        let created = WinTimestamp::from_reader(stream)
            .context(err::FailedToReadWindowsTime)?
            .to_datetime();
        let modified = WinTimestamp::from_reader(stream)
            .context(err::FailedToReadWindowsTime)?
            .to_datetime();
        let mft_modified = WinTimestamp::from_reader(stream)
            .context(err::FailedToReadWindowsTime)?
            .to_datetime();
        let accessed = WinTimestamp::from_reader(stream)
            .context(err::FailedToReadWindowsTime)?
            .to_datetime();

        let logical_size = stream.read_u64::<LittleEndian>()?;
        let physical_size = stream.read_u64::<LittleEndian>()?;
        let flags = FileAttributeFlags::from_bits_truncate(stream.read_u32::<LittleEndian>()?);
        let reparse_value = stream.read_u32::<LittleEndian>()?;
        let name_length = stream.read_u8()?;
        let namespace = stream.read_u8()?;

        let mut name_buffer = vec![0; (name_length as usize * 2) as usize];
        stream.read_exact(&mut name_buffer)?;

        let name = match UTF_16LE.decode(&name_buffer, DecoderTrap::Ignore) {
            Ok(s) => s,
            Err(_e) => return err::InvalidFilename {}.fail(),
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