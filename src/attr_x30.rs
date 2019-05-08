use crate::err::{self, Result};

use byteorder::{LittleEndian, ReadBytesExt};
use encoding::all::UTF_16LE;
use encoding::{DecoderTrap, Encoding};

use std::io::Read;

use chrono::{DateTime, Utc};
use serde::Serialize;

use winstructs::reference::MftReference;
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
    pub flags: u32,
    pub reparse_value: u32,
    pub name_length: u8,
    pub namespace: u8,
    pub name: String,
    pub fullname: Option<String>,
}

// TODO: fix docs (use correct idioms)
impl FileNameAttr {
    /// Parse a Filename attrbiute buffer.
    ///
    /// # Example
    ///
    /// Parse a raw buffer.
    ///
    /// ```
    /// use rustymft::attr_x30::FileNameAttr;
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
    /// let attribute = match FileNameAttr::new(attribute_buffer) {
    /// 	Ok(attribute) => attribute,
    /// 	Err(error) => panic!(error)
    /// };
    ///
    /// assert_eq!(attribute.parent.0, 1407374883553285);
    /// assert_eq!(attribute.created.0, 130146182088895957);
    /// assert_eq!(attribute.modified.0, 130146182088895957);
    /// assert_eq!(attribute.mft_modified.0, 130146182088895957);
    /// assert_eq!(attribute.accessed.0, 130146182088895957);
    /// assert_eq!(attribute.logical_size, 67108864);
    /// assert_eq!(attribute.physical_size, 67108864);
    /// assert_eq!(attribute.flags, 6);
    /// assert_eq!(attribute.reparse_value, 0);
    /// assert_eq!(attribute.name_length, 8);
    /// assert_eq!(attribute.namespace, 3);
    /// assert_eq!(attribute.name, "$LogFile");
    /// # }
    /// ```
    pub fn from_reader<R: Read>(reader: &mut R) -> Result<FileNameAttr> {
        let parent = MftReference(reader.read_u64::<LittleEndian>()?);
        let created = WinTimestamp::from_reader(reader)?.to_datetime();
        let modified = WinTimestamp::from_reader(reader)?.to_datetime();
        let mft_modified = WinTimestamp::from_reader(reader)?.to_datetime();
        let accessed = WinTimestamp::from_reader(reader)?.to_datetime();
        let logical_size = reader.read_u64::<LittleEndian>()?;
        let physical_size = reader.read_u64::<LittleEndian>()?;
        let flags = reader.read_u32::<LittleEndian>()?;
        let reparse_value = reader.read_u32::<LittleEndian>()?;
        let name_length = reader.read_u8()?;
        let namespace = reader.read_u8()?;

        let mut name_buffer = vec![0; (name_length as usize * 2) as usize];
        reader.read_exact(&mut name_buffer)?;

        let name = match UTF_16LE.decode(&name_buffer, DecoderTrap::Ignore) {
            Ok(s) => s,
            Err(_e) => return err::InvalidFilename {}.fail(),
        };

        let fullname = None;

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
            fullname,
        })
    }
}
