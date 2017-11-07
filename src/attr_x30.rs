use errors::{MftError};
use rwinstructs::timestamp::{WinTimestamp};
use rwinstructs::reference::{MftReference};
use byteorder::{ReadBytesExt, LittleEndian};
use encoding::{Encoding, DecoderTrap};
use encoding::all::UTF_16LE;
use std::io::Read;
use std::mem;
use serde::ser::SerializeStruct;
use serde::ser;

#[derive(Clone, Debug)]
pub struct FileNameAttr {
    pub parent: MftReference,
    pub created: WinTimestamp,
    pub modified: WinTimestamp,
    pub mft_modified: WinTimestamp,
    pub accessed: WinTimestamp,
    pub logical_size: u64,
    pub physical_size: u64,
    pub flags: u32,
    pub reparse_value: u32,
    pub name_length: u8,
    pub namespace: u8,
    pub name: String,
    pub fullname: Option<String>
}
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
    pub fn new(mut buffer: &[u8]) -> Result<FileNameAttr,MftError> {
        let parent = MftReference(buffer.read_u64::<LittleEndian>()?);
        let created = WinTimestamp(buffer.read_u64::<LittleEndian>()?);
        let modified = WinTimestamp(buffer.read_u64::<LittleEndian>()?);
        let mft_modified = WinTimestamp(buffer.read_u64::<LittleEndian>()?);
        let accessed = WinTimestamp(buffer.read_u64::<LittleEndian>()?);
        let logical_size = buffer.read_u64::<LittleEndian>()?;
        let physical_size = buffer.read_u64::<LittleEndian>()?;
        let flags = buffer.read_u32::<LittleEndian>()?;
        let reparse_value = buffer.read_u32::<LittleEndian>()?;
        let name_length = buffer.read_u8()?;
        let namespace = buffer.read_u8()?;

        let mut name_buffer = vec![0; (name_length as usize * 2) as usize];
        buffer.read_exact(&mut name_buffer)?;

        let name = match UTF_16LE.decode(&name_buffer,DecoderTrap::Ignore){
            Ok(filename) => filename,
            Err(error) => return Err(
                MftError::decode_error(
                    format!("Error decoding name in filename attribute. [{}]",error)
                )
            )
        };

        let fullname = None;

        Ok(
            FileNameAttr {
                parent: parent,
                created: created,
                modified: modified,
                mft_modified: mft_modified,
                accessed: accessed,
                logical_size: logical_size,
                physical_size: physical_size,
                flags: flags,
                reparse_value: reparse_value,
                name_length: name_length,
                namespace: namespace,
                name: name,
                fullname: fullname
            }
        )
    }
}

impl ser::Serialize for FileNameAttr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: ser::Serializer
    {
        let mut state = serializer.serialize_struct("FileNameAttr", 13)?;

        state.serialize_field("parent",&self.parent)?;
        state.serialize_field("created", &format!("{}",&self.created))?;
        state.serialize_field("modified", &format!("{}",&self.modified))?;
        state.serialize_field("mft_modified", &format!("{}",&self.mft_modified))?;
        state.serialize_field("accessed", &self.accessed)?;
        state.serialize_field("logical_size", &self.logical_size)?;
        state.serialize_field("physical_size", &self.physical_size)?;
        state.serialize_field("flags", &self.flags)?;
        state.serialize_field("reparse_value", &self.reparse_value)?;
        state.serialize_field("name_length", &self.name_length)?;
        state.serialize_field("namespace", &self.namespace)?;
        state.serialize_field("name", &format!("{}",&self.name))?;

        match self.fullname {
            Some(ref fullname) => {
                state.serialize_field("fullname", &format!("{}",&fullname))?;
            },
            None => {}
        }

        state.end()
    }
}
