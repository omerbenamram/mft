use errors::{MftError};
use rwinstructs::timestamp::{WinTimestamp};
use byteorder::{ReadBytesExt,LittleEndian};
use serde::ser::SerializeStruct;
use serde::ser;

#[derive(Debug, Clone)]
pub struct StandardInfoAttr {
    pub created: WinTimestamp,
    pub modified: WinTimestamp,
    pub mft_modified: WinTimestamp,
    pub accessed: WinTimestamp,
    pub file_flags: u32,
    pub max_version: u32,
    pub version: u32,
    pub class_id: u32,
    pub owner_id: u32,
    pub security_id: u32,
    pub quota: u64,
    pub usn: u64
}
impl StandardInfoAttr {
    /// Parse a Standard Information attrbiute buffer.
    ///
    /// # Example
    ///
    /// Parse a raw buffer.
    ///
    /// ```
    /// use rustymft::attr_x10::StandardInfoAttr;
    /// # fn test_standard_information() {
    /// let attribute_buffer: &[u8] = &[
    /// 	0x2F,0x6D,0xB6,0x6F,0x0C,0x97,0xCE,0x01,0x56,0xCD,0x1A,0x75,0x73,0xB5,0xCE,0x01,
    /// 	0x56,0xCD,0x1A,0x75,0x73,0xB5,0xCE,0x01,0x56,0xCD,0x1A,0x75,0x73,0xB5,0xCE,0x01,
    /// 	0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    /// 	0x00,0x00,0x00,0x00,0xB0,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    /// 	0x68,0x58,0xA0,0x0A,0x02,0x00,0x00,0x00
    /// ];
    ///
    /// let attribute = StandardInfoAttr::new(attribute_buffer).unwrap();
    ///
    /// assert_eq!(attribute.created.0, 130207518909951279);
    /// assert_eq!(attribute.modified.0, 130240946730880342);
    /// assert_eq!(attribute.mft_modified.0, 130240946730880342);
    /// assert_eq!(attribute.accessed.0, 130240946730880342);
    /// assert_eq!(attribute.file_flags, 32);
    /// assert_eq!(attribute.max_version, 0);
    /// assert_eq!(attribute.version, 0);
    /// assert_eq!(attribute.class_id, 0);
    /// assert_eq!(attribute.security_id, 1456);
    /// assert_eq!(attribute.quota, 0);
    /// assert_eq!(attribute.usn, 8768215144);
    /// # }
    /// ```
    pub fn new(mut buffer: &[u8])->Result<StandardInfoAttr,MftError> {
        let created = WinTimestamp(buffer.read_u64::<LittleEndian>()?);
        let modified = WinTimestamp(buffer.read_u64::<LittleEndian>()?);
        let mft_modified = WinTimestamp(buffer.read_u64::<LittleEndian>()?);
        let accessed = WinTimestamp(buffer.read_u64::<LittleEndian>()?);
        let file_flags = buffer.read_u32::<LittleEndian>()?;
        let max_version = buffer.read_u32::<LittleEndian>()?;
        let version = buffer.read_u32::<LittleEndian>()?;
        let class_id = buffer.read_u32::<LittleEndian>()?;
        let owner_id = buffer.read_u32::<LittleEndian>()?;
        let security_id = buffer.read_u32::<LittleEndian>()?;
        let quota = buffer.read_u64::<LittleEndian>()?;
        let usn = buffer.read_u64::<LittleEndian>()?;

        Ok(
            StandardInfoAttr {
                created: created,
                modified: modified,
                mft_modified: mft_modified,
                accessed: accessed,
                file_flags: file_flags,
                max_version: max_version,
                version: version,
                class_id: class_id,
                owner_id: owner_id,
                security_id: security_id,
                quota: quota,
                usn: usn
            }
        )
    }
}

impl ser::Serialize for StandardInfoAttr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: ser::Serializer
    {
        let mut state = serializer.serialize_struct("StandardInfoAttr", 5)?;
        state.serialize_field("created", &format!("{}",&self.created))?;
        state.serialize_field("modified", &format!("{}",&self.created))?;
        state.serialize_field("mft_modified", &format!("{}",&self.created))?;
        state.serialize_field("accessed", &format!("{}",&self.created))?;
        state.serialize_field("file_flags", &self.file_flags)?;
        state.serialize_field("max_version", &self.max_version)?;
        state.serialize_field("class_id", &self.class_id)?;
        state.serialize_field("owner_id", &self.owner_id)?;
        state.serialize_field("security_id", &self.security_id)?;
        state.serialize_field("quota", &format!("{}",&self.quota))?;
        state.serialize_field("usn", &format!("{}",&self.usn))?;
        state.end()
    }
}
