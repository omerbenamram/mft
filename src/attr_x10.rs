use errors::{MftError};
use rwinstructs::timestamp::{WinTimestamp};
use rwinstructs::serialize::{serialize_u64};
use byteorder::{ReadBytesExt, LittleEndian};
use std::io::Read;
use std::mem;

#[derive(Serialize, Debug)]
pub struct StandardInformationAttribute {
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
    #[serde(serialize_with = "serialize_u64")]
    pub quota: u64,
    #[serde(serialize_with = "serialize_u64")]
    pub usn: u64
}
impl StandardInformationAttribute {
    pub fn new<R: Read>(mut reader: R) -> Result<StandardInformationAttribute,MftError> {
        let mut attribute: StandardInformationAttribute = unsafe {
            mem::zeroed()
        };

        attribute.created = WinTimestamp(reader.read_u64::<LittleEndian>()?);
        attribute.modified = WinTimestamp(reader.read_u64::<LittleEndian>()?);
        attribute.mft_modified = WinTimestamp(reader.read_u64::<LittleEndian>()?);
        attribute.accessed = WinTimestamp(reader.read_u64::<LittleEndian>()?);
        attribute.file_flags = reader.read_u32::<LittleEndian>()?;
        attribute.max_version = reader.read_u32::<LittleEndian>()?;
        attribute.version = reader.read_u32::<LittleEndian>()?;
        attribute.class_id = reader.read_u32::<LittleEndian>()?;
        attribute.owner_id = reader.read_u32::<LittleEndian>()?;
        attribute.security_id = reader.read_u32::<LittleEndian>()?;
        attribute.quota = reader.read_u64::<LittleEndian>()?;
        attribute.usn = reader.read_u64::<LittleEndian>()?;

        Ok(attribute)
    }
}

#[cfg(test)]
mod tests {
    use super::StandardInformationAttribute;

    #[test]
    fn si_attribute_test_01() {
        let attribute_buffer: &[u8] = &[
            0x2F,0x6D,0xB6,0x6F,0x0C,0x97,0xCE,0x01,0x56,0xCD,0x1A,0x75,0x73,0xB5,0xCE,0x01,
            0x56,0xCD,0x1A,0x75,0x73,0xB5,0xCE,0x01,0x56,0xCD,0x1A,0x75,0x73,0xB5,0xCE,0x01,
            0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0xB0,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x68,0x58,0xA0,0x0A,0x02,0x00,0x00,0x00
        ];

        let attribute = match StandardInformationAttribute::new(attribute_buffer) {
            Ok(attribute) => attribute,
            Err(error) => panic!(error)
        };

        assert_eq!(attribute.created.0, 130207518909951279);
        assert_eq!(attribute.modified.0, 130240946730880342);
        assert_eq!(attribute.mft_modified.0, 130240946730880342);
        assert_eq!(attribute.accessed.0, 130240946730880342);
        assert_eq!(attribute.file_flags, 32);
        assert_eq!(attribute.max_version, 0);
        assert_eq!(attribute.version, 0);
        assert_eq!(attribute.class_id, 0);
        assert_eq!(attribute.security_id, 1456);
        assert_eq!(attribute.quota, 0);
        assert_eq!(attribute.usn, 8768215144);
    }
}
