use errors::{MftError};
use rwinstructs::timestamp::{WinTimestamp};
use rwinstructs::reference::{MftReference};
use rwinstructs::serialize::{serialize_u64};
use byteorder::{ReadBytesExt, LittleEndian};
use encoding::{Encoding, DecoderTrap};
use encoding::all::UTF_16LE;
use std::io::Read;
use std::mem;

#[derive(Serialize, Clone, Debug)]
pub struct FileNameAttr {
    pub parent: MftReference,
    pub created: WinTimestamp,
    pub modified: WinTimestamp,
    pub mft_modified: WinTimestamp,
    pub accessed: WinTimestamp,
    #[serde(serialize_with = "serialize_u64")]
    pub logical_size: u64,
    #[serde(serialize_with = "serialize_u64")]
    pub physical_size: u64,
    pub flags: u32,
    pub reparse_value: u32,
    pub name_length: u8,
    pub namespace: u8,
    pub name: String,
    pub fullname: Option<String>
}
impl FileNameAttr {
    pub fn new<R: Read>(mut reader: R) -> Result<FileNameAttr,MftError> {
        let mut attribute: FileNameAttr = unsafe {
            mem::zeroed()
        };

        attribute.parent = MftReference(reader.read_u64::<LittleEndian>()?);
        attribute.created = WinTimestamp(reader.read_u64::<LittleEndian>()?);
        attribute.modified = WinTimestamp(reader.read_u64::<LittleEndian>()?);
        attribute.mft_modified = WinTimestamp(reader.read_u64::<LittleEndian>()?);
        attribute.accessed = WinTimestamp(reader.read_u64::<LittleEndian>()?);
        attribute.logical_size = reader.read_u64::<LittleEndian>()?;
        attribute.physical_size = reader.read_u64::<LittleEndian>()?;
        attribute.flags = reader.read_u32::<LittleEndian>()?;
        attribute.reparse_value = reader.read_u32::<LittleEndian>()?;
        attribute.name_length = reader.read_u8()?;
        attribute.namespace = reader.read_u8()?;

        let mut name_buffer = vec![0; (attribute.name_length as usize * 2) as usize];
        reader.read_exact(&mut name_buffer)?;

        attribute.name = match UTF_16LE.decode(&name_buffer,DecoderTrap::Ignore){
            Ok(filename) => filename,
            Err(error) => return Err(
                MftError::decode_error(
                    format!("Error decoding name in filename attribute. [{}]",error)
                )
            )
        };

        Ok(attribute)
    }
}

#[cfg(test)]
mod tests {
    use super::FileNameAttr;

    #[test]
    fn fn_attribute_test_01() {
        let attribute_buffer: &[u8] = &[
            0x05,0x00,0x00,0x00,0x00,0x00,0x05,0x00,0xD5,0x2D,0x48,0x58,0x43,0x5F,0xCE,0x01,
            0xD5,0x2D,0x48,0x58,0x43,0x5F,0xCE,0x01,0xD5,0x2D,0x48,0x58,0x43,0x5F,0xCE,0x01,
            0xD5,0x2D,0x48,0x58,0x43,0x5F,0xCE,0x01,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x00,0x06,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x08,0x03,0x24,0x00,0x4C,0x00,0x6F,0x00,0x67,0x00,0x46,0x00,0x69,0x00,0x6C,0x00,
            0x65,0x00,0x00,0x00,0x00,0x00,0x00,0x00
        ];

        let attribute = match FileNameAttr::new(attribute_buffer) {
            Ok(attribute) => attribute,
            Err(error) => panic!(error)
        };

        assert_eq!(attribute.parent.0, 1407374883553285);
        assert_eq!(attribute.created.0, 130146182088895957);
        assert_eq!(attribute.modified.0, 130146182088895957);
        assert_eq!(attribute.mft_modified.0, 130146182088895957);
        assert_eq!(attribute.accessed.0, 130146182088895957);
        assert_eq!(attribute.logical_size, 67108864);
        assert_eq!(attribute.physical_size, 67108864);
        assert_eq!(attribute.flags, 6);
        assert_eq!(attribute.reparse_value, 0);
        assert_eq!(attribute.name_length, 8);
        assert_eq!(attribute.namespace, 3);
        assert_eq!(attribute.name, "$LogFile");
    }
}
