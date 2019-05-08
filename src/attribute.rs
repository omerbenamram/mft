use crate::errors::{MftError};
use crate::utils;
use crate::attr_x10::{StandardInfoAttr};
use crate::attr_x30::{FileNameAttr};
use rwinstructs::serialize::{serialize_u64};
use byteorder::{ReadBytesExt, LittleEndian};
use encoding::{Encoding, DecoderTrap};
use encoding::all::UTF_16LE;
use serde::{ser};
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::mem;

#[derive(Clone, Debug)]
pub struct RawAttribute(
    pub Vec<u8>
);
impl ser::Serialize for RawAttribute {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: ser::Serializer
    {
        serializer.serialize_str(
            &format!("{}",
            utils::to_hex_string(&self.0))
        )
    }
}

#[derive(Serialize, Clone, Debug)]
#[serde(untagged)]
pub enum AttributeContent {
    Raw(RawAttribute),
    AttrX10(StandardInfoAttr),
    AttrX30(FileNameAttr),
    None
}

bitflags! {
    pub flags AttributeDataFlags: u16 {
        const IS_COMPRESSED     = 0x0001,
        const COMPRESSION_MASK  = 0x00FF,
        const ENCRYPTED         = 0x4000,
        const SPARSE            = 0x8000
    }
}

pub fn serialize_attr_data_flags<S>(&item: &AttributeDataFlags, serializer: S)
    -> Result<S::Ok, S::Error> where S: ser::Serializer
{
    serializer.serialize_str(&format!("{:?}", item))
}

#[derive(Serialize, Clone, Debug)]
pub struct AttributeHeader {
    pub attribute_type: u32,
    #[serde(skip_serializing)]
    pub attribute_size: u32,
    pub resident_flag: u8, // 0 -> resident; 1 -> non-resident
    #[serde(skip_serializing)]
    pub name_size: u8,
    #[serde(skip_serializing)]
    pub name_offset: u16,
    #[serde(serialize_with = "serialize_attr_data_flags")]
    pub data_flags: AttributeDataFlags,
    pub id: u16,
    pub name: String,
    // 16
    pub residential_header: ResidentialHeader
}
impl AttributeHeader {
    pub fn new<R: Read+Seek>(mut reader: R) -> Result<AttributeHeader,MftError> {
        let mut attribute_header: AttributeHeader = unsafe {
            mem::zeroed()
        };

        let current_offset = reader.seek(SeekFrom::Current(0))?;
        // println!("at offset {}",current_offset);

        attribute_header.attribute_type = reader.read_u32::<LittleEndian>()?;
        if attribute_header.attribute_type == 0xFFFFFFFF {
            return Ok(attribute_header);
        }
        attribute_header.attribute_size = reader.read_u32::<LittleEndian>()?;
        attribute_header.resident_flag = reader.read_u8()?;
        attribute_header.name_size = reader.read_u8()?;
        attribute_header.name_offset = reader.read_u16::<LittleEndian>()?;
        attribute_header.data_flags = AttributeDataFlags::from_bits_truncate(
            reader.read_u16::<LittleEndian>()?
        );
        attribute_header.id = reader.read_u16::<LittleEndian>()?;

        if attribute_header.resident_flag == 0 {
            attribute_header.residential_header = ResidentialHeader::Resident(
                ResidentHeader::new(
                    &mut reader
                )?
            );
        } else if attribute_header.resident_flag == 1 {
            attribute_header.residential_header = ResidentialHeader::NonResident(
                NonResidentHeader::new(
                    &mut reader
                )?
            );
        } else {
            panic!(
                "Unhandled resident flag: {} (offet: {})",
                attribute_header.resident_flag,
                current_offset
            );
        }

        if attribute_header.name_size > 0 {
            // Seek to offset
            reader.seek(
                SeekFrom::Start(
                    current_offset + attribute_header.name_offset as u64
                )
            )?;

            let mut name_buffer = vec![0; (attribute_header.name_size * 2) as usize];
            reader.read_exact(&mut name_buffer)?;

            attribute_header.name = match UTF_16LE.decode(&name_buffer,DecoderTrap::Ignore){
                Ok(filename) => filename,
                Err(error) => return Err(
                    MftError::decode_error(
                        format!("Error decoding filename in header. [{}]",error)
                    )
                )
            };
        }

        Ok(attribute_header)
    }
}

#[derive(Serialize, Clone, Debug)]
#[serde(untagged)]
pub enum ResidentialHeader{
    None,
    Resident(ResidentHeader),
    NonResident(NonResidentHeader)
}

#[derive(Serialize, Clone, Debug)]
pub struct ResidentHeader{
    #[serde(skip_serializing)]
    pub data_size: u32,
    #[serde(skip_serializing)]
    pub data_offset: u16,
    pub index_flag: u8,
    #[serde(skip_serializing)]
    pub padding: u8,
}
impl ResidentHeader {
    pub fn new<R: Read>(mut reader: R) -> Result<ResidentHeader,MftError> {
        let mut residential_header: ResidentHeader = unsafe {
            mem::zeroed()
        };

        residential_header.data_size = reader.read_u32::<LittleEndian>()?;
        residential_header.data_offset = reader.read_u16::<LittleEndian>()?;
        residential_header.index_flag = reader.read_u8()?;
        residential_header.padding = reader.read_u8()?;

        Ok(residential_header)
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct NonResidentHeader{
    #[serde(serialize_with = "serialize_u64")]
    pub vnc_first: u64,
    #[serde(serialize_with = "serialize_u64")]
    pub vnc_last: u64,
    #[serde(skip_serializing)]
    pub datarun_offset: u16,
    pub unit_compression_size: u16,
    #[serde(skip_serializing)]
    pub padding: u32,
    #[serde(serialize_with = "serialize_u64")]
    pub size_allocated: u64,
    #[serde(serialize_with = "serialize_u64")]
    pub size_real: u64,
    #[serde(serialize_with = "serialize_u64")]
    pub size_compressed: u64,
    // pub size_total_allocated: Option<u64>
}
impl NonResidentHeader {
    pub fn new<R: Read>(mut reader: R) -> Result<NonResidentHeader,MftError> {
        let mut residential_header: NonResidentHeader = unsafe {
            mem::zeroed()
        };

        residential_header.vnc_first = reader.read_u64::<LittleEndian>()?;
        residential_header.vnc_last = reader.read_u64::<LittleEndian>()?;
        residential_header.datarun_offset = reader.read_u16::<LittleEndian>()?;
        residential_header.unit_compression_size = reader.read_u16::<LittleEndian>()?;
        residential_header.padding = reader.read_u32::<LittleEndian>()?;
        residential_header.size_allocated = reader.read_u64::<LittleEndian>()?;
        residential_header.size_real = reader.read_u64::<LittleEndian>()?;
        residential_header.size_compressed = reader.read_u64::<LittleEndian>()?;

        // if residential_header.unit_compression_size > 0 {
        //     residential_header.size_total_allocated = Some(reader.read_u64::<LittleEndian>()?);
        // }

        Ok(residential_header)
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct MftAttribute{
    pub header: AttributeHeader,
    pub content: AttributeContent
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use super::AttributeHeader;

    #[test]
    fn attribute_test_01_resident() {
        let raw: &[u8] = &[
            0x10,0x00,0x00,0x00,0x60,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x48,0x00,0x00,0x00,0x18,0x00,0x00,0x00
        ];
        let attribute_buffer = Cursor::new(raw);

        let attribute_header = match AttributeHeader::new(attribute_buffer) {
            Ok(attribute_header) => attribute_header,
            Err(error) => panic!(error)
        };

        assert_eq!(attribute_header.attribute_type, 16);
        assert_eq!(attribute_header.attribute_size, 96);
        assert_eq!(attribute_header.resident_flag, 0);
        assert_eq!(attribute_header.name_size, 0);
        assert_eq!(attribute_header.name_offset, 0);
    }

    #[test]
    fn attribute_test_01_nonresident() {
        let raw: &[u8] = &[
            0x80,0x00,0x00,0x00,0x50,0x00,0x00,0x00,0x01,0x00,0x40,0x00,0x00,0x00,0x06,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xBF,0x1E,0x01,0x00,0x00,0x00,0x00,0x00,
            0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xEC,0x11,0x00,0x00,0x00,0x00,
            0x00,0x00,0xEC,0x11,0x00,0x00,0x00,0x00,0x00,0x00,0xEC,0x11,0x00,0x00,0x00,0x00,
            0x33,0x20,0xC8,0x00,0x00,0x00,0x0C,0x32,0xA0,0x56,0xE3,0xE6,0x24,0x00,0xFF,0xFF
        ];

        let attribute_buffer = Cursor::new(raw);

        let attribute_header = match AttributeHeader::new(attribute_buffer) {
            Ok(attribute_header) => attribute_header,
            Err(error) => panic!(error)
        };

        assert_eq!(attribute_header.attribute_type, 128);
        assert_eq!(attribute_header.attribute_size, 80);
        assert_eq!(attribute_header.resident_flag, 1);
        assert_eq!(attribute_header.name_size, 0);
        assert_eq!(attribute_header.name_offset, 64);
    }
}
