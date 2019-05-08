use crate::attr_x10::StandardInfoAttr;
use crate::attr_x30::FileNameAttr;
use crate::err::{self, Result};
use crate::utils::read_utf16_string;
use crate::{utils, ReadSeek};


use bitflags::bitflags;
use byteorder::{LittleEndian, ReadBytesExt};

use serde::{ser, Serialize};
use std::io::Read;

#[derive(Clone, Debug)]
pub struct RawAttribute(pub Vec<u8>);

impl ser::Serialize for RawAttribute {
    fn serialize<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&utils::to_hex_string(&self.0).to_string())
    }
}

#[derive(Serialize, Clone, Debug)]
#[serde(untagged)]
pub enum AttributeContent {
    Raw(RawAttribute),
    AttrX10(StandardInfoAttr),
    AttrX30(FileNameAttr),
    None,
}

bitflags! {
    #[derive(Default)]
    pub struct AttributeDataFlags: u16 {
        const IS_COMPRESSED     = 0x0001;
        const COMPRESSION_MASK  = 0x00FF;
        const ENCRYPTED         = 0x4000;
        const SPARSE            = 0x8000;
    }
}

pub fn serialize_attr_data_flags<S>(
    item: &AttributeDataFlags,
    serializer: S,
) -> ::std::result::Result<S::Ok, S::Error>
where
    S: ser::Serializer,
{
    serializer.serialize_str(&format!("{:?}", item))
}

#[derive(Serialize, Clone, Debug, Default)]
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
    pub residential_header: ResidentialHeader,
}

impl AttributeHeader {
    pub fn from_stream<S: ReadSeek>(stream: &mut S) -> Result<AttributeHeader> {
        let current_offset = stream.tell()?;

        let attribute_type = stream.read_u32::<LittleEndian>()?;
        // The attribute list is terminated with 0xFFFFFFFF ($END).
        if attribute_type == 0xFFFF_FFFF {
            return Ok(AttributeHeader {
                attribute_type: 0xFFFF_FFFF,
                ..Default::default()
            });
        }

        let attribute_size = stream.read_u32::<LittleEndian>()?;
        let resident_flag = stream.read_u8()?;
        let name_size = stream.read_u8()?;
        let name_offset = stream.read_u16::<LittleEndian>()?;
        let data_flags = AttributeDataFlags::from_bits_truncate(stream.read_u16::<LittleEndian>()?);
        let id = stream.read_u16::<LittleEndian>()?;

        let residential_header = match resident_flag {
            0 => ResidentialHeader::Resident(ResidentHeader::new(stream)?),
            1 => ResidentialHeader::NonResident(NonResidentHeader::new(stream)?),
            _ => {
                return err::UnhandledResidentFlag {
                    flag: resident_flag,
                    offset: current_offset,
                }
                .fail();
            }
        };

        let name = if name_size > 0 {
            read_utf16_string(stream, Some(name_size as usize))?
        } else {
            String::new()
        };

        Ok(AttributeHeader {
            attribute_type,
            attribute_size,
            resident_flag,
            name_size,
            name_offset,
            data_flags,
            id,
            name,
            residential_header,
        })
    }
}

#[derive(Serialize, Clone, Debug)]
#[serde(untagged)]
pub enum ResidentialHeader {
    None,
    Resident(ResidentHeader),
    NonResident(NonResidentHeader),
}

impl Default for ResidentialHeader {
    fn default() -> Self {
        ResidentialHeader::None
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct ResidentHeader {
    #[serde(skip_serializing)]
    pub data_size: u32,
    #[serde(skip_serializing)]
    pub data_offset: u16,
    pub index_flag: u8,
    #[serde(skip_serializing)]
    pub padding: u8,
}

impl ResidentHeader {
    pub fn new<R: Read>(reader: &mut R) -> Result<ResidentHeader> {
        Ok(ResidentHeader {
            data_size: reader.read_u32::<LittleEndian>()?,
            data_offset: reader.read_u16::<LittleEndian>()?,
            index_flag: reader.read_u8()?,
            padding: reader.read_u8()?,
        })
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct NonResidentHeader {
    pub vnc_first: u64,
    pub vnc_last: u64,
    #[serde(skip_serializing)]
    pub datarun_offset: u16,
    pub unit_compression_size: u16,
    #[serde(skip_serializing)]
    pub padding: u32,
    pub size_allocated: u64,
    pub size_real: u64,
    pub size_compressed: u64,
    // pub size_total_allocated: Option<u64>
}
impl NonResidentHeader {
    pub fn new<R: Read>(reader: &mut R) -> Result<NonResidentHeader> {
        let vnc_first = reader.read_u64::<LittleEndian>()?;
        let vnc_last = reader.read_u64::<LittleEndian>()?;
        let datarun_offset = reader.read_u16::<LittleEndian>()?;
        let unit_compression_size = reader.read_u16::<LittleEndian>()?;
        let padding = reader.read_u32::<LittleEndian>()?;
        let size_allocated = reader.read_u64::<LittleEndian>()?;
        let size_real = reader.read_u64::<LittleEndian>()?;
        let size_compressed = reader.read_u64::<LittleEndian>()?;

        // if residential_header.unit_compression_size > 0 {
        //     residential_header.size_total_allocated = Some(reader.read_u64::<LittleEndian>()?);
        // }

        Ok(NonResidentHeader {
            vnc_first,
            vnc_last,
            datarun_offset,
            unit_compression_size,
            padding,
            size_allocated,
            size_real,
            size_compressed,
        })
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct MftAttribute {
    pub header: AttributeHeader,
    pub content: AttributeContent,
}

#[cfg(test)]
mod tests {
    use super::AttributeHeader;
    use std::io::Cursor;

    #[test]
    fn attribute_test_01_resident() {
        let raw: &[u8] = &[
            0x10, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00,
        ];
        let mut cursor = Cursor::new(raw);

        let attribute_header = match AttributeHeader::from_stream(&mut cursor) {
            Ok(attribute_header) => attribute_header,
            Err(error) => panic!(error),
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
            0x80, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x40, 0x00, 0x00, 0x00,
            0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBF, 0x1E, 0x01, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xEC, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xEC, 0x11, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0xEC, 0x11, 0x00, 0x00, 0x00, 0x00, 0x33, 0x20, 0xC8, 0x00, 0x00, 0x00,
            0x0C, 0x32, 0xA0, 0x56, 0xE3, 0xE6, 0x24, 0x00, 0xFF, 0xFF,
        ];

        let mut cursor = Cursor::new(raw);

        let attribute_header = match AttributeHeader::from_stream(&mut cursor) {
            Ok(attribute_header) => attribute_header,
            Err(error) => panic!(error),
        };

        assert_eq!(attribute_header.attribute_type, 128);
        assert_eq!(attribute_header.attribute_size, 80);
        assert_eq!(attribute_header.resident_flag, 1);
        assert_eq!(attribute_header.name_size, 0);
        assert_eq!(attribute_header.name_offset, 64);
    }
}
