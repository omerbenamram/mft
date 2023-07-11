use crate::attribute::{AttributeDataFlags, MftAttributeType};
use crate::err::{Error, Result};
use crate::utils::read_utf16_string;

use byteorder::{LittleEndian, ReadBytesExt};
use num_traits::FromPrimitive;
use serde::Serialize;
use std::io::{Read, Seek, SeekFrom};

/// Represents the union defined in
/// <https://docs.microsoft.com/en-us/windows/desktop/devnotes/attribute-record-header>
#[derive(Serialize, Clone, Debug)]
pub struct MftAttributeHeader {
    pub type_code: MftAttributeType,
    /// The size of the attribute record, in bytes.
    /// This value reflects the required size for the record variant and is always rounded to the nearest quadword boundary.
    pub record_length: u32,
    /// If the FormCode member is RESIDENT_FORM (0x00), the union is a Resident structure.
    /// If FormCode is NONRESIDENT_FORM (0x01), the union is a Nonresident structure.
    pub form_code: u8,
    pub residential_header: ResidentialHeader,
    /// The size of the optional attribute name, in characters, or 0 if there is no attribute name.
    /// The maximum attribute name length is 255 characters.
    pub name_size: u8,
    /// The offset of the attribute name from the start of the attribute record, in bytes.
    /// If the NameLength member is 0, this member is undefined.
    pub name_offset: Option<u16>,
    pub data_flags: AttributeDataFlags,
    /// The unique instance for this attribute in the file record.
    pub instance: u16,
    pub name: String,
    /// start of the attribute; used for calculating relative offsets
    pub start_offset: u64
}

#[derive(Serialize, Clone, Debug)]
#[serde(untagged)]
pub enum ResidentialHeader {
    Resident(ResidentHeader),
    NonResident(NonResidentHeader),
}

impl MftAttributeHeader {
    /// Tries to read an AttributeHeader from the stream.
    /// Will return `None` if the type code is $END.
    pub fn from_stream<S: Read + Seek>(stream: &mut S) -> Result<Option<MftAttributeHeader>> {
        let attribute_header_start_offset = stream.stream_position()?;

        let type_code_value = stream.read_u32::<LittleEndian>()?;

        if type_code_value == 0xFFFF_FFFF {
            return Ok(None);
        }

        let type_code = match MftAttributeType::from_u32(type_code_value) {
            Some(attribute_type) => attribute_type,
            None => {
                return Err(Error::UnknownAttributeType {
                    attribute_type: type_code_value,
                })
            }
        };

        let attribute_size = stream.read_u32::<LittleEndian>()?;
        let resident_flag = stream.read_u8()?;
        let name_size = stream.read_u8()?;
        let name_offset = {
            // We always read the two bytes to advance the stream.
            let value = stream.read_u16::<LittleEndian>()?;
            if name_size > 0 {
                Some(value)
            } else {
                None
            }
        };

        let data_flags = AttributeDataFlags::from_bits_truncate(stream.read_u16::<LittleEndian>()?);
        let id = stream.read_u16::<LittleEndian>()?;

        let residential_header = match resident_flag {
            0 => ResidentialHeader::Resident(ResidentHeader::from_stream(stream)?),
            1 => ResidentialHeader::NonResident(NonResidentHeader::from_stream(stream)?),
            _ => {
                return Err(Error::UnhandledResidentFlag {
                    flag: resident_flag,
                    offset: stream.stream_position()?,
                })
            }
        };

        // Name is optional, and will not be present if size == 0.
        let name = if name_size > 0 {
            stream.seek(SeekFrom::Start(
                attribute_header_start_offset
                    + u64::from(name_offset.expect("name_size > 0 is invariant")),
            ))?;
            read_utf16_string(stream, Some(name_size as usize))?
        } else {
            String::new()
        };

        Ok(Some(MftAttributeHeader {
            type_code,
            record_length: attribute_size,
            form_code: resident_flag,
            name_size,
            name_offset,
            data_flags,
            instance: id,
            name,
            residential_header,
            start_offset: attribute_header_start_offset
        }))
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct ResidentHeader {
    #[serde(skip_serializing)]
    /// The size of the attribute value, in bytes.
    pub data_size: u32,
    #[serde(skip_serializing)]
    /// The offset to the value from the start of the attribute record, in bytes.
    pub data_offset: u16,
    pub index_flag: u8,
    pub padding: u8,
}

impl ResidentHeader {
    pub fn from_stream<R: Read>(reader: &mut R) -> Result<ResidentHeader> {
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
    /// The lowest virtual cluster number (VCN) covered by this attribute record.
    pub vnc_first: u64,
    /// The highest VCN covered by this attribute record.
    pub vnc_last: u64,
    #[serde(skip_serializing)]
    /// The offset to the mapping pairs array from the start of the attribute record, in bytes. For more information, see Remarks.
    pub datarun_offset: u16,
    /// Reserved UCHAR\[6]
    pub unit_compression_size: u16,
    #[serde(skip_serializing)]
    pub padding: u32,

    /// The allocated size of the file, in bytes.
    /// This value is an even multiple of the cluster size.
    /// This member is not valid if the LowestVcn member is nonzero.
    pub allocated_length: u64,
    pub file_size: u64,
    ///  Contains the valid data size in number of bytes.
    /// This value is not valid if the first VCN is nonzero.
    pub valid_data_length: u64,
    pub total_allocated: Option<u64>,
}

impl NonResidentHeader {
    pub fn from_stream<R: Read>(reader: &mut R) -> Result<NonResidentHeader> {
        let vnc_first = reader.read_u64::<LittleEndian>()?;
        let vnc_last = reader.read_u64::<LittleEndian>()?;
        let datarun_offset = reader.read_u16::<LittleEndian>()?;
        let unit_compression_size = reader.read_u16::<LittleEndian>()?;
        let padding = reader.read_u32::<LittleEndian>()?;
        let allocated_length = reader.read_u64::<LittleEndian>()?;
        let file_size = reader.read_u64::<LittleEndian>()?;
        let valid_data_length = reader.read_u64::<LittleEndian>()?;

        let total_allocated = if unit_compression_size > 0 {
            Some(reader.read_u64::<LittleEndian>()?)
        } else {
            None
        };

        Ok(NonResidentHeader {
            vnc_first,
            vnc_last,
            datarun_offset,
            unit_compression_size,
            padding,
            allocated_length,
            file_size,
            valid_data_length,
            total_allocated,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::MftAttributeHeader;
    use crate::attribute::MftAttributeType;
    use std::io::Cursor;

    #[test]
    fn attribute_test_01_resident() {
        let raw: &[u8] = &[
            0x10, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00,
        ];

        let mut cursor = Cursor::new(raw);

        let attribute_header = MftAttributeHeader::from_stream(&mut cursor)
            .expect("Should not be $End")
            .expect("Shold parse correctly");

        assert_eq!(
            attribute_header.type_code,
            MftAttributeType::StandardInformation
        );
        assert_eq!(attribute_header.record_length, 96);
        assert_eq!(attribute_header.form_code, 0);
        assert_eq!(attribute_header.name_size, 0);
        assert_eq!(attribute_header.name_offset, None);
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

        let attribute_header = MftAttributeHeader::from_stream(&mut cursor)
            .expect("Should not be $End")
            .expect("Shold parse correctly");

        assert_eq!(attribute_header.type_code, MftAttributeType::DATA);
        assert_eq!(attribute_header.record_length, 80);
        assert_eq!(attribute_header.form_code, 1);
        assert_eq!(attribute_header.name_size, 0);
        assert_eq!(attribute_header.name_offset, None);
    }
}
