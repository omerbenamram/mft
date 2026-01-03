use crate::Utf16LeStr;
use crate::attribute::{AttributeDataFlags, MftAttributeType};
use crate::err::{Error, Result};

use byteorder::{ByteOrder, LittleEndian};
use num_traits::FromPrimitive;
use serde::Serialize;
use std::io;

fn get_slice(buf: &[u8], offset: usize, len: usize) -> io::Result<&[u8]> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "offset overflow"))?;
    buf.get(offset..end)
        .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
}

fn read_u8(buf: &[u8], offset: usize) -> io::Result<u8> {
    buf.get(offset)
        .copied()
        .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
}

fn read_u16_le(buf: &[u8], offset: usize) -> io::Result<u16> {
    Ok(LittleEndian::read_u16(get_slice(buf, offset, 2)?))
}

fn read_u32_le(buf: &[u8], offset: usize) -> io::Result<u32> {
    Ok(LittleEndian::read_u32(get_slice(buf, offset, 4)?))
}

fn read_u64_le(buf: &[u8], offset: usize) -> io::Result<u64> {
    Ok(LittleEndian::read_u64(get_slice(buf, offset, 8)?))
}

/// Represents the union defined in
/// <https://docs.microsoft.com/en-us/windows/desktop/devnotes/attribute-record-header>
#[derive(Serialize, Clone, Debug)]
pub struct MftAttributeHeader<'a> {
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
    pub name: Utf16LeStr<'a>,
    /// start of the attribute; used for calculating relative offsets
    pub start_offset: u64,
}

#[derive(Serialize, Clone, Debug)]
#[serde(untagged)]
pub enum ResidentialHeader {
    Resident(ResidentHeader),
    NonResident(NonResidentHeader),
}

impl<'a> MftAttributeHeader<'a> {
    /// Parse an attribute header from an attribute record slice.
    ///
    /// Returns `Ok(None)` if the type code is `$END` (`0xFFFF_FFFF`).
    pub fn from_slice(
        record: &'a [u8],
        attribute_start_offset: u64,
    ) -> Result<Option<MftAttributeHeader<'a>>> {
        let type_code_value = read_u32_le(record, 0)?;
        if type_code_value == 0xFFFF_FFFF {
            return Ok(None);
        }

        let type_code =
            MftAttributeType::from_u32(type_code_value).ok_or(Error::UnknownAttributeType {
                attribute_type: type_code_value,
            })?;

        let record_length = read_u32_le(record, 4)?;
        let form_code = read_u8(record, 8)?;
        let name_size = read_u8(record, 9)?;
        let name_offset_raw = read_u16_le(record, 10)?;
        let name_offset = (name_size > 0).then_some(name_offset_raw);

        let data_flags = AttributeDataFlags::from_bits_truncate(read_u16_le(record, 12)?);
        let instance = read_u16_le(record, 14)?;

        let residential_header = match form_code {
            0 => {
                let data_size = read_u32_le(record, 16)?;
                let data_offset = read_u16_le(record, 20)?;
                let index_flag = read_u8(record, 22)?;
                let padding = read_u8(record, 23)?;
                ResidentialHeader::Resident(ResidentHeader {
                    data_size,
                    data_offset,
                    index_flag,
                    padding,
                })
            }
            1 => {
                let vnc_first = read_u64_le(record, 16)?;
                let vnc_last = read_u64_le(record, 24)?;
                let datarun_offset = read_u16_le(record, 32)?;
                let unit_compression_size = read_u16_le(record, 34)?;
                let padding = read_u32_le(record, 36)?;
                let allocated_length = read_u64_le(record, 40)?;
                let file_size = read_u64_le(record, 48)?;
                let valid_data_length = read_u64_le(record, 56)?;

                let total_allocated = if unit_compression_size > 0 {
                    Some(read_u64_le(record, 64)?)
                } else {
                    None
                };

                ResidentialHeader::NonResident(NonResidentHeader {
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
            _ => {
                return Err(Error::UnhandledResidentFlag {
                    flag: form_code,
                    offset: attribute_start_offset,
                });
            }
        };

        let name = if name_size > 0 {
            let off = name_offset_raw as usize;
            let len_bytes = name_size as usize * 2;
            let name_bytes = record
                .get(off..off + len_bytes)
                .ok_or(Error::InvalidFilename)?;
            Utf16LeStr::from_utf16le_bytes_until_nul(name_bytes)
        } else {
            Utf16LeStr::empty()
        };

        Ok(Some(MftAttributeHeader {
            type_code,
            record_length,
            form_code,
            residential_header,
            name_size,
            name_offset,
            data_flags,
            instance,
            name,
            start_offset: attribute_start_offset,
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
    pub fn from_stream<R: std::io::Read>(reader: &mut R) -> Result<ResidentHeader> {
        use byteorder::ReadBytesExt;
        Ok(ResidentHeader {
            data_size: reader.read_u32::<byteorder::LittleEndian>()?,
            data_offset: reader.read_u16::<byteorder::LittleEndian>()?,
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
    pub fn from_stream<R: std::io::Read>(reader: &mut R) -> Result<NonResidentHeader> {
        use byteorder::ReadBytesExt;
        let vnc_first = reader.read_u64::<byteorder::LittleEndian>()?;
        let vnc_last = reader.read_u64::<byteorder::LittleEndian>()?;
        let datarun_offset = reader.read_u16::<byteorder::LittleEndian>()?;
        let unit_compression_size = reader.read_u16::<byteorder::LittleEndian>()?;
        let padding = reader.read_u32::<byteorder::LittleEndian>()?;
        let allocated_length = reader.read_u64::<byteorder::LittleEndian>()?;
        let file_size = reader.read_u64::<byteorder::LittleEndian>()?;
        let valid_data_length = reader.read_u64::<byteorder::LittleEndian>()?;

        let total_allocated = if unit_compression_size > 0 {
            Some(reader.read_u64::<byteorder::LittleEndian>()?)
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

    #[test]
    fn attribute_test_01_resident() {
        let raw: &[u8] = &[
            0x10, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00,
        ];

        let attribute_header = MftAttributeHeader::from_slice(raw, 0)
            .expect("Shold parse correctly")
            .expect("Should not be $End");

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

        let attribute_header = MftAttributeHeader::from_slice(raw, 0)
            .expect("Shold parse correctly")
            .expect("Should not be $End");

        assert_eq!(attribute_header.type_code, MftAttributeType::DATA);
        assert_eq!(attribute_header.record_length, 80);
        assert_eq!(attribute_header.form_code, 1);
        assert_eq!(attribute_header.name_size, 0);
        assert_eq!(attribute_header.name_offset, None);
    }
}
