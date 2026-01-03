use crate::Utf16LeStr;
use crate::err::{Error, Result};

use serde::Serialize;

use std::io::Cursor;
use winstructs::ntfs::mft_reference::MftReference;

/// The AttributeListAttr represents the $20 attribute, which contains a list
/// of attribute entries in child entries.
///
#[derive(Serialize, Clone, Debug)]
pub struct AttributeListAttr<'a> {
    /// A list of AttributeListEntry that make up this AttributeListAttr
    pub entries: Vec<AttributeListEntry<'a>>,
}

impl<'a> AttributeListAttr<'a> {
    /// Read AttributeListAttr from a resident attribute value slice.
    ///
    ///  # Example
    ///
    /// Parse a raw buffer.
    ///
    /// ```
    /// use mft::attribute::x20::AttributeListAttr;
    /// # use std::io::Cursor;
    /// let attribute_content_buffer: &[u8] = &[
    ///     0x10,0x00,0x00,0x00,0x20,0x00,0x00,0x1A,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    ///     0x23,0x27,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x12,0x07,0x80,0xF8,0xFF,0xFF,
    ///     0x30,0x00,0x00,0x00,0x20,0x00,0x00,0x1A,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    ///     0x23,0x27,0x00,0x00,0x00,0x00,0x01,0x00,0x03,0x00,0x00,0x00,0x69,0x00,0x6E,0x00,
    ///     0x30,0x00,0x00,0x00,0x20,0x00,0x00,0x1A,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    ///     0x0F,0xCF,0x01,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x8A,0x0C,0xA0,0xF8,0xFF,0xFF,
    ///     0x90,0x00,0x00,0x00,0x28,0x00,0x04,0x1A,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    ///     0x0F,0xCF,0x01,0x00,0x00,0x00,0x02,0x00,0x01,0x00,0x24,0x00,0x49,0x00,0x33,0x00,
    ///     0x30,0x00,0x79,0x00,0x73,0x00,0xAD,0xEF,0xA0,0x00,0x00,0x00,0x28,0x00,0x04,0x1A,
    ///     0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0F,0xCF,0x01,0x00,0x00,0x00,0x02,0x00,
    ///     0x02,0x00,0x24,0x00,0x49,0x00,0x33,0x00,0x30,0x00,0x00,0x00,0x00,0x00,0x78,0x56,
    ///     0xB0,0x00,0x00,0x00,0x28,0x00,0x04,0x1A,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    ///     0x0F,0xCF,0x01,0x00,0x00,0x00,0x02,0x00,0x03,0x00,0x24,0x00,0x49,0x00,0x33,0x00,
    ///     0x30,0x00,0x00,0x00,0x00,0x00,0x65,0x00,0x00,0x01,0x00,0x00,0x30,0x00,0x09,0x1A,
    ///     0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x23,0x27,0x00,0x00,0x00,0x00,0x01,0x00,
    ///     0x08,0x00,0x24,0x00,0x54,0x00,0x58,0x00,0x46,0x00,0x5F,0x00,0x44,0x00,0x41,0x00,
    ///     0x54,0x00,0x41,0x00,0x00,0x00,0x00,0x00
    /// ];
    ///
    /// let attribute_list = AttributeListAttr::from_slice(attribute_content_buffer).unwrap();
    ///
    /// assert_eq!(attribute_list.entries.len(), 7);
    /// ```
    pub fn from_slice(value: &'a [u8]) -> Result<AttributeListAttr<'a>> {
        let mut entries: Vec<AttributeListEntry<'a>> = Vec::new();

        let mut offset = 0usize;
        while offset < value.len() {
            if value.len().saturating_sub(offset) < AttributeListEntry::MIN_LEN {
                break;
            }

            let entry = AttributeListEntry::from_slice_at(value, offset)?;
            let record_length = entry.record_length as usize;
            if record_length == 0 {
                return Err(Error::Any {
                    detail: "attribute list entry record_length is 0".to_string(),
                });
            }

            entries.push(entry);
            offset = offset
                .checked_add(record_length)
                .ok_or_else(|| Error::Any {
                    detail: "attribute list offset overflow".to_string(),
                })?;
        }

        Ok(Self { entries })
    }
}

/// An AttributeListAttr is made up off multiple AttributeListEntry structs.
/// <https://docs.microsoft.com/en-us/windows/win32/devnotes/attribute-list-entry>
///
#[derive(Serialize, Clone, Debug)]
pub struct AttributeListEntry<'a> {
    /// The attribute code
    pub attribute_type: u32,
    /// This entry length
    pub record_length: u16,
    /// Attribute name length (0 means no name)
    pub name_length: u8,
    /// Attribute name offset
    pub name_offset: u8,
    /// This member is zero unless the attribute requires multiple file record
    /// segments and unless this entry is a reference to a segment other than the first one.
    /// In this case, this value is the lowest VCN that is described by the referenced segment.
    pub lowest_vcn: u64,
    /// The segments MFT reference
    pub segment_reference: MftReference,
    /// The attribute's id
    pub reserved: u16,
    /// The attribute's name
    pub name: Utf16LeStr<'a>,
}
impl<'a> AttributeListEntry<'a> {
    const MIN_LEN: usize = 26;

    /// Create AttributeListEntry from a resident attribute value slice at `offset`.
    ///
    ///  # Example
    ///
    /// Parse a raw buffer.
    ///
    /// ```
    /// use mft::attribute::x20::AttributeListEntry;
    /// # use std::io::Cursor;
    /// let attribute_buffer: &[u8] = &[
    ///     0x10,0x00,0x00,0x00,0x20,0x00,0x00,0x1A,
    ///     0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    ///     0x23,0x27,0x00,0x00,0x00,0x00,0x01,0x00,
    ///     0x00,0x00,0x12,0x07,0x80,0xF8,0xFF,0xFF
    /// ];
    ///
    /// let attribute_entry = AttributeListEntry::from_slice_at(attribute_buffer, 0).unwrap();
    ///
    /// assert_eq!(attribute_entry.attribute_type, 16);
    /// assert_eq!(attribute_entry.record_length, 32);
    /// assert_eq!(attribute_entry.name_length, 0);
    /// assert_eq!(attribute_entry.name_offset, 26);
    /// assert_eq!(attribute_entry.lowest_vcn, 0);
    /// assert_eq!(attribute_entry.segment_reference.entry, 10019);
    /// assert_eq!(attribute_entry.segment_reference.sequence, 1);
    /// assert_eq!(attribute_entry.reserved, 0);
    /// assert!(attribute_entry.name.is_empty());
    /// ```
    pub fn from_slice_at(value: &'a [u8], offset: usize) -> Result<AttributeListEntry<'a>> {
        if value.len().saturating_sub(offset) < Self::MIN_LEN {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
        }

        let attribute_type = u32::from_le_bytes([
            value[offset],
            value[offset + 1],
            value[offset + 2],
            value[offset + 3],
        ]);
        let record_length = u16::from_le_bytes([value[offset + 4], value[offset + 5]]);
        let name_length = value[offset + 6];
        let name_offset = value[offset + 7];
        let lowest_vcn = u64::from_le_bytes([
            value[offset + 8],
            value[offset + 9],
            value[offset + 10],
            value[offset + 11],
            value[offset + 12],
            value[offset + 13],
            value[offset + 14],
            value[offset + 15],
        ]);

        let segment_reference = {
            let mut cursor = Cursor::new(&value[offset + 16..offset + 24]);
            MftReference::from_reader(&mut cursor).map_err(Error::failed_to_read_mft_reference)?
        };
        let reserved = u16::from_le_bytes([value[offset + 24], value[offset + 25]]);

        let name = if name_length > 0 {
            let name_off = offset + name_offset as usize;
            let name_len_bytes = name_length as usize * 2;
            let name_bytes = value
                .get(name_off..name_off + name_len_bytes)
                .ok_or(Error::InvalidFilename)?;
            Utf16LeStr::from_utf16le_bytes(name_bytes)
        } else {
            Utf16LeStr::empty()
        };

        Ok(AttributeListEntry {
            attribute_type,
            record_length,
            name_length,
            name_offset,
            lowest_vcn,
            segment_reference,
            reserved,
            name,
        })
    }
}
