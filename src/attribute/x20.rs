use crate::err::{Error, Result};
use crate::ReadSeek;

use byteorder::{LittleEndian, ReadBytesExt};
use encoding::all::UTF_16LE;
use encoding::{DecoderTrap, Encoding};

use serde::Serialize;

use std::io::SeekFrom;
use winstructs::ntfs::mft_reference::MftReference;

/// The AttributeListAttr represents the $20 attribute, which contains a list
/// of attribute entries in child entries.
///
#[derive(Serialize, Clone, Debug)]
pub struct AttributeListAttr {
    /// A list of AttributeListEntry that make up this AttributeListAttr
    pub entries: Vec<AttributeListEntry>,
}
impl AttributeListAttr {
    /// Read AttributeListAttr from stream. Stream should be the size of the attribute's data itself
    /// if no stream_size is passed in.
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
    /// let attribute_list = AttributeListAttr::from_stream(
    ///     &mut Cursor::new(attribute_content_buffer),
    ///     None
    /// ).unwrap();
    ///
    /// assert_eq!(attribute_list.entries.len(), 7);
    /// ```
    pub fn from_stream<S: ReadSeek>(
        mut stream: &mut S,
        stream_size: Option<u64>,
    ) -> Result<AttributeListAttr> {
        let mut start_offset = stream.tell()?;
        let end_offset = match stream_size {
            Some(s) => s,
            None => {
                // If no stream size was passed in we seek to the end of the stream,
                // then tell to get the ending offset, then seek back to the start,
                // thus, its better to just pass the stream size.
                stream.seek(SeekFrom::End(0))?;

                let offset = stream.tell()?;

                stream.seek(SeekFrom::Start(0))?;

                offset
            }
        };

        let mut entries: Vec<AttributeListEntry> = Vec::new();

        // iterate attribute content parsing attribute list entries
        while start_offset < end_offset {
            // parse the entry from the stream
            let attr_entry = AttributeListEntry::from_stream(&mut stream)?;

            // update the starting offset
            start_offset += attr_entry.record_length as u64;

            // add attribute entry to entries vec
            entries.push(attr_entry);

            // seek the stream to next start offset to avoid padding
            stream.seek(SeekFrom::Start(start_offset))?;
        }

        Ok(Self { entries })
    }
}

/// An AttributeListAttr is made up off multiple AttributeListEntry structs.
/// https://docs.microsoft.com/en-us/windows/win32/devnotes/attribute-list-entry
///
#[derive(Serialize, Clone, Debug)]
pub struct AttributeListEntry {
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
    pub name: String,
}
impl AttributeListEntry {
    /// Create AttributeListEntry from a stream.
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
    /// let attribute_entry = AttributeListEntry::from_stream(
    ///     &mut Cursor::new(attribute_buffer)
    /// ).unwrap();
    ///
    /// assert_eq!(attribute_entry.attribute_type, 16);
    /// assert_eq!(attribute_entry.record_length, 32);
    /// assert_eq!(attribute_entry.name_length, 0);
    /// assert_eq!(attribute_entry.name_offset, 26);
    /// assert_eq!(attribute_entry.lowest_vcn, 0);
    /// assert_eq!(attribute_entry.segment_reference.entry, 10019);
    /// assert_eq!(attribute_entry.segment_reference.sequence, 1);
    /// assert_eq!(attribute_entry.reserved, 0);
    /// assert_eq!(attribute_entry.name, "".to_string());
    /// ```
    pub fn from_stream<S: ReadSeek>(stream: &mut S) -> Result<AttributeListEntry> {
        let start_offset = stream.tell()?;

        let attribute_type = stream.read_u32::<LittleEndian>()?;
        let record_length = stream.read_u16::<LittleEndian>()?;
        let name_length = stream.read_u8()?;
        let name_offset = stream.read_u8()?;
        let lowest_vcn = stream.read_u64::<LittleEndian>()?;
        let segment_reference =
            MftReference::from_reader(stream).map_err(Error::failed_to_read_mft_reference)?;
        let reserved = stream.read_u16::<LittleEndian>()?;

        let name = if name_length > 0 {
            stream.seek(SeekFrom::Start(start_offset + u64::from(name_offset)))?;

            let mut name_buffer = vec![0; (name_length as usize * 2) as usize];
            stream.read_exact(&mut name_buffer)?;

            match UTF_16LE.decode(&name_buffer, DecoderTrap::Ignore) {
                Ok(s) => s,
                Err(_e) => return Err(Error::InvalidFilename {}),
            }
        } else {
            String::new()
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
