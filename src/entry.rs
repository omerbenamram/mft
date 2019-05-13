use crate::enumerator::PathMapping;
use crate::err::{self, Result};

use crate::{attribute, ReadSeek};
use log::{debug, trace};
use snafu::{ensure, OptionExt, ResultExt};

use winstructs::ntfs::mft_reference::MftReference;

use byteorder::{LittleEndian, ReadBytesExt};

use bitflags::bitflags;
use serde::ser::{self, SerializeStruct, Serializer};
use serde::Serialize;

use crate::attribute::header::{AttributeHeader, ResidentialHeader};
use crate::attribute::x10::StandardInfoAttr;
use crate::attribute::{Attribute, AttributeType, MftAttributeContent};

use crate::attribute::raw::RawAttribute;
use crate::attribute::x30::FileNameAttr;
use std::io::Read;
use std::io::SeekFrom;
use std::io::{Cursor, Seek};
use std::mem;

const SEQUENCE_NUMBER_STRIDE: u16 = 512;

#[derive(Debug)]
pub struct MftEntry {
    pub header: EntryHeader,
    pub data: Vec<u8>,
}

impl ser::Serialize for MftEntry {
    fn serialize<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Color", 2)?;
        let attributes: Vec<Attribute> = self.iter_attributes().filter_map(Result::ok).collect();
        state.serialize_field("header", &self.header)?;
        state.serialize_field("attributes", &attributes)?;
        state.end()
    }
}

/// https://docs.microsoft.com/en-us/windows/desktop/devnotes/file-record-segment-header
/// The MFT entry can be filled entirely with 0-byte values.
#[derive(Serialize, Debug)]
pub struct EntryHeader {
    /// MULTI_SECTOR_HEADER
    /// The signature. This value is a convenience to the user.
    /// This is either "BAAD" or "FILE"
    pub signature: [u8; 4],
    #[serde(skip_serializing)]
    /// The offset to the update sequence array, from the start of this structure.
    /// The update sequence array must end before the last USHORT value in the first sector.
    pub usa_offset: u16,
    pub usa_size: u16,
    /// The sequence number.
    /// This value is incremented each time that a file record segment is freed; it is 0 if the segment is not used.
    /// The SequenceNumber field of a file reference must match the contents of this field;
    /// if they do not match, the file reference is incorrect and probably obsolete.
    pub logfile_sequence_number: u64,
    #[serde(skip_serializing)]
    pub sequence: u16,
    pub hard_link_count: u16,
    #[serde(skip_serializing)]
    /// The offset of the first attribute record, in bytes.
    pub first_attribute_record_offset: u16,
    #[serde(serialize_with = "serialize_entry_flags")]
    pub flags: EntryFlags,
    #[serde(skip_serializing)]
    /// Contains the number of bytes of the MFT entry that are in use
    pub used_entry_size: u32,
    #[serde(skip_serializing)]
    pub total_entry_size: u32,
    /// A file reference to the base file record segment for this file.
    /// If this is the base file record, the value is 0. See MFT_SEGMENT_REFERENCE.
    pub base_reference: MftReference,
    #[serde(skip_serializing)]
    pub next_attribute_id: u16,
    #[serde(skip_serializing)]
    pub record_number: u64,
    pub update_sequence_value: u32,
    pub entry_reference: MftReference,
}
bitflags! {
    pub struct EntryFlags: u16 {
        const ALLOCATED     = 0x01;
        const INDEX_PRESENT = 0x02;
        const UNKNOWN_1     = 0x04;
        const UNKNOWN_2     = 0x08;
    }
}

pub fn serialize_entry_flags<S>(
    item: &EntryFlags,
    serializer: S,
) -> ::std::result::Result<S::Ok, S::Error>
where
    S: ser::Serializer,
{
    serializer.serialize_str(&format!("{:?}", item))
}

impl EntryHeader {
    pub fn from_reader<R: Read>(reader: &mut R) -> Result<EntryHeader> {
        let mut signature = [0; 4];
        reader.read_exact(&mut signature)?;

        // Corrupted entry
        ensure!(
            &signature != b"BAAD",
            err::InvalidEntrySignature {
                bad_sig: signature.to_vec()
            }
        );

        // Empty entry
        ensure!(
            &signature != b"\x00\x00\x00\x00",
            err::InvalidEntrySignature {
                bad_sig: signature.to_vec()
            }
        );

        let usa_offset = reader.read_u16::<LittleEndian>()?;
        let usa_size = reader.read_u16::<LittleEndian>()?;
        let logfile_sequence_number = reader.read_u64::<LittleEndian>()?;
        let sequence = reader.read_u16::<LittleEndian>()?;
        let hard_link_count = reader.read_u16::<LittleEndian>()?;
        let fst_attr_offset = reader.read_u16::<LittleEndian>()?;
        let flags = EntryFlags::from_bits_truncate(reader.read_u16::<LittleEndian>()?);
        let entry_size_real = reader.read_u32::<LittleEndian>()?;
        let entry_size_allocated = reader.read_u32::<LittleEndian>()?;
        let base_reference =
            MftReference::from_reader(reader).context(err::FailedToReadMftReference)?;
        let next_attribute_id = reader.read_u16::<LittleEndian>()?;

        ensure!(
            usa_offset == 48,
            err::InvalidUsaOffset { offset: usa_offset }
        );

        let _padding = reader.read_u16::<LittleEndian>()?;
        let record_number = u64::from(reader.read_u32::<LittleEndian>()?);

        let entry_reference = MftReference::new(record_number as u64, sequence);

        Ok(EntryHeader {
            signature,
            usa_offset,
            usa_size,
            logfile_sequence_number,
            sequence,
            hard_link_count,
            first_attribute_record_offset: fst_attr_offset,
            flags,
            used_entry_size: entry_size_real,
            total_entry_size: entry_size_allocated,
            base_reference,
            next_attribute_id,
            record_number,
            update_sequence_value: 0,
            entry_reference,
        })
    }
}

impl MftEntry {
    /// Initializes an MFT Entry from a buffer.
    /// Since the parser is the entity responsible for knowing the entry size,
    /// we take ownership of the buffer instead of trying to read it from stream.
    pub fn from_buffer(mut buffer: Vec<u8>) -> Result<MftEntry> {
        let mut cursor = Cursor::new(&buffer);
        // Get Header
        let entry_header = EntryHeader::from_reader(&mut cursor)?;
        trace!("Number of sectors: {:#?}", entry_header);

        Self::apply_fixups(&entry_header, &mut buffer)?;

        Ok(MftEntry {
            header: entry_header,
            data: buffer,
        })
    }

    /// Applies the update sequence array fixups.
    /// https://docs.microsoft.com/en-us/windows/desktop/devnotes/multi-sector-header
    /// **Note**: The fixup will be written at the end of each 512-byte stride,
    /// even if the device has more (or less) than 512 bytes per sector.
    #[must_use]
    fn apply_fixups(header: &EntryHeader, buffer: &mut [u8]) -> Result<()> {
        let number_of_fixups = u32::from(header.usa_size - 1);
        trace!("Number of fixups: {}", number_of_fixups);

        // Each fixup is a 2-byte element, and there are `usa_size` of them.
        let fixups_start_offset = header.usa_offset as usize;
        let fixups_end_offset = fixups_start_offset + (header.usa_size * 2) as usize;

        let fixups = buffer[fixups_start_offset..fixups_end_offset].to_vec();
        let mut fixups = fixups.chunks(2);

        // There should always be bytes here, but just in case we put zeroes, so it will fail later.
        let update_sequence = fixups.next().unwrap_or(&[0, 0]);

        // We need to compare each last two bytes each 512-bytes stride with the update_sequence,
        // And if they match, replace those bytes with the matching bytes from the fixup_sequence.
        for (stride_number, fixup_bytes) in (0..number_of_fixups).zip(fixups) {
            let sector_start_offset = (stride_number * u32::from(SEQUENCE_NUMBER_STRIDE)) as usize;

            let end_of_sector_bytes_start_offset =
                (sector_start_offset + SEQUENCE_NUMBER_STRIDE as usize) - 2;
            let end_of_sector_bytes_end_offset =
                sector_start_offset + SEQUENCE_NUMBER_STRIDE as usize;

            let end_of_sector_bytes =
                &mut buffer[end_of_sector_bytes_start_offset..end_of_sector_bytes_end_offset];

            ensure!(
                end_of_sector_bytes == update_sequence,
                err::FailedToApplyFixup {
                    stride_number,
                    end_of_sector_bytes: end_of_sector_bytes.to_vec(),
                    fixup_bytes: fixup_bytes.to_vec()
                }
            );

            end_of_sector_bytes.copy_from_slice(&fixup_bytes);
        }

        Ok(())
    }

    pub fn is_allocated(&self) -> bool {
        self.header.flags.bits() & 0x01 != 0
    }

    pub fn is_dir(&self) -> bool {
        self.header.flags.bits() & 0x02 != 0
    }

    pub fn get_pathmap(&self) -> Option<PathMapping> {
        for attribute in self.iter_attributes().filter_map(|a| a.ok()) {
            if let attribute::MftAttributeContent::AttrX30(ref attrib) = attribute.data {
                if attrib.namespace != 2 {
                    return Some(PathMapping {
                        name: attrib.name.clone(),
                        parent: attrib.parent,
                    });
                }
            }
        }

        None
    }

    //    pub fn set_full_names(&mut self, mft_handler: &mut MftHandler) {
    //        if self.attributes.contains_key("0x0030") {
    //            if let Some(attr_list) = self.attributes.get_mut("0x0030") {
    //                for attribute in attr_list.iter_mut() {
    //                    // Check if resident content
    //                    if let attribute::AttributeContent::AttrX30(ref mut attrib) = attribute.content
    //                    {
    //                        // Get fullpath
    //                        let fullpath = mft_handler.get_fullpath(attrib.parent);
    //                        // Set fullname
    //                        let fullname = fullpath + "/" + attrib.name.as_str();
    //                        // Set attribute to fullname
    //                        attrib.fullname = Some(fullname);
    //                    }
    //                }
    //            }
    //        }
    //    }

    /// Returns an iterator over the attributes of the entry.
    pub fn iter_attributes(&self) -> impl Iterator<Item = Result<Attribute>> + '_ {
        let mut cursor = Cursor::new(&self.data);
        let mut offset = u64::from(self.header.first_attribute_record_offset);
        let mut exhausted = false;

        std::iter::from_fn(move || {
            if exhausted {
                return None;
            }

            match cursor
                .seek(SeekFrom::Start(offset))
                .eager_context(err::IoError)
            {
                Ok(_) => {}
                Err(e) => {
                    exhausted = true;
                    return Some(Err(e));
                }
            };

            match AttributeHeader::from_stream(&mut cursor) {
                Ok(maybe_header) => match maybe_header {
                    Some(header) => {
                        // Increment offset before moving header.
                        offset += u64::from(header.record_length);

                        // Check if the header is resident, and if it is, read the attribute content.
                        match header.residential_header {
                            ResidentialHeader::Resident(ref resident) => match header.type_code {
                                AttributeType::StandardInformation => {
                                    match StandardInfoAttr::from_reader(&mut cursor) {
                                        Ok(content) => Some(Ok(Attribute {
                                            header,
                                            data: MftAttributeContent::AttrX10(content),
                                        })),
                                        Err(e) => Some(Err(e)),
                                    }
                                }
                                AttributeType::FileName => {
                                    match FileNameAttr::from_reader(&mut cursor) {
                                        Ok(content) => Some(Ok(Attribute {
                                            header,
                                            data: MftAttributeContent::AttrX30(content),
                                        })),
                                        Err(e) => Some(Err(e)),
                                    }
                                }
                                _ => {
                                    let mut data = vec![0_u8; resident.data_size as usize];

                                    match cursor.read_exact(&mut data).eager_context(err::IoError) {
                                        Ok(_) => {}
                                        Err(err) => return Some(Err(err)),
                                    };

                                    Some(Ok(Attribute {
                                        header,
                                        data: MftAttributeContent::Raw(RawAttribute(data)),
                                    }))
                                }
                            },
                            ResidentialHeader::NonResident(_) => Some(Ok(Attribute {
                                header,
                                data: MftAttributeContent::None,
                            })),
                        }
                    }
                    None => None,
                },
                Err(e) => {
                    exhausted = true;
                    Some(Err(e))
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::EntryHeader;
    use std::io::Cursor;

    #[test]
    fn mft_header_test_01() {
        let header_buffer: &[u8] = &[
            0x46, 0x49, 0x4C, 0x45, 0x30, 0x00, 0x03, 0x00, 0xCC, 0xB3, 0x7D, 0x84, 0x0C, 0x00,
            0x00, 0x00, 0x05, 0x00, 0x01, 0x00, 0x38, 0x00, 0x05, 0x00, 0x48, 0x03, 0x00, 0x00,
            0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00,
            0x00, 0x00, 0xD5, 0x95, 0x00, 0x00, 0x53, 0x57, 0x81, 0x37, 0x00, 0x00, 0x00, 0x00,
        ];

        let entry_header = EntryHeader::from_reader(&mut Cursor::new(header_buffer)).unwrap();

        assert_eq!(entry_header.signature, 1_162_627_398);
        assert_eq!(entry_header.usa_offset, 48);
        assert_eq!(entry_header.usa_size, 3);
        assert_eq!(entry_header.logfile_sequence_number, 53_762_438_092);
        assert_eq!(entry_header.sequence, 5);
        assert_eq!(entry_header.hard_link_count, 1);
        assert_eq!(entry_header.first_attribute_record_offset, 56);
        assert_eq!(entry_header.flags.bits(), 5);
        assert_eq!(entry_header.used_entry_size, 840);
        assert_eq!(entry_header.total_entry_size, 1024);
        assert_eq!(entry_header.base_reference.entry, 0);
        assert_eq!(entry_header.next_attribute_id, 6);
        assert_eq!(entry_header.record_number, 38357);
    }
}
