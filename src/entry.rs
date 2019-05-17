use crate::err::{self, Result};
use crate::impl_serialize_for_bitflags;

use log::trace;
use snafu::{ensure, ResultExt};

use winstructs::ntfs::mft_reference::MftReference;

use byteorder::{LittleEndian, ReadBytesExt};

use bitflags::bitflags;
use serde::ser::{self, SerializeStruct, Serializer};
use serde::Serialize;

use crate::attribute::header::{MftAttributeHeader, ResidentialHeader};
use crate::attribute::x10::StandardInfoAttr;
use crate::attribute::{MftAttribute, MftAttributeContent, MftAttributeType};

use crate::attribute::raw::RawAttribute;
use crate::attribute::x30::FileNameAttr;
use std::io::Read;
use std::io::SeekFrom;
use std::io::{Cursor, Seek};

const SEQUENCE_NUMBER_STRIDE: usize = 512;

#[derive(Debug, Clone)]
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
        let attributes: Vec<MftAttribute> = self.iter_attributes().filter_map(Result::ok).collect();
        state.serialize_field("header", &self.header)?;
        state.serialize_field("attributes", &attributes)?;
        state.end()
    }
}

/// https://docs.microsoft.com/en-us/windows/desktop/devnotes/file-record-segment-header
/// The MFT entry can be filled entirely with 0-byte values.
#[derive(Serialize, Debug, Clone)]
pub struct EntryHeader {
    /// MULTI_SECTOR_HEADER
    /// The signature. This value is a convenience to the user.
    /// This is either "BAAD" or "FILE"
    pub signature: [u8; 4],
    /// The offset to the update sequence array, from the start of this structure.
    /// The update sequence array must end before the last USHORT value in the first sector.
    pub usa_offset: u16,
    pub usa_size: u16,
    /// The sequence number.
    /// This value is incremented each time that a file record segment is freed; it is 0 if the segment is not used.
    /// The SequenceNumber field of a file reference must match the contents of this field;
    /// if they do not match, the file reference is incorrect and probably obsolete.
    pub logfile_sequence_number: u64,
    pub sequence: u16,
    pub hard_link_count: u16,
    /// The offset of the first attribute record, in bytes.
    pub first_attribute_record_offset: u16,
    pub flags: EntryFlags,
    /// Contains the number of bytes of the MFT entry that are in use
    pub used_entry_size: u32,
    pub total_entry_size: u32,
    /// A file reference to the base file record segment for this file.
    /// If this is the base file record, the value is 0. See MFT_SEGMENT_REFERENCE.
    pub base_reference: MftReference,
    pub next_attribute_id: u16,
    pub record_number: u64,
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

impl_serialize_for_bitflags! {EntryFlags}

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
        for (stride_number, fixup_bytes) in (0_usize..number_of_fixups as usize).zip(fixups) {
            let sector_start_offset = stride_number * SEQUENCE_NUMBER_STRIDE;

            let end_of_sector_bytes_end_offset = sector_start_offset + SEQUENCE_NUMBER_STRIDE;
            let end_of_sector_bytes_start_offset = end_of_sector_bytes_end_offset - 2;

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

    /// Returns an iterator over the attributes of the entry.
    pub fn iter_attributes(&self) -> impl Iterator<Item = Result<MftAttribute>> + '_ {
        let mut cursor = Cursor::new(&self.data);
        let mut offset = u64::from(self.header.first_attribute_record_offset);
        let mut exhausted = false;

        std::iter::from_fn(move || {
            if exhausted {
                return None;
            }

            match cursor.seek(SeekFrom::Start(offset)).context(err::IoError) {
                Ok(_) => {}
                Err(e) => {
                    exhausted = true;
                    return Some(Err(e.into()));
                }
            };

            match MftAttributeHeader::from_stream(&mut cursor) {
                Ok(maybe_header) => match maybe_header {
                    Some(header) => {
                        // Increment offset before moving header.
                        offset += u64::from(header.record_length);

                        // Check if the header is resident, and if it is, read the attribute content.
                        match header.residential_header {
                            ResidentialHeader::Resident(ref resident) => match header.type_code {
                                MftAttributeType::StandardInformation => {
                                    match StandardInfoAttr::from_reader(&mut cursor) {
                                        Ok(content) => Some(Ok(MftAttribute {
                                            header,
                                            data: MftAttributeContent::AttrX10(content),
                                        })),
                                        Err(e) => Some(Err(e)),
                                    }
                                }
                                MftAttributeType::FileName => {
                                    match FileNameAttr::from_stream(&mut cursor) {
                                        Ok(content) => Some(Ok(MftAttribute {
                                            header,
                                            data: MftAttributeContent::AttrX30(content),
                                        })),
                                        Err(e) => Some(Err(e.into())),
                                    }
                                }
                                _ => {
                                    let mut data = vec![0_u8; resident.data_size as usize];

                                    match cursor.read_exact(&mut data).context(err::IoError) {
                                        Ok(_) => {}
                                        Err(err) => return Some(Err(err.into())),
                                    };

                                    Some(Ok(MftAttribute {
                                        header,
                                        data: MftAttributeContent::Raw(RawAttribute(data)),
                                    }))
                                }
                            },
                            ResidentialHeader::NonResident(_) => Some(Ok(MftAttribute {
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

        assert_eq!(&entry_header.signature, b"FILE");
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
