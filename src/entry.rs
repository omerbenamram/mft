use crate::err::{Error, Result};
use crate::impl_serialize_for_bitflags;

use log::{trace, warn};

use winstructs::ntfs::mft_reference::MftReference;

use byteorder::{LittleEndian, ReadBytesExt};

use bitflags::bitflags;
use serde::Serialize;
use serde::ser::{self, SerializeSeq, SerializeStruct, Serializer};

use crate::attribute::header::MftAttributeHeader;
use crate::attribute::x30::{FileNameAttr, FileNamespace};
use crate::attribute::{MftAttribute, MftAttributeContent, MftAttributeType};

use std::io::{self, Cursor, Read};

pub const ZERO_HEADER: &[u8; 4] = b"\x00\x00\x00\x00";
pub const BAAD_HEADER: &[u8; 4] = b"BAAD";
pub const FILE_HEADER: &[u8; 4] = b"FILE";

#[derive(Debug, Clone)]
pub struct MftEntry {
    pub header: EntryHeader,
    pub data: Vec<u8>,
    /// Valid fixup allows you to check if the fixup value in the entry's blocks
    /// matched the fixup array value. It is optional because in the case of
    /// from_buffer_skip_fixup(), no fixup is even checked, thus, valid_fixup is None
    pub valid_fixup: Option<bool>,
}

impl ser::Serialize for MftEntry {
    fn serialize<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        struct Attributes<'a> {
            entry: &'a MftEntry,
        }

        impl ser::Serialize for Attributes<'_> {
            fn serialize<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let mut seq = serializer.serialize_seq(None)?;
                for attr in self.entry.iter_attributes().filter_map(Result::ok) {
                    seq.serialize_element(&attr)?;
                }
                seq.end()
            }
        }

        let mut state = serializer.serialize_struct("MftEntry", 3)?;
        state.serialize_field("header", &self.header)?;
        state.serialize_field("attributes", &Attributes { entry: self })?;
        state.serialize_field("valid_fixup", &self.valid_fixup)?;
        state.end()
    }
}

/// <https://docs.microsoft.com/en-us/windows/desktop/devnotes/file-record-segment-header>
/// The MFT entry can be filled entirely with 0-byte values.
#[derive(Serialize, Debug, Clone)]
pub struct EntryHeader {
    /// MULTI_SECTOR_HEADER
    /// The signature. This value is a convenience to the user.
    /// This is either "BAAD", "FILE", or "\x00\x00\x00\x00"
    pub signature: [u8; 4],
    /// The offset to the update sequence array, from the start of this structure.
    /// The update sequence array must end before the last USHORT value in the first sector.
    pub usa_offset: u16,
    pub usa_size: u16,
    /// Metadata transaction journal sequence number (Reserved1 in windows docs)
    /// Contains a $LogFile Sequence Number (LSN) (metz)
    pub metadata_transaction_journal: u64,
    /// The sequence number.
    /// This value is incremented each time that a file record segment is freed; it is 0 if the segment is not used.
    /// The SequenceNumber field of a file reference must match the contents of this field;
    /// if they do not match, the file reference is incorrect and probably obsolete.
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
    pub first_attribute_id: u16,
    pub record_number: u64,
}
bitflags! {
    #[derive(Clone, Debug, PartialEq)]
    pub struct EntryFlags: u16 {
        const ALLOCATED             = 0x01;
        const INDEX_PRESENT         = 0x02;
        const IS_EXTENSION          = 0x04; //Record is an exension (Set for records in the $Extend directory)
        const SPECIAL_INDEX_PRESENT = 0x08; //Special index present (Set for non-directory records containing an index: $Secure, $ObjID, $Quota, $Reparse)
    }
}

impl_serialize_for_bitflags! {EntryFlags}

impl EntryHeader {
    /// Reads an entry from a stream, will error if the entry is empty (zeroes)
    /// Since the entry id is not present in the header, it should be provided by the caller.
    pub fn from_reader<R: Read>(reader: &mut R, entry_id: u64) -> Result<EntryHeader> {
        let mut signature = [0; 4];
        reader.read_exact(&mut signature)?;

        let header_is_valid = [FILE_HEADER, BAAD_HEADER, ZERO_HEADER].contains(&&signature);

        if !header_is_valid {
            return Err(Error::InvalidEntrySignature {
                bad_sig: signature.to_vec(),
            });
        }

        if signature == *ZERO_HEADER {
            return Ok(Self::zero());
        }

        let usa_offset = reader.read_u16::<LittleEndian>()?;
        let usa_size = reader.read_u16::<LittleEndian>()?;
        let logfile_sequence_number = reader.read_u64::<LittleEndian>()?;
        let sequence = reader.read_u16::<LittleEndian>()?;
        let hard_link_count = reader.read_u16::<LittleEndian>()?;
        let first_attribute_offset = reader.read_u16::<LittleEndian>()?;
        let flags = EntryFlags::from_bits_truncate(reader.read_u16::<LittleEndian>()?);
        let entry_size_real = reader.read_u32::<LittleEndian>()?;
        let entry_size_allocated = reader.read_u32::<LittleEndian>()?;

        let base_reference =
            MftReference::from_reader(reader).map_err(Error::failed_to_read_mft_reference)?;

        let first_attribute_id = reader.read_u16::<LittleEndian>()?;

        Ok(EntryHeader {
            signature,
            usa_offset,
            usa_size,
            metadata_transaction_journal: logfile_sequence_number,
            sequence,
            hard_link_count,
            first_attribute_record_offset: first_attribute_offset,
            flags,
            used_entry_size: entry_size_real,
            total_entry_size: entry_size_allocated,
            base_reference,
            first_attribute_id,
            record_number: entry_id,
        })
    }

    pub fn is_valid(&self) -> bool {
        self.signature == *FILE_HEADER
    }

    pub fn zero() -> Self {
        EntryHeader {
            signature: *ZERO_HEADER,
            usa_offset: 0,
            usa_size: 0,
            metadata_transaction_journal: 0,
            sequence: 0,
            hard_link_count: 0,
            first_attribute_record_offset: 0,
            flags: EntryFlags::from_bits_truncate(0),
            used_entry_size: 0,
            total_entry_size: 0,
            base_reference: MftReference {
                entry: 0,
                sequence: 0,
            },
            first_attribute_id: 0,
            record_number: 0,
        }
    }
}

impl MftEntry {
    /// Initializes an MFT Entry from a buffer.
    /// Since the parser is the entity responsible for knowing the entry size,
    /// we take ownership of the buffer instead of trying to read it from stream.
    pub fn from_buffer(mut buffer: Vec<u8>, entry_number: u64) -> Result<MftEntry> {
        let mut cursor = Cursor::new(&buffer);
        // Get Header
        let entry_header = EntryHeader::from_reader(&mut cursor, entry_number)?;
        trace!("Number of sectors: {entry_header:#?}");

        let valid_fixup = if entry_header.is_valid() {
            Some(Self::apply_fixups(&entry_header, &mut buffer)?)
        } else {
            None
        };

        Ok(MftEntry {
            header: entry_header,
            data: buffer,
            valid_fixup,
        })
    }

    /// Initializes an MFT Entry from a buffer but skips checking and fixing the
    /// fixup array. This will throw InvalidEntrySignature error if the entry header
    /// is not valid.
    pub fn from_buffer_skip_fixup(buffer: Vec<u8>, entry_number: u64) -> Result<MftEntry> {
        let mut cursor = Cursor::new(&buffer);
        // Get Header
        let entry_header = EntryHeader::from_reader(&mut cursor, entry_number)?;
        trace!("Number of sectors: {entry_header:#?}");

        if !entry_header.is_valid() {
            return Err(Error::InvalidEntrySignature {
                bad_sig: entry_header.signature.to_vec(),
            });
        }

        Ok(MftEntry {
            header: entry_header,
            data: buffer,
            valid_fixup: None,
        })
    }

    /// Retrieves most human-readable representation of a file path entry.
    /// Will prefer `Win32` file name attributes, and fallback to `Dos` paths.
    pub fn find_best_name_attribute(&self) -> Option<FileNameAttr<'_>> {
        let mut first: Option<FileNameAttr<'_>> = None;
        let mut best_win32: Option<FileNameAttr<'_>> = None;

        for attr in self
            .iter_attributes_matching(Some(vec![MftAttributeType::FileName]))
            .filter_map(Result::ok)
        {
            let Some(fname) = attr.data.as_file_name() else {
                continue;
            };

            if first.is_none() {
                first = Some(fname.clone());
            }

            if matches!(
                fname.namespace,
                FileNamespace::Win32 | FileNamespace::Win32AndDos
            ) {
                best_win32 = Some(fname.clone());
            }
        }

        best_win32.or(first)
    }

    /// Applies the update sequence array fixups.
    /// https://docs.microsoft.com/en-us/windows/desktop/devnotes/multi-sector-header
    /// **Note**: The fixup will be written at the end of each 512-byte stride,
    /// even if the device has more (or less) than 512 bytes per sector.
    /// The returned result is true if all fixup blocks had the fixup array value, or
    /// false if a block's fixup value did not match the array's value.
    fn apply_fixups(header: &EntryHeader, buffer: &mut [u8]) -> Result<bool> {
        let number_of_fixups = u32::from(header.usa_size.saturating_sub(1));
        trace!("Number of fixups: {number_of_fixups}");

        let entry_id = header.record_number;
        crate::ntfs::apply_update_sequence_array_fixups_in_place_with(
            buffer,
            header.usa_offset,
            header.usa_size,
            |m| {
                warn!(
                    "[entry: {}] fixup bytes are not equal to update sequence value - stride_number: {}, end_of_sector_bytes: {:?}, fixup_bytes: {:?}",
                    entry_id,
                    m.sector_idx,
                    m.end_of_sector_bytes.to_vec(),
                    m.replacement_bytes.to_vec()
                );
            },
        )
    }

    pub fn is_allocated(&self) -> bool {
        self.header.flags.bits() & 0x01 != 0
    }

    pub fn is_dir(&self) -> bool {
        self.header.flags.bits() & 0x02 != 0
    }

    /// Returns an iterator over all the attributes of the entry.
    pub fn iter_attributes(&self) -> impl Iterator<Item = Result<MftAttribute<'_>>> + '_ {
        self.iter_attributes_matching(None)
    }

    /// Returns an iterator over the attributes in the list given in `types`, skips other attributes.
    pub fn iter_attributes_matching(
        &self,
        types: Option<Vec<MftAttributeType>>,
    ) -> impl Iterator<Item = Result<MftAttribute<'_>>> + '_ {
        let data = self.data.as_slice();
        let mut offset = self.header.first_attribute_record_offset as usize;
        let mut exhausted = false;

        std::iter::from_fn(move || {
            loop {
                if exhausted {
                    return None;
                }

                // Need at least type_code + record_length.
                if offset + 8 > data.len() {
                    exhausted = true;
                    return Some(Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()));
                }

                let type_code_value = u32::from_le_bytes([
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                ]);
                if type_code_value == 0xFFFF_FFFF {
                    return None;
                }

                let record_length = u32::from_le_bytes([
                    data[offset + 4],
                    data[offset + 5],
                    data[offset + 6],
                    data[offset + 7],
                ]) as usize;

                if record_length == 0 || offset + record_length > data.len() {
                    exhausted = true;
                    return Some(Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()));
                }

                let record = &data[offset..offset + record_length];
                let start_offset = offset as u64;
                offset += record_length;

                let header = match MftAttributeHeader::from_slice(record, start_offset) {
                    Ok(Some(h)) => h,
                    Ok(None) => return None,
                    Err(e) => {
                        exhausted = true;
                        return Some(Err(e));
                    }
                };

                // Skip attribute if filtered
                if let Some(filter) = &types
                    && !filter.contains(&header.type_code)
                {
                    continue;
                }

                let content = match MftAttributeContent::from_record(record, &header) {
                    Ok(c) => c,
                    Err(e) => return Some(Err(e)),
                };

                return Some(Ok(MftAttribute {
                    header,
                    data: content,
                }));
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

        let entry_header =
            EntryHeader::from_reader(&mut Cursor::new(header_buffer), 38357).unwrap();

        assert_eq!(&entry_header.signature, b"FILE");
        assert_eq!(entry_header.usa_offset, 48);
        assert_eq!(entry_header.usa_size, 3);
        assert_eq!(entry_header.metadata_transaction_journal, 53_762_438_092);
        assert_eq!(entry_header.sequence, 5);
        assert_eq!(entry_header.hard_link_count, 1);
        assert_eq!(entry_header.first_attribute_record_offset, 56);
        assert_eq!(entry_header.flags.bits(), 5);
        assert_eq!(entry_header.used_entry_size, 840);
        assert_eq!(entry_header.total_entry_size, 1024);
        assert_eq!(entry_header.base_reference.entry, 0);
        assert_eq!(entry_header.first_attribute_id, 6);
        assert_eq!(entry_header.record_number, 38357);
    }
}
