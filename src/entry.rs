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
                // Preserve the first Win32/Win32AndDos name for stability.
                // MFT entries can contain multiple Win32 names (e.g. hard links), and there
                // isn't a canonical choice without directory context.
                if best_win32.is_none() {
                    best_win32 = Some(fname.clone());
                }
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

                // Need at least type_code (u32). The $END marker is just a type_code
                // (0xFFFF_FFFF) and has no record_length.
                let type_code_end = match offset.checked_add(4) {
                    Some(end) => end,
                    None => {
                        exhausted = true;
                        return Some(Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()));
                    }
                };
                if type_code_end > data.len() {
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

                // Need at least type_code + record_length for real attributes.
                let header_end = match offset.checked_add(8) {
                    Some(end) => end,
                    None => {
                        exhausted = true;
                        return Some(Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()));
                    }
                };
                if header_end > data.len() {
                    exhausted = true;
                    return Some(Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()));
                }

                let record_length = u32::from_le_bytes([
                    data[offset + 4],
                    data[offset + 5],
                    data[offset + 6],
                    data[offset + 7],
                ]) as usize;

                let record_end = match offset.checked_add(record_length) {
                    Some(end) => end,
                    None => {
                        exhausted = true;
                        return Some(Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()));
                    }
                };

                if record_length == 0 || record_end > data.len() {
                    exhausted = true;
                    return Some(Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()));
                }

                let record = &data[offset..record_end];
                let start_offset = offset as u64;
                offset = record_end;

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
    use super::{EntryHeader, MftEntry};
    use crate::attribute::x30::FileNamespace;
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

    #[test]
    #[cfg(target_pointer_width = "32")]
    fn iter_attributes_rejects_overflowing_record_length_without_panicking() {
        // Regression test for 32-bit overflow:
        // prior code used `offset + record_length` without checked arithmetic, which can wrap and
        // allow an invalid slice like `data[100..50]` to panic.
        let offset: usize = 100;
        let record_length = u32::MAX - 50; // `offset + record_length` wraps on 32-bit.

        let mut data = vec![0u8; 256];
        data[offset..offset + 4].copy_from_slice(&0x30u32.to_le_bytes()); // FILE_NAME (arbitrary)
        data[offset + 4..offset + 8].copy_from_slice(&record_length.to_le_bytes());

        let mut header = EntryHeader::zero();
        header.first_attribute_record_offset = offset as u16;

        let entry = MftEntry {
            header,
            data,
            valid_fixup: None,
        };

        let first = entry
            .iter_attributes()
            .next()
            .expect("expected an iterator item");
        assert!(first.is_err());
    }

    fn filename_value_bytes(name: &str, namespace: FileNamespace) -> Vec<u8> {
        // Based on the example in `attribute::x30` docs; timestamps/flags are arbitrary
        // but valid. Only `namespace` + `name` matter for this test.
        let mut v = Vec::new();

        // Parent directory reference (8 bytes): entry=5, sequence=5.
        v.extend_from_slice(&[0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00]);

        // 4x FILETIME timestamps.
        const FT: [u8; 8] = [0xD5, 0x2D, 0x48, 0x58, 0x43, 0x5F, 0xCE, 0x01];
        v.extend_from_slice(&FT);
        v.extend_from_slice(&FT);
        v.extend_from_slice(&FT);
        v.extend_from_slice(&FT);

        // Sizes.
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00]); // 64MiB
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00]); // 64MiB

        // Flags (6) + reparse value (0).
        v.extend_from_slice(&[0x06, 0x00, 0x00, 0x00]);
        v.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        // Name length + namespace.
        let name_len: u8 = name.len().try_into().expect("name too long for test");
        v.push(name_len);
        v.push(namespace as u8);

        // UTF-16LE bytes (ASCII-only for this test).
        for b in name.as_bytes() {
            v.push(*b);
            v.push(0);
        }

        v
    }

    fn resident_attribute_record(type_code: u32, value: &[u8]) -> Vec<u8> {
        // Attribute header is 24 bytes for resident attributes with no name.
        const HEADER_LEN: usize = 24;
        let mut record_length = HEADER_LEN + value.len();
        // Attributes are quadword-aligned on disk; keep it aligned to match real layout.
        record_length = (record_length + 7) & !7;

        let mut r = vec![0u8; record_length];
        r[0..4].copy_from_slice(&type_code.to_le_bytes());
        r[4..8].copy_from_slice(&(record_length as u32).to_le_bytes());
        r[8] = 0; // resident
        r[9] = 0; // name length
        r[10..12].copy_from_slice(&0u16.to_le_bytes()); // name offset (unused)
        r[12..14].copy_from_slice(&0u16.to_le_bytes()); // flags
        r[14..16].copy_from_slice(&0u16.to_le_bytes()); // instance
        r[16..20].copy_from_slice(&(value.len() as u32).to_le_bytes()); // value length
        r[20..22].copy_from_slice(&(HEADER_LEN as u16).to_le_bytes()); // value offset
        r[22] = 0; // index flag
        r[23] = 0; // padding

        r[HEADER_LEN..HEADER_LEN + value.len()].copy_from_slice(value);
        r
    }

    #[test]
    fn find_best_name_attribute_prefers_first_win32_over_later_win32() {
        // Regression test: avoid returning the *last* Win32 FILE_NAME attribute.
        let v1 = filename_value_bytes("first.txt", FileNamespace::Win32);
        let v2 = filename_value_bytes("second.txt", FileNamespace::Win32);

        let a1 = resident_attribute_record(0x30, &v1);
        let a2 = resident_attribute_record(0x30, &v2);

        let mut data = Vec::new();
        data.extend_from_slice(&a1);
        data.extend_from_slice(&a2);
        data.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // $END

        let mut header = EntryHeader::zero();
        header.first_attribute_record_offset = 0;

        let entry = MftEntry {
            header,
            data,
            valid_fixup: None,
        };

        let best = entry
            .find_best_name_attribute()
            .expect("expected FILE_NAME attribute");
        assert_eq!(best.name.to_utf8_string(), "first.txt");
    }

    #[test]
    fn iter_attributes_stops_on_end_marker_without_record_length() {
        // If the attribute list is tightly packed and ends with only the 4-byte $END marker
        // (0xFFFF_FFFF), the iterator must stop cleanly (return None) without trying to read
        // a non-existent record length.
        let v1 = filename_value_bytes("one.txt", FileNamespace::Win32);
        let a1 = resident_attribute_record(0x30, &v1);

        let mut data = Vec::new();
        data.extend_from_slice(&a1);
        data.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // $END (exactly 4 bytes)

        let mut header = EntryHeader::zero();
        header.first_attribute_record_offset = 0;

        let entry = MftEntry {
            header,
            data,
            valid_fixup: None,
        };

        let mut it = entry.iter_attributes();
        assert!(it.next().expect("expected first attribute").is_ok());
        assert!(it.next().is_none());
    }
}
