use crate::err::{Error, Result};
use crate::impl_serialize_for_bitflags;

use log::{trace, warn};

use winstructs::ntfs::mft_reference::MftReference;

use byteorder::{LittleEndian, ReadBytesExt};

use bitflags::bitflags;
use serde::Serialize;
use serde::ser::{self, SerializeSeq, SerializeStruct, Serializer};

use crate::attribute::header::{MftAttributeHeader, ResidentialHeader};
use crate::attribute::x30::{FileNameAttr, FileNamespace, NameInParent};
use crate::attribute::{MftAttribute, MftAttributeContent, MftAttributeType};

use std::cell::RefCell;
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
        /// Streams the attributes that parsed, and collects the errors from the ones that
        /// didn't so they can be emitted after the list in the same pass.
        struct Attributes<'a> {
            entry: &'a MftEntry,
            errors: RefCell<Vec<String>>,
        }

        impl ser::Serialize for Attributes<'_> {
            fn serialize<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let mut seq = serializer.serialize_seq(None)?;
                for attr in self.entry.iter_attributes() {
                    match attr {
                        Ok(attr) => seq.serialize_element(&attr)?,
                        Err(e) => self.errors.borrow_mut().push(error_chain_message(&e)),
                    }
                }
                seq.end()
            }
        }

        let attributes = Attributes {
            entry: self,
            errors: RefCell::new(Vec::new()),
        };

        let mut state = serializer.serialize_struct("MftEntry", 4)?;
        state.serialize_field("header", &self.header)?;
        state.serialize_field("attributes", &attributes)?;
        state.serialize_field("valid_fixup", &self.valid_fixup)?;
        // Only present when an attribute failed to parse, so clean entries are unchanged.
        let errors = attributes.errors.into_inner();
        if errors.is_empty() {
            state.skip_field("errors")?;
        } else {
            state.serialize_field("errors", &errors)?;
        }
        state.end()
    }
}

/// Formats an error with its chain of sources, e.g. "An I/O error has occurred: failed to fill
/// whole buffer", since the top-level message alone often doesn't say what went wrong.
fn error_chain_message(error: &Error) -> String {
    let mut message = error.to_string();
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
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
        let flags = EntryFlags::from_bits_retain(reader.read_u16::<LittleEndian>()?);
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

    /// Whether this is a base record, as opposed to an extension record holding attributes moved
    /// out of one. An extension record of `$MFT` (entry 0) is told apart by its non-zero sequence.
    pub fn is_base_record(&self) -> bool {
        self.base_reference.entry == 0 && self.base_reference.sequence == 0
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
            flags: EntryFlags::empty(),
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
    /// Will prefer `Win32` file name attributes, then `POSIX` ones, and fallback to `Dos` paths.
    ///
    /// Only this record's own attributes are considered. Use [`find_best_name_attribute_in`]
    /// with the entry's extension records (see [`crate::MftParser::get_extension_entries`]) to
    /// also consider names stored there.
    pub fn find_best_name_attribute(&self) -> Option<FileNameAttr<'_>> {
        self.find_best_file_name(|value| {
            let name = FileNameAttr::from_slice(value).ok()?;
            Some((name.namespace, name))
        })
    }

    /// The name and parent of [`MftEntry::find_best_name_attribute`], for path resolution, which
    /// skips the sizes and flags of each `$FILE_NAME`.
    pub(crate) fn find_best_name_in_parent(&self) -> Option<NameInParent<'_>> {
        self.find_best_file_name(|value| {
            let name = NameInParent::from_slice(value)?;
            Some((name.namespace, name))
        })
    }

    /// The [`BestName`] of this record's `$FILE_NAME` values, each read by `parse`.
    fn find_best_file_name<'a, N: Clone>(
        &'a self,
        parse: impl Fn(&'a [u8]) -> Option<(FileNamespace, N)>,
    ) -> Option<N> {
        let mut names = BestName::default();
        for (header, record) in self
            .iter_attribute_records_where(|type_code| {
                type_code == MftAttributeType::FileName as u32
            })
            .filter_map(Result::ok)
        {
            // Like `MftAttributeContent::from_record`, which only parses a resident `$FILE_NAME`.
            if let ResidentialHeader::Resident(resident) = &header.residential_header
                && let Some((namespace, name)) = resident.value(record).ok().and_then(&parse)
            {
                names.offer(namespace, &name);
                if names.is_decided() {
                    break;
                }
            }
        }
        names.best()
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
        self.iter_attribute_records_matching(types).map(|record| {
            let (header, record) = record?;
            let data = MftAttributeContent::from_record(record, &header)?;
            Ok(MftAttribute { header, data })
        })
    }

    /// Like [`MftEntry::iter_attributes_matching`], but yields each attribute's header and raw
    /// record without parsing its content, so a header survives content that fails to parse.
    pub fn iter_attribute_records_matching(
        &self,
        types: Option<Vec<MftAttributeType>>,
    ) -> impl Iterator<Item = Result<(MftAttributeHeader<'_>, &[u8])>> + '_ {
        // Filter on raw type codes so attributes with an unknown type code can still be skipped.
        let type_codes: Option<Vec<u32>> =
            types.map(|types| types.into_iter().map(|t| t as u32).collect());
        self.iter_attribute_records_where(move |type_code| {
            type_codes
                .as_ref()
                .is_none_or(|codes| codes.contains(&type_code))
        })
    }

    /// [`MftEntry::iter_attribute_records_matching`], for the attributes whose raw type code
    /// passes `wanted`.
    fn iter_attribute_records_where<'a>(
        &'a self,
        wanted: impl Fn(u32) -> bool + 'a,
    ) -> impl Iterator<Item = Result<(MftAttributeHeader<'a>, &'a [u8])>> + 'a {
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

                // Skip filtered-out attributes before parsing their header, so an attribute the
                // caller did not ask for (including one with an unknown type code) never errors.
                if !wanted(type_code_value) {
                    continue;
                }

                // An unknown type code only invalidates this attribute: its record_length was
                // bounds-checked above, so report it and move on to the next record instead of
                // dropping the rest of the entry. Any other header error means the record itself is malformed
                // (its length can't be trusted), so stop rather than resync at a bogus offset.
                let header = match MftAttributeHeader::from_slice(record, start_offset) {
                    Ok(Some(h)) => h,
                    Ok(None) => return None,
                    Err(e @ Error::UnknownAttributeType { .. }) => return Some(Err(e)),
                    Err(e) => {
                        exhausted = true;
                        return Some(Err(e));
                    }
                };

                return Some(Ok((header, record)));
            }
        })
    }
}

/// The best name of a file whose attributes are spread over a base record and its extension
/// records (from [`crate::MftParser::get_extension_entries`]).
///
/// This is the base record's [`MftEntry::find_best_name_attribute`], unless the base record has
/// no name or only a `Dos` one: then its extension records are searched too, preferring a `Win32`
/// name there over the base record's short name. NTFS moves the long name out of a full base
/// record and keeps the short one, so only searching the base record gives `PROGRA~1`-style
/// paths.
pub fn find_best_name_attribute_in<'a>(
    base: &'a MftEntry,
    extensions: &'a [MftEntry],
) -> Option<FileNameAttr<'a>> {
    let mut names = BestNames::default();
    for (record, is_base) in
        std::iter::once((base, true)).chain(extensions.iter().map(|e| (e, false)))
    {
        for attr in record
            .iter_attributes_matching(Some(vec![MftAttributeType::FileName]))
            .filter_map(Result::ok)
        {
            if let Some(fname) = attr.data.as_file_name() {
                names.offer(fname, is_base);
            }
        }
    }
    names.best()
}

/// Picks the best of the names offered to it: the first `Win32` one, else the first long one,
/// else the first one.
struct BestName<N> {
    first: Option<N>,
    first_long: Option<N>,
    best_win32: Option<N>,
}

// Not derived, which would require `N: Default`.
impl<N> Default for BestName<N> {
    fn default() -> Self {
        BestName {
            first: None,
            first_long: None,
            best_win32: None,
        }
    }
}

impl<N: Clone> BestName<N> {
    fn offer(&mut self, namespace: FileNamespace, name: &N) {
        if self.first.is_none() {
            self.first = Some(name.clone());
        }
        if self.first_long.is_none() && namespace.is_long() {
            self.first_long = Some(name.clone());
        }

        if matches!(namespace, FileNamespace::Win32 | FileNamespace::Win32AndDos) {
            // Preserve the first Win32/Win32AndDos name for stability.
            // MFT entries can contain multiple Win32 names (e.g. hard links), and there
            // isn't a canonical choice without directory context.
            if self.best_win32.is_none() {
                self.best_win32 = Some(name.clone());
            }
        }
    }

    /// Whether no name offered later can be picked over the ones so far.
    fn is_decided(&self) -> bool {
        self.best_win32.is_some()
    }

    fn best(self) -> Option<N> {
        // A `POSIX` name is still a long name, better than the `Dos` one.
        self.best_win32.or(self.first_long).or(self.first)
    }
}

/// The best name of a base record and its extension records, offered in one pass: see
/// [`find_best_name_attribute_in`].
#[derive(Default)]
pub(crate) struct BestNames<'a> {
    base: BestName<FileNameAttr<'a>>,
    all: BestName<FileNameAttr<'a>>,
}

impl<'a> BestNames<'a> {
    pub(crate) fn offer(&mut self, fname: &FileNameAttr<'a>, in_base_record: bool) {
        if in_base_record {
            self.base.offer(fname.namespace, fname);
        }
        self.all.offer(fname.namespace, fname);
    }

    pub(crate) fn best(self) -> Option<FileNameAttr<'a>> {
        let base_name = self.base.best();
        if base_name.as_ref().is_some_and(|n| n.namespace.is_long()) {
            return base_name;
        }
        self.all.best()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{EntryHeader, MftEntry, find_best_name_attribute_in};
    use crate::MftParser;
    use crate::attribute::x30::FileNamespace;
    use crate::attribute::{MftAttribute, MftAttributeType};
    use crate::err::{Error, Result};
    use crate::tests::fixtures::mft_sample;
    use std::io::Cursor;

    const HEADER_38357: &[u8] = &[
        0x46, 0x49, 0x4C, 0x45, 0x30, 0x00, 0x03, 0x00, 0xCC, 0xB3, 0x7D, 0x84, 0x0C, 0x00, 0x00,
        0x00, 0x05, 0x00, 0x01, 0x00, 0x38, 0x00, 0x05, 0x00, 0x48, 0x03, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0xD5,
        0x95, 0x00, 0x00, 0x53, 0x57, 0x81, 0x37, 0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn mft_header_test_01() {
        let entry_header = EntryHeader::from_reader(&mut Cursor::new(HEADER_38357), 38357).unwrap();

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
    fn entry_flags_keep_unknown_bits() {
        let mut header_buffer = HEADER_38357.to_vec();
        header_buffer[22..24].copy_from_slice(&0x8011u16.to_le_bytes());

        let entry_header =
            EntryHeader::from_reader(&mut Cursor::new(header_buffer), 38357).unwrap();

        assert_eq!(entry_header.flags.bits(), 0x8011);
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

    /// An MFT reference to `entry`: its number in the low 48 bits and `sequence` in the high 16.
    pub(crate) fn mft_reference_bytes(entry: u64, sequence: u16) -> [u8; 8] {
        (entry | (u64::from(sequence) << 48)).to_le_bytes()
    }

    /// A `$FILE_NAME` value for an ASCII `name` in the root, based on the example in the
    /// `attribute::x30` docs. Its timestamps, sizes and flags are arbitrary but valid.
    pub(crate) fn filename_value_bytes(name: &str, namespace: FileNamespace) -> Vec<u8> {
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

        // UTF-16LE bytes.
        for b in name.as_bytes() {
            v.push(*b);
            v.push(0);
        }

        v
    }

    pub(crate) fn resident_attribute_record(type_code: u32, value: &[u8]) -> Vec<u8> {
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

        let entry = entry_with_attributes(&[
            resident_attribute_record(0x30, &v1),
            resident_attribute_record(0x30, &v2),
        ]);

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
        // `entry_with_attributes` appends exactly the 4-byte $END marker.
        let entry = entry_with_attributes(&[resident_attribute_record(0x30, &v1)]);

        let mut it = entry.iter_attributes();
        assert!(it.next().expect("expected first attribute").is_ok());
        assert!(it.next().is_none());
    }

    fn entry_with_attributes(records: &[Vec<u8>]) -> MftEntry {
        let mut data = Vec::new();
        for r in records {
            data.extend_from_slice(r);
        }
        data.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // $END

        let mut header = EntryHeader::zero();
        header.first_attribute_record_offset = 0;

        MftEntry {
            header,
            data,
            valid_fixup: None,
        }
    }

    #[test]
    fn iter_attributes_continues_past_unknown_attribute_type() {
        // An unknown type code only invalidates that attribute; its record length is still
        // usable, so the attributes after it must still be returned. Filtering happens on the raw
        // type code, so a caller that did not ask for the unknown type never sees the error.
        let fname = filename_value_bytes("after.txt", FileNamespace::Win32);
        let entry = entry_with_attributes(&[
            resident_attribute_record(0x1234, &[0xAA; 8]),
            resident_attribute_record(0x30, &fname),
        ]);
        let name_of = |attr: &Result<MftAttribute<'_>>| {
            attr.as_ref()
                .unwrap()
                .data
                .as_file_name()
                .unwrap()
                .name
                .to_utf8_string()
        };

        let all: Vec<_> = entry.iter_attributes().collect();
        assert_eq!(all.len(), 2);
        assert!(matches!(
            all[0],
            Err(Error::UnknownAttributeType {
                attribute_type: 0x1234
            })
        ));
        assert_eq!(name_of(&all[1]), "after.txt");

        let names: Vec<_> = entry
            .iter_attributes_matching(Some(vec![MftAttributeType::FileName]))
            .collect();
        assert_eq!(names.len(), 1);
        assert_eq!(name_of(&names[0]), "after.txt");
    }

    #[test]
    fn iter_attributes_stops_after_malformed_attribute_header() {
        // A header error other than an unknown type code (here: an invalid form code) means the
        // record length can't be trusted, so iteration must stop instead of resyncing.
        let fname = filename_value_bytes("after.txt", FileNamespace::Win32);
        let mut bad = resident_attribute_record(0x80, &[0xAA; 8]);
        bad[8] = 0x7F; // invalid form code
        let entry = entry_with_attributes(&[bad, resident_attribute_record(0x30, &fname)]);

        let results: Vec<_> = entry.iter_attributes().collect();
        assert_eq!(results.len(), 1);
        assert!(matches!(
            results[0],
            Err(Error::UnhandledResidentFlag { flag: 0x7F, .. })
        ));
    }

    #[test]
    fn property_set_attribute_is_known() {
        // 0xF0 $PROPERTY_SET exists on NT4-era volumes; it should parse as a raw attribute.
        let entry = entry_with_attributes(&[resident_attribute_record(0xF0, &[0x01; 8])]);

        let attr = entry
            .iter_attributes()
            .next()
            .expect("expected an attribute")
            .expect("expected $PROPERTY_SET to parse");
        assert_eq!(attr.header.type_code, MftAttributeType::PropertySet);
    }

    #[test]
    fn find_best_name_in_parent_picks_the_best_name_attribute() {
        let mut parser = MftParser::from_path(mft_sample()).unwrap();

        let mut named = 0;
        for entry in parser.iter_entries().filter_map(Result::ok) {
            let name = entry
                .find_best_name_in_parent()
                .map(|n| (n.parent, n.namespace, n.name));
            // Parses each attribute whole, unlike the lookups on `MftEntry`.
            let full =
                find_best_name_attribute_in(&entry, &[]).map(|f| (f.parent, f.namespace, f.name));
            named += usize::from(full.is_some());
            assert_eq!(name, full, "entry {}", entry.header.record_number);
        }
        assert!(named > 0);
    }
}
