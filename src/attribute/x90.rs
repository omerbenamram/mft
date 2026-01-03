use crate::err::{Error, Result};
use crate::impl_serialize_for_bitflags;

use byteorder::{LittleEndian, ReadBytesExt};

use bitflags::bitflags;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use serde::Serialize;
use std::io::Cursor;
use winstructs::ntfs::mft_reference::MftReference;

use crate::attribute::x30::FileNameAttr;

/// $IndexRoot Attribute
#[derive(Serialize, Clone, Debug)]
pub struct IndexRootAttr<'a> {
    /// Unique Id assigned to file
    pub attribute_type: u32,
    /// Collation rule used to sort the index entries.
    /// If type is $FILENAME, this must be COLLATION_FILENAME
    pub collation_rule: IndexCollationRules,
    /// The index entry size
    pub index_entry_size: u32,
    /// The index entry number of cluster blocks
    pub index_entry_number_of_cluster_blocks: u32, // really 1 byte with 3 bytes padding

    pub relative_offset_to_index_node: u32,
    pub index_node_length: u32,
    pub index_node_allocation_length: u32,
    pub index_root_flags: IndexRootFlags, // 0x00 = Small Index (fits in Index Root); 0x01 = Large index (Index Allocation needed)
    pub index_entries: IndexEntries<'a>,
}

/// Enum sources:
/// https://opensource.apple.com/source/ntfs/ntfs-52/kext/ntfs_layout.h
/// https://docs.huihoo.com/doxygen/linux/kernel/3.7/layout_8h_source.html
///
#[derive(Serialize, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u32)]
#[derive(FromPrimitive)]
pub enum IndexCollationRules {
    CollationBinary = 0x00,
    CollationFilename = 0x01,
    CollationUnicodeString = 0x02,
    CollationNtofsUlong = 0x10,
    CollationNtofsSid = 0x11,
    CollationNtofsSecurityHash = 0x12,
    CollationNtofsUlongs = 0x13,
}

bitflags! {
    #[derive(Clone, Debug, PartialEq)]
    pub struct IndexRootFlags: u32 {
        const SMALL_INDEX = 0x00;
        const LARGE_INDEX = 0x01;
    }
}
impl_serialize_for_bitflags! {IndexRootFlags}

impl<'a> IndexRootAttr<'a> {
    /// Data size should be either 16 or 64
    pub fn from_slice(value: &'a [u8]) -> Result<IndexRootAttr<'a>> {
        let mut stream = Cursor::new(value);

        let attribute_type = stream.read_u32::<LittleEndian>()?;
        let collation_rule_val = stream.read_u32::<LittleEndian>()?;
        let collation_rule = IndexCollationRules::from_u32(collation_rule_val);
        let collation_rule = match collation_rule {
            None => {
                return Err(Error::UnknownCollationType {
                    collation_type: collation_rule_val,
                });
            }
            Some(collation_rule) => collation_rule,
        };
        let index_entry_size = stream.read_u32::<LittleEndian>()?;
        let index_entry_number_of_cluster_blocks = stream.read_u32::<LittleEndian>()?;
        let index_node_start_pos = stream.position() as usize;
        let relative_offset_to_index_node = stream.read_u32::<LittleEndian>()?;
        let index_node_length = stream.read_u32::<LittleEndian>()?;
        let index_node_allocation_length = stream.read_u32::<LittleEndian>()?;
        let index_root_flags =
            IndexRootFlags::from_bits_truncate(stream.read_u32::<LittleEndian>()?);
        let index_entries = IndexEntries::from_slice(
            value,
            index_node_length,
            index_node_start_pos,
            stream.position() as usize,
        )?;

        Ok(IndexRootAttr {
            attribute_type,
            collation_rule,
            index_entry_size,
            index_entry_number_of_cluster_blocks,
            relative_offset_to_index_node,
            index_node_length,
            index_node_allocation_length,
            index_root_flags,
            index_entries,
        })
    }
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct IndexEntryHeader<'a> {
    pub mft_reference: MftReference,
    pub index_record_length: u16,
    pub attr_fname_length: u16,
    pub flags: IndexEntryFlags,
    pub fname_info: FileNameAttr<'a>,
}
bitflags! {
    #[derive(Clone, Debug, PartialEq)]
    pub struct IndexEntryFlags: u32 {
        const INDEX_ENTRY_NODE = 0x01;
        const INDEX_ENTRY_END  = 0x02;
    }
}
impl_serialize_for_bitflags! {IndexEntryFlags}

impl<'a> IndexEntryHeader<'a> {
    pub fn from_slice_at(
        value: &'a [u8],
        offset: usize,
    ) -> Result<Option<(IndexEntryHeader<'a>, usize)>> {
        const INDEX_ENTRY_HEADER_LEN: u16 = 16;

        let mut stream = Cursor::new(value);
        stream.set_position(offset as u64);
        let start_pos = stream.position() as usize;

        let mft_reference =
            MftReference::from_reader(&mut stream).map_err(Error::failed_to_read_mft_reference)?;
        if mft_reference.entry > 0 && mft_reference.sequence > 0 {
            let index_record_length = stream.read_u16::<LittleEndian>()?;
            if index_record_length == 0 {
                return Err(Error::Any {
                    detail: "index entry record_length is 0".to_string(),
                });
            }
            if index_record_length < INDEX_ENTRY_HEADER_LEN {
                return Err(Error::Any {
                    detail: format!(
                        "index entry record_length {index_record_length} is smaller than minimum {INDEX_ENTRY_HEADER_LEN}"
                    ),
                });
            }
            let end_pos = start_pos
                .checked_add(usize::from(index_record_length))
                .ok_or_else(|| Error::Any {
                    detail: "index entry offset overflow".to_string(),
                })?;
            let attr_fname_length = stream.read_u16::<LittleEndian>()?;
            let flags = IndexEntryFlags::from_bits_truncate(stream.read_u32::<LittleEndian>()?);

            let fname_start = stream.position() as usize;
            if fname_start > end_pos || end_pos > value.len() {
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
            }
            let fname_info = FileNameAttr::from_slice(&value[fname_start..end_pos])?;

            Ok(Some((
                IndexEntryHeader {
                    mft_reference,
                    index_record_length,
                    attr_fname_length,
                    flags,
                    fname_info,
                },
                end_pos,
            )))
        } else {
            Ok(None)
        }
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct IndexEntries<'a> {
    pub index_entries: Vec<IndexEntryHeader<'a>>,
}

impl<'a> IndexEntries<'a> {
    pub fn from_slice(
        value: &'a [u8],
        index_node_length: u32,
        index_node_start_pos: usize,
        mut offset: usize,
    ) -> Result<Self> {
        let index_node_end = index_node_start_pos
            .checked_add(index_node_length as usize)
            .ok_or_else(|| Error::Any {
                detail: "index node end offset overflow".to_string(),
            })?;
        if index_node_end > value.len() {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
        }

        let mut index_entries: Vec<IndexEntryHeader<'a>> = Vec::new();
        while offset < index_node_end {
            match IndexEntryHeader::from_slice_at(value, offset)? {
                Some((entry, next_offset)) => {
                    if next_offset <= offset {
                        return Err(Error::Any {
                            detail: format!(
                                "index entry next offset {next_offset} did not advance past {offset}"
                            ),
                        });
                    }
                    if next_offset > index_node_end {
                        return Err(Error::Any {
                            detail: format!(
                                "index entry end offset {next_offset} exceeds index node end {index_node_end}"
                            ),
                        });
                    }
                    index_entries.push(entry);
                    offset = next_offset;
                }
                None => break,
            }
        }

        Ok(IndexEntries { index_entries })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attribute::x30::FileNamespace;

    fn mft_reference_bytes(entry: u64, sequence: u16) -> [u8; 8] {
        // NTFS MFT reference is a 48-bit entry number plus a 16-bit sequence number (little-endian).
        let mut out = [0u8; 8];
        out[0] = (entry & 0xFF) as u8;
        out[1] = ((entry >> 8) & 0xFF) as u8;
        out[2] = ((entry >> 16) & 0xFF) as u8;
        out[3] = ((entry >> 24) & 0xFF) as u8;
        out[4] = ((entry >> 32) & 0xFF) as u8;
        out[5] = ((entry >> 40) & 0xFF) as u8;
        out[6] = (sequence & 0xFF) as u8;
        out[7] = (sequence >> 8) as u8;
        out
    }

    #[test]
    fn index_entry_record_length_zero_is_error() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&mft_reference_bytes(1, 1));
        buf.extend_from_slice(&0u16.to_le_bytes()); // record_length
        buf.extend_from_slice(&0u16.to_le_bytes()); // attr_fname_length
        buf.extend_from_slice(&0u32.to_le_bytes()); // flags/reserved

        let err = IndexEntryHeader::from_slice_at(&buf, 0).unwrap_err();
        match err {
            Error::Any { detail } => assert!(detail.contains("record_length is 0")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn index_entry_end_offset_exceeds_index_node_is_error() {
        // Build one valid index entry of 82 bytes (header 16 + FileNameAttr 66),
        // but claim the index node only has 40 bytes.
        let mut fname = Vec::new();
        fname.extend_from_slice(&mft_reference_bytes(5, 1)); // parent
        fname.extend_from_slice(&0u64.to_le_bytes()); // created
        fname.extend_from_slice(&0u64.to_le_bytes()); // modified
        fname.extend_from_slice(&0u64.to_le_bytes()); // mft_modified
        fname.extend_from_slice(&0u64.to_le_bytes()); // accessed
        fname.extend_from_slice(&0u64.to_le_bytes()); // logical size
        fname.extend_from_slice(&0u64.to_le_bytes()); // physical size
        fname.extend_from_slice(&0u32.to_le_bytes()); // flags
        fname.extend_from_slice(&0u32.to_le_bytes()); // reparse
        fname.push(0); // name_length
        fname.push(FileNamespace::Win32 as u8); // namespace
        assert_eq!(fname.len(), 66);

        let mut buf = Vec::new();
        buf.extend_from_slice(&mft_reference_bytes(1, 1)); // mft_reference
        buf.extend_from_slice(&(82u16).to_le_bytes()); // record_length
        buf.extend_from_slice(&(66u16).to_le_bytes()); // attr_fname_length
        buf.extend_from_slice(&0u32.to_le_bytes()); // flags/reserved
        buf.extend_from_slice(&fname);
        assert_eq!(buf.len(), 82);

        let err = IndexEntries::from_slice(&buf, 40, 0, 0).unwrap_err();
        match err {
            Error::Any { detail } => assert!(detail.contains("exceeds index node end")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    #[cfg(target_pointer_width = "32")]
    fn index_node_end_offset_overflow_is_error() {
        let buf = [0u8; 64];

        // On 32-bit targets, `index_node_start_pos + index_node_length` can overflow if the
        // length comes from untrusted on-disk data.
        let err = IndexEntries::from_slice(&buf, u32::MAX, 16, 32).unwrap_err();
        match err {
            Error::Any { detail } => assert!(detail.contains("index node end offset overflow")),
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
