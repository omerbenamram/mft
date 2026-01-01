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
        let mut stream = Cursor::new(value);
        stream.set_position(offset as u64);
        let start_pos = stream.position() as usize;

        let mft_reference =
            MftReference::from_reader(&mut stream).map_err(Error::failed_to_read_mft_reference)?;
        if mft_reference.entry > 0 && mft_reference.sequence > 0 {
            let index_record_length = stream.read_u16::<LittleEndian>()?;
            let end_pos = start_pos + usize::from(index_record_length);
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
        let end_pos = index_node_start_pos + index_node_length as usize;
        if end_pos > value.len() {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
        }

        let mut index_entries: Vec<IndexEntryHeader<'a>> = Vec::new();
        while offset < end_pos {
            match IndexEntryHeader::from_slice_at(value, offset)? {
                Some((entry, next_offset)) => {
                    index_entries.push(entry);
                    offset = next_offset;
                }
                None => break,
            }
        }

        Ok(IndexEntries { index_entries })
    }
}
