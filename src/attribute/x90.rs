use crate::attribute::MftAttributeType;
use crate::attribute::raw::data_as_hex;
use crate::attribute::x50::sid;
use crate::attribute::xc0::tag_name;
use crate::err::{Error, Result};
use crate::impl_serialize_for_bitflags;
use crate::utils::{read_guid, read_u32, read_u64, windows_filetime_to_timestamp};

use byteorder::{ByteOrder, LittleEndian, ReadBytesExt};

use bitflags::bitflags;
use jiff::Timestamp;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use serde::Serialize;
use std::io::Cursor;
use winstructs::guid::Guid;
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
        // The flags are one byte, followed by three reserved bytes.
        let index_root_flags =
            IndexRootFlags::from_bits_retain(stream.read_u32::<LittleEndian>()? & 0xFF);
        // Indexes of `$FILE_NAME` (`$I30`) index attribute type 0x30. Every other index is a view
        // index, such as `$Secure:$SDH`, which indexes no attribute (type 0) and whose entries carry
        // a key and data.
        let index_entries = if attribute_type == MftAttributeType::FileName as u32 {
            IndexEntries::from_slice(
                value,
                index_node_length,
                index_node_start_pos,
                stream.position() as usize,
            )?
        } else {
            // The node's entries, from the first one to the end of the node.
            let entries = value
                .get(index_node_start_pos..)
                .and_then(|node| node.get(..index_node_length as usize))
                .and_then(|node| node.get(relative_offset_to_index_node as usize..))
                .ok_or_else(|| Error::Any {
                    detail: "view index node runs past the index root".to_string(),
                })?;
            IndexEntries {
                index_entries: Vec::new(),
                view_entries: ViewIndexEntry::from_node(entries, collation_rule)?,
            }
        };

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
            // The flags are two bytes, followed by two reserved bytes.
            let flags =
                IndexEntryFlags::from_bits_retain(stream.read_u32::<LittleEndian>()? & 0xFFFF);

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
    /// The entries of a `$FILE_NAME` index (`$I30`).
    pub index_entries: Vec<IndexEntryHeader<'a>>,
    /// The entries of a view index, such as `$Secure:$SDH` or `$Extend\$Quota:$Q`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub view_entries: Vec<ViewIndexEntry<'a>>,
}

/// An entry of a view index: an index whose keys aren't file names.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct ViewIndexEntry<'a> {
    pub flags: IndexEntryFlags,
    #[serde(flatten)]
    pub value: ViewIndexValue<'a>,
}

/// A view index entry's key and data, decoded for the indexes NTFS keeps in its metadata files.
/// The index is recognized from its collation rule and the sizes of the key and data.
#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(tag = "type")]
pub enum ViewIndexValue<'a> {
    /// `$Secure:$SDH`, the security descriptors by hash, or `$Secure:$SII`, by id. Both point at
    /// the descriptor's entry in the `$Secure:$SDS` stream.
    SecurityDescriptor {
        hash: u32,
        security_id: u32,
        sds_offset: u64,
        sds_length: u32,
    },
    /// `$Extend\$ObjId:$O`: the file an object id belongs to.
    ObjectId {
        object_id: Guid,
        mft_reference: MftReference,
        birth_volume_id: Guid,
        birth_object_id: Guid,
        domain_id: Guid,
    },
    /// `$Extend\$Quota:$O`: the quota owner id of a SID.
    QuotaOwner { sid: String, owner_id: u32 },
    /// `$Extend\$Quota:$Q`: an owner's quota and disk usage.
    Quota {
        owner_id: u32,
        version: u32,
        quota_flags: u32,
        bytes_used: u64,
        change_time: Timestamp,
        /// -1 means no limit.
        warning_limit: i64,
        /// -1 means no limit.
        hard_limit: i64,
        /// When the warning limit was exceeded, if it was.
        exceeded_time: Option<Timestamp>,
        /// Missing for the default quota entry.
        sid: Option<String>,
    },
    /// `$Extend\$Reparse:$R`: a file with a reparse point, by tag.
    Reparse {
        tag: u32,
        /// The name of a documented tag, as in `ReparsePointAttr::tag_name`.
        tag_name: Option<&'static str>,
        mft_reference: MftReference,
    },
    /// Any other index.
    Other {
        #[serde(serialize_with = "data_as_hex")]
        key: &'a [u8],
        #[serde(serialize_with = "data_as_hex")]
        data: &'a [u8],
    },
}

impl<'a> ViewIndexEntry<'a> {
    /// Reads the view index entries at the start of `node`, up to its end entry.
    /// <https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc#index-entry>
    fn from_node(node: &'a [u8], collation_rule: IndexCollationRules) -> Result<Vec<Self>> {
        const ENTRY_HEADER_LEN: usize = 16;
        let truncated = || Error::Any {
            detail: "view index entry runs past the index node".to_string(),
        };

        let mut entries = Vec::new();
        let mut offset = 0;
        while offset < node.len() {
            let header = node
                .get(offset..offset + ENTRY_HEADER_LEN)
                .ok_or_else(truncated)?;
            let field = |at| usize::from(LittleEndian::read_u16(&header[at..]));
            let (data_offset, data_length) = (field(0), field(2));
            let (length, key_length) = (field(8), field(10));
            let flags = IndexEntryFlags::from_bits_retain(field(12) as u32);
            if flags.contains(IndexEntryFlags::INDEX_ENTRY_END) {
                break;
            }
            if length < ENTRY_HEADER_LEN {
                return Err(Error::Any {
                    detail: format!("view index entry length {length} is too small"),
                });
            }

            let entry = node.get(offset..offset + length).ok_or_else(truncated)?;
            let key = entry
                .get(ENTRY_HEADER_LEN..ENTRY_HEADER_LEN + key_length)
                .ok_or_else(truncated)?;
            let data = entry
                .get(data_offset..data_offset + data_length)
                .ok_or_else(truncated)?;
            let value = ViewIndexValue::decode(collation_rule, key, data)
                .unwrap_or(ViewIndexValue::Other { key, data });
            entries.push(ViewIndexEntry { flags, value });
            offset += length;
        }
        Ok(entries)
    }
}

impl<'a> ViewIndexValue<'a> {
    /// Decodes the key and data of a known index, or `None` if they don't match its layout.
    fn decode(collation_rule: IndexCollationRules, key: &[u8], data: &[u8]) -> Option<Self> {
        let reference = |buf: &[u8], offset: usize| read_u64(buf, offset).map(MftReference::from);
        // A SID that fills `buf`.
        let whole_sid = |buf: &[u8]| {
            sid(buf, 0)
                .filter(|&(_, length)| length == buf.len())
                .map(|(sid, _)| sid)
        };

        Some(match (collation_rule, key.len(), data.len()) {
            // The data is the descriptor's `$SDS` entry header, which starts with its hash and id.
            // `$SDH` is keyed by both and `$SII` by the id, so the key ends where the id does.
            (IndexCollationRules::CollationNtofsSecurityHash, 8, 20)
            | (IndexCollationRules::CollationNtofsUlong, 4, 20) => {
                if data[8 - key.len()..8] != *key {
                    return None;
                }
                ViewIndexValue::SecurityDescriptor {
                    hash: read_u32(data, 0)?,
                    security_id: read_u32(data, 4)?,
                    sds_offset: read_u64(data, 8)?,
                    sds_length: read_u32(data, 16)?,
                }
            }
            (IndexCollationRules::CollationNtofsUlongs, 16, 56) => ViewIndexValue::ObjectId {
                object_id: read_guid(key, 0)?,
                mft_reference: reference(data, 0)?,
                birth_volume_id: read_guid(data, 8)?,
                birth_object_id: read_guid(data, 24)?,
                domain_id: read_guid(data, 40)?,
            },
            (IndexCollationRules::CollationNtofsUlongs, 12, 0) => {
                let tag = read_u32(key, 0)?;
                ViewIndexValue::Reparse {
                    tag,
                    tag_name: tag_name(tag),
                    mft_reference: reference(key, 4)?,
                }
            }
            (IndexCollationRules::CollationNtofsSid, _, 4) => ViewIndexValue::QuotaOwner {
                sid: whole_sid(key)?,
                owner_id: read_u32(data, 0)?,
            },
            (IndexCollationRules::CollationNtofsUlong, 4, 48..) => ViewIndexValue::Quota {
                owner_id: read_u32(key, 0)?,
                version: read_u32(data, 0)?,
                quota_flags: read_u32(data, 4)?,
                bytes_used: read_u64(data, 8)?,
                change_time: windows_filetime_to_timestamp(read_u64(data, 16)?).ok()?,
                warning_limit: read_u64(data, 24)? as i64,
                hard_limit: read_u64(data, 32)? as i64,
                exceeded_time: match read_u64(data, 40)? {
                    0 => None,
                    t => Some(windows_filetime_to_timestamp(t).ok()?),
                },
                sid: match &data[48..] {
                    [] => None,
                    rest => Some(whole_sid(rest)?),
                },
            },
            _ => return None,
        })
    }
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

        Ok(IndexEntries {
            index_entries,
            view_entries: Vec::new(),
        })
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

    /// A view index entry with `key` and `data`, padded to 8 bytes like NTFS writes them.
    fn view_entry(key: &[u8], data: &[u8], flags: u16) -> Vec<u8> {
        let data_offset = 16 + key.len();
        let length = (data_offset + data.len()).next_multiple_of(8);
        let mut buf = Vec::new();
        buf.extend_from_slice(&(data_offset as u16).to_le_bytes());
        buf.extend_from_slice(&(data.len() as u16).to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&(length as u16).to_le_bytes());
        buf.extend_from_slice(&(key.len() as u16).to_le_bytes());
        buf.extend_from_slice(&flags.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(key);
        buf.extend_from_slice(data);
        buf.resize(length, 0);
        buf
    }

    fn end_entry() -> Vec<u8> {
        view_entry(&[], &[], IndexEntryFlags::INDEX_ENTRY_END.bits() as u16)
    }

    fn guid(first: u8) -> Vec<u8> {
        (first..first + 16).collect()
    }

    #[test]
    fn view_entries_decode_object_ids_and_reparse_points() {
        let mut data = mft_reference_bytes(40, 3).to_vec();
        data.extend(guid(0x10));
        data.extend(guid(0x20));
        data.extend(guid(0x30));
        let mut node = view_entry(&guid(0), &data, 0);
        node.extend(end_entry());

        let entries =
            ViewIndexEntry::from_node(&node, IndexCollationRules::CollationNtofsUlongs).unwrap();
        let guid_of = |first| Guid::from_buffer(&guid(first)).unwrap();
        assert_eq!(
            entries,
            vec![ViewIndexEntry {
                flags: IndexEntryFlags::empty(),
                value: ViewIndexValue::ObjectId {
                    object_id: guid_of(0),
                    mft_reference: MftReference::new(40, 3),
                    birth_volume_id: guid_of(0x10),
                    birth_object_id: guid_of(0x20),
                    domain_id: guid_of(0x30),
                },
            }]
        );

        let mut key = 0xA000_0003u32.to_le_bytes().to_vec();
        key.extend(mft_reference_bytes(1234, 7));
        let mut node = view_entry(&key, &[], 0);
        node.extend(end_entry());
        let entries =
            ViewIndexEntry::from_node(&node, IndexCollationRules::CollationNtofsUlongs).unwrap();
        assert_eq!(
            entries[0].value,
            ViewIndexValue::Reparse {
                tag: 0xA000_0003,
                tag_name: Some("MOUNT_POINT"),
                mft_reference: MftReference::new(1234, 7),
            }
        );
    }

    #[test]
    fn view_entries_of_unknown_layout_keep_key_and_data() {
        let mut node = view_entry(&[1, 2, 3], &[4, 5], 0);
        // A SID index whose key isn't a SID.
        node.extend(view_entry(&[9; 8], &[0; 4], 0));
        node.extend(end_entry());
        // Bytes after the end entry aren't entries.
        node.extend(view_entry(&[7], &[], 0));

        let other = |rule| {
            ViewIndexEntry::from_node(&node, rule)
                .unwrap()
                .into_iter()
                .map(|entry| entry.value)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            other(IndexCollationRules::CollationNtofsSid),
            vec![
                ViewIndexValue::Other {
                    key: &[1, 2, 3],
                    data: &[4, 5],
                },
                ViewIndexValue::Other {
                    key: &[9; 8],
                    data: &[0; 4],
                },
            ]
        );
    }

    #[test]
    fn view_entry_past_the_index_node_is_error() {
        let mut node = view_entry(&[0; 4], &[0; 20], 0);
        node.extend(end_entry());
        for end in [8, 20] {
            let err =
                ViewIndexEntry::from_node(&node[..end], IndexCollationRules::CollationNtofsUlong)
                    .unwrap_err();
            assert!(
                err.to_string().contains("past the index node"),
                "{end}: {err}"
            );
        }

        // An entry whose data runs past its own length.
        let mut node = view_entry(&[0; 4], &[], 0);
        node[2] = 20;
        let err =
            ViewIndexEntry::from_node(&node, IndexCollationRules::CollationNtofsUlong).unwrap_err();
        assert!(err.to_string().contains("past the index node"), "{err}");
    }

    #[test]
    fn view_index_node_past_the_index_root_is_error() {
        let mut value = Vec::new();
        for field in [0u32, 0x10, 4096, 1, 16, 1000, 1000, 0] {
            value.extend_from_slice(&field.to_le_bytes());
        }
        value.extend(end_entry());
        let err = IndexRootAttr::from_slice(&value).unwrap_err();
        assert!(err.to_string().contains("past the index root"), "{err}");

        // The same root with the node's real length parses, with no entries.
        value[20..24].copy_from_slice(&32u32.to_le_bytes());
        let root = IndexRootAttr::from_slice(&value).unwrap();
        assert!(root.index_entries.view_entries.is_empty());
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
