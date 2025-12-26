use crate::ntfs::name::FileNameKey;
use crate::ntfs::{Error, Result};
use crate::parse::Reader;
use bitflags::bitflags;
use mft::ntfs::apply_update_sequence_array_fixups_in_place;

pub const INDEX_RECORD_SIGNATURE: &[u8; 4] = b"INDX";

#[derive(Debug, Clone)]
pub struct IndexRootHeader {
    pub attribute_type: u32,
    pub collation_type: u32,
    pub index_entry_size: u32,
    pub index_entry_number_of_cluster_blocks: u32,
}

impl IndexRootHeader {
    pub fn parse(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            attribute_type: r.u32_le("index_root.attribute_type")?,
            collation_type: r.u32_le("index_root.collation_type")?,
            index_entry_size: r.u32_le("index_root.index_entry_size")?,
            index_entry_number_of_cluster_blocks: r
                .u32_le("index_root.index_entry_number_of_cluster_blocks")?,
        })
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct IndexNodeFlags: u32 {
        /// Indicates the presence of an $INDEX_ALLOCATION attribute.
        const HAS_ALLOCATION_ATTRIBUTE = 0x0000_0001;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct IndexValueFlags: u32 {
        const IS_BRANCH_NODE = 0x0000_0001;
        const IS_LAST        = 0x0000_0002;
    }
}

#[derive(Debug, Clone)]
pub struct IndexNodeHeader {
    /// Offset relative to the start of the index node header.
    pub index_values_offset: u32,
    pub size: u32,
    pub allocated_size: u32,
    pub flags: IndexNodeFlags,
}

impl IndexNodeHeader {
    pub fn parse(r: &mut Reader<'_>) -> Result<Self> {
        let index_values_offset = r.u32_le("index_node.index_values_offset")?;
        let size = r.u32_le("index_node.size")?;
        let allocated_size = r.u32_le("index_node.allocated_size")?;
        let flags = IndexNodeFlags::from_bits_truncate(r.u32_le("index_node.flags")?);

        if size > 0 && size < 16 {
            return Err(Error::InvalidData {
                message: format!("index node size too small: {size}"),
            });
        }
        if size > 0
            && (index_values_offset < 16
                || index_values_offset > size
                || index_values_offset % 8 != 0)
        {
            return Err(Error::InvalidData {
                message: format!(
                    "index values offset out of bounds: offset={index_values_offset} size={size}"
                ),
            });
        }

        Ok(Self {
            index_values_offset,
            size,
            allocated_size,
            flags,
        })
    }
}

#[derive(Debug, Clone)]
pub struct IndexRecordHeader {
    pub signature: [u8; 4],
    pub fixup_values_offset: u16,
    pub number_of_fixup_values: u16,
    pub journal_sequence_number: u64,
    pub vcn: u64,
}

impl IndexRecordHeader {
    pub fn parse(r: &mut Reader<'_>) -> Result<Self> {
        let sig = r.take("index_record.signature", 4)?;
        let signature: [u8; 4] = sig.try_into().expect("len=4");
        Ok(Self {
            signature,
            fixup_values_offset: r.u16_le("index_record.fixup_values_offset")?,
            number_of_fixup_values: r.u16_le("index_record.number_of_fixup_values")?,
            journal_sequence_number: r.u64_le("index_record.journal_sequence_number")?,
            vcn: r.u64_le("index_record.vcn")?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct IndexValue {
    pub file_reference_raw: u64,
    pub size: u16,
    pub key_data_size: u16,
    pub flags: IndexValueFlags,
    pub file_name: Option<FileNameKey>,
    pub sub_node_vcn: Option<u64>,
}

impl IndexValue {
    pub fn is_last(&self) -> bool {
        self.flags.contains(IndexValueFlags::IS_LAST)
    }

    pub fn parse(r: &mut Reader<'_>) -> Result<Self> {
        let file_reference_raw = r.u64_le("index_value.file_reference")?;
        let size = r.u16_le("index_value.size")?;
        let key_data_size = r.u16_le("index_value.key_data_size")?;
        let flags = IndexValueFlags::from_bits_truncate(r.u32_le("index_value.flags")?);

        if size < 16 {
            return Err(Error::InvalidData {
                message: format!("index value size too small: {size}"),
            });
        }

        let payload_len = (size as usize).saturating_sub(16);
        let payload_offset = r.stream_offset();
        let payload = r.take("index_value.payload", payload_len)?;

        let key_len = key_data_size as usize;
        if key_len > payload.len() {
            return Err(Error::InvalidData {
                message: format!(
                    "index value key length out of bounds: key_len={key_len} payload_len={}",
                    payload.len()
                ),
            });
        }

        let key = &payload[..key_len];
        let file_name = if !key.is_empty() {
            // In $I30 indexes, the key is a FILE_NAME attribute.
            Some(FileNameKey::parse(key, payload_offset)?)
        } else {
            None
        };

        let sub_node_vcn = if flags.contains(IndexValueFlags::IS_BRANCH_NODE) {
            if payload.len() < 8 {
                return Err(Error::InvalidData {
                    message: "branch node index value missing sub-node VCN".to_string(),
                });
            }
            let tail = &payload[payload.len() - 8..];
            Some(u64::from_le_bytes(tail.try_into().expect("len=8")))
        } else {
            None
        };

        Ok(Self {
            file_reference_raw,
            size,
            key_data_size,
            flags,
            file_name,
            sub_node_vcn,
        })
    }
}

#[derive(Debug, Clone)]
pub struct IndexNode {
    pub header: IndexNodeHeader,
    pub values: Vec<IndexValue>,
}

impl IndexNode {
    pub fn parse_from_node_start(buf: &[u8], base_offset: u64, node_start: usize) -> Result<Self> {
        let node_buf = buf.get(node_start..).ok_or_else(|| Error::InvalidData {
            message: "index node start out of bounds".to_string(),
        })?;

        let mut r = Reader::with_base_offset(node_buf, base_offset + node_start as u64);
        let header = IndexNodeHeader::parse(&mut r)?;

        if header.size == 0 {
            return Ok(Self {
                header,
                values: Vec::new(),
            });
        }

        let values_start = node_start + header.index_values_offset as usize;
        let values_end = node_start + header.size as usize;
        if values_end > buf.len() || values_start > values_end {
            return Err(Error::InvalidData {
                message: format!(
                    "index values region out of bounds: start={values_start} end={values_end} buf_len={}",
                    buf.len()
                ),
            });
        }

        let mut values = Vec::new();
        let mut cur = values_start;

        while cur < values_end {
            let mut vr = Reader::with_base_offset(
                buf.get(cur..values_end).ok_or_else(|| Error::InvalidData {
                    message: "index value slice out of bounds".to_string(),
                })?,
                base_offset + cur as u64,
            );
            let value = IndexValue::parse(&mut vr)?;
            let value_size = value.size as usize;
            values.push(value.clone());

            if value.is_last() {
                break;
            }

            if value_size == 0 {
                break;
            }
            cur = cur.saturating_add(value_size);
        }

        Ok(Self { header, values })
    }
}

#[derive(Debug, Clone)]
pub struct IndexRoot {
    pub root_header: IndexRootHeader,
    pub node: IndexNode,
}

impl IndexRoot {
    pub fn parse(buf: &[u8], base_offset: u64) -> Result<Self> {
        let mut r = Reader::with_base_offset(buf, base_offset);
        let root_header = IndexRootHeader::parse(&mut r)?;

        // The node header begins immediately after the root header (16 bytes).
        let node_start = 16;
        let node = IndexNode::parse_from_node_start(buf, base_offset, node_start)?;

        Ok(Self { root_header, node })
    }
}

/// Applies USA fixups in-place to an INDX record buffer.
pub fn apply_index_record_fixups(record: &mut [u8]) -> Result<()> {
    if record.len() < 24 {
        return Err(Error::InvalidData {
            message: "index record too small".to_string(),
        });
    }

    let fixup_values_offset = u16::from_le_bytes(record[4..6].try_into().expect("len=2"));
    let number_of_fixup_values = u16::from_le_bytes(record[6..8].try_into().expect("len=2"));

    // Best-effort: apply fixups even if the update-sequence value does not match.
    // We still error on structurally invalid/corrupt fixup arrays.
    match apply_update_sequence_array_fixups_in_place(
        record,
        fixup_values_offset,
        number_of_fixup_values,
    ) {
        Ok(_) => Ok(()),
        Err(mft::err::Error::Any { detail }) => Err(Error::InvalidData { message: detail }),
        Err(e) => Err(Error::InvalidData {
            message: e.to_string(),
        }),
    }
}
