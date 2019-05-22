use crate::err::Result;
use crate::ReadSeek;
use byteorder::{LittleEndian, ReadBytesExt};

use serde::Serialize;

/// $IndexRoot Attribute
#[derive(Serialize, Clone, Debug)]
pub struct IndexRootAttr {
    /// Unique Id assigned to file
    pub attribute_type: u32,
    /// Collation rule used to sort the index entries.
    /// If type is $FILENAME, this must be COLLATION_FILENAME
    pub collation_rule: u32,
    /// The index entry size
    pub index_entry_size: u32,
    /// The index entry number of cluster blocks
    pub index_entry_number_of_cluster_blocks: u32,
}

impl IndexRootAttr {
    /// Data size should be either 16 or 64
    pub fn from_stream<S: ReadSeek>(stream: &mut S) -> Result<IndexRootAttr> {
        Ok(IndexRootAttr {
            attribute_type: stream.read_u32::<LittleEndian>()?,
            collation_rule: stream.read_u32::<LittleEndian>()?,
            index_entry_size: stream.read_u32::<LittleEndian>()?,
            index_entry_number_of_cluster_blocks: stream.read_u32::<LittleEndian>()?,
        })
    }
}
