use std::io::{Read, Seek};

use crate::err::{Error, Result};
use serde::Serialize;
use winstructs::guid::Guid;

/// $Data Attribute
#[derive(Serialize, Clone, Debug)]
pub struct ObjectIdAttr {
    /// Unique Id assigned to file
    pub object_id: Guid,
    /// Volume where file was created
    pub birth_volume_id: Option<Guid>,
    /// Original Object Id of file
    pub birth_object_id: Option<Guid>,
    /// Domain in which object was created
    pub domain_id: Option<Guid>,
}

impl ObjectIdAttr {
    /// Data size should be either 16 or 64
    pub fn from_stream<S: Read + Seek>(stream: &mut S, data_size: usize) -> Result<ObjectIdAttr> {
        let object_id = Guid::from_reader(stream).map_err(Error::failed_to_read_guid)?;
        let (birth_volume_id, birth_object_id, domain_id) = if data_size == 64 {
            let g1 = Guid::from_reader(stream).map_err(Error::failed_to_read_guid)?;
            let g2 = Guid::from_reader(stream).map_err(Error::failed_to_read_guid)?;
            let g3 = Guid::from_reader(stream).map_err(Error::failed_to_read_guid)?;
            (Some(g1), Some(g2), Some(g3))
        } else {
            (None, None, None)
        };

        Ok(ObjectIdAttr {
            object_id,
            birth_volume_id,
            birth_object_id,
            domain_id,
        })
    }
}
