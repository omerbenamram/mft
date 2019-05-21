use crate::err::{self, Result};
use crate::ReadSeek;
use serde::Serialize;
use snafu::ResultExt;
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
    pub fn from_stream<S: ReadSeek>(stream: &mut S, data_size: usize) -> Result<ObjectIdAttr> {
        let object_id = Guid::from_stream(stream).context(err::FailedToReadGuid)?;
        let (birth_volume_id, birth_object_id, domain_id) = if data_size == 64 {
            let g1 = Guid::from_stream(stream).context(err::FailedToReadGuid)?;
            let g2 = Guid::from_stream(stream).context(err::FailedToReadGuid)?;
            let g3 = Guid::from_stream(stream).context(err::FailedToReadGuid)?;
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
