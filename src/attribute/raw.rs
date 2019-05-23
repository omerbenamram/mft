use crate::attribute::MftAttributeType;
use crate::err::{self, Result};
use crate::{utils, ReadSeek};
use serde::{ser, Serialize};
use snafu::ResultExt;

/// Placeholder attribute for currently unparsed attributes.
#[derive(Serialize, Clone, Debug)]
pub struct RawAttribute {
    pub attribute_type: MftAttributeType,
    #[serde(serialize_with = "data_as_hex")]
    pub data: Vec<u8>,
}

impl RawAttribute {
    pub fn from_stream<S: ReadSeek>(
        stream: &mut S,
        attribute_type: MftAttributeType,
        data_size: usize,
    ) -> Result<Self> {
        let mut data = vec![0_u8; data_size];

        stream.read_exact(&mut data).context(err::IoError)?;

        Ok(RawAttribute {
            attribute_type,
            data,
        })
    }
}

fn data_as_hex<S>(x: &[u8], s: S) -> std::result::Result<S::Ok, S::Error>
where
    S: ser::Serializer,
{
    s.serialize_str(&utils::to_hex_string(x))
}
