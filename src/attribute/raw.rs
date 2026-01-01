use crate::attribute::MftAttributeType;
use crate::utils;
use serde::{Serialize, ser};

/// Placeholder attribute for currently unparsed attributes.
#[derive(Serialize, Clone, Debug)]
pub struct RawAttribute<'a> {
    pub attribute_type: MftAttributeType,
    #[serde(serialize_with = "data_as_hex")]
    pub data: &'a [u8],
}

impl<'a> RawAttribute<'a> {
    pub fn from_slice(attribute_type: MftAttributeType, data: &'a [u8]) -> Self {
        RawAttribute {
            attribute_type,
            data,
        }
    }
}

fn data_as_hex<S>(x: &[u8], s: S) -> std::result::Result<S::Ok, S::Error>
where
    S: ser::Serializer,
{
    s.serialize_str(&utils::to_hex_string(x))
}
