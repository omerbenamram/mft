use crate::utils;
use serde::ser;

/// Placeholder attribute for currently unparsed attributes.
#[derive(Clone, Debug)]
pub struct RawAttribute(pub Vec<u8>);

impl ser::Serialize for RawAttribute {
    fn serialize<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&utils::to_hex_string(&self.0).to_string())
    }
}
