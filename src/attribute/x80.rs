use crate::utils;
use serde::ser;

/// $Data Attribute
#[derive(Clone, Copy, Debug)]
pub struct DataAttr<'a>(&'a [u8]);

impl<'a> DataAttr<'a> {
    pub fn from_slice(data: &'a [u8]) -> DataAttr<'a> {
        DataAttr(data)
    }

    pub fn data(&self) -> &'a [u8] {
        self.0
    }
}

impl ser::Serialize for DataAttr<'_> {
    fn serialize<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&utils::to_hex_string(self.0))
    }
}
