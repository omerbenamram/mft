use crate::err::{self, Result};
use crate::{utils, ReadSeek};
use serde::ser;
use snafu::ResultExt;

/// $Data Attribute
#[derive(Clone, Debug)]
pub struct DataAttr(Vec<u8>);

impl DataAttr {
    pub fn from_stream<S: ReadSeek>(stream: &mut S, data_size: usize) -> Result<DataAttr> {
        let mut data = vec![0_u8; data_size];

        stream.read_exact(&mut data).context(err::IoError)?;

        Ok(DataAttr(data))
    }

    pub fn data(&self) -> &[u8] {
        &self.0
    }
}

impl ser::Serialize for DataAttr {
    fn serialize<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&utils::to_hex_string(&self.0).to_string())
    }
}
