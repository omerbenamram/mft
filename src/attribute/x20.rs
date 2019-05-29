use crate::err::{self, Result};
use crate::ReadSeek;
use log::trace;
use snafu::OptionExt;

use byteorder::{LittleEndian, ReadBytesExt};
use encoding::all::UTF_16LE;
use encoding::{DecoderTrap, Encoding};

use serde::Serialize;

use snafu::ResultExt;
use std::io::SeekFrom;
use winstructs::ntfs::mft_reference::MftReference;

#[derive(Serialize, Clone, Debug)]
pub struct AttributeListAttr {
    pub attribute_type: u32,
    pub record_length: u16,
    pub first_vcn: u64,
    pub base_reference: MftReference,
    pub attribute_id: u16,
    pub name: String,
}

impl AttributeListAttr {
    pub fn from_stream<S: ReadSeek>(stream: &mut S) -> Result<AttributeListAttr> {
        let start_offset = stream.tell()?;

        trace!("Offset {}: AttributeListAttr", start_offset);

        let attribute_type = stream.read_u32::<LittleEndian>()?;
        let record_length = stream.read_u16::<LittleEndian>()?;
        let name_length = stream.read_u8()?;
        let name_offset = stream.read_u8()?;
        let first_vcn = stream.read_u64::<LittleEndian>()?;
        let base_reference =
            MftReference::from_reader(stream).context(err::FailedToReadMftReference)?;
        let attribute_id = stream.read_u16::<LittleEndian>()?;

        let name = if name_length > 0 {
            stream.seek(SeekFrom::Start(start_offset + u64::from(name_offset)))?;

            let mut name_buffer = vec![0; (name_length as usize * 2) as usize];
            stream.read_exact(&mut name_buffer)?;

            match UTF_16LE.decode(&name_buffer, DecoderTrap::Ignore) {
                Ok(s) => s,
                Err(_e) => return err::InvalidFilename {}.fail(),
            }
        } else {
            String::new()
        };

        Ok(AttributeListAttr {
            attribute_type,
            record_length,
            first_vcn,
            base_reference,
            attribute_id,
            name,
        })
    }
}
