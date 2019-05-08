use crate::err::{self, Result};

use crate::attr_x10::StandardInfoAttr;
use crate::attr_x30::FileNameAttr;
use crate::attribute;
use crate::enumerator::PathMapping;
use crate::mft::MftHandler;
use snafu::ensure;

use std::collections::BTreeMap;

use winstructs::reference::MftReference;

use byteorder::{LittleEndian, ReadBytesExt};

use bitflags::bitflags;
use serde::{ser, Serialize};

use std::io::Cursor;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;

//https://github.com/libyal/libfsntfs/blob/master/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc#5-the-master-file-table-mft

bitflags! {
    pub struct EntryFlags: u16 {
        const ALLOCATED     = 0x01;
        const INDEX_PRESENT = 0x02;
        const UNKNOWN_1     = 0x04;
        const UNKNOWN_2     = 0x08;
    }
}
pub fn serialize_entry_flags<S>(
    item: &EntryFlags,
    serializer: S,
) -> ::std::result::Result<S::Ok, S::Error>
where
    S: ser::Serializer,
{
    serializer.serialize_str(&format!("{:?}", item))
}

#[derive(Serialize, Debug)]
pub struct EntryHeader {
    pub signature: u32,
    #[serde(skip_serializing)]
    pub usa_offset: u16,
    #[serde(skip_serializing)]
    pub usa_size: u16,
    pub logfile_sequence_number: u64,
    #[serde(skip_serializing)]
    pub sequence: u16,
    pub hard_link_count: u16,
    #[serde(skip_serializing)]
    pub fst_attr_offset: u16,
    #[serde(serialize_with = "serialize_entry_flags")]
    pub flags: EntryFlags,
    #[serde(skip_serializing)]
    pub entry_size_real: u32,
    #[serde(skip_serializing)]
    pub entry_size_allocated: u32,
    pub base_reference: MftReference,
    #[serde(skip_serializing)]
    pub next_attribute_id: u16,
    #[serde(skip_serializing)]
    pub record_number: u64,
    pub update_sequence_value: u32,
    pub entry_reference: MftReference,
}

impl EntryHeader {
    pub fn from_reader<R: Read>(reader: &mut R, _entry: u64) -> Result<EntryHeader> {
        let signature = reader.read_u32::<LittleEndian>()?;

        ensure!(
            signature == 1_162_627_398,
            err::InvalidEntrySignature { bad_sig: signature }
        );

        let usa_offset = reader.read_u16::<LittleEndian>()?;
        let usa_size = reader.read_u16::<LittleEndian>()?;
        let logfile_sequence_number = reader.read_u64::<LittleEndian>()?;
        let sequence = reader.read_u16::<LittleEndian>()?;
        let hard_link_count = reader.read_u16::<LittleEndian>()?;
        let fst_attr_offset = reader.read_u16::<LittleEndian>()?;
        let flags = EntryFlags::from_bits_truncate(reader.read_u16::<LittleEndian>()?);
        let entry_size_real = reader.read_u32::<LittleEndian>()?;
        let entry_size_allocated = reader.read_u32::<LittleEndian>()?;
        let base_reference = MftReference(reader.read_u64::<LittleEndian>()?);
        let next_attribute_id = reader.read_u16::<LittleEndian>()?;

        ensure!(
            usa_offset == 48,
            err::InvalidUsaOffset { offset: usa_offset }
        );

        let _padding = reader.read_u16::<LittleEndian>()?;
        let record_number = u64::from(reader.read_u32::<LittleEndian>()?);

        let entry_reference = MftReference::get_from_entry_and_seq(record_number as u64, sequence);

        Ok(EntryHeader {
            signature,
            usa_offset,
            usa_size,
            logfile_sequence_number,
            sequence,
            hard_link_count,
            fst_attr_offset,
            flags,
            entry_size_real,
            entry_size_allocated,
            base_reference,
            next_attribute_id,
            record_number,
            update_sequence_value: 0,
            entry_reference,
        })
    }
}

#[derive(Serialize, Debug)]
pub struct MftEntry {
    pub header: EntryHeader,
    pub attributes: BTreeMap<String, Vec<attribute::MftAttribute>>,
}
impl MftEntry {
    pub fn new(buffer: Vec<u8>, entry: u64) -> Result<MftEntry> {
        let mut cursor = Cursor::new(&buffer);
        // Get Header
        let entry_header = EntryHeader::from_reader(&mut cursor, entry)?;

        let mut mft_entry = MftEntry {
            header: entry_header,
            attributes: BTreeMap::new(),
        };

        mft_entry.read_attributes(&mut cursor)?;

        Ok(mft_entry)
    }

    pub fn is_allocated(&self) -> bool {
        self.header.flags.bits() & 0x01 != 0
    }

    pub fn is_dir(&self) -> bool {
        self.header.flags.bits() & 0x02 != 0
    }

    pub fn get_pathmap(&self) -> Option<PathMapping> {
        if let Some(fn_attr_list) = self.attributes.get("0x0030") {
            for attribute in fn_attr_list {
                if let attribute::AttributeContent::AttrX30(ref attrib) = attribute.content {
                    if attrib.namespace != 2 {
                        return Some(PathMapping {
                            name: attrib.name.clone(),
                            parent: MftReference(attrib.parent.0),
                        });
                    }
                }
            }
        }

        None
    }

    //    // TODO: what is this function?
    //    pub fn buffer_fixup(&self, buffer: &mut [u8]) {
    //        let fixup_values = &buffer[(self.header.usa_offset + 2) as usize
    //            ..((self.header.usa_offset + 2) + ((self.header.usa_size - 1) * 2)) as usize]
    //            .to_vec();
    //
    //        for i in 0..(self.header.usa_size - 1) {
    //            let ofs = (i * 512) as usize;
    //            *buffer.get_mut(ofs + 510).unwrap() = fixup_values[i as usize];
    //            *buffer.get_mut(ofs + 511).unwrap() = fixup_values[(i + 1) as usize];
    //        }
    //    }

    fn read_attributes<S: Read + Seek>(&mut self, buffer: &mut S) -> Result<u32> {
        let mut current_offset =
            buffer.seek(SeekFrom::Start(u64::from(self.header.fst_attr_offset)))?;

        let attr_count: u32 = 0;

        loop {
            let attribute_header = attribute::AttributeHeader::from_stream(buffer)?;

            if attribute_header.attribute_type == 0xFFFF_FFFF {
                break;
            }

            match attribute_header.residential_header {
                attribute::ResidentialHeader::Resident(ref header) => {
                    // Create attribute content to parse buffer into
                    // Get attribute contents
                    let attr_content = match attribute_header.attribute_type {
                        0x10 => attribute::AttributeContent::AttrX10(
                            StandardInfoAttr::from_reader(buffer)?,
                        ),
                        0x30 => {
                            attribute::AttributeContent::AttrX30(FileNameAttr::from_reader(buffer)?)
                        }
                        _ => {
                            let mut content_buffer = vec![0; header.data_size as usize];
                            buffer.read_exact(&mut content_buffer)?;

                            attribute::AttributeContent::Raw(attribute::RawAttribute(
                                content_buffer,
                            ))
                        }
                    };

                    self.set_attribute(attribute::MftAttribute {
                        header: attribute_header.clone(),
                        content: attr_content,
                    });
                }
                attribute::ResidentialHeader::NonResident(_) => {
                    // No content, so push header into attributes
                    self.set_attribute(attribute::MftAttribute {
                        header: attribute_header.clone(),
                        content: attribute::AttributeContent::None,
                    });
                }
                attribute::ResidentialHeader::None => {
                    // Not sure about this...
                }
            }

            current_offset = buffer.seek(SeekFrom::Start(
                current_offset + u64::from(attribute_header.attribute_size),
            ))?;
        }

        Ok(attr_count)
    }

    pub fn set_attribute(&mut self, attribute: attribute::MftAttribute) {
        // This could maybe use some refactoring??
        // Check if attribute type is already in mapping
        let attr_type = format!("0x{:04X}", attribute.header.attribute_type);
        self.attributes
            .entry(attr_type)
            .or_insert_with(Vec::new)
            .push(attribute);
    }

    pub fn set_full_names(&mut self, mft_handler: &mut MftHandler) {
        if self.attributes.contains_key("0x0030") {
            if let Some(attr_list) = self.attributes.get_mut("0x0030") {
                for attribute in attr_list.iter_mut() {
                    // Check if resident content
                    if let attribute::AttributeContent::AttrX30(ref mut attrib) = attribute.content
                    {
                        // Get fullpath
                        let fullpath = mft_handler.get_fullpath(attrib.parent);
                        // Set fullname
                        let fullname = fullpath + "/" + attrib.name.as_str();
                        // Set attribute to fullname
                        attrib.fullname = Some(fullname);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::EntryHeader;
    use std::io::Cursor;

    #[test]
    fn mft_header_test_01() {
        let header_buffer: &[u8] = &[
            0x46, 0x49, 0x4C, 0x45, 0x30, 0x00, 0x03, 0x00, 0xCC, 0xB3, 0x7D, 0x84, 0x0C, 0x00,
            0x00, 0x00, 0x05, 0x00, 0x01, 0x00, 0x38, 0x00, 0x05, 0x00, 0x48, 0x03, 0x00, 0x00,
            0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00,
            0x00, 0x00, 0xD5, 0x95, 0x00, 0x00, 0x53, 0x57, 0x81, 0x37, 0x00, 0x00, 0x00, 0x00,
        ];

        let entry_header = EntryHeader::from_reader(&mut Cursor::new(header_buffer), 0).unwrap();

        assert_eq!(entry_header.signature, 1_162_627_398);
        assert_eq!(entry_header.usa_offset, 48);
        assert_eq!(entry_header.usa_size, 3);
        assert_eq!(entry_header.logfile_sequence_number, 53_762_438_092);
        assert_eq!(entry_header.sequence, 5);
        assert_eq!(entry_header.hard_link_count, 1);
        assert_eq!(entry_header.fst_attr_offset, 56);
        assert_eq!(entry_header.flags.bits(), 5);
        assert_eq!(entry_header.entry_size_real, 840);
        assert_eq!(entry_header.entry_size_allocated, 1024);
        assert_eq!(entry_header.base_reference.0, 0);
        assert_eq!(entry_header.next_attribute_id, 6);
        assert_eq!(entry_header.record_number, 38357);
    }
}
