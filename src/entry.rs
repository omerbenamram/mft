use crate::attr_x10::StandardInfoAttr;
use crate::attr_x30::FileNameAttr;
use crate::attribute;
use crate::enumerator::PathMapping;
use crate::errors::MftError;
use crate::mft::MftHandler;
use std::collections::BTreeMap;

use rwinstructs::reference::MftReference;

use byteorder::{LittleEndian, ReadBytesExt};

use bitflags::bitflags;
use serde::{ser, Serialize};
use std::io::Cursor;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::mem;

//https://github.com/libyal/libfsntfs/blob/master/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc#5-the-master-file-table-mft

bitflags! {
    struct EntryFlags: u16 {
        const ALLOCATED     = 0x01;
        const INDEX_PRESENT = 0x02;
        const UNKNOWN_1     = 0x04;
        const UNKNOWN_2     = 0x08;
    }
}
pub fn serialize_entry_flags<S>(item: &EntryFlags, serializer: S) -> Result<S::Ok, S::Error>
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
    pub padding: Option<u16>,
    #[serde(skip_serializing)]
    pub record_number: u64,
    pub update_sequence_value: u32,
    pub entry_reference: MftReference,
}
impl EntryHeader {
    pub fn new<R: Read>(mut reader: R, entry: u64) -> Result<EntryHeader, MftError> {
        let mut entry_header: EntryHeader = unsafe { mem::zeroed() };

        entry_header.signature = reader.read_u32::<LittleEndian>()?;
        if entry_header.signature != 1162627398 {
            return Err(MftError::invalid_entry_signature(format!(
                "Bad signature: {:04X}",
                entry_header.signature
            )));
        }

        entry_header.usa_offset = reader.read_u16::<LittleEndian>()?;
        entry_header.usa_size = reader.read_u16::<LittleEndian>()?;
        entry_header.logfile_sequence_number = reader.read_u64::<LittleEndian>()?;
        entry_header.sequence = reader.read_u16::<LittleEndian>()?;
        entry_header.hard_link_count = reader.read_u16::<LittleEndian>()?;
        entry_header.fst_attr_offset = reader.read_u16::<LittleEndian>()?;
        entry_header.flags = EntryFlags::from_bits_truncate(reader.read_u16::<LittleEndian>()?);
        entry_header.entry_size_real = reader.read_u32::<LittleEndian>()?;
        entry_header.entry_size_allocated = reader.read_u32::<LittleEndian>()?;
        entry_header.base_reference = MftReference(reader.read_u64::<LittleEndian>()?);
        entry_header.next_attribute_id = reader.read_u16::<LittleEndian>()?;

        if entry_header.usa_offset == 48 {
            entry_header.padding = Some(reader.read_u16::<LittleEndian>()?);
            entry_header.record_number = reader.read_u32::<LittleEndian>()? as u64;
        } else {
            entry_header.record_number = entry as u64;
            panic!(
                "Unhandled update sequence array offset: {}",
                entry_header.usa_offset
            )
        }

        entry_header.entry_reference = MftReference::get_from_entry_and_seq(
            entry_header.record_number as u64,
            entry_header.sequence,
        );

        Ok(entry_header)
    }
}

#[derive(Serialize, Debug)]
pub struct MftEntry {
    pub header: EntryHeader,
    pub attributes: BTreeMap<String, Vec<attribute::MftAttribute>>,
}
impl MftEntry {
    pub fn new(mut buffer: Vec<u8>, entry: u64) -> Result<MftEntry, MftError> {
        // Get Header
        let entry_header = EntryHeader::new(buffer.as_slice(), entry)?;

        let mut mft_entry = MftEntry {
            header: entry_header,
            attributes: BTreeMap::new(),
        };

        // Fixup buffer
        mft_entry.buffer_fixup(&mut buffer);

        mft_entry.read_attributes(Cursor::new(buffer.as_slice()))?;

        Ok(mft_entry)
    }

    pub fn is_allocated(&self) -> bool {
        if self.header.flags.bits() & 0x01 != 0 {
            true
        } else {
            false
        }
    }

    pub fn is_dir(&self) -> bool {
        if self.header.flags.bits() & 0x02 != 0 {
            true
        } else {
            false
        }
    }

    pub fn get_pathmap(&self) -> Option<PathMapping> {
        match self.attributes.get("0x0030") {
            Some(fn_attr_list) => {
                for attribute in fn_attr_list {
                    match attribute.content {
                        attribute::AttributeContent::AttrX30(ref attrib) => {
                            if attrib.namespace != 2 {
                                return Some(PathMapping {
                                    name: attrib.name.clone(),
                                    parent: MftReference(attrib.parent.0),
                                });
                            }
                        }
                        _ => {}
                    }
                }
            }
            None => {}
        }

        None
    }

    pub fn buffer_fixup(&self, buffer: &mut [u8]) {
        let fixup_values = &buffer[(self.header.usa_offset + 2) as usize
            ..((self.header.usa_offset + 2) + ((self.header.usa_size - 1) * 2)) as usize]
            .to_vec();

        for i in 0..(self.header.usa_size - 1) {
            let ofs = (i * 512) as usize;
            *buffer.get_mut(ofs + 510).unwrap() = fixup_values[i as usize];
            *buffer.get_mut(ofs + 511).unwrap() = fixup_values[(i + 1) as usize];
        }
    }

    fn read_attributes<Rs: Read + Seek>(&mut self, mut buffer: Rs) -> Result<u32, MftError> {
        let mut current_offset =
            buffer.seek(SeekFrom::Start(self.header.fst_attr_offset as u64))?;

        let attr_count: u32 = 0;

        loop {
            let attribute_header = attribute::AttributeHeader::new(&mut buffer)?;

            if attribute_header.attribute_type == 0xFFFFFFFF {
                break;
            }

            match attribute_header.residential_header {
                attribute::ResidentialHeader::Resident(ref header) => {
                    // Create buffer for raw attribute content
                    let mut content_buffer = vec![0; header.data_size as usize];

                    // read into content buffer
                    buffer.read_exact(&mut content_buffer).unwrap();

                    // Create attribute content to parse buffer into
                    let mut attr_content: attribute::AttributeContent = unsafe { mem::zeroed() };

                    // Get attribute contents
                    match attribute_header.attribute_type {
                        0x10 => {
                            let attr = StandardInfoAttr::new(content_buffer.as_slice())?;

                            attr_content = attribute::AttributeContent::AttrX10(attr);
                        }
                        0x30 => {
                            let attr = FileNameAttr::new(content_buffer.as_slice())?;

                            attr_content = attribute::AttributeContent::AttrX30(attr);
                        }
                        _ => {
                            attr_content = attribute::AttributeContent::Raw(
                                attribute::RawAttribute(content_buffer),
                            );
                        }
                    }

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
                current_offset + attribute_header.attribute_size as u64,
            ))?;
        }

        Ok(attr_count)
    }

    pub fn set_attribute(&mut self, attribute: attribute::MftAttribute) {
        // This could maybe use some refactoring??
        // Check if attribute type is already in mapping
        let attr_type = format!("0x{:04X}", attribute.header.attribute_type);
        if self.attributes.contains_key(&attr_type) {
            // We already have a list for this attribute, get mut ref
            if let Some(attr_list) = self.attributes.get_mut(&attr_type) {
                // append the attribute to list
                attr_list.push(attribute);
            }
        } else {
            // Create new attribute list
            let mut attr_list: Vec<attribute::MftAttribute> = Vec::new();
            // Insert value into list
            attr_list.push(attribute);
            // Set attribute list to key of attrib type
            self.attributes.insert(attr_type, attr_list);
        }
    }

    pub fn set_fullnames(&mut self, mft_handler: &mut MftHandler) {
        if self.attributes.contains_key("0x0030") {
            if let Some(attr_list) = self.attributes.get_mut("0x0030") {
                for attribute in attr_list.iter_mut() {
                    // Check if resident content
                    match attribute.content {
                        attribute::AttributeContent::AttrX30(ref mut attrib) => {
                            // Get fullpath
                            let fullpath = mft_handler.get_fullpath(attrib.parent);
                            // Set fullname
                            let fullname = fullpath + "/" + attrib.name.as_str();
                            // Set attribute to fullname
                            attrib.fullname = Some(fullname);
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::EntryHeader;

    #[test]
    fn mft_header_test_01() {
        let header_buffer: &[u8] = &[
            0x46, 0x49, 0x4C, 0x45, 0x30, 0x00, 0x03, 0x00, 0xCC, 0xB3, 0x7D, 0x84, 0x0C, 0x00,
            0x00, 0x00, 0x05, 0x00, 0x01, 0x00, 0x38, 0x00, 0x05, 0x00, 0x48, 0x03, 0x00, 0x00,
            0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00,
            0x00, 0x00, 0xD5, 0x95, 0x00, 0x00, 0x53, 0x57, 0x81, 0x37, 0x00, 0x00, 0x00, 0x00,
        ];

        let entry_header = match EntryHeader::new(header_buffer, 0) {
            Ok(entry_header) => entry_header,
            Err(error) => panic!(error),
        };

        assert_eq!(entry_header.signature, 1162627398);
        assert_eq!(entry_header.usa_offset, 48);
        assert_eq!(entry_header.usa_size, 3);
        assert_eq!(entry_header.logfile_sequence_number, 53762438092);
        assert_eq!(entry_header.sequence, 5);
        assert_eq!(entry_header.hard_link_count, 1);
        assert_eq!(entry_header.fst_attr_offset, 56);
        assert_eq!(entry_header.flags.bits(), 5);
        assert_eq!(entry_header.entry_size_real, 840);
        assert_eq!(entry_header.entry_size_allocated, 1024);
        assert_eq!(entry_header.base_reference.0, 0);
        assert_eq!(entry_header.next_attribute_id, 6);
        assert_eq!(entry_header.padding, Some(0));
        assert_eq!(entry_header.record_number, 38357);
    }
}
