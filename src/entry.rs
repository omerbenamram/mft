use errors::{MftError};
use attribute;
use utils;
use attr_x10;
use attr_x30;
use rwinstructs::reference::{MftReference};
use rwinstructs::serialize::{serialize_u64};
use byteorder::{ReadBytesExt, LittleEndian};
use serde::{ser};
use std::io::Cursor;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::mem;

//https://github.com/libyal/libfsntfs/blob/master/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc#5-the-master-file-table-mft

bitflags! {
    pub flags EntryFlags: u16 {
        const ALLOCATED     = 0x01,
        const INDEX_PRESENT = 0x02,
        const UNKNOWN_1     = 0x04,
        const UNKNOWN_2     = 0x08
    }
}
pub fn serialize_entry_flags<S>(&item: &EntryFlags, serializer: S) -> Result<S::Ok, S::Error>
    where S: ser::Serializer
{
    serializer.serialize_str(&format!("{:?}", item))
}

#[derive(Serialize, Debug)]
pub struct EntryHeader{
    pub signature: u32,
    pub usa_offset: u16,
    pub usa_size: u16,
    #[serde(serialize_with = "serialize_u64")]
    pub logfile_sequence_number: u64,
    pub sequence: u16,
    pub hard_link_count: u16,
    pub fst_attr_offset: u16,
    #[serde(serialize_with = "serialize_entry_flags")]
    pub flags: EntryFlags,
    pub entry_size_real: u32,
    pub entry_size_allocated: u32,
    pub base_reference: MftReference,
    pub next_attribute_id: u16,
    #[serde(skip_serializing)]
    pub padding: Option<u16>,
    pub record_number: Option<u32>,
    pub update_sequence_value: u32
}
impl EntryHeader{
    pub fn new<R: Read>(mut reader: R, entry: Option<u64>) -> Result<EntryHeader,MftError> {
        let mut entry_header: EntryHeader = unsafe {
            mem::zeroed()
        };

        entry_header.signature = reader.read_u32::<LittleEndian>()?;
        if entry_header.signature != 1162627398 {
            return Err(
                MftError::invalid_entry_signature(
                    format!("Bad signature: {:04X}",entry_header.signature)
                )
            );
        }

        entry_header.usa_offset = reader.read_u16::<LittleEndian>()?;
        entry_header.usa_size = reader.read_u16::<LittleEndian>()?;
        entry_header.logfile_sequence_number = reader.read_u64::<LittleEndian>()?;
        entry_header.sequence = reader.read_u16::<LittleEndian>()?;
        entry_header.hard_link_count = reader.read_u16::<LittleEndian>()?;
        entry_header.fst_attr_offset = reader.read_u16::<LittleEndian>()?;
        entry_header.flags = EntryFlags::from_bits_truncate(
            reader.read_u16::<LittleEndian>()?
        );
        entry_header.entry_size_real = reader.read_u32::<LittleEndian>()?;
        entry_header.entry_size_allocated = reader.read_u32::<LittleEndian>()?;
        entry_header.base_reference = MftReference(reader.read_u64::<LittleEndian>()?);
        entry_header.next_attribute_id = reader.read_u16::<LittleEndian>()?;

        if entry_header.usa_offset == 48 {
            entry_header.padding = Some(reader.read_u16::<LittleEndian>()?);
            entry_header.record_number = Some(reader.read_u32::<LittleEndian>()?);
        } else {
            panic!(
                "Unhandled update sequence array offset: {}",
                entry_header.usa_offset
            )
        }

        Ok(entry_header)
    }
}

#[derive(Serialize, Debug)]
pub struct MftEntry{
    pub header: EntryHeader,
    pub attr_standard_info: Option<Vec<attr_x10::StandardInformationAttribute>>,
    pub attr_filename: Option<Vec<attr_x30::FileNameAttribute>>
}
impl MftEntry{
    pub fn new(mut buffer: Vec<u8>, entry: Option<u64>) -> Result<MftEntry,MftError> {
        let mut mft_entry: MftEntry = unsafe {
            mem::zeroed()
        };

        // Get Header
        mft_entry.header = EntryHeader::new(
            buffer.as_slice(),
            entry
        )?;

        // Fixup buffer
        mft_entry.buffer_fixup(
            &mut buffer
        );

        mft_entry.read_attributes(
            Cursor::new(buffer.as_slice())
        )?;

        Ok(mft_entry)
    }

    pub fn buffer_fixup(&self, mut buffer: &mut[u8]){
        // start offset (skip the first value (+2))
        let so = (self.header.usa_offset + 2) as usize;
        // array length
        let al = (self.header.usa_size - 1 * 2) as usize;

        let fixup_values = &buffer[
            (self.header.usa_offset + 2) as usize..
            ((self.header.usa_offset + 2)+((self.header.usa_size - 1) * 2)) as usize
        ].to_vec();

        for i in 0..(self.header.usa_size-1) {
            let ofs = (i * 512) as usize;
            *buffer.get_mut(ofs + 510).unwrap() = fixup_values[i as usize];
            *buffer.get_mut(ofs + 511).unwrap() = fixup_values[(i+1) as usize];
        }
    }

    fn read_attributes<Rs: Read+Seek>(&mut self, mut buffer: Rs) -> Result<u32,MftError>{
        let mut current_offset = buffer.seek(
            SeekFrom::Start(self.header.fst_attr_offset as u64)
        )?;
        let attr_count: u32 = 0;

        while true {
            let attribute_header = attribute::AttributeHeader::new(
                &mut buffer
            )?;

            match attribute_header.attribute_type {
                0x10 => {
                    let si_attr = attr_x10::StandardInformationAttribute::new(&mut buffer)?;

                    if self.attr_standard_info.is_none(){
                        self.attr_standard_info = Some(Vec::new());
                    }

                    self.attr_standard_info.as_mut().unwrap().push(si_attr);
                },
                0x30 => {
                    let fn_attr = attr_x30::FileNameAttribute::new(&mut buffer)?;
                    if self.attr_filename.is_none(){
                        self.attr_filename = Some(Vec::new());
                    }

                    self.attr_filename.as_mut().unwrap().push(fn_attr);
                },
                0xFFFFFFFF => {
                    // println!("END OF ATTRIBUTES");
                    break;
                },
                _ => {
                    // println!(
                    //     "UNHANDLED ATTRIBUTE: 0x{:04X} at offset {}",
                    //     attribute_header.attribute_type,
                    //     current_offset
                    // );
                }
            }

            current_offset = buffer.seek(
                SeekFrom::Start(current_offset + attribute_header.attribute_size as u64)
            )?;
        }
        Ok(attr_count)
    }
}

#[cfg(test)]
mod tests {
    use super::EntryHeader;

    #[test]
    fn mft_header_test_01() {
        let header_buffer: &[u8] = &[
            0x46,0x49,0x4C,0x45,0x30,0x00,0x03,0x00,0xCC,0xB3,0x7D,0x84,0x0C,0x00,0x00,0x00,
            0x05,0x00,0x01,0x00,0x38,0x00,0x05,0x00,0x48,0x03,0x00,0x00,0x00,0x04,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x06,0x00,0x00,0x00,0xD5,0x95,0x00,0x00,
            0x53,0x57,0x81,0x37,0x00,0x00,0x00,0x00
        ];

        let entry_header = match EntryHeader::new(header_buffer,None) {
            Ok(entry_header) => entry_header,
            Err(error) => panic!(error)
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
        assert_eq!(entry_header.record_number, Some(38357));
    }
}
