use byteorder::{ByteOrder, LittleEndian};
use serde::Serialize;

/// $EA_INFORMATION Attribute: the sizes of the file's extended attributes in `$EA`.
/// <https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_full_ea_information>
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct EaInformationAttr {
    /// The size of the extended attributes in the packed form that `FILE_FULL_EA_INFORMATION`
    /// lists use.
    pub packed_ea_size: u16,
    /// How many extended attributes have the `NEED_EA` flag.
    pub need_ea_count: u16,
    /// The size of the `$EA` attribute's value.
    pub unpacked_ea_size: u32,
}

impl EaInformationAttr {
    /// Parses an `$EA_INFORMATION` value. Returns `None` when it is shorter than 8 bytes.
    ///
    /// # Example
    ///
    /// ```
    /// use mft::attribute::xd0::EaInformationAttr;
    ///
    /// let attribute = EaInformationAttr::from_slice(&[0x6F, 0, 0, 0, 0x7C, 0, 0, 0]).unwrap();
    /// assert_eq!(attribute.packed_ea_size, 111);
    /// assert_eq!(attribute.need_ea_count, 0);
    /// assert_eq!(attribute.unpacked_ea_size, 124);
    /// ```
    pub fn from_slice(value: &[u8]) -> Option<Self> {
        let value = value.get(..8)?;
        Some(EaInformationAttr {
            packed_ea_size: LittleEndian::read_u16(&value[0..2]),
            need_ea_count: LittleEndian::read_u16(&value[2..4]),
            unpacked_ea_size: LittleEndian::read_u32(&value[4..8]),
        })
    }
}
