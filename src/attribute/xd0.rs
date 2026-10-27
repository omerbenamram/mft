use crate::utils::{read_u16, read_u32};
use serde::Serialize;

/// $EA_INFORMATION Attribute: the sizes of the file's extended attributes in `$EA`.
/// <https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_full_ea_information>
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct EaInformationAttr {
    /// The size of the extended attributes in packed form: each one's flags, lengths, name
    /// and value, without the next entry offsets and padding that `$EA` stores.
    pub packed_ea_size: u16,
    /// How many extended attributes have the `NEED_EA` flag.
    pub need_ea_count: u16,
    /// The size of the extended attributes as `$EA` stores them (`FILE_FULL_EA_INFORMATION`
    /// entries), which is the size of its value.
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
        Some(EaInformationAttr {
            packed_ea_size: read_u16(value, 0)?,
            need_ea_count: read_u16(value, 2)?,
            unpacked_ea_size: read_u32(value, 4)?,
        })
    }
}
