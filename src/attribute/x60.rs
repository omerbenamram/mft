use crate::Utf16LeStr;
use serde::Serialize;

/// $VOLUME_NAME Attribute. Present in the `$Volume` file (entry 3).
#[derive(Serialize, Clone, Debug)]
pub struct VolumeNameAttr<'a> {
    /// The volume label. Empty when the volume has no label.
    pub name: Utf16LeStr<'a>,
}

impl<'a> VolumeNameAttr<'a> {
    /// The attribute value is the label as UTF-16LE, without a terminator.
    ///
    /// # Example
    ///
    /// ```
    /// use mft::attribute::x60::VolumeNameAttr;
    ///
    /// let value: &[u8] = &[0x44, 0x00, 0x61, 0x00, 0x74, 0x00, 0x61, 0x00];
    /// let attribute = VolumeNameAttr::from_slice(value);
    ///
    /// assert_eq!(attribute.name.to_utf8_string(), "Data");
    /// ```
    pub fn from_slice(value: &'a [u8]) -> VolumeNameAttr<'a> {
        VolumeNameAttr {
            name: Utf16LeStr::from_utf16le_bytes(value),
        }
    }
}
