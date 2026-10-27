use crate::err::Result;
use crate::impl_serialize_for_bitflags;

use bitflags::bitflags;
use serde::Serialize;
use std::io::{Error, ErrorKind};

/// $VOLUME_INFORMATION Attribute. Present in the `$Volume` file (entry 3).
/// <https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc#volume_information_attribute>
#[derive(Serialize, Clone, Debug)]
pub struct VolumeInformationAttr {
    /// NTFS major version, e.g. 3 for NTFS 3.1.
    pub major_version: u8,
    /// NTFS minor version, e.g. 1 for NTFS 3.1.
    pub minor_version: u8,
    pub flags: VolumeFlags,
}

bitflags! {
    /// Flag sources:
    /// <https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc#volume_flags>
    #[derive(Clone, Debug, PartialEq)]
    pub struct VolumeFlags: u16 {
        const IS_DIRTY            = 0x0001;
        const RESIZE_LOG_FILE     = 0x0002;
        const UPGRADE_ON_MOUNT    = 0x0004;
        const MOUNTED_ON_NT4      = 0x0008;
        const DELETE_USN_UNDERWAY = 0x0010;
        const REPAIR_OBJECT_ID    = 0x0020;
        // 0x0080 is set on most volumes formatted by Windows 7 and later; its meaning is not
        // documented, so it is kept as an unnamed bit.
        const CHKDSK_UNDERWAY     = 0x4000;
        const MODIFIED_BY_CHKDSK  = 0x8000;
    }
}

impl_serialize_for_bitflags! {VolumeFlags}

impl VolumeInformationAttr {
    /// The value is 8 reserved bytes, the major and minor version, then 2 bytes of flags.
    /// Some versions append 4 more reserved bytes.
    ///
    /// # Example
    ///
    /// ```
    /// use mft::attribute::x70::{VolumeFlags, VolumeInformationAttr};
    ///
    /// let value: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0x03, 0x01, 0x01, 0x00];
    /// let attribute = VolumeInformationAttr::from_slice(value).unwrap();
    ///
    /// assert_eq!((attribute.major_version, attribute.minor_version), (3, 1));
    /// assert_eq!(attribute.flags, VolumeFlags::IS_DIRTY);
    /// ```
    pub fn from_slice(value: &[u8]) -> Result<VolumeInformationAttr> {
        let [
            _,
            _,
            _,
            _,
            _,
            _,
            _,
            _,
            major_version,
            minor_version,
            f0,
            f1,
            ..,
        ] = *value
        else {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                format!(
                    "$VOLUME_INFORMATION is {} bytes, expected at least 12",
                    value.len()
                ),
            )
            .into());
        };

        Ok(VolumeInformationAttr {
            major_version,
            minor_version,
            flags: VolumeFlags::from_bits_retain(u16::from_le_bytes([f0, f1])),
        })
    }
}
