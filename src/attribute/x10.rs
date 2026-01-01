use std::io::{Read, Seek};

use crate::attribute::FileAttributeFlags;
use crate::err::Result;

use byteorder::{LittleEndian, ReadBytesExt};
use jiff::Timestamp;
use log::trace;
use serde::Serialize;
use std::io::{Cursor, ErrorKind};

#[derive(Serialize, Debug, Clone)]
pub struct StandardInfoAttr {
    #[serde(serialize_with = "crate::utils::serialize_timestamp_chrono_compat")]
    pub created: Timestamp,
    #[serde(serialize_with = "crate::utils::serialize_timestamp_chrono_compat")]
    pub modified: Timestamp,
    #[serde(serialize_with = "crate::utils::serialize_timestamp_chrono_compat")]
    pub mft_modified: Timestamp,
    #[serde(serialize_with = "crate::utils::serialize_timestamp_chrono_compat")]
    pub accessed: Timestamp,
    /// DOS File Permissions
    pub file_flags: FileAttributeFlags,
    pub max_version: u32,
    pub version: u32,
    pub class_id: u32,
    pub owner_id: u32,
    pub security_id: u32,
    pub quota: u64,
    pub usn: u64,
}

impl StandardInfoAttr {
    /// Parse a Standard Information attribute buffer whose length is the attribute value size.
    ///
    /// NTFS uses (at least) two layouts:
    /// - **48 bytes** (NTFS < 3.0): ends at `class_id`
    /// - **72 bytes** (NTFS >= 3.0): includes `owner_id`, `security_id`, `quota`, and `usn`
    pub fn from_slice(value: &[u8]) -> Result<StandardInfoAttr> {
        if value.len() < 48 {
            return Err(std::io::Error::from(ErrorKind::UnexpectedEof).into());
        }
        if value.len() != 48 && value.len() < 72 {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "$STANDARD_INFORMATION has unsupported size {} (expected 48 or >=72)",
                    value.len()
                ),
            )
            .into());
        }

        let mut reader = Cursor::new(value);

        // Timestamps are stored as Windows FILETIME (100ns since 1601-01-01 UTC).
        let created =
            crate::utils::windows_filetime_to_timestamp(reader.read_u64::<LittleEndian>()?)?;
        let modified =
            crate::utils::windows_filetime_to_timestamp(reader.read_u64::<LittleEndian>()?)?;
        let mft_modified =
            crate::utils::windows_filetime_to_timestamp(reader.read_u64::<LittleEndian>()?)?;
        let accessed =
            crate::utils::windows_filetime_to_timestamp(reader.read_u64::<LittleEndian>()?)?;

        let file_flags = FileAttributeFlags::from_bits_truncate(reader.read_u32::<LittleEndian>()?);
        let max_version = reader.read_u32::<LittleEndian>()?;
        let version = reader.read_u32::<LittleEndian>()?;
        let class_id = reader.read_u32::<LittleEndian>()?;

        let (owner_id, security_id, quota, usn) = if value.len() >= 72 {
            (
                reader.read_u32::<LittleEndian>()?,
                reader.read_u32::<LittleEndian>()?,
                reader.read_u64::<LittleEndian>()?,
                reader.read_u64::<LittleEndian>()?,
            )
        } else {
            (0, 0, 0, 0)
        };

        Ok(StandardInfoAttr {
            created,
            modified,
            mft_modified,
            accessed,
            file_flags,
            max_version,
            version,
            class_id,
            owner_id,
            security_id,
            quota,
            usn,
        })
    }

    /// Parse a Standard Information attrbiute buffer.
    ///
    /// # Example
    ///
    /// Parse a raw buffer.
    ///
    /// ```
    /// use mft::attribute::x10::StandardInfoAttr;
    /// use mft::attribute::FileAttributeFlags;
    /// # use std::io::Cursor;
    /// let attribute_buffer: &[u8] = &[
    ///     0x2F,0x6D,0xB6,0x6F,0x0C,0x97,0xCE,0x01,0x56,0xCD,0x1A,0x75,0x73,0xB5,0xCE,0x01,
    ///     0x56,0xCD,0x1A,0x75,0x73,0xB5,0xCE,0x01,0x56,0xCD,0x1A,0x75,0x73,0xB5,0xCE,0x01,
    ///     0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    ///     0x00,0x00,0x00,0x00,0xB0,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    ///     0x68,0x58,0xA0,0x0A,0x02,0x00,0x00,0x00
    /// ];
    ///
    /// let attribute = StandardInfoAttr::from_reader(&mut Cursor::new(attribute_buffer)).unwrap();
    ///
    /// assert_eq!(attribute.created.as_second(), 1376278290);
    /// assert_eq!(attribute.modified.as_second(), 1379621073);
    /// assert_eq!(attribute.mft_modified.as_second(), 1379621073);
    /// assert_eq!(attribute.accessed.as_second(), 1379621073);
    /// assert_eq!(attribute.file_flags.bits(), 32);
    /// assert_eq!(attribute.max_version, 0);
    /// assert_eq!(attribute.version, 0);
    /// assert_eq!(attribute.class_id, 0);
    /// assert_eq!(attribute.security_id, 1456);
    /// assert_eq!(attribute.quota, 0);
    /// assert_eq!(attribute.usn, 8768215144);
    /// ```
    pub fn from_reader<S: Read + Seek>(reader: &mut S) -> Result<StandardInfoAttr> {
        trace!("Offset {}: StandardInfoAttr", reader.stream_position()?);
        // Timestamps are stored as Windows FILETIME (100ns since 1601-01-01 UTC).
        let created =
            crate::utils::windows_filetime_to_timestamp(reader.read_u64::<LittleEndian>()?)?;
        let modified =
            crate::utils::windows_filetime_to_timestamp(reader.read_u64::<LittleEndian>()?)?;
        let mft_modified =
            crate::utils::windows_filetime_to_timestamp(reader.read_u64::<LittleEndian>()?)?;
        let accessed =
            crate::utils::windows_filetime_to_timestamp(reader.read_u64::<LittleEndian>()?)?;

        Ok(StandardInfoAttr {
            created,
            modified,
            mft_modified,
            accessed,
            file_flags: FileAttributeFlags::from_bits_truncate(reader.read_u32::<LittleEndian>()?),
            max_version: reader.read_u32::<LittleEndian>()?,
            version: reader.read_u32::<LittleEndian>()?,
            class_id: reader.read_u32::<LittleEndian>()?,
            owner_id: reader.read_u32::<LittleEndian>()?,
            security_id: reader.read_u32::<LittleEndian>()?,
            quota: reader.read_u64::<LittleEndian>()?,
            usn: reader.read_u64::<LittleEndian>()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::StandardInfoAttr;
    use crate::attribute::FileAttributeFlags;
    use crate::err::Error;

    // Test vectors are based on the doc-test buffer above.
    const STDINFO_72: &[u8] = &[
        0x2F, 0x6D, 0xB6, 0x6F, 0x0C, 0x97, 0xCE, 0x01, 0x56, 0xCD, 0x1A, 0x75, 0x73, 0xB5, 0xCE,
        0x01, 0x56, 0xCD, 0x1A, 0x75, 0x73, 0xB5, 0xCE, 0x01, 0x56, 0xCD, 0x1A, 0x75, 0x73, 0xB5,
        0xCE, 0x01, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xB0, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x68, 0x58, 0xA0, 0x0A, 0x02, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn from_slice_len_48_treats_extended_fields_as_absent() {
        // Spec note: the "base" STANDARD_INFORMATION value layout is 48 bytes; the extended
        // layout is 72 bytes. When a value is 48 bytes, the additional fields are not present
        // and must not be read from subsequent bytes in the file record.
        //
        // See: external/refs/specs/NTFS-standard-information.md
        let buf48 = &STDINFO_72[..48];
        let attr = StandardInfoAttr::from_slice(buf48).unwrap();

        assert_eq!(attr.created.as_second(), 1376278290);
        assert_eq!(attr.modified.as_second(), 1379621073);
        assert_eq!(attr.mft_modified.as_second(), 1379621073);
        assert_eq!(attr.accessed.as_second(), 1379621073);
        assert_eq!(attr.file_flags, FileAttributeFlags::FILE_ATTRIBUTE_ARCHIVE);
        assert_eq!(attr.max_version, 0);
        assert_eq!(attr.version, 0);
        assert_eq!(attr.class_id, 0);

        // Extended fields absent => zero.
        assert_eq!(attr.owner_id, 0);
        assert_eq!(attr.security_id, 0);
        assert_eq!(attr.quota, 0);
        assert_eq!(attr.usn, 0);
    }

    #[test]
    fn from_slice_len_72_parses_extended_fields() {
        let attr = StandardInfoAttr::from_slice(STDINFO_72).unwrap();

        assert_eq!(attr.created.as_second(), 1376278290);
        assert_eq!(attr.modified.as_second(), 1379621073);
        assert_eq!(attr.mft_modified.as_second(), 1379621073);
        assert_eq!(attr.accessed.as_second(), 1379621073);
        assert_eq!(attr.file_flags.bits(), 32);
        assert_eq!(attr.max_version, 0);
        assert_eq!(attr.version, 0);
        assert_eq!(attr.class_id, 0);
        assert_eq!(attr.security_id, 1456);
        assert_eq!(attr.quota, 0);
        assert_eq!(attr.usn, 8768215144);
    }

    #[test]
    fn from_slice_rejects_intermediate_sizes() {
        let buf60 = [0u8; 60];
        let err = StandardInfoAttr::from_slice(&buf60).unwrap_err();
        match err {
            Error::IoError { source } => {
                assert_eq!(source.kind(), std::io::ErrorKind::InvalidData);
                assert!(
                    source.to_string().contains("unsupported size"),
                    "unexpected io error message for len=60: {source}"
                );
            }
            other => panic!("unexpected error kind for len=60: {other:?}"),
        }
    }
}
