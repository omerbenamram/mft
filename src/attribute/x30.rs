use crate::Utf16LeStr;
use crate::attribute::FileAttributeFlags;
use crate::err::{Error, Result};
use crate::utils::{read_u64, windows_filetime_to_timestamp};
use log::trace;

use byteorder::{LittleEndian, ReadBytesExt};
use jiff::Timestamp;
use num_traits::FromPrimitive;
use serde::Serialize;
use std::io::Cursor;

use winstructs::ntfs::mft_reference::MftReference;

#[derive(FromPrimitive, Serialize, Clone, Copy, Debug, PartialOrd, PartialEq)]
#[repr(u8)]
pub enum FileNamespace {
    POSIX = 0,
    Win32 = 1,
    DOS = 2,
    Win32AndDos = 3,
}

impl FileNamespace {
    /// Whether a name in this namespace is more than an 8.3 short name.
    pub(crate) fn is_long(self) -> bool {
        self != FileNamespace::DOS
    }
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct FileNameAttr<'a> {
    pub parent: MftReference,
    #[serde(serialize_with = "crate::utils::serialize_timestamp")]
    pub created: Timestamp,
    #[serde(serialize_with = "crate::utils::serialize_timestamp")]
    pub modified: Timestamp,
    #[serde(serialize_with = "crate::utils::serialize_timestamp")]
    pub mft_modified: Timestamp,
    #[serde(serialize_with = "crate::utils::serialize_timestamp")]
    pub accessed: Timestamp,
    /// The file's real (logical) size, as of the last time this name was updated.
    pub logical_size: u64,
    /// The size allocated on disk, as of the last time this name was updated.
    pub physical_size: u64,
    pub flags: FileAttributeFlags,
    pub reparse_value: u32,
    pub name_length: u8,
    pub namespace: FileNamespace,
    pub name: Utf16LeStr<'a>,
}

impl<'a> FileNameAttr<'a> {
    /// Parse a Filename attrbiute buffer.
    ///
    /// # Example
    ///
    /// Parse a raw buffer.
    ///
    /// ```
    /// use mft::attribute::x30::{FileNameAttr, FileNamespace};
    /// # use std::io::Cursor;
    /// let attribute_buffer: &[u8] = &[
    ///     0x05,0x00,0x00,0x00,0x00,0x00,0x05,0x00,0xD5,0x2D,0x48,0x58,0x43,0x5F,0xCE,0x01,
    ///     0xD5,0x2D,0x48,0x58,0x43,0x5F,0xCE,0x01,0xD5,0x2D,0x48,0x58,0x43,0x5F,0xCE,0x01,
    ///     0xD5,0x2D,0x48,0x58,0x43,0x5F,0xCE,0x01,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x00,
    ///     0x00,0x00,0x00,0x03,0x00,0x00,0x00,0x00,0x06,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    ///     0x08,0x03,0x24,0x00,0x4C,0x00,0x6F,0x00,0x67,0x00,0x46,0x00,0x69,0x00,0x6C,0x00,
    ///     0x65,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    /// ];
    ///
    /// let attribute = FileNameAttr::from_slice(attribute_buffer).unwrap();
    ///
    /// assert_eq!(attribute.parent.entry, 5);
    /// assert_eq!(attribute.created.as_second(), 1370144608);
    /// assert_eq!(attribute.modified.as_second(), 1370144608);
    /// assert_eq!(attribute.mft_modified.as_second(), 1370144608);
    /// assert_eq!(attribute.accessed.as_second(), 1370144608);
    /// // Allocated size (0x28) and real size (0x30) differ, so a swap would be caught here.
    /// assert_eq!(attribute.logical_size, 50331648);
    /// assert_eq!(attribute.physical_size, 67108864);
    /// assert_eq!(attribute.flags.bits(), 6);
    /// assert_eq!(attribute.reparse_value, 0);
    /// assert_eq!(attribute.name_length, 8);
    /// assert_eq!(attribute.namespace, FileNamespace::Win32AndDos);
    /// assert_eq!(attribute.name.to_utf8_string(), "$LogFile");
    /// ```
    pub fn from_slice(value: &'a [u8]) -> Result<FileNameAttr<'a>> {
        let mut stream = Cursor::new(value);
        trace!("Offset {}: FilenameAttr", stream.position());

        let parent =
            MftReference::from_reader(&mut stream).map_err(Error::failed_to_read_mft_reference)?;
        // Timestamps are stored as Windows FILETIME (100ns since 1601-01-01 UTC).
        let created =
            crate::utils::windows_filetime_to_timestamp(stream.read_u64::<LittleEndian>()?)?;
        let modified =
            crate::utils::windows_filetime_to_timestamp(stream.read_u64::<LittleEndian>()?)?;
        let mft_modified =
            crate::utils::windows_filetime_to_timestamp(stream.read_u64::<LittleEndian>()?)?;
        let accessed =
            crate::utils::windows_filetime_to_timestamp(stream.read_u64::<LittleEndian>()?)?;

        // The allocated size comes first (0x28), then the real size (0x30).
        let physical_size = stream.read_u64::<LittleEndian>()?;
        let logical_size = stream.read_u64::<LittleEndian>()?;
        let flags = FileAttributeFlags::from_bits_retain(stream.read_u32::<LittleEndian>()?);
        let reparse_value = stream.read_u32::<LittleEndian>()?;
        let name_length = stream.read_u8()?;
        let namespace = stream.read_u8()?;
        let namespace =
            FileNamespace::from_u8(namespace).ok_or(Error::UnknownNamespace { namespace })?;

        let name_pos = stream.position() as usize;
        let name_len_bytes = name_length as usize * 2;
        let name_bytes = value
            .get(name_pos..name_pos + name_len_bytes)
            .ok_or(Error::InvalidFilename)?;
        let name = Utf16LeStr::from_utf16le_bytes(name_bytes);

        Ok(FileNameAttr {
            parent,
            created,
            modified,
            mft_modified,
            accessed,
            logical_size,
            physical_size,
            flags,
            reparse_value,
            name_length,
            namespace,
            name,
        })
    }
}

/// The parts of a `$FILE_NAME` that path resolution needs: the name, and the entry number of the
/// directory it is in.
#[derive(Clone, Copy, Debug)]
pub(crate) struct NameInParent<'a> {
    pub(crate) parent: u64,
    pub(crate) namespace: FileNamespace,
    pub(crate) name: Utf16LeStr<'a>,
}

impl<'a> NameInParent<'a> {
    /// Reads the name and parent of a `$FILE_NAME` value, skipping its sizes and flags. Accepts
    /// exactly the values [`FileNameAttr::from_slice`] accepts, so that paths and parsed attributes
    /// agree on an entry's best name.
    pub(crate) fn from_slice(value: &'a [u8]) -> Option<NameInParent<'a>> {
        // `FileNameAttr::from_slice` rejects a timestamp out of range.
        let timestamps_valid = (0x08..0x28).step_by(8).all(|offset| {
            read_u64(value, offset)
                .is_some_and(|filetime| windows_filetime_to_timestamp(filetime).is_ok())
        });
        if !timestamps_valid {
            return None;
        }

        // The name follows the fixed fields, the last of which are its length and namespace.
        let name_length = usize::from(*value.get(0x40)?);
        let namespace = FileNamespace::from_u8(*value.get(0x41)?)?;
        let name = value.get(0x42..0x42 + name_length * 2)?;
        Some(NameInParent {
            parent: MftReference::from(read_u64(value, 0)?).entry,
            namespace,
            name: Utf16LeStr::from_utf16le_bytes(name),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{FileNameAttr, FileNamespace, NameInParent};
    use crate::entry::tests::filename_value_bytes;

    #[test]
    fn name_in_parent_accepts_what_file_name_attr_accepts() {
        let assert_agree = |value: &[u8]| {
            let name = NameInParent::from_slice(value).map(|n| (n.parent, n.namespace, n.name));
            let full = FileNameAttr::from_slice(value)
                .ok()
                .map(|f| (f.parent.entry, f.namespace, f.name));
            assert_eq!(name, full, "value {value:02X?}");
        };

        let log_file = filename_value_bytes("$LogFile", FileNamespace::Win32AndDos);
        assert!(NameInParent::from_slice(&log_file).is_some());
        for len in 0..=log_file.len() {
            assert_agree(&log_file[..len]);
        }
        // Covers out-of-range timestamps, overlong names and unknown namespaces.
        for position in 0..log_file.len() {
            for byte in [0x00, 0x01, 0x04, 0x7F, 0x80, 0xFF] {
                let mut value = log_file.clone();
                value[position] = byte;
                assert_agree(&value);
            }
        }
    }

    #[test]
    fn flags_keep_unknown_bits() {
        let mut value = vec![0u8; 66];
        value[0x38..0x3C].copy_from_slice(&0x8000_0006u32.to_le_bytes());

        let attr = FileNameAttr::from_slice(&value).unwrap();

        assert_eq!(attr.flags.bits(), 0x8000_0006);
    }
}
