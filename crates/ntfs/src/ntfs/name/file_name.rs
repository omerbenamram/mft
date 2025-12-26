use crate::ntfs::{Error, Result};

/// A parsed NTFS `FILE_NAME` attribute value as used as a key in the `$I30` index.
///
/// This is a minimal, **strict** parser that preserves the raw UTF-16 code units of the name.
/// It intentionally does not attempt to interpret the UTF-16 as Unicode scalar values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileNameKey {
    parent_reference_raw: u64,
    name_space: u8,
    name_utf16: Vec<u16>,
}

impl FileNameKey {
    /// Parses a `FILE_NAME` attribute value from `buf`.
    ///
    /// `base_offset` is used only for error messages.
    pub fn parse(buf: &[u8], base_offset: u64) -> Result<Self> {
        // FILE_NAME fixed prefix is 66 bytes, then name_length * 2 bytes of UTF-16LE.
        const FIXED_LEN: usize = 66;
        if buf.len() < FIXED_LEN {
            return Err(Error::InvalidData {
                message: format!(
                    "FILE_NAME key too small at 0x{base_offset:x}: len={} < {FIXED_LEN}",
                    buf.len()
                ),
            });
        }

        let parent_reference_raw = u64::from_le_bytes(
            buf.get(0..8)
                .ok_or_else(|| Error::InvalidData {
                    message: "FILE_NAME missing parent reference".to_string(),
                })?
                .try_into()
                .expect("len=8"),
        );

        let name_length = buf[64] as usize;
        let name_space = buf[65];

        let name_bytes_len = name_length
            .checked_mul(2)
            .ok_or_else(|| Error::InvalidData {
                message: format!(
                    "FILE_NAME name length overflow at 0x{base_offset:x}: name_length={name_length}"
                ),
            })?;
        let expected_len = FIXED_LEN
            .checked_add(name_bytes_len)
            .ok_or_else(|| Error::InvalidData {
                message: format!(
                    "FILE_NAME length overflow at 0x{base_offset:x}: fixed={FIXED_LEN} name_bytes={name_bytes_len}"
                ),
            })?;

        if buf.len() != expected_len {
            return Err(Error::InvalidData {
                message: format!(
                    "FILE_NAME key length mismatch at 0x{base_offset:x}: expected {expected_len} bytes (name_length={name_length}), got {}",
                    buf.len()
                ),
            });
        }

        let name_bytes = &buf[FIXED_LEN..];
        debug_assert_eq!(name_bytes.len(), name_bytes_len);

        let name_utf16 = name_bytes
            .chunks_exact(2)
            .map(|two| u16::from_le_bytes([two[0], two[1]]))
            .collect::<Vec<_>>();

        Ok(Self {
            parent_reference_raw,
            name_space,
            name_utf16,
        })
    }

    /// Parent directory entry number (file record number), masked to 48 bits.
    pub fn parent_entry_id(&self) -> u64 {
        self.parent_reference_raw & 0x0000_FFFF_FFFF_FFFF
    }

    pub fn name_space(&self) -> u8 {
        self.name_space
    }

    pub fn name_utf16(&self) -> &[u16] {
        &self.name_utf16
    }

    pub fn into_name_utf16(self) -> Vec<u16> {
        self.name_utf16
    }
}
