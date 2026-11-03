//! References to MFT entries.

use std::io::{self, Read};

use byteorder::{LittleEndian, ReadBytesExt};
use serde::Serialize;

/// A file reference: a 48-bit MFT entry number and the 16-bit sequence number the entry had
/// when the reference was written.
///
/// <https://learn.microsoft.com/en-us/windows/win32/devnotes/mft-segment-reference>
///
/// # Example
///
/// ```
/// # use mft::MftReference;
/// let reference = MftReference::from(0x9168_0000_0000_0073);
/// assert_eq!(reference, MftReference::new(115, 37224));
/// ```
#[derive(Serialize, Debug, Hash, Eq, PartialEq, Copy, Clone)]
pub struct MftReference {
    pub entry: u64,
    pub sequence: u16,
}

impl MftReference {
    pub fn new(entry: u64, sequence: u16) -> Self {
        MftReference { entry, sequence }
    }

    /// Reads a little-endian 8-byte reference from `reader`.
    pub fn from_reader<R: Read>(reader: &mut R) -> io::Result<Self> {
        Ok(Self::from(reader.read_u64::<LittleEndian>()?))
    }
}

impl From<u64> for MftReference {
    fn from(reference: u64) -> Self {
        MftReference {
            entry: reference & 0x0000_FFFF_FFFF_FFFF,
            sequence: (reference >> 48) as u16,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MftReference;
    use std::io::Cursor;

    #[test]
    fn reads_entry_and_sequence() {
        let raw = [0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68, 0x91];
        let reference = MftReference::from_reader(&mut Cursor::new(raw)).unwrap();
        assert_eq!(reference, MftReference::new(115, 37224));
    }

    #[test]
    fn serializes_as_entry_and_sequence() {
        assert_eq!(
            serde_json::to_string(&MftReference::new(5, 5)).unwrap(),
            r#"{"entry":5,"sequence":5}"#
        );
    }
}
