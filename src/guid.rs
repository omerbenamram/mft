//! GUIDs, as NTFS stores them in `$OBJECT_ID`, `$LOGGED_UTILITY_STREAM` and view indexes.

use std::fmt::{self, Display};
use std::io::{self, Cursor, Read};

use byteorder::{LittleEndian, ReadBytesExt};
use serde::ser;

/// A GUID in its Windows layout: three little-endian integers followed by 8 bytes.
///
/// <https://learn.microsoft.com/en-us/windows/win32/api/guiddef/ns-guiddef-guid>
///
/// # Example
///
/// ```
/// # use mft::Guid;
/// let raw_guid: &[u8] = &[0x25, 0x96, 0x84, 0x54, 0x78, 0x54, 0x94, 0x49,
///                         0xa5, 0xba, 0x3e, 0x3b, 0x3, 0x28, 0xc3, 0xd];
///
/// let guid = Guid::from_buffer(raw_guid).unwrap();
///
/// assert_eq!(guid.to_string(), "54849625-5478-4994-A5BA-3E3B0328C30D");
/// ```
#[derive(PartialOrd, Ord, PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

impl Guid {
    /// Creates a GUID from its components.
    pub fn new(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Guid {
        Guid {
            data1,
            data2,
            data3,
            data4,
        }
    }

    /// Reads a GUID from the first 16 bytes of `buffer`.
    pub fn from_buffer(buffer: &[u8]) -> io::Result<Guid> {
        Self::from_reader(&mut Cursor::new(buffer))
    }

    /// Reads a GUID from `stream`.
    pub fn from_reader<T: Read>(stream: &mut T) -> io::Result<Guid> {
        let data1 = stream.read_u32::<LittleEndian>()?;
        let data2 = stream.read_u16::<LittleEndian>()?;
        let data3 = stream.read_u16::<LittleEndian>()?;

        let mut data4 = [0; 8];
        stream.read_exact(&mut data4)?;

        Ok(Guid::new(data1, data2, data3, data4))
    }
}

impl Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let d = &self.data4;
        write!(
            f,
            "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            self.data1, self.data2, self.data3, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]
        )
    }
}

/// The string form in lowercase, e.g. `54849625-5478-4994-a5ba-3e3b0328c30d`, as SDDL writes it.
impl fmt::LowerHex for Guid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let d = &self.data4;
        write!(
            f,
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.data1, self.data2, self.data3, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]
        )
    }
}

/// Serialized as its string form, e.g. `"54849625-5478-4994-A5BA-3E3B0328C30D"`.
impl ser::Serialize for Guid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.collect_str(self)
    }
}

#[cfg(test)]
mod tests {
    use super::Guid;

    #[test]
    fn short_buffer_is_an_error() {
        assert!(Guid::from_buffer(&[0; 15]).is_err());
    }

    #[test]
    fn serializes_as_string() {
        let guid = Guid::new(
            0x5484_9625,
            0x5478,
            0x4994,
            [0xa5, 0xba, 0x3e, 0x3b, 3, 0x28, 0xc3, 0xd],
        );
        assert_eq!(
            serde_json::to_string(&guid).unwrap(),
            "\"54849625-5478-4994-A5BA-3E3B0328C30D\""
        );
    }
}
