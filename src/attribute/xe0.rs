use std::borrow::Cow;

use crate::attribute::raw::data_as_hex;
use crate::impl_serialize_for_bitflags;
use crate::utils::{read_u16, read_u32};
use bitflags::bitflags;
use byteorder::{ByteOrder, LittleEndian};
use serde::Serialize;

/// $EA Attribute: the file's extended attributes, as a list of `FILE_FULL_EA_INFORMATION`
/// entries.
/// <https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_full_ea_information>
///
/// Windows itself stores metadata here: WSL keeps Linux owners and modes in `$LXUID`, `$LXGID`,
/// `$LXMOD` and `$LXDEV`, code integrity keeps `$CI.CATALOGHINT`, and the kernel keeps caches
/// such as `$KERNEL.PURGE.ESBCACHE`.
#[derive(Serialize, Clone, Debug)]
pub struct EaAttr<'a> {
    pub entries: Vec<EaEntry<'a>>,
}

/// One extended attribute.
#[derive(Serialize, Clone, Debug)]
pub struct EaEntry<'a> {
    pub flags: EaFlags,
    /// The name, which is ASCII.
    pub name: Cow<'a, str>,
    pub value: EaValue<'a>,
}

bitflags! {
    #[derive(Default, Clone, Debug, PartialEq)]
    pub struct EaFlags: u8 {
        /// The file can't be read correctly without this extended attribute.
        const NEED_EA = 0x80;
    }
}

impl_serialize_for_bitflags! {EaFlags}

/// The value of an extended attribute. Values that Windows defines a layout for are decoded,
/// and the rest are kept as bytes.
#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(tag = "type")]
pub enum EaValue<'a> {
    /// `$LXUID`, `$LXGID` or `$LXMOD`: a WSL file's Linux owner, group or mode.
    /// <https://learn.microsoft.com/en-us/windows/wsl/file-permissions>
    LxInteger { value: u32 },
    /// `$LXDEV`: the device numbers of a WSL device file.
    LxDevice { major: u32, minor: u32 },
    /// `$CI.CATALOGHINT`: the name of the security catalog that signs the file.
    CatalogHint { catalog: Cow<'a, str> },
    /// Any other value, or one that doesn't match its name's layout.
    Other {
        #[serde(serialize_with = "data_as_hex")]
        data: &'a [u8],
    },
}

/// The fixed part of an entry: next entry offset, flags, name length and value length.
const ENTRY_HEADER_LEN: usize = 8;

impl<'a> EaAttr<'a> {
    /// Parses an `$EA` value. Each entry gives the offset of the next one, and the list ends
    /// at an offset of 0 or at the end of the value. Returns `None` when an entry runs past the
    /// value, overlaps the next one or has no NUL after its name.
    ///
    /// # Example
    ///
    /// ```
    /// use mft::attribute::xe0::{EaAttr, EaValue};
    ///
    /// // `$LXUID` = 1000, the only entry.
    /// let mut value = vec![0, 0, 0, 0, 0x00, 6, 4, 0];
    /// value.extend_from_slice(b"$LXUID\0");
    /// value.extend_from_slice(&1000u32.to_le_bytes());
    ///
    /// let attribute = EaAttr::from_slice(&value).unwrap();
    /// assert_eq!(attribute.entries[0].name, "$LXUID");
    /// assert_eq!(attribute.entries[0].value, EaValue::LxInteger { value: 1000 });
    /// ```
    pub fn from_slice(value: &'a [u8]) -> Option<Self> {
        let mut entries = Vec::new();
        let mut offset = 0;
        while offset < value.len() {
            let entry = &value[offset..];
            let next_entry_offset = read_u32(entry, 0)? as usize;
            let flags = EaFlags::from_bits_retain(*entry.get(4)?);
            let name_len = usize::from(*entry.get(5)?);
            let value_len = usize::from(read_u16(entry, 6)?);

            // The name is followed by a NUL, then the value.
            let name = entry.get(ENTRY_HEADER_LEN..ENTRY_HEADER_LEN + name_len)?;
            if *entry.get(ENTRY_HEADER_LEN + name_len)? != 0 {
                return None;
            }
            let value_start = ENTRY_HEADER_LEN + name_len + 1;
            let entry_len = value_start + value_len;
            let data = entry.get(value_start..entry_len)?;

            let name = String::from_utf8_lossy(name);
            let value = EaValue::decode(&name, data);
            entries.push(EaEntry { flags, name, value });

            match next_entry_offset {
                0 => break,
                next if next < entry_len => return None,
                next => offset = offset.checked_add(next)?,
            }
        }
        Some(EaAttr { entries })
    }
}

impl<'a> EaValue<'a> {
    fn decode(name: &str, data: &'a [u8]) -> Self {
        match (name, data.len()) {
            ("$LXUID" | "$LXGID" | "$LXMOD", 4) => EaValue::LxInteger {
                value: LittleEndian::read_u32(data),
            },
            ("$LXDEV", 8) => EaValue::LxDevice {
                major: LittleEndian::read_u32(&data[0..4]),
                minor: LittleEndian::read_u32(&data[4..8]),
            },
            ("$CI.CATALOGHINT", _) => Self::catalog_hint(data).unwrap_or(EaValue::Other { data }),
            _ => EaValue::Other { data },
        }
    }

    /// A catalog hint is a version (1), the name's length, then the name.
    fn catalog_hint(data: &'a [u8]) -> Option<Self> {
        let version = read_u16(data, 0)?;
        let len = usize::from(read_u16(data, 2)?);
        if version != 1 {
            return None;
        }
        let catalog = String::from_utf8_lossy(data.get(4..4 + len)?);
        Some(EaValue::CatalogHint { catalog })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(flags: u8, name: &str, value: &[u8]) -> Vec<u8> {
        let mut out = vec![0; 4];
        out.push(flags);
        out.push(name.len() as u8);
        out.extend_from_slice(&(value.len() as u16).to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        out.extend_from_slice(value);
        out
    }

    /// Chains entries the way `$EA` stores them: each one padded to 4 bytes and pointing at the
    /// next, including the last.
    fn link(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        for entry in entries {
            let start = out.len();
            out.extend(entry);
            out.resize(out.len().next_multiple_of(4), 0);
            let len = (out.len() - start) as u32;
            out[start..start + 4].copy_from_slice(&len.to_le_bytes());
        }
        out
    }

    #[test]
    fn parses_wsl_entries_padded_to_four_bytes() {
        let value = link(&[
            entry(0, "$LXUID", &1000u32.to_le_bytes()),
            entry(0, "$LXGID", &1000u32.to_le_bytes()),
            entry(0, "$LXMOD", &0o100644u32.to_le_bytes()),
            entry(
                0,
                "$LXDEV",
                &[8u32.to_le_bytes(), 1u32.to_le_bytes()].concat(),
            ),
        ]);

        let attribute = EaAttr::from_slice(&value).unwrap();
        let values: Vec<_> = attribute
            .entries
            .iter()
            .map(|e| (e.name.as_ref(), &e.value))
            .collect();
        assert_eq!(
            values,
            [
                ("$LXUID", &EaValue::LxInteger { value: 1000 }),
                ("$LXGID", &EaValue::LxInteger { value: 1000 }),
                ("$LXMOD", &EaValue::LxInteger { value: 0o100644 }),
                ("$LXDEV", &EaValue::LxDevice { major: 8, minor: 1 }),
            ]
        );
    }

    #[test]
    fn keeps_unknown_and_malformed_values_as_bytes() {
        let value = link(&[
            entry(0x80, "$LXUID", &[1, 2]),
            entry(0, "$CI.CATALOGHINT", &[2, 0, 1, 0, b'x']),
        ]);

        let attribute = EaAttr::from_slice(&value).unwrap();
        assert_eq!(attribute.entries[0].flags, EaFlags::NEED_EA);
        assert_eq!(attribute.entries[0].value, EaValue::Other { data: &[1, 2] });
        assert_eq!(
            attribute.entries[1].value,
            EaValue::Other {
                data: &[2, 0, 1, 0, b'x']
            }
        );
    }

    #[test]
    fn rejects_entries_that_run_past_the_value_or_overlap() {
        let value = entry(0, "$LXUID", &1000u32.to_le_bytes());
        assert!(EaAttr::from_slice(&value[..value.len() - 1]).is_none());

        // A name length one short leaves the name's last byte where the NUL should be.
        let mut misaligned = value.clone();
        misaligned[5] -= 1;
        assert!(EaAttr::from_slice(&misaligned).is_none());

        let mut overlapping = value.clone();
        overlapping[0..4].copy_from_slice(&4u32.to_le_bytes());
        overlapping.extend(&value);
        assert!(EaAttr::from_slice(&overlapping).is_none());
    }
}
