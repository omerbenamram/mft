use std::borrow::Cow;

use crate::Utf16LeStr;
use crate::attribute::raw::data_as_hex;
use crate::utils::{read_guid, read_u16, read_u32};
use serde::Serialize;
use winstructs::guid::Guid;

/// $REPARSE_POINT Attribute.
/// <https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_reparse_data_buffer>
#[derive(Serialize, Clone, Debug)]
pub struct ReparsePointAttr<'a> {
    /// The reparse tag, which says which file system filter owns the data.
    pub tag: u32,
    /// The name of a documented tag (for example `SYMLINK` or `MOUNT_POINT`), without the
    /// `IO_REPARSE_TAG_` prefix.
    pub tag_name: Option<&'static str>,
    /// Third-party (non-Microsoft) tags carry the GUID of the owning filter.
    pub guid: Option<Guid>,
    pub data: ReparseData<'a>,
}

/// The tag-specific part of a reparse point.
#[derive(Serialize, Clone, Debug)]
#[serde(tag = "type")]
pub enum ReparseData<'a> {
    /// `IO_REPARSE_TAG_SYMLINK`.
    SymbolicLink {
        substitute_name: Utf16LeStr<'a>,
        print_name: Utf16LeStr<'a>,
        /// The target is relative to the link's directory.
        relative: bool,
    },
    /// `IO_REPARSE_TAG_MOUNT_POINT`: a junction or a volume mount point.
    MountPoint {
        substitute_name: Utf16LeStr<'a>,
        print_name: Utf16LeStr<'a>,
    },
    /// `IO_REPARSE_TAG_APPEXECLINK`: an app execution alias (for example under
    /// `%LOCALAPPDATA%\Microsoft\WindowsApps`).
    AppExecLink {
        package_id: Utf16LeStr<'a>,
        app_user_model_id: Utf16LeStr<'a>,
        target_path: Utf16LeStr<'a>,
    },
    /// `IO_REPARSE_TAG_LX_SYMLINK`: a symbolic link created from WSL.
    LxSymlink { target: Cow<'a, str> },
    /// Any other tag, or data that doesn't match its tag's layout.
    Other {
        #[serde(serialize_with = "data_as_hex")]
        data: &'a [u8],
    },
}

const TAG_MOUNT_POINT: u32 = 0xA000_0003;
const TAG_SYMLINK: u32 = 0xA000_000C;
const TAG_APPEXECLINK: u32 = 0x8000_001B;
const TAG_LX_SYMLINK: u32 = 0xA000_001D;

/// Set on tags owned by Microsoft. Other tags have a GUID after the header.
const TAG_MICROSOFT_BIT: u32 = 0x8000_0000;

/// `SYMLINK_FLAG_RELATIVE`.
const SYMLINK_FLAG_RELATIVE: u32 = 0x1;

impl<'a> ReparsePointAttr<'a> {
    /// Parses a reparse point value: a tag, the data length, 2 reserved bytes, a GUID for
    /// third-party tags, then the tag-specific data. Returns `None` when the value is too short
    /// for that header; data that doesn't match the tag's layout is kept as
    /// [`ReparseData::Other`].
    ///
    /// # Example
    ///
    /// ```
    /// use mft::attribute::xc0::{ReparseData, ReparsePointAttr};
    ///
    /// // A junction to `C:\Users` (substitute name `\??\C:\Users`, print name `C:\Users`).
    /// let mut value = vec![0x03, 0x00, 0x00, 0xA0, 0x34, 0x00, 0x00, 0x00];
    /// value.extend_from_slice(&[0x00, 0x00, 0x18, 0x00, 0x1A, 0x00, 0x10, 0x00]);
    /// for c in "\\??\\C:\\Users\0C:\\Users\0".encode_utf16() {
    ///     value.extend_from_slice(&c.to_le_bytes());
    /// }
    ///
    /// let reparse_point = ReparsePointAttr::from_slice(&value).unwrap();
    /// assert_eq!(reparse_point.tag_name, Some("MOUNT_POINT"));
    /// match reparse_point.data {
    ///     ReparseData::MountPoint { substitute_name, print_name } => {
    ///         assert_eq!(substitute_name.to_utf8_string(), "\\??\\C:\\Users");
    ///         assert_eq!(print_name.to_utf8_string(), "C:\\Users");
    ///     }
    ///     other => panic!("unexpected {other:?}"),
    /// }
    /// ```
    pub fn from_slice(value: &'a [u8]) -> Option<ReparsePointAttr<'a>> {
        let tag = read_u32(value, 0)?;
        let data_length = usize::from(read_u16(value, 4)?);

        let (guid, data_offset) = if tag & TAG_MICROSOFT_BIT == 0 {
            (Some(read_guid(value, 8)?), 24)
        } else {
            (None, 8)
        };

        // Tolerate a data length that overruns the value; use what is there.
        let data = value
            .get(data_offset..)
            .map(|rest| &rest[..data_length.min(rest.len())])
            .unwrap_or_default();

        Some(ReparsePointAttr {
            tag,
            tag_name: tag_name(tag),
            guid,
            data: ReparseData::parse(tag, data).unwrap_or(ReparseData::Other { data }),
        })
    }
}

impl<'a> ReparseData<'a> {
    /// Returns `None` when the data doesn't match the tag's layout.
    fn parse(tag: u32, data: &'a [u8]) -> Option<ReparseData<'a>> {
        match tag {
            TAG_SYMLINK => {
                let (substitute_name, print_name) = name_pair(data, 12)?;
                let flags = read_u32(data, 8)?;
                Some(ReparseData::SymbolicLink {
                    substitute_name,
                    print_name,
                    relative: flags & SYMLINK_FLAG_RELATIVE != 0,
                })
            }
            TAG_MOUNT_POINT => {
                let (substitute_name, print_name) = name_pair(data, 8)?;
                Some(ReparseData::MountPoint {
                    substitute_name,
                    print_name,
                })
            }
            TAG_APPEXECLINK => {
                // A version (3), then NUL-terminated UTF-16 strings.
                let mut rest = data.get(4..)?;
                let mut next = || {
                    let s = Utf16LeStr::from_utf16le_bytes_until_nul(rest);
                    // `None` when the string has no NUL terminator.
                    rest = rest.get(s.as_utf16le_bytes().len() + 2..)?;
                    Some(s)
                };
                Some(ReparseData::AppExecLink {
                    package_id: next()?,
                    app_user_model_id: next()?,
                    target_path: next()?,
                })
            }
            TAG_LX_SYMLINK => {
                // A version (2), then the target as UTF-8.
                let target = data.get(4..)?;
                Some(ReparseData::LxSymlink {
                    target: String::from_utf8_lossy(target),
                })
            }
            _ => None,
        }
    }
}

/// Reads the substitute and print names of a symlink or mount point. `path_buffer` is the
/// offset of the path buffer within `data`; the name offsets are relative to it.
fn name_pair(data: &[u8], path_buffer: usize) -> Option<(Utf16LeStr<'_>, Utf16LeStr<'_>)> {
    let field = |i: usize| read_u16(data, i).map(usize::from);
    let name = |offset: usize, length: usize| -> Option<Utf16LeStr<'_>> {
        let start = path_buffer.checked_add(offset)?;
        Some(Utf16LeStr::from_utf16le_bytes(
            data.get(start..start.checked_add(length)?)?,
        ))
    };

    Some((name(field(0)?, field(2)?)?, name(field(4)?, field(6)?)?))
}

/// Names for the documented reparse tags.
/// <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/c8e77b37-3909-4fe6-a4ea-2b9d423b1ee4>
pub fn tag_name(tag: u32) -> Option<&'static str> {
    Some(match tag {
        0x0000_0000 => "RESERVED_ZERO",
        0x0000_0001 => "RESERVED_ONE",
        0x0000_0002 => "RESERVED_TWO",
        TAG_MOUNT_POINT => "MOUNT_POINT",
        0xC000_0004 => "HSM",
        0x8000_0005 => "DRIVE_EXTENDER",
        0x8000_0006 => "HSM2",
        0x8000_0007 => "SIS",
        0x8000_0008 => "WIM",
        0x8000_0009 => "CSV",
        0x8000_000A => "DFS",
        0x8000_000B => "FILTER_MANAGER",
        TAG_SYMLINK => "SYMLINK",
        0xA000_0010 => "IIS_CACHE",
        0x8000_0012 => "DFSR",
        0x8000_0013 => "DEDUP",
        0xC000_0014 => "APPXSTRM",
        0x8000_0014 => "NFS",
        0x8000_0015 => "FILE_PLACEHOLDER",
        0x8000_0016 => "DFM",
        0x8000_0017 => "WOF",
        0x8000_0018 => "WCI",
        0x9000_1018 => "WCI_1",
        0xA000_0019 => "GLOBAL_REPARSE",
        0x9000_001A => "CLOUD",
        t if t & 0xFFFF_0FFF == 0x9000_001A => "CLOUD_N",
        TAG_APPEXECLINK => "APPEXECLINK",
        0x9000_001C => "PROJFS",
        TAG_LX_SYMLINK => "LX_SYMLINK",
        0x8000_001E => "STORAGE_SYNC",
        0xA000_001F => "WCI_TOMBSTONE",
        0x8000_0020 => "UNHANDLED",
        0x8000_0021 => "ONEDRIVE",
        0xA000_0022 => "PROJFS_TOMBSTONE",
        0x8000_0023 => "AF_UNIX",
        0x8000_0024 => "LX_FIFO",
        0x8000_0025 => "LX_CHR",
        0x8000_0026 => "LX_BLK",
        0xA000_0027 => "WCI_LINK",
        0xA000_1027 => "WCI_LINK_1",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    /// Builds a reparse point value: header, optional GUID, then `data`.
    fn reparse_value(tag: u32, guid: Option<[u8; 16]>, data: &[u8]) -> Vec<u8> {
        let mut v = tag.to_le_bytes().to_vec();
        v.extend_from_slice(&(data.len() as u16).to_le_bytes());
        v.extend_from_slice(&[0, 0]);
        if let Some(guid) = guid {
            v.extend_from_slice(&guid);
        }
        v.extend_from_slice(data);
        v
    }

    /// Symlink / mount point data: four name fields, optional flags, then the path buffer.
    fn link_data(substitute: &str, print: &str, flags: Option<u32>) -> Vec<u8> {
        let (sub, prn) = (utf16(substitute), utf16(print));
        let mut v = Vec::new();
        for field in [0, sub.len(), sub.len(), prn.len()] {
            v.extend_from_slice(&(field as u16).to_le_bytes());
        }
        if let Some(flags) = flags {
            v.extend_from_slice(&flags.to_le_bytes());
        }
        v.extend_from_slice(&sub);
        v.extend_from_slice(&prn);
        v
    }

    #[test]
    fn relative_symlink() {
        let value = reparse_value(TAG_SYMLINK, None, &link_data("..\\a", "..\\a", Some(1)));
        let rp = ReparsePointAttr::from_slice(&value).unwrap();

        assert_eq!(rp.tag_name, Some("SYMLINK"));
        assert!(rp.guid.is_none());
        match rp.data {
            ReparseData::SymbolicLink {
                substitute_name,
                print_name,
                relative,
            } => {
                assert_eq!(substitute_name, "..\\a");
                assert_eq!(print_name, "..\\a");
                assert!(relative);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn app_exec_link() {
        let mut data = 3u32.to_le_bytes().to_vec();
        for s in [
            "Pkg_8wekyb3d8bbwe",
            "Pkg_8wekyb3d8bbwe!App",
            "C:\\Program Files\\a.exe",
            "0",
        ] {
            data.extend_from_slice(&utf16(s));
            data.extend_from_slice(&[0, 0]);
        }
        let value = reparse_value(TAG_APPEXECLINK, None, &data);

        match ReparsePointAttr::from_slice(&value).unwrap().data {
            ReparseData::AppExecLink {
                package_id,
                app_user_model_id,
                target_path,
            } => {
                assert_eq!(package_id, "Pkg_8wekyb3d8bbwe");
                assert_eq!(app_user_model_id, "Pkg_8wekyb3d8bbwe!App");
                assert_eq!(target_path, "C:\\Program Files\\a.exe");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn lx_symlink() {
        let mut data = 2u32.to_le_bytes().to_vec();
        data.extend_from_slice(b"/usr/bin/python3");
        let value = reparse_value(TAG_LX_SYMLINK, None, &data);

        match ReparsePointAttr::from_slice(&value).unwrap().data {
            ReparseData::LxSymlink { target } => assert_eq!(target, "/usr/bin/python3"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn third_party_tag_has_guid_and_raw_data() {
        let value = reparse_value(0x0000_1234, Some([0xAB; 16]), &[1, 2, 3]);
        let rp = ReparsePointAttr::from_slice(&value).unwrap();

        assert_eq!(rp.tag_name, None);
        assert!(rp.guid.is_some());
        assert!(matches!(rp.data, ReparseData::Other { data: [1, 2, 3] }));
    }

    #[test]
    fn malformed_data_falls_back_to_raw() {
        // A mount point whose name offsets point past the end of the data.
        let mut data = link_data("\\??\\C:\\x", "C:\\x", None);
        data[0] = 0xFF;
        let value = reparse_value(TAG_MOUNT_POINT, None, &data);
        let rp = ReparsePointAttr::from_slice(&value).unwrap();

        assert_eq!(rp.tag_name, Some("MOUNT_POINT"));
        assert!(matches!(rp.data, ReparseData::Other { .. }));
    }

    #[test]
    fn short_value_is_none() {
        assert!(ReparsePointAttr::from_slice(&[0x03, 0x00, 0x00, 0xA0]).is_none());
        // Third-party tags need room for the GUID.
        assert!(ReparsePointAttr::from_slice(&reparse_value(0x1234, None, &[])).is_none());
    }

    #[test]
    fn cloud_tag_variants_are_named() {
        assert_eq!(tag_name(0x9000_001A), Some("CLOUD"));
        assert_eq!(tag_name(0x9000_701A), Some("CLOUD_N"));
        assert_eq!(tag_name(0x9000_701B), None);
    }
}
