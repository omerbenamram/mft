use std::fmt::Write;

use crate::attribute::raw::data_as_hex;
use crate::impl_serialize_for_bitflags;
use crate::utils::{read_u16, read_u32};
use bitflags::bitflags;
use serde::Serialize;
use winstructs::guid::Guid;

/// $SECURITY_DESCRIPTOR Attribute: a self-relative security descriptor.
/// <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7d4dac05-9cef-4563-a058-f108abecce1d>
///
/// Since NTFS 3.0, most files only keep a security ID in `$STANDARD_INFORMATION` and the
/// descriptor itself is in `$Secure`, so a resident one is mostly found on system files and on
/// volumes that started out as NTFS 1.x.
///
/// Parsed here rather than with `winstructs::security`, which in 0.3.2 drops the control flags,
/// miscomputes SID authorities and reads object ACE GUIDs whether or not they are present.
#[derive(Serialize, Clone, Debug)]
pub struct SecurityDescriptorAttr<'a> {
    pub revision: u8,
    pub control: SecurityDescriptorControl,
    /// The owner, as a SID string (`S-1-5-18`). Absent when the descriptor has none.
    pub owner: Option<String>,
    pub group: Option<String>,
    /// Only read when `control` has `SE_SACL_PRESENT`.
    pub sacl: Option<Acl<'a>>,
    /// Only read when `control` has `SE_DACL_PRESENT`. A present flag without a DACL is a
    /// NULL DACL, which grants everyone full access.
    pub dacl: Option<Acl<'a>>,
}

bitflags! {
    /// `SECURITY_DESCRIPTOR_CONTROL`.
    #[derive(Default, Clone, Debug, PartialEq)]
    pub struct SecurityDescriptorControl: u16 {
        const SE_OWNER_DEFAULTED       = 0x0001;
        const SE_GROUP_DEFAULTED       = 0x0002;
        const SE_DACL_PRESENT          = 0x0004;
        const SE_DACL_DEFAULTED        = 0x0008;
        const SE_SACL_PRESENT          = 0x0010;
        const SE_SACL_DEFAULTED        = 0x0020;
        const SE_DACL_UNTRUSTED        = 0x0040;
        const SE_SERVER_SECURITY       = 0x0080;
        const SE_DACL_AUTO_INHERIT_REQ = 0x0100;
        const SE_SACL_AUTO_INHERIT_REQ = 0x0200;
        const SE_DACL_AUTO_INHERITED   = 0x0400;
        const SE_SACL_AUTO_INHERITED   = 0x0800;
        const SE_DACL_PROTECTED        = 0x1000;
        const SE_SACL_PROTECTED        = 0x2000;
        const SE_RM_CONTROL_VALID      = 0x4000;
        const SE_SELF_RELATIVE         = 0x8000;
    }
}

impl_serialize_for_bitflags! {SecurityDescriptorControl}

/// An access control list.
#[derive(Serialize, Clone, Debug)]
pub struct Acl<'a> {
    pub revision: u8,
    pub entries: Vec<Ace<'a>>,
}

/// An access control entry.
/// <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586>
#[derive(Serialize, Clone, Debug)]
pub struct Ace<'a> {
    pub ace_type: u8,
    /// The name of a documented type (for example `ACCESS_ALLOWED`), without the `_ACE_TYPE`
    /// suffix.
    pub ace_type_name: Option<&'static str>,
    pub flags: AceFlags,
    /// The access mask. Absent for types whose layout isn't decoded.
    pub access_mask: Option<u32>,
    /// The object type of an object ACE, when its flags say it has one.
    pub object_type: Option<Guid>,
    /// The inherited object type of an object ACE, when its flags say it has one.
    pub inherited_object_type: Option<Guid>,
    pub sid: Option<String>,
    /// The bytes after the decoded fields (for example a callback ACE's application data), or
    /// the whole body for types whose layout isn't decoded.
    #[serde(serialize_with = "data_as_hex")]
    pub data: &'a [u8],
}

bitflags! {
    #[derive(Default, Clone, Debug, PartialEq)]
    pub struct AceFlags: u8 {
        const OBJECT_INHERIT_ACE         = 0x01;
        const CONTAINER_INHERIT_ACE      = 0x02;
        const NO_PROPAGATE_INHERIT_ACE   = 0x04;
        const INHERIT_ONLY_ACE           = 0x08;
        const INHERITED_ACE              = 0x10;
        const CRITICAL_ACE_FLAG          = 0x20;
        const SUCCESSFUL_ACCESS_ACE_FLAG = 0x40;
        const FAILED_ACCESS_ACE_FLAG     = 0x80;
    }
}

impl_serialize_for_bitflags! {AceFlags}

/// `ACE_OBJECT_TYPE_PRESENT` and `ACE_INHERITED_OBJECT_TYPE_PRESENT`.
const OBJECT_TYPE_PRESENT: u32 = 0x1;
const INHERITED_OBJECT_TYPE_PRESENT: u32 = 0x2;

impl<'a> SecurityDescriptorAttr<'a> {
    /// Parses a self-relative security descriptor. Returns `None` when a SID or ACL runs past
    /// the value, or an ACE past its ACL.
    ///
    /// # Example
    ///
    /// ```
    /// use mft::attribute::x50::{SecurityDescriptorAttr, SecurityDescriptorControl};
    ///
    /// // Owner SYSTEM (S-1-5-18), group Administrators (S-1-5-32-544), no ACLs.
    /// let value: &[u8] = &[
    ///     0x01, 0x00, 0x00, 0x80, 0x14, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
    ///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
    ///     0x12, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00,
    ///     0x00, 0x00, 0x20, 0x02, 0x00, 0x00,
    /// ];
    ///
    /// let descriptor = SecurityDescriptorAttr::from_slice(value).unwrap();
    /// assert_eq!(descriptor.control, SecurityDescriptorControl::SE_SELF_RELATIVE);
    /// assert_eq!(descriptor.owner.as_deref(), Some("S-1-5-18"));
    /// assert_eq!(descriptor.group.as_deref(), Some("S-1-5-32-544"));
    /// assert!(descriptor.dacl.is_none());
    /// ```
    pub fn from_slice(value: &'a [u8]) -> Option<Self> {
        let control = SecurityDescriptorControl::from_bits_retain(read_u16(value, 2)?);
        let sid_at = |field| match read_u32(value, field)? {
            0 => Some(None),
            offset => sid(value, offset as usize).map(|(sid, _)| Some(sid)),
        };
        let acl_at = |field, present| match read_u32(value, field)? {
            offset if offset != 0 && control.contains(present) => {
                Acl::from_slice(value.get(offset as usize..)?).map(Some)
            }
            _ => Some(None),
        };

        Some(SecurityDescriptorAttr {
            revision: *value.first()?,
            owner: sid_at(4)?,
            group: sid_at(8)?,
            sacl: acl_at(12, SecurityDescriptorControl::SE_SACL_PRESENT)?,
            dacl: acl_at(16, SecurityDescriptorControl::SE_DACL_PRESENT)?,
            control,
        })
    }
}

impl<'a> Acl<'a> {
    /// Parses an ACL at the start of `value`. Its ACEs must fit in the ACL's size.
    fn from_slice(value: &'a [u8]) -> Option<Self> {
        let size = usize::from(read_u16(value, 2)?);
        let count = read_u16(value, 4)?;
        let acl = value.get(..size)?;

        let mut offset = 8;
        let entries = (0..count)
            .map(|_| {
                let ace_size = usize::from(read_u16(acl, offset + 2)?);
                let ace = acl.get(offset..offset.checked_add(ace_size)?)?;
                offset += ace_size;
                Ace::from_slice(ace)
            })
            .collect::<Option<_>>()?;

        Some(Acl {
            revision: *acl.first()?,
            entries,
        })
    }
}

impl<'a> Ace<'a> {
    /// Parses one ACE, `ace` being exactly its size.
    fn from_slice(ace: &'a [u8]) -> Option<Self> {
        let ace_type = *ace.first()?;
        let flags = AceFlags::from_bits_retain(*ace.get(1)?);
        let body = ace.get(4..)?;

        let mut decoded = Ace {
            ace_type,
            ace_type_name: ace_type_name(ace_type),
            flags,
            access_mask: None,
            object_type: None,
            inherited_object_type: None,
            sid: None,
            data: body,
        };

        let sid_offset = match ace_type {
            // The compound ACE and undocumented types keep their body undecoded.
            0x04 | 0x16.. => return Some(decoded),
            // Object ACEs: the mask, which object types follow, the object types, then the SID.
            0x05..=0x08 | 0x0B | 0x0C | 0x0F | 0x10 => {
                let object_flags = read_u32(body, 4)?;
                let mut offset = 8;
                for (present, object_type) in [
                    (OBJECT_TYPE_PRESENT, &mut decoded.object_type),
                    (
                        INHERITED_OBJECT_TYPE_PRESENT,
                        &mut decoded.inherited_object_type,
                    ),
                ] {
                    if object_flags & present != 0 {
                        *object_type =
                            Some(Guid::from_buffer(body.get(offset..offset + 16)?).ok()?);
                        offset += 16;
                    }
                }
                offset
            }
            // The other documented types: the mask, then the SID.
            _ => 4,
        };

        decoded.access_mask = Some(read_u32(body, 0)?);
        let (sid, sid_len) = sid(body, sid_offset)?;
        decoded.sid = Some(sid);
        decoded.data = body.get(sid_offset + sid_len..)?;
        Some(decoded)
    }
}

/// Formats the SID at `offset` as a string, and returns its length.
/// <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f992ad60-0fe4-4b87-9fed-beb478836861>
fn sid(value: &[u8], offset: usize) -> Option<(String, usize)> {
    let header = value.get(offset..offset.checked_add(8)?)?;
    let count = usize::from(header[1]);
    // The identifier authority is a 48-bit big-endian number.
    let authority = header[2..8]
        .iter()
        .fold(0u64, |acc, &b| (acc << 8) | u64::from(b));

    let mut sid = format!("S-{}-{authority}", header[0]);
    for i in 0..count {
        let sub_authority = read_u32(value, offset + 8 + 4 * i)?;
        let _ = write!(sid, "-{sub_authority}");
    }
    Some((sid, 8 + 4 * count))
}

/// Names for the documented ACE types.
fn ace_type_name(ace_type: u8) -> Option<&'static str> {
    Some(match ace_type {
        0x00 => "ACCESS_ALLOWED",
        0x01 => "ACCESS_DENIED",
        0x02 => "SYSTEM_AUDIT",
        0x03 => "SYSTEM_ALARM",
        0x04 => "ACCESS_ALLOWED_COMPOUND",
        0x05 => "ACCESS_ALLOWED_OBJECT",
        0x06 => "ACCESS_DENIED_OBJECT",
        0x07 => "SYSTEM_AUDIT_OBJECT",
        0x08 => "SYSTEM_ALARM_OBJECT",
        0x09 => "ACCESS_ALLOWED_CALLBACK",
        0x0A => "ACCESS_DENIED_CALLBACK",
        0x0B => "ACCESS_ALLOWED_CALLBACK_OBJECT",
        0x0C => "ACCESS_DENIED_CALLBACK_OBJECT",
        0x0D => "SYSTEM_AUDIT_CALLBACK",
        0x0E => "SYSTEM_ALARM_CALLBACK",
        0x0F => "SYSTEM_AUDIT_CALLBACK_OBJECT",
        0x10 => "SYSTEM_ALARM_CALLBACK_OBJECT",
        0x11 => "SYSTEM_MANDATORY_LABEL",
        0x12 => "SYSTEM_RESOURCE_ATTRIBUTE",
        0x13 => "SYSTEM_SCOPED_POLICY_ID",
        0x14 => "SYSTEM_PROCESS_TRUST_LABEL",
        0x15 => "SYSTEM_ACCESS_FILTER",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `$Volume` descriptor from `samples/MFT`: owner and group Administrators, and a DACL
    /// allowing SYSTEM and Administrators.
    const VOLUME: &str = "01000480480000005800000000000000140000000200340002000000000014009F011200010100000000000512000000000018009F011200010200000000000520000000200200000102000000000005200000002002000001020000000000052000000020020000";

    fn volume() -> Vec<u8> {
        (0..VOLUME.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&VOLUME[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn parses_owner_group_and_dacl() {
        let value = volume();
        let descriptor = SecurityDescriptorAttr::from_slice(&value).unwrap();
        assert_eq!(
            descriptor.control,
            SecurityDescriptorControl::SE_SELF_RELATIVE
                | SecurityDescriptorControl::SE_DACL_PRESENT
        );
        assert_eq!(descriptor.owner.as_deref(), Some("S-1-5-32-544"));
        assert_eq!(descriptor.group.as_deref(), Some("S-1-5-32-544"));
        assert!(descriptor.sacl.is_none());

        let aces: Vec<_> = descriptor
            .dacl
            .unwrap()
            .entries
            .into_iter()
            .map(|ace| (ace.ace_type_name, ace.access_mask, ace.sid, ace.data.len()))
            .collect();
        assert_eq!(
            aces,
            [
                (
                    Some("ACCESS_ALLOWED"),
                    Some(0x0012_019F),
                    Some("S-1-5-18".into()),
                    0
                ),
                (
                    Some("ACCESS_ALLOWED"),
                    Some(0x0012_019F),
                    Some("S-1-5-32-544".into()),
                    0
                ),
            ]
        );
    }

    #[test]
    fn absent_owner_and_null_dacl() {
        let mut value = volume();
        value[4..8].fill(0);
        value[16..20].fill(0);
        let descriptor = SecurityDescriptorAttr::from_slice(&value).unwrap();
        assert!(descriptor.owner.is_none());
        // SE_DACL_PRESENT without a DACL: a NULL DACL.
        assert!(descriptor.dacl.is_none());
        assert!(
            descriptor
                .control
                .contains(SecurityDescriptorControl::SE_DACL_PRESENT)
        );
    }

    #[test]
    fn acl_offsets_without_their_present_flag_are_ignored() {
        let mut value = volume();
        // Clear SE_DACL_PRESENT, and point the SACL at the DACL without setting its flag.
        value[2] &= !0x04;
        value[12..16].copy_from_slice(&0x14u32.to_le_bytes());
        let descriptor = SecurityDescriptorAttr::from_slice(&value).unwrap();
        assert!(descriptor.dacl.is_none());
        assert!(descriptor.sacl.is_none());
    }

    #[test]
    fn sid_authority_is_48_bit_big_endian() {
        let value = [1, 1, 0, 0, 0, 1, 0, 0, 7, 0, 0, 0];
        assert_eq!(sid(&value, 0), Some(("S-1-65536-7".to_string(), 12)));
    }

    #[test]
    fn object_ace_reads_only_the_object_types_it_flags() {
        // ACCESS_ALLOWED_OBJECT with only an inherited object type, then SID S-1-1-0.
        let mut ace = vec![0x05, 0x00, 0, 0];
        ace.extend_from_slice(&0x10u32.to_le_bytes());
        ace.extend_from_slice(&INHERITED_OBJECT_TYPE_PRESENT.to_le_bytes());
        ace.extend_from_slice(&[0xAA; 16]);
        ace.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]);
        let size = ace.len() as u16;
        ace[2..4].copy_from_slice(&size.to_le_bytes());

        let ace = Ace::from_slice(&ace).unwrap();
        assert!(ace.object_type.is_none());
        assert!(ace.inherited_object_type.is_some());
        assert_eq!(ace.sid.as_deref(), Some("S-1-1-0"));
    }

    #[test]
    fn unknown_ace_type_keeps_its_body() {
        let ace = [0x40, 0x00, 6, 0, 0xAB, 0xCD];
        let ace = Ace::from_slice(&ace).unwrap();
        assert_eq!(ace.ace_type_name, None);
        assert_eq!(ace.access_mask, None);
        assert_eq!(ace.data, &[0xAB, 0xCD]);
    }

    #[test]
    fn corrupt_sizes_are_rejected() {
        // An ACE size below its own header.
        let mut value = volume();
        value[0x1E..0x20].copy_from_slice(&3u16.to_le_bytes());
        assert!(SecurityDescriptorAttr::from_slice(&value).is_none());

        // An ACL size too small for its ACEs.
        let mut value = volume();
        value[0x16..0x18].copy_from_slice(&0x1Cu16.to_le_bytes());
        assert!(SecurityDescriptorAttr::from_slice(&value).is_none());

        // A truncated value.
        assert!(SecurityDescriptorAttr::from_slice(&volume()[..0x30]).is_none());
    }
}
