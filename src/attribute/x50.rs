use crate::utils::{read_u16, read_u32};
use std::io::Cursor;
use winstructs::security::SecurityDescriptor;

/// Parses a resident `$SECURITY_DESCRIPTOR` value: a self-relative security descriptor with the
/// owner, group and access control lists. Since NTFS 3.0, most files only keep a security ID in
/// `$STANDARD_INFORMATION` and the descriptor itself is in `$Secure`, so this is mostly found on
/// system files and on volumes that started out as NTFS 1.x. Returns `None` when the value
/// doesn't parse.
///
/// # Example
///
/// ```
/// use mft::attribute::x50::parse_security_descriptor;
///
/// // Owner SYSTEM (S-1-5-18), group Administrators (S-1-5-32-544), no ACLs.
/// let value: &[u8] = &[
///     0x01, 0x00, 0x00, 0x80, 0x14, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
///     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
///     0x12, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00,
///     0x00, 0x00, 0x20, 0x02, 0x00, 0x00,
/// ];
///
/// let descriptor = parse_security_descriptor(value).unwrap();
/// assert_eq!(descriptor.owner_sid.to_string(), "S-1-5-18");
/// assert_eq!(descriptor.group_sid.to_string(), "S-1-5-32-544");
/// assert!(descriptor.dacl.is_none());
/// ```
pub fn parse_security_descriptor(value: &[u8]) -> Option<SecurityDescriptor> {
    if !aces_have_valid_sizes(value) {
        return None;
    }
    SecurityDescriptor::from_stream(&mut Cursor::new(value)).ok()
}

/// `winstructs` takes the 4-byte header off each ACE's size without checking it, which
/// underflows on a corrupt size below 4. Checks every ACE of the SACL (offset at 12) and DACL
/// (offset at 16) first.
fn aces_have_valid_sizes(value: &[u8]) -> bool {
    [12, 16].into_iter().all(|field| {
        let Some(acl_offset) = read_u32(value, field) else {
            return false;
        };
        if acl_offset == 0 {
            return true;
        }
        let acl_offset = acl_offset as usize;
        let Some(count) = read_u16(value, acl_offset.saturating_add(4)) else {
            return false;
        };
        let mut ace_offset = acl_offset.saturating_add(8);
        (0..count).all(|_| match read_u16(value, ace_offset.saturating_add(2)) {
            Some(size) if size >= 4 => {
                ace_offset = ace_offset.saturating_add(usize::from(size));
                true
            }
            _ => false,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `$Volume` descriptor from `samples/MFT`: owner SYSTEM, group Administrators and a
    /// DACL with two ACEs.
    const VOLUME: &str = "01000480480000005800000000000000140000000200340002000000000014009F011200010100000000000512000000000018009F011200010200000000000520000000200200000102000000000005200000002002000001020000000000052000000020020000";

    fn volume() -> Vec<u8> {
        (0..VOLUME.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&VOLUME[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn parses_owner_group_and_dacl() {
        let descriptor = parse_security_descriptor(&volume()).unwrap();
        assert_eq!(descriptor.owner_sid.to_string(), "S-1-5-32-544");
        assert_eq!(descriptor.group_sid.to_string(), "S-1-5-32-544");
        let dacl = descriptor.dacl.unwrap();
        assert_eq!(dacl.entries.len(), 2);
        assert!(descriptor.sacl.is_none());
    }

    #[test]
    fn ace_size_below_its_header_is_rejected_not_a_panic() {
        let mut value = volume();
        // The DACL starts at 0x14, and its first ACE's size is at 0x14 + 8 + 2.
        value[0x1E..0x20].copy_from_slice(&3u16.to_le_bytes());
        assert!(parse_security_descriptor(&value).is_none());
    }

    #[test]
    fn truncated_value_is_rejected() {
        let value = volume();
        assert!(parse_security_descriptor(&value[..0x30]).is_none());
    }
}
