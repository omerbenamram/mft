//! NTFS name matching primitives (UTF-16 code units + deterministic case folding).
//!
//! Key properties:
//! - Comparisons operate on **UTF-16 code units** (`u16`), not Unicode scalar values.
//!   NTFS names may contain **unpaired surrogates**, which must be preserved and compared
//!   deterministically.
//! - Case-insensitive comparisons use the per-volume `$UpCase` table, making behavior
//!   deterministic and independent of host locale/Unicode library behavior.

pub mod file_name;
pub mod upcase;

use std::cmp::Ordering;

pub use file_name::FileNameKey;
pub use upcase::UpcaseTable;

/// Case-sensitive equality over UTF-16 code units.
pub fn eq_case_sensitive(a: &[u16], b: &[u16]) -> bool {
    a == b
}

/// NTFS case-insensitive equality over UTF-16 code units using a `$UpCase` table.
pub fn eq_case_insensitive_ntfs(upcase: &UpcaseTable, a: &[u16], b: &[u16]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .all(|(&aa, &bb)| upcase.map_u16(aa) == upcase.map_u16(bb))
}

/// NTFS case-insensitive ordering over UTF-16 code units using a `$UpCase` table.
///
/// This matches the typical collation behavior used by the `$I30` filename index:
/// compare the uppercased code units lexicographically, then by length.
pub fn cmp_case_insensitive_ntfs(upcase: &UpcaseTable, a: &[u16], b: &[u16]) -> Ordering {
    for (&aa, &bb) in a.iter().zip(b.iter()) {
        let aa = upcase.map_u16(aa);
        let bb = upcase.map_u16(bb);
        if aa != bb {
            return aa.cmp(&bb);
        }
    }
    a.len().cmp(&b.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eq_case_sensitive_works_for_surrogates() {
        let a = vec![0x0041, 0xD800, 0x0042]; // 'A', unpaired high surrogate, 'B'
        let b = vec![0x0041, 0xD800, 0x0042];
        let c = vec![0x0041, 0xD801, 0x0042];
        assert!(eq_case_sensitive(&a, &b));
        assert!(!eq_case_sensitive(&a, &c));
    }

    #[test]
    fn test_eq_case_insensitive_ntfs_ascii_and_non_ascii_with_synthetic_table() {
        let mut map = (0u32..upcase::UPCASE_CHARACTER_COUNT as u32)
            .map(|v| v as u16)
            .collect::<Vec<_>>();

        // ASCII mapping for test.
        map[b'a' as usize] = b'A' as u16;
        map[b'z' as usize] = b'Z' as u16;

        // Non-ASCII example: ä (U+00E4) -> Ä (U+00C4)
        map[0x00E4] = 0x00C4;

        let up = UpcaseTable::from_mapping_for_tests(map);

        assert!(eq_case_insensitive_ntfs(
            &up,
            &[b'a' as u16],
            &[b'A' as u16]
        ));
        assert!(eq_case_insensitive_ntfs(&up, &[0x00E4], &[0x00C4]));

        // Surrogates remain deterministic (identity mapping by default).
        assert!(eq_case_insensitive_ntfs(&up, &[0xD800], &[0xD800]));
        assert!(!eq_case_insensitive_ntfs(&up, &[0xD800], &[0xD801]));
    }

    #[test]
    fn test_cmp_case_insensitive_ntfs_is_lexicographic_then_by_length() {
        let up = UpcaseTable::identity_for_tests();
        assert_eq!(
            cmp_case_insensitive_ntfs(&up, &[b'a' as u16], &[b'b' as u16]),
            std::cmp::Ordering::Less
        );
        assert_eq!(
            cmp_case_insensitive_ntfs(&up, &[b'a' as u16], &[b'a' as u16, b'a' as u16]),
            std::cmp::Ordering::Less
        );
    }
}
