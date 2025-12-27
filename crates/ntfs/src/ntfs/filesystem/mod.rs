mod file_system;

pub use file_system::{DirectoryEntry, FileSystem};

/// Returns `true` if the directory entry name is `"."` or `".."`.
///
/// These entries are typically present in directory indexes but are not useful for most callers.
pub fn is_dot_dir_entry(name: &str) -> bool {
    name == "." || name == ".."
}

/// Joins an NTFS path (using `\` separators) with a child name.
///
/// This helper keeps the root path as `\` (i.e. `join_ntfs_child_path("\\", "Windows")`
/// becomes `\\Windows`).
pub fn join_ntfs_child_path(parent_path: &str, child_name: &str) -> String {
    if parent_path == "\\" {
        return format!("\\{child_name}");
    }
    if parent_path.ends_with('\\') {
        return format!("{parent_path}{child_name}");
    }
    format!("{parent_path}\\{child_name}")
}

#[cfg(test)]
mod tests {
    use super::{is_dot_dir_entry, join_ntfs_child_path};

    #[test]
    fn test_is_dot_dir_entry() {
        assert!(is_dot_dir_entry("."));
        assert!(is_dot_dir_entry(".."));
        assert!(!is_dot_dir_entry("..."));
        assert!(!is_dot_dir_entry("Windows"));
    }

    #[test]
    fn test_join_ntfs_child_path_root() {
        assert_eq!(join_ntfs_child_path("\\", "Windows"), "\\Windows");
    }

    #[test]
    fn test_join_ntfs_child_path_non_root() {
        assert_eq!(
            join_ntfs_child_path("\\Windows", "System32"),
            "\\Windows\\System32"
        );
    }

    #[test]
    fn test_join_ntfs_child_path_parent_with_trailing_separator() {
        assert_eq!(
            join_ntfs_child_path("\\Windows\\", "System32"),
            "\\Windows\\System32"
        );
    }
}
