//! Sleuthkit bodyfile output for `ewfinfo -B`.
//!
//! libewf’s `ewfinfo` can emit logical file information in “bodyfile” format (`-B`). The bodyfile
//! is written to a file path provided on the command line, and (in libewf) is driven by traversing
//! the logical file tree (`-H`) or printing a specific entry (`-F`).
//!
//! References:
//! - `external/libewf/ewftools/info_handle.c` (bodyfile columns and traversal)
//! - `external/libewf/ewftools/bodyfile.c` (escaping rules for the name field)
//! - `external/libewf/manuals/ewfinfo.1`

use ewf::LefEntry;

use crate::logical;

/// Escapes a bodyfile name value.
///
/// This is a small, Rust-native equivalent of libewf’s
/// `bodyfile_path_string_copy_from_file_entry_path(...)`:
///
/// - Escape character (`\`) becomes `\\`
/// - Bodyfile separator (`|`) becomes `\|`
/// - ASCII control characters are replaced by `\x##` (lowercase hex)
pub fn escape_bodyfile_name(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        let code = ch as u32;

        // Control characters.
        if code <= 0x1f || (0x7f..=0x9f).contains(&code) {
            out.push('\\');
            out.push('x');
            out.push_str(&format!("{code:02x}"));
            continue;
        }

        // Escape `\` and `|`.
        if ch == '\\' || ch == '|' {
            out.push('\\');
            out.push(ch);
            continue;
        }

        out.push(ch);
    }
    out
}

pub fn render_bodyfile_line(entry: &LefEntry, separator: char) -> String {
    // Colums in a Sleuthkit 3.x and later bodyfile (as used by libewf):
    // MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
    //
    // libewf currently prints:
    // - a constant `0` as MD5,
    // - `0` for UID/GID (TODO in upstream),
    // - seconds since epoch as `%.9f`.
    let name = escape_bodyfile_name(&logical::display_path(&entry.path, separator));
    let inode = entry.file_identifier.unwrap_or(0);

    let mode = if entry.is_dir {
        "drwxrwxrwx"
    } else {
        "-rwxrwxrwx"
    };

    let atime = entry.access_time.unwrap_or(0) as f64;
    let mtime = entry.modification_time.unwrap_or(0) as f64;
    let ctime = entry.entry_modification_time.unwrap_or(0) as f64;
    let crtime = entry.creation_time.unwrap_or(0) as f64;

    format!(
        "0|{name}|{inode}|{mode}|0|0|{}|{atime:.9}|{mtime:.9}|{ctime:.9}|{crtime:.9}\n",
        entry.size
    )
}

pub fn render_bodyfile(entries: &[LefEntry], separator: char) -> String {
    let mut out = String::new();
    for e in entries {
        out.push_str(&render_bodyfile_line(e, separator));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ewf::LefEntry;

    #[test]
    fn test_escape_bodyfile_name_escapes_separator_and_backslash() {
        assert_eq!(escape_bodyfile_name(r"dir\file|name"), r"dir\\file\|name");
    }

    #[test]
    fn test_escape_bodyfile_name_escapes_control_chars() {
        assert_eq!(escape_bodyfile_name("a\nb"), r"a\x0ab");
    }

    #[test]
    fn test_render_bodyfile_line_shape() {
        let e = LefEntry {
            path: "dir/file.txt".to_string(),
            is_dir: false,
            size: 5,
            extents: vec![],
            file_identifier: Some(42),
            access_time: Some(100),
            modification_time: Some(200),
            entry_modification_time: Some(300),
            creation_time: Some(400),
        };

        assert_eq!(
            render_bodyfile_line(&e, '/'),
            "0|dir/file.txt|42|-rwxrwxrwx|0|0|5|100.000000000|200.000000000|300.000000000|400.000000000\n"
        );
    }
}
