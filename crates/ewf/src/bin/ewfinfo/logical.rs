//! Formatting helpers for `ewfinfo` logical-evidence modes (`-F` / `-H`).
//!
//! These outputs intentionally live in the binary crate (not `ewf`’s library API), mirroring
//! libewf’s `info_handle_file_entry_*` and `info_handle_logical_files_hierarchy_*` printing
//! functions.
//!
//! References:
//! - `external/libewf/ewftools/info_handle.c`
//! - `external/libewf/manuals/ewfinfo.1`

use ewf::LefEntry;

pub fn normalize_query_path(path: &str) -> String {
    // Match `ewf::LefReader`’s normalization (`normalize_lef_path`).
    path.replace('\\', "/").trim_start_matches("./").to_string()
}

pub fn display_path(path: &str, separator: char) -> String {
    match separator {
        '/' => path.to_string(),
        '\\' => path.replace('/', "\\"),
        other => path.replace('/', &other.to_string()),
    }
}

pub fn find_entry_by_path<'a>(entries: &'a [LefEntry], query: &str) -> Option<&'a LefEntry> {
    let want = normalize_query_path(query);
    entries.iter().find(|e| e.path == want)
}

pub fn render_hierarchy_text(entries: &[LefEntry], separator: char) -> String {
    let mut out = String::new();
    for e in entries {
        out.push_str(&display_path(&e.path, separator));
        out.push('\n');
    }
    out
}

pub fn render_file_entry_text(entry: &LefEntry, separator: char) -> String {
    let mut out = String::new();

    out.push_str("File entry information:\n");
    out.push_str(&format!(
        "\tName\t\t\t\t: {}\n",
        display_path(&entry.path, separator)
    ));
    out.push_str(&format!(
        "\tType\t\t\t\t: {}\n",
        if entry.is_dir { "directory" } else { "file" }
    ));

    match entry.file_identifier {
        Some(v) => out.push_str(&format!("\tFile identifier\t\t\t: {v}\n")),
        None => out.push_str("\tFile identifier\t\t\t: N/A\n"),
    }

    out.push_str(&format!("\tSize\t\t\t\t: {}\n", entry.size));

    let fmt_time = |t: Option<i64>| match t {
        Some(v) => v.to_string(),
        None => "N/A".to_string(),
    };

    out.push_str(&format!(
        "\tAccess time\t\t\t: {}\n",
        fmt_time(entry.access_time)
    ));
    out.push_str(&format!(
        "\tModification time\t\t: {}\n",
        fmt_time(entry.modification_time)
    ));
    out.push_str(&format!(
        "\tEntry modification time\t\t: {}\n",
        fmt_time(entry.entry_modification_time)
    ));
    out.push_str(&format!(
        "\tCreation time\t\t\t: {}\n",
        fmt_time(entry.creation_time)
    ));

    out.push('\n');

    if entry.extents.is_empty() {
        out.push_str("Extents: none\n");
        return out;
    }

    out.push_str("Extents:\n");
    for (idx, ext) in entry.extents.iter().enumerate() {
        out.push_str(&format!(
            "\t{idx}\t\t\t\t: offset={} size={}\n",
            ext.offset, ext.size
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ewf::LefExtent;

    #[test]
    fn test_normalize_query_path_backslashes_and_dot_slash() {
        assert_eq!(normalize_query_path(r".\dir\file.txt"), "dir/file.txt");
    }

    #[test]
    fn test_render_hierarchy_text_respects_separator() {
        let entries = vec![
            LefEntry {
                path: "dir".to_string(),
                is_dir: true,
                size: 0,
                extents: vec![],
                file_identifier: Some(1),
                access_time: None,
                modification_time: None,
                entry_modification_time: None,
                creation_time: None,
            },
            LefEntry {
                path: "dir/file.txt".to_string(),
                is_dir: false,
                size: 5,
                extents: vec![LefExtent { offset: 0, size: 5 }],
                file_identifier: Some(2),
                access_time: None,
                modification_time: None,
                entry_modification_time: None,
                creation_time: None,
            },
        ];

        assert_eq!(
            render_hierarchy_text(&entries, '\\'),
            "dir\ndir\\file.txt\n"
        );
    }
}
