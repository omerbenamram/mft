use std::cmp::Reverse;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use mft::attribute::x30::FileNamespace;
use mft::attribute::{FileAttributeFlags, MftAttributeType};

/// A read-only, metadata-only view built from a standalone `$MFT` snapshot.
///
/// This is intentionally limited:
/// - Directory listings are derived from `FILE_NAME` attributes (so hardlinks can appear).
/// - File content export is **not** available (no clusters / data runs can be followed).
#[derive(Debug)]
pub struct MftOnlySnapshot {
    entry_meta: HashMap<u64, EntryMeta>,
    children_by_parent: HashMap<u64, Vec<DirChild>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryMeta {
    pub is_dir: bool,
    pub is_allocated: bool,
    pub efs_encrypted: bool,
}

#[derive(Clone, Debug)]
pub struct DirChild {
    pub name: String,
    pub entry_id: u64,
    pub namespace: FileNamespace,
    pub logical_size: u64,
    pub modified_unix_s: i64,
}

impl MftOnlySnapshot {
    pub fn open(path: &Path) -> Result<Arc<Self>, String> {
        let mut parser =
            mft::MftParser::from_path(path).map_err(|e| format!("open MFT snapshot: {e}"))?;
        let entry_count = parser.get_entry_count();

        // Group `FILE_NAME` attrs by (entry_id, parent_id) so we can filter DOS 8.3 aliases when a
        // Win32 long name exists for the same parent.
        let mut file_names_by_entry_parent: HashMap<(u64, u64), Vec<DirChild>> = HashMap::new();
        let mut entry_meta: HashMap<u64, EntryMeta> = HashMap::new();

        for entry_id in 0..entry_count {
            let entry = match parser.get_entry(entry_id) {
                Ok(e) => e,
                Err(_) => continue,
            };
            if !entry.header.is_valid() {
                continue;
            }

            entry_meta.insert(
                entry_id,
                EntryMeta {
                    is_dir: entry.is_dir(),
                    is_allocated: entry.is_allocated(),
                    efs_encrypted: is_entry_efs_encrypted(&entry),
                },
            );

            for attr in entry
                .iter_attributes_matching(Some(vec![MftAttributeType::FileName]))
                .filter_map(std::result::Result::ok)
            {
                let Some(fname) = attr.data.into_file_name() else {
                    continue;
                };

                let parent_id = fname.parent.entry;
                file_names_by_entry_parent
                    .entry((entry_id, parent_id))
                    .or_default()
                    .push(DirChild {
                        name: fname.name,
                        entry_id,
                        namespace: fname.namespace,
                        logical_size: fname.logical_size,
                        modified_unix_s: fname.modified.as_second(),
                    });
            }
        }

        // Apply DOS alias filtering and invert into parent -> children.
        let mut children_by_parent: HashMap<u64, Vec<DirChild>> = HashMap::new();
        for ((_entry_id, parent_id), mut items) in file_names_by_entry_parent {
            let has_win32 = items.iter().any(|i| {
                matches!(
                    i.namespace,
                    FileNamespace::Win32 | FileNamespace::Win32AndDos
                )
            });
            if has_win32 {
                items.retain(|i| i.namespace != FileNamespace::DOS);
            }

            children_by_parent
                .entry(parent_id)
                .or_default()
                .extend(items);
        }

        Ok(Arc::new(Self {
            entry_meta,
            children_by_parent,
        }))
    }

    pub fn entry_meta(&self, entry_id: u64) -> Option<EntryMeta> {
        self.entry_meta.get(&entry_id).copied()
    }

    pub fn list_children(&self, parent_id: u64) -> Vec<DirChild> {
        self.children_by_parent
            .get(&parent_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Resolves an NTFS-style directory path (e.g. `\Windows\System32`) to an MFT entry id.
    ///
    /// Notes:
    /// - Resolution is case-insensitive (ASCII).
    /// - Only directories are returned (since the GUI currently navigates directories).
    pub fn resolve_dir_path_including_deleted(&self, path: &str) -> Result<u64, String> {
        let mut p = path.trim().replace('/', "\\");
        if p.is_empty() || p == "\\" {
            return Ok(5);
        }

        // Allow drive-letter paths (`C:\Windows`).
        if p.len() >= 2 && p.as_bytes()[1] == b':' {
            p = p[2..].to_string();
        }

        let p = p.trim_matches('\\');
        if p.is_empty() {
            return Ok(5);
        }

        let mut cur = 5_u64;
        for part in p.split('\\').filter(|s| !s.is_empty() && *s != ".") {
            let Some(children) = self.children_by_parent.get(&cur) else {
                return Err(format!("path not found: {path}"));
            };

            let next = children
                .iter()
                .filter(|c| c.name.eq_ignore_ascii_case(part))
                .filter_map(|c| {
                    let meta = self.entry_meta(c.entry_id)?;
                    if !meta.is_dir {
                        return None;
                    }
                    let key = (
                        meta.is_allocated,
                        namespace_rank(c.namespace.clone()),
                        Reverse(c.entry_id),
                    );
                    Some((c.entry_id, key))
                })
                .max_by_key(|(_id, key)| *key)
                .map(|(id, _)| id)
                .ok_or_else(|| format!("path not found: {path}"))?;

            cur = next;
        }

        Ok(cur)
    }
}

fn namespace_rank(ns: FileNamespace) -> u8 {
    match ns {
        FileNamespace::Win32AndDos => 3,
        FileNamespace::Win32 => 2,
        FileNamespace::POSIX => 1,
        FileNamespace::DOS => 0,
    }
}

fn is_entry_efs_encrypted(entry: &mft::MftEntry) -> bool {
    for attr in entry
        .iter_attributes_matching(Some(vec![MftAttributeType::StandardInformation]))
        .filter_map(std::result::Result::ok)
    {
        if let Some(si) = attr.data.into_standard_info()
            && si
                .file_flags
                .contains(FileAttributeFlags::FILE_ATTRIBUTE_ENCRYPTED)
        {
            return true;
        }
    }
    false
}
