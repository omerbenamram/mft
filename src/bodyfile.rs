//! Sleuth Kit bodyfile output, for timelining with `mactime` and similar tools.
//!
//! Lines follow the TSK 3.x layout that `fls -m` writes for NTFS:
//! `MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime`
//! <https://wiki.sleuthkit.org/index.php?title=Body_file>
use crate::attribute::header::ResidentialHeader;
use crate::attribute::{FileAttributeFlags, MftAttribute, MftAttributeType};
use crate::entry::MftEntry;

use jiff::Timestamp;
use std::io::{self, Write};
use std::path::{Component, Path};

/// MACB timestamps of one bodyfile line, as Unix seconds.
#[derive(Default)]
struct Times {
    accessed: i64,
    modified: i64,
    changed: i64,
    created: i64,
}

impl Times {
    fn new(
        accessed: Timestamp,
        modified: Timestamp,
        changed: Timestamp,
        created: Timestamp,
    ) -> Self {
        Times {
            accessed: unix_seconds(accessed),
            modified: unix_seconds(modified),
            changed: unix_seconds(changed),
            created: unix_seconds(created),
        }
    }
}

/// Writes the bodyfile lines for one entry the way `fls -m` does for NTFS:
///
/// - one line per `$DATA` attribute and per `$INDEX_ROOT` attribute, with the
///   `$STANDARD_INFORMATION` timestamps. Named streams other than a directory's `$I30` index are
///   written as `<path>:<stream>`;
/// - one line named `<path> ($FILE_NAME)` with the timestamps of the `$FILE_NAME` attribute that
///   `full_path` was built from.
///
/// The inode column is `<entry>-<attribute type>-<attribute id>` and the size column is that
/// attribute's size. Unallocated entries get ` (deleted)` after their name. Entries without a
/// `$FILE_NAME` attribute (unused or extension records) are skipped, since `fls` can't reach
/// them either. Attributes stored in extension records (through an `$ATTRIBUTE_LIST`) are not
/// followed, so a file whose `$DATA` lives there gets a single line without an attribute.
pub fn write_entry<W: Write>(out: &mut W, entry: &MftEntry, full_path: &Path) -> io::Result<()> {
    let attributes: Vec<MftAttribute> = entry
        .iter_attributes_matching(Some(vec![
            MftAttributeType::StandardInformation,
            MftAttributeType::FileName,
            MftAttributeType::DATA,
            MftAttributeType::IndexRoot,
        ]))
        .filter_map(Result::ok)
        .collect();

    let best_name = entry.find_best_name_attribute();
    if best_name.is_none() {
        return Ok(());
    }

    let standard_info = attributes.iter().find_map(|a| a.data.as_standard_info());
    let times = standard_info.map_or_else(Times::default, |si| {
        Times::new(si.accessed, si.modified, si.mft_modified, si.created)
    });

    let line = Line {
        path: bodyfile_path(full_path),
        deleted: if entry.is_allocated() {
            ""
        } else {
            " (deleted)"
        },
        record: entry.header.record_number,
        mode: mode(entry, standard_info.map(|si| &si.file_flags)),
        uid: standard_info.map_or(0, |si| si.owner_id),
    };

    let mut printed_stream = false;
    for attribute in &attributes {
        match attribute.header.type_code {
            MftAttributeType::DATA | MftAttributeType::IndexRoot => {
                let name = &attribute.header.name;
                let is_stream = !name.is_empty()
                    && !(attribute.header.type_code == MftAttributeType::IndexRoot
                        && name.to_utf8_string() == "$I30");
                let suffix = if is_stream {
                    format!(":{}", sanitize(&name.to_utf8_string()))
                } else {
                    String::new()
                };
                line.write(out, &suffix, Some(attribute), &times)?;
                printed_stream = true;
            }
            MftAttributeType::FileName => {
                if let Some(fname) = attribute.data.as_file_name()
                    && Some(fname) == best_name.as_ref()
                {
                    let fn_times = Times::new(
                        fname.accessed,
                        fname.modified,
                        fname.mft_modified,
                        fname.created,
                    );
                    line.write(out, " ($FILE_NAME)", Some(attribute), &fn_times)?;
                }
            }
            _ => {}
        }
    }

    // Like `fls`, still write a line for an entry without any stream.
    if !printed_stream {
        line.write(out, "", None, &times)?;
    }

    Ok(())
}

/// The columns shared by every line of one entry.
struct Line {
    path: String,
    deleted: &'static str,
    record: u64,
    mode: String,
    uid: u32,
}

impl Line {
    fn write<W: Write>(
        &self,
        out: &mut W,
        suffix: &str,
        attribute: Option<&MftAttribute>,
        times: &Times,
    ) -> io::Result<()> {
        let Line {
            path,
            deleted,
            record,
            mode,
            uid,
        } = self;
        let (inode, size) = match attribute {
            Some(a) => (
                format!(
                    "{record}-{}-{}",
                    a.header.type_code.clone() as u32,
                    a.header.instance
                ),
                attribute_size(a),
            ),
            None => (record.to_string(), 0),
        };
        writeln!(
            out,
            "0|{path}{suffix}{deleted}|{inode}|{mode}|{uid}|0|{size}|{}|{}|{}|{}",
            times.accessed, times.modified, times.changed, times.created,
        )
    }
}

/// `fls` mode column: the name type, then an `ls`-style mode. NTFS has no permissions, so TSK
/// derives them from the DOS flags: read unless read-only, write unless hidden, always execute.
/// Names of deleted entries have an unknown type (`-`).
fn mode(entry: &MftEntry, flags: Option<&FileAttributeFlags>) -> String {
    let meta_type = if entry.is_dir() { 'd' } else { 'r' };
    let name_type = if entry.is_allocated() { meta_type } else { '-' };
    let has = |flag| flags.is_some_and(|f| f.contains(flag));
    let read = if has(FileAttributeFlags::FILE_ATTRIBUTE_READONLY) {
        '-'
    } else {
        'r'
    };
    let write = if has(FileAttributeFlags::FILE_ATTRIBUTE_HIDDEN) {
        '-'
    } else {
        'w'
    };
    let rwx: String = [read, write, 'x'].iter().collect();
    format!("{name_type}/{meta_type}{rwx}{rwx}{rwx}")
}

/// The size of an attribute's value (the logical size for non-resident data).
fn attribute_size(attribute: &MftAttribute) -> u64 {
    match &attribute.header.residential_header {
        ResidentialHeader::Resident(r) => u64::from(r.data_size),
        ResidentialHeader::NonResident(nr) => nr.file_size,
    }
}

/// `fls` writes absolute paths with `/` separators, whatever the host platform.
fn bodyfile_path(full_path: &Path) -> String {
    let mut out = String::new();
    for component in full_path.components() {
        if let Component::Normal(part) = component {
            out.push('/');
            out.push_str(&sanitize(&part.to_string_lossy()));
        }
    }
    if out.is_empty() {
        out.push('/');
    }
    out
}

/// Replaces control characters with `^` like `fls` does, and `|` too so a name can't break the
/// line apart.
fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_control() || c == '|' { '^' } else { c })
        .collect()
}

/// Bodyfiles hold Unix seconds. Unset NTFS timestamps (FILETIME 0, i.e. 1601) and anything
/// else before 1970 are written as 0, like `fls` does.
fn unix_seconds(ts: Timestamp) -> i64 {
    ts.as_second().max(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizes_separators_and_control_characters() {
        assert_eq!(sanitize("a|b\\c\td"), "a^b\\c^d");
    }

    #[test]
    fn paths_are_absolute_with_forward_slashes() {
        let path = Path::new("Windows").join("System32").join("cmd.exe");
        assert_eq!(bodyfile_path(&path), "/Windows/System32/cmd.exe");
        assert_eq!(bodyfile_path(Path::new("")), "/");
    }
}
