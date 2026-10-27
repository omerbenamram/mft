//! Sleuth Kit bodyfile output, for timelining with `mactime` and similar tools.
//!
//! Lines follow the TSK 3.x layout that `fls -m` writes for NTFS:
//! `MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime`
//! <https://wiki.sleuthkit.org/index.php?title=Body_file>
use crate::attribute::header::ResidentialHeader;
use crate::attribute::x10::StandardInfoAttr;
use crate::attribute::x30::FileNameAttr;
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

impl From<&StandardInfoAttr> for Times {
    fn from(si: &StandardInfoAttr) -> Self {
        Times {
            accessed: unix_seconds(si.accessed),
            modified: unix_seconds(si.modified),
            changed: unix_seconds(si.mft_modified),
            created: unix_seconds(si.created),
        }
    }
}

impl From<&FileNameAttr<'_>> for Times {
    fn from(fname: &FileNameAttr<'_>) -> Self {
        Times {
            accessed: unix_seconds(fname.accessed),
            modified: unix_seconds(fname.modified),
            changed: unix_seconds(fname.mft_modified),
            created: unix_seconds(fname.created),
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
/// attribute's size. Unallocated entries get ` (deleted)` after their name. Extension records,
/// and entries without a `$FILE_NAME` attribute, are skipped, since `fls` can't reach them
/// either. Attributes stored in extension records (through an `$ATTRIBUTE_LIST`) are not
/// followed, so a file whose `$DATA` lives there gets a single line without an attribute.
pub fn write_entry<W: Write>(out: &mut W, entry: &MftEntry, full_path: &Path) -> io::Result<()> {
    // An extension record can hold `$FILE_NAME` attributes moved out of its base record (e.g. a
    // file with many hard links), but it has no `$STANDARD_INFORMATION` and isn't a file itself.
    if entry.header.base_reference.entry != 0 {
        return Ok(());
    }

    let best_name = entry.find_best_name_attribute();
    if best_name.is_none() {
        return Ok(());
    }

    let attributes: Vec<MftAttribute> = entry
        .iter_attributes_matching(Some(vec![
            MftAttributeType::StandardInformation,
            MftAttributeType::FileName,
            MftAttributeType::DATA,
            MftAttributeType::IndexRoot,
        ]))
        .filter_map(Result::ok)
        .collect();

    let standard_info = attributes.iter().find_map(|a| a.data.as_standard_info());
    let times = standard_info.map_or_else(Times::default, Times::from);

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
                // A directory's `$I30` index is its default stream, like an unnamed `$DATA`.
                let mut suffix = String::new();
                let default_stream = name.is_empty()
                    || (attribute.header.type_code == MftAttributeType::IndexRoot
                        && name.eq_utf8("$I30"));
                if !default_stream {
                    suffix.push(':');
                    name.with_utf8(|s| push_sanitized(&mut suffix, s));
                }
                line.write(out, &suffix, Some(attribute), &times)?;
                printed_stream = true;
            }
            MftAttributeType::FileName => {
                if let Some(fname) = attribute.data.as_file_name()
                    && Some(fname) == best_name.as_ref()
                {
                    line.write(out, " ($FILE_NAME)", Some(attribute), &Times::from(fname))?;
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
        write!(
            out,
            "0|{}{suffix}{}|{}",
            self.path, self.deleted, self.record
        )?;
        let size = match attribute {
            Some(a) => {
                let type_code = a.header.type_code.clone() as u32;
                write!(out, "-{type_code}-{}", a.header.instance)?;
                attribute_size(a)
            }
            None => 0,
        };
        writeln!(
            out,
            "|{}|{}|0|{size}|{}|{}|{}|{}",
            self.mode, self.uid, times.accessed, times.modified, times.changed, times.created,
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
    let rwx = match (
        has(FileAttributeFlags::FILE_ATTRIBUTE_READONLY),
        has(FileAttributeFlags::FILE_ATTRIBUTE_HIDDEN),
    ) {
        (false, false) => "rwx",
        (true, false) => "-wx",
        (false, true) => "r-x",
        (true, true) => "--x",
    };
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
            push_sanitized(&mut out, &part.to_string_lossy());
        }
    }
    if out.is_empty() {
        out.push('/');
    }
    out
}

/// Replaces C0 control characters (below 0x20) with `^` like `fls` does, and `|` too so a name
/// can't break the line apart.
fn push_sanitized(out: &mut String, name: &str) {
    out.extend(
        name.chars()
            .map(|c| if c < ' ' || c == '|' { '^' } else { c }),
    );
}

/// Bodyfiles hold Unix seconds. Unset NTFS timestamps (FILETIME 0, i.e. 1601) and anything
/// else before 1970 are written as 0; `fls` would wrap them around as unsigned 32-bit values.
fn unix_seconds(ts: Timestamp) -> i64 {
    ts.as_second().max(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizes_separators_and_control_characters() {
        let sanitize = |name| {
            let mut out = String::new();
            push_sanitized(&mut out, name);
            out
        };
        assert_eq!(sanitize("a|b\\c\td"), "a^b\\c^d");
        assert_eq!(sanitize("a\nb\u{7f}\u{85}"), "a^b\u{7f}\u{85}");
    }

    #[test]
    fn paths_are_absolute_with_forward_slashes() {
        let path = Path::new("Windows").join("System32").join("cmd.exe");
        assert_eq!(bodyfile_path(&path), "/Windows/System32/cmd.exe");
        assert_eq!(bodyfile_path(Path::new("")), "/");
    }
}
