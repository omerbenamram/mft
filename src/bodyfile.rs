//! Sleuth Kit bodyfile output, for timelining with `mactime` and similar tools.
//!
//! Lines follow the TSK 3.x layout that `fls -m` writes for NTFS:
//! `MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime`
//! <https://wiki.sleuthkit.org/index.php?title=Body_file>
use crate::attribute::header::MftAttributeHeader;
use crate::attribute::x10::StandardInfoAttr;
use crate::attribute::x30::FileNameAttr;
use crate::attribute::{FileAttributeFlags, MftAttributeContent, MftAttributeType};
use crate::entry::{MftEntry, find_best_name_attribute_in};

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
/// either.
///
/// `extensions` are the entry's extension records (from
/// [`crate::MftParser::get_extension_entries`]): attributes stored there through an
/// `$ATTRIBUTE_LIST` get their lines too, numbered with the base entry like `fls` does.
pub fn write_entry<W: Write>(
    out: &mut W,
    entry: &MftEntry,
    extensions: &[MftEntry],
    full_path: &Path,
) -> io::Result<()> {
    // An extension record can hold `$FILE_NAME` attributes moved out of its base record (e.g. a
    // file with many hard links), but it has no `$STANDARD_INFORMATION` and isn't a file itself.
    if !entry.header.is_base_record() {
        return Ok(());
    }

    let best_name = find_best_name_attribute_in(entry, extensions);
    if best_name.is_none() {
        return Ok(());
    }

    // A stream line only needs the attribute header, so only the timestamp attributes' content is
    // parsed: a `$DATA` or `$INDEX_ROOT` whose content is corrupt still gets its line.
    let attributes: Vec<(MftAttributeHeader, Option<MftAttributeContent>)> = std::iter::once(entry)
        .chain(extensions)
        .flat_map(|record| {
            record.iter_attribute_records_matching(Some(vec![
                MftAttributeType::StandardInformation,
                MftAttributeType::FileName,
                MftAttributeType::DATA,
                MftAttributeType::IndexRoot,
            ]))
        })
        .filter_map(Result::ok)
        .map(|(header, record)| {
            let content = matches!(
                header.type_code,
                MftAttributeType::StandardInformation | MftAttributeType::FileName
            )
            .then(|| MftAttributeContent::from_record(record, &header).ok())
            .flatten();
            (header, content)
        })
        .collect();

    let standard_info = attributes
        .iter()
        .find_map(|(_, content)| content.as_ref()?.as_standard_info());
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
    for (header, content) in &attributes {
        match header.type_code {
            MftAttributeType::DATA | MftAttributeType::IndexRoot => {
                // A non-resident attribute split over several records repeats in each of them,
                // and only the one starting at VCN 0 has the stream's size.
                if header.is_continuation() {
                    continue;
                }
                let name = &header.name;
                // A directory's `$I30` index is its default stream, like an unnamed `$DATA`.
                let mut suffix = String::new();
                let default_stream = name.is_empty()
                    || (header.type_code == MftAttributeType::IndexRoot && name.eq_utf8("$I30"));
                if !default_stream {
                    suffix.push(':');
                    name.with_utf8(|s| push_sanitized(&mut suffix, s));
                }
                line.write(out, &suffix, Some(header), &times)?;
                printed_stream = true;
            }
            MftAttributeType::FileName => {
                if let Some(fname) = content.as_ref().and_then(|c| c.as_file_name())
                    && Some(fname) == best_name.as_ref()
                {
                    line.write(out, " ($FILE_NAME)", Some(header), &Times::from(fname))?;
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
        header: Option<&MftAttributeHeader>,
        times: &Times,
    ) -> io::Result<()> {
        write!(
            out,
            "0|{}{suffix}{}|{}",
            self.path, self.deleted, self.record
        )?;
        let size = match header {
            Some(h) => {
                let type_code = h.type_code.clone() as u32;
                write!(out, "-{type_code}-{}", h.instance)?;
                h.value_size()
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

    /// The `$MFT` entry of the sample, and the record offset of its unnamed `$DATA` attribute.
    fn mft_entry_and_data_offset() -> (MftEntry, usize) {
        let sample = Path::new(env!("CARGO_MANIFEST_DIR")).join("samples/MFT");
        let entry = crate::MftParser::from_path(sample)
            .unwrap()
            .get_entry(0)
            .unwrap();
        let data = entry
            .iter_attributes_matching(Some(vec![MftAttributeType::DATA]))
            .next()
            .unwrap()
            .unwrap();
        let offset = data.header.start_offset as usize;
        (entry, offset)
    }

    fn lines(entry: &MftEntry) -> Vec<String> {
        let mut out = Vec::new();
        write_entry(&mut out, entry, &[], Path::new("$MFT")).unwrap();
        String::from_utf8(out)
            .unwrap()
            .lines()
            .map(|l| l.split('|').take(7).collect::<Vec<_>>().join("|"))
            .collect()
    }

    #[test]
    fn stream_line_survives_undecodable_data_runs() {
        let (mut entry, offset) = mft_entry_and_data_offset();
        let datarun_offset =
            u16::from_le_bytes([entry.data[offset + 0x20], entry.data[offset + 0x21]]) as usize;
        // A run header claiming 15-byte length and offset fields runs past the record.
        entry.data[offset + datarun_offset] = 0xFF;
        assert!(entry.iter_attributes().any(|a| a.is_err()));

        assert_eq!(
            lines(&entry),
            [
                "0|/$MFT ($FILE_NAME)|0-48-3|r/rr-xr-xr-x|0|0|74",
                "0|/$MFT|0-128-1|r/rr-xr-xr-x|0|0|13402112",
            ]
        );
    }

    #[test]
    fn data_continuation_records_get_no_line() {
        let (mut entry, offset) = mft_entry_and_data_offset();
        // Lowest VCN, at 0x10 in a non-resident attribute header.
        entry.data[offset + 0x10] = 1;

        assert_eq!(
            lines(&entry),
            [
                "0|/$MFT ($FILE_NAME)|0-48-3|r/rr-xr-xr-x|0|0|74",
                "0|/$MFT|0|r/rr-xr-xr-x|0|0|0",
            ]
        );
    }

    #[test]
    fn paths_are_absolute_with_forward_slashes() {
        let path = Path::new("Windows").join("System32").join("cmd.exe");
        assert_eq!(bodyfile_path(&path), "/Windows/System32/cmd.exe");
        assert_eq!(bodyfile_path(Path::new("")), "/");
    }
}
