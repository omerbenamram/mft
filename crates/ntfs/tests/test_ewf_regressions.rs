use ntfs::image::EwfImage;
use ntfs::ntfs::{FileSystem, Volume};
use md5::{Digest as _, Md5};
use sha1::Sha1;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;
use std::sync::Arc;

mod common;

fn md5_hex(bytes: &[u8]) -> String {
    hex::encode(Md5::digest(bytes))
}

fn sha1_hex(bytes: &[u8]) -> String {
    hex::encode(Sha1::digest(bytes))
}

fn extract_tag_value(line: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = line.find(&open)? + open.len();
    let end = line[start..].find(&close)? + start;
    Some(line[start..end].to_string())
}

/// Parses `ntfs1-gen2.xml` and returns `{ filename -> (md5, sha1) }` for the requested files.
fn read_reference_hashes(
    path: &Path,
    wanted: &[&str],
) -> io::Result<HashMap<String, (String, String)>> {
    let wanted_set: HashSet<&str> = wanted.iter().copied().collect();
    let f = File::open(path)?;
    let r = BufReader::new(f);

    let mut out: HashMap<String, (String, String)> = HashMap::new();

    let mut cur_filename: Option<String> = None;
    let mut cur_md5: Option<String> = None;
    let mut cur_sha1: Option<String> = None;

    for line in r.lines() {
        let line = line?;
        if let Some(v) = extract_tag_value(&line, "filename") {
            cur_filename = Some(v);
        }
        if let Some(v) = extract_tag_value(&line, "md5") {
            cur_md5 = Some(v);
        }
        if let Some(v) = extract_tag_value(&line, "sha1") {
            cur_sha1 = Some(v);
        }

        if line.contains("</fileobject>") {
            if let (Some(filename), Some(md5), Some(sha1)) =
                (cur_filename.take(), cur_md5.take(), cur_sha1.take())
            {
                if wanted_set.contains(filename.as_str()) {
                    out.insert(filename, (md5, sha1));
                }
            } else {
                cur_filename = None;
                cur_md5 = None;
                cur_sha1 = None;
            }
        }
    }

    Ok(out)
}

#[test]
fn test_ewf_gen2_file_hashes_match_reference_xml() {
    // Pick a mix of:
    // - small root directory files (including a non-resident PFX)
    // - large files inside a directory
    // - a compressed-directory file to ensure NTFS decompression and EWF offsets stay correct
    let wanted = [
        "EFS-key-info.txt",
        "EFS-key-no-password.pfx",
        "EFS-key-password.pfx",
        "EFS-key-password-strong-protection.pfx",
        "RAW/NIST_logo.jpg",
        "Compressed/NIST_logo.jpg",
    ];

    let xml_path = common::ntfs_fixture_path("ntfs1-gen2.xml");
    if !common::ensure_fixture(&xml_path) {
        return;
    }
    let expected = read_reference_hashes(&xml_path, &wanted).expect("read reference hashes");
    assert_eq!(
        expected.len(),
        wanted.len(),
        "reference xml did not contain all wanted files"
    );

    let img_path = common::ntfs_fixture_path("ntfs1-gen2.E01");
    if !common::ensure_fixture(&img_path) {
        return;
    }
    let img = EwfImage::open(img_path).unwrap();
    let volume = Volume::open(Arc::new(img), 0).unwrap();
    let fs = FileSystem::new(volume);

    for filename in wanted {
        let (md5_expected, sha1_expected) = expected
            .get(filename)
            .unwrap_or_else(|| panic!("missing expected hashes for {filename}"))
            .clone();

        let entry_id = fs.resolve_path(filename).unwrap();
        let bytes = fs.read_file_default_stream(entry_id).unwrap();

        assert_eq!(md5_hex(&bytes), md5_expected, "md5 mismatch for {filename}");
        assert_eq!(
            sha1_hex(&bytes),
            sha1_expected,
            "sha1 mismatch for {filename}"
        );
    }
}
