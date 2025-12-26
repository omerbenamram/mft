use mft::attribute::header::ResidentialHeader;
use mft::attribute::{AttributeDataFlags, MftAttributeType};
use ntfs::image::AffImage;
use ntfs::ntfs::{FileSystem, Volume};
use std::collections::HashMap;
use std::sync::Arc;

mod common;

fn build_name_map(
    entries: Vec<ntfs::ntfs::filesystem::DirectoryEntry>,
) -> HashMap<String, u64> {
    let mut m = HashMap::new();
    for e in entries {
        if e.name == "." || e.name.starts_with('$') || e.name.contains('~') {
            continue;
        }
        m.insert(e.name.clone(), e.entry_id);
    }
    m
}

fn data_info(fs: &FileSystem, entry_id: u64) -> (u64, bool) {
    let entry = fs.volume().read_mft_entry(entry_id).unwrap();
    let attr = entry
        .iter_attributes_matching(Some(vec![MftAttributeType::DATA]))
        .filter_map(std::result::Result::ok)
        .find(|a| a.header.name.is_empty());

    let Some(attr) = attr else {
        return (0, false);
    };

    match &attr.header.residential_header {
        ResidentialHeader::Resident(r) => (r.data_size as u64, false),
        ResidentialHeader::NonResident(nr) => {
            let is_compressed = attr
                .header
                .data_flags
                .contains(AttributeDataFlags::IS_COMPRESSED)
                || nr.unit_compression_size > 0;
            (nr.file_size, is_compressed)
        }
    }
}

fn has_attribute_list(fs: &FileSystem, entry_id: u64) -> bool {
    let entry = fs.volume().read_mft_entry(entry_id).unwrap();
    entry
        .iter_attributes_matching(Some(vec![MftAttributeType::AttributeList]))
        .any(|a| a.is_ok())
}

#[test]
fn test_read_compressed_file_matches_raw() {
    let path = common::ntfs_fixture_path("ntfs1-gen1.aff");
    if !common::ensure_fixture(&path) {
        return;
    }
    let img = AffImage::open(path).unwrap();
    let volume = Volume::open(Arc::new(img), 0).unwrap();
    let fs = FileSystem::new(volume);

    let raw_dir = fs.resolve_path("\\Raw").unwrap();
    let compressed_dir = fs.resolve_path("\\Compressed").unwrap();

    let raw_map = build_name_map(fs.read_dir(raw_dir).unwrap());
    let compressed_map = build_name_map(fs.read_dir(compressed_dir).unwrap());

    // Pick the smallest compressed file that exists in both directories.
    let mut best: Option<(String, u64, u64, u64)> = None; // (name, raw_id, compressed_id, size)
    for (name, &compressed_id) in &compressed_map {
        let Some(&raw_id) = raw_map.get(name) else {
            continue;
        };
        let (size, is_compressed) = data_info(&fs, compressed_id);
        if !is_compressed || size == 0 {
            continue;
        }
        match best {
            None => best = Some((name.clone(), raw_id, compressed_id, size)),
            Some((_, _, _, best_size)) if size < best_size => {
                best = Some((name.clone(), raw_id, compressed_id, size))
            }
            _ => {}
        }
    }

    let (name, raw_id, compressed_id, size) = best.expect("no compressed file found in fixture");
    // Keep the test fast.
    assert!(
        size <= 2_000_000,
        "picked file too large: {name} size={size}"
    );

    let raw_bytes = fs.read_file_default_stream(raw_id).unwrap();
    let compressed_bytes = fs.read_file_default_stream(compressed_id).unwrap();
    assert_eq!(raw_bytes, compressed_bytes, "content mismatch for {name}");
}

#[test]
fn test_read_attribute_list_backed_file_len_matches() {
    let path = common::ntfs_fixture_path("ntfs1-gen1.aff");
    if !common::ensure_fixture(&path) {
        return;
    }
    let img = AffImage::open(path).unwrap();
    let volume = Volume::open(Arc::new(img), 0).unwrap();
    let fs = FileSystem::new(volume);

    // Scan root directory for a reasonably-sized file that uses an attribute list.
    let mut candidate: Option<(String, u64, u64)> = None; // (name, id, size)
    for e in fs.read_dir(5).unwrap() {
        if e.name == "." {
            continue;
        }
        if !has_attribute_list(&fs, e.entry_id) {
            continue;
        }
        let (size, _compressed) = data_info(&fs, e.entry_id);
        if size == 0 || size > 2_000_000 {
            continue;
        }
        candidate = Some((e.name, e.entry_id, size));
        break;
    }

    // If the fixture doesn't contain a small attribute-list-backed file in root, don't fail the suite.
    let Some((name, entry_id, size)) = candidate else {
        return;
    };

    let bytes = fs.read_file_default_stream(entry_id).unwrap();
    assert_eq!(bytes.len() as u64, size, "unexpected size for {name}");
}
