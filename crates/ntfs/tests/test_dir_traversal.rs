use ntfs::image::AffImage;
use ntfs::ntfs::{FileSystem, Volume};
use std::collections::HashSet;
use std::sync::Arc;

mod common;

#[test]
fn test_root_directory_contains_expected_directories() {
    let path = common::ntfs_fixture_path("ntfs1-gen0.aff");
    if !common::ensure_fixture(&path) {
        return;
    }
    let img = AffImage::open(path).unwrap();
    let volume = Volume::open(Arc::new(img), 0).unwrap();
    let fs = FileSystem::new(volume);

    let entries = fs.read_dir(5).unwrap();
    let names: HashSet<String> = entries.into_iter().map(|e| e.name).collect();

    assert!(names.iter().any(|n| n.eq_ignore_ascii_case("Raw")));
    assert!(names.iter().any(|n| n.eq_ignore_ascii_case("Compressed")));
    assert!(names.iter().any(|n| n.eq_ignore_ascii_case("Encrypted")));
}

#[test]
fn test_resolve_path_raw_directory() {
    // gen0 has an empty Raw directory; use gen1 to validate non-empty directory traversal.
    let path = common::ntfs_fixture_path("ntfs1-gen1.aff");
    if !common::ensure_fixture(&path) {
        return;
    }
    let img = AffImage::open(path).unwrap();
    let volume = Volume::open(Arc::new(img), 0).unwrap();
    let fs = FileSystem::new(volume);

    let raw_id = fs.resolve_path("\\Raw").unwrap();
    let entries = fs.read_dir(raw_id).unwrap();
    assert!(!entries.is_empty());
}
