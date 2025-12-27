use ntfs::image::{EwfImage, RawImage};
use ntfs::ntfs::{FileSystem, Volume};
use std::sync::Arc;

mod common;

#[test]
fn test_filesystem_is_entry_allocated_matches_deleted_fixture_7() {
    let img_path = common::undelete7_fixture_path("7-ntfs-undel.dd");
    if !common::ensure_fixture(&img_path) {
        return;
    }
    let img = RawImage::open(img_path).unwrap();
    let volume = Volume::open(Arc::new(img), 0).unwrap();
    let fs = FileSystem::new(volume);

    // Root directory is allocated.
    assert!(fs.is_entry_allocated(5).unwrap());

    // Known deleted entries from DFTT image #7.
    for id in [29_u64, 30, 31, 32, 35, 36, 37, 38] {
        assert!(
            !fs.is_entry_allocated(id).unwrap(),
            "expected entry {id} to be not allocated (deleted)"
        );
    }
}

#[test]
fn test_filesystem_is_entry_efs_encrypted_detects_encrypted_fixture_gen2() {
    let img_path = common::ntfs_fixture_path("ntfs1-gen2.E01");
    if !common::ensure_fixture(&img_path) {
        return;
    }
    let img = EwfImage::open(img_path).unwrap();
    let volume = Volume::open(Arc::new(img), 0).unwrap();
    let fs = FileSystem::new(volume);

    let encrypted_id = fs.resolve_path("\\Encrypted\\logfile1.txt").unwrap();
    let raw_id = fs.resolve_path("\\Raw\\logfile1.txt").unwrap();

    assert!(fs.is_entry_efs_encrypted(encrypted_id).unwrap());
    assert!(!fs.is_entry_efs_encrypted(raw_id).unwrap());
}

#[test]
fn test_export_file_default_stream_to_path_matches_read_bytes() {
    let img_path = common::undelete7_fixture_path("7-ntfs-undel.dd");
    if !common::ensure_fixture(&img_path) {
        return;
    }
    let img = RawImage::open(img_path).unwrap();
    let volume = Volume::open(Arc::new(img), 0).unwrap();
    let fs = FileSystem::new(volume);

    // One resident + one non-resident case.
    for id in [37_u64, 32] {
        let expected = fs.read_file_default_stream(id).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join(format!("entry-{id}.bin"));

        fs.export_file_default_stream_to_path(id, &out).unwrap();

        let got = std::fs::read(&out).unwrap();
        assert_eq!(got, expected, "export mismatch for entry {id}");
    }
}
