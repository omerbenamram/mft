use md5::{Digest as _, Md5};
use ntfs::image::RawImage;
use ntfs::ntfs::{FileSystem, Volume};
use std::sync::Arc;

mod common;

fn md5_hex(bytes: &[u8]) -> String {
    let mut h = Md5::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn assert_stream_md5(
    fs: &FileSystem,
    entry_id: u64,
    stream_name: &str,
    expected_len: usize,
    expected_md5: &str,
) {
    let bytes = fs.read_file_stream(entry_id, stream_name).unwrap();
    assert_eq!(
        bytes.len(),
        expected_len,
        "unexpected len for entry {entry_id} stream `{stream_name}`"
    );
    assert_eq!(
        md5_hex(&bytes),
        expected_md5,
        "unexpected MD5 for entry {entry_id} stream `{stream_name}`"
    );
}

#[test]
fn test_ntfs_undelete_7_deleted_file_stream_md5s_match_reference() {
    // DFXML "Digital Forensics Tool Testing Image (#7)", NTFS Undelete Test #1.
    // Reference values are listed in `testdata/ntfs/7-undel-ntfs/index.html`.
    let img_path = common::undelete7_fixture_path("7-ntfs-undel.dd");
    if !common::ensure_fixture(&img_path) {
        return;
    }
    let img = RawImage::open(img_path).unwrap();
    let volume = Volume::open(Arc::new(img), 0).unwrap();
    let fs = FileSystem::new(volume);

    // Resident file.
    assert_stream_md5(&fs, 37, "", 101, "9036637712b491904cd0bfbdbe648453");
    // Single cluster file.
    assert_stream_md5(&fs, 31, "", 780, "59b20779f69ff9f0ac5fcd2c38835a79");
    // Multiple cluster file (non-fragmented).
    assert_stream_md5(&fs, 32, "", 3801, "ffd27bd782bdce67750b6b9ee069d2ef");
    // Alternate Data Stream.
    assert_stream_md5(&fs, 32, "ADS", 1234, "ba1b9eedb1c091ddca253d35dde8f616");
    // Fragmented files.
    assert_stream_md5(&fs, 29, "", 1584, "7a3bc5b763bef201202108f4ba128149");
    assert_stream_md5(&fs, 30, "", 3873, "0e80ab84ef0087e60dfc67b88a1cf13e");
    // File in deleted directories.
    assert_stream_md5(&fs, 36, "", 1715, "59cf0e9cd107bc1e75afb7374f6e05bb");
    assert_stream_md5(&fs, 35, "", 2027, "21121699487f3fbbdb9a4b3391b6d3e0");
    // File whose parent directory entry has been reallocated.
    assert_stream_md5(&fs, 38, "", 1005, "c229626f6a71b167ad7e50c4f2fccdb1");
}

#[test]
fn test_ntfs_undelete_7_md5_streaming_matches_reference() {
    // Validate the streaming MD5 implementation used by ntfsinfo bodyfile output.
    let img_path = common::undelete7_fixture_path("7-ntfs-undel.dd");
    if !common::ensure_fixture(&img_path) {
        return;
    }
    let img = RawImage::open(img_path).unwrap();
    let volume = Volume::open(Arc::new(img), 0).unwrap();
    let fs = FileSystem::new(volume);

    let cases = [
        (37_u64, "", "9036637712b491904cd0bfbdbe648453"),
        (31, "", "59b20779f69ff9f0ac5fcd2c38835a79"),
        (32, "", "ffd27bd782bdce67750b6b9ee069d2ef"),
        (32, "ADS", "ba1b9eedb1c091ddca253d35dde8f616"),
        (29, "", "7a3bc5b763bef201202108f4ba128149"),
        (30, "", "0e80ab84ef0087e60dfc67b88a1cf13e"),
        (36, "", "59cf0e9cd107bc1e75afb7374f6e05bb"),
        (35, "", "21121699487f3fbbdb9a4b3391b6d3e0"),
        (38, "", "c229626f6a71b167ad7e50c4f2fccdb1"),
    ];

    for (entry_id, stream, expected) in cases {
        let got = fs.md5_file_stream(entry_id, stream).unwrap();
        assert_eq!(
            got, expected,
            "unexpected streaming MD5 for entry {entry_id} stream `{stream}`"
        );
    }
}

#[test]
fn test_ntfs_undelete_7_deleted_file_names_visible_in_mft() {
    let img_path = common::undelete7_fixture_path("7-ntfs-undel.dd");
    if !common::ensure_fixture(&img_path) {
        return;
    }
    let img = RawImage::open(img_path).unwrap();
    let volume = Volume::open(Arc::new(img), 0).unwrap();
    let fs = FileSystem::new(volume);

    // Deleted entries should still expose their FILE_NAME attributes, which is the minimum needed
    // to “see deleted file names”.
    let cases = [
        (29_u64, "frag1.dat"),
        (30, "frag2.dat"),
        (31, "sing1.dat"),
        (32, "mult1.dat"),
        (35, "frag3.dat"),
        (36, "mult2.dat"),
        (37, "res1.dat"),
        (38, "sing2.dat"),
    ];

    for (entry_id, expected_name) in cases {
        let entry = fs.volume().read_mft_entry(entry_id).unwrap();
        let name = entry
            .find_best_name_attribute()
            .expect("missing FILE_NAME attribute")
            .name;
        assert!(
            name.eq_ignore_ascii_case(expected_name),
            "unexpected name for entry {entry_id}: got={name:?} expected={expected_name:?}"
        );
    }
}

#[test]
fn test_ntfs_undelete_7_resolve_deleted_paths_via_parent_scan() {
    let img_path = common::undelete7_fixture_path("7-ntfs-undel.dd");
    if !common::ensure_fixture(&img_path) {
        return;
    }
    let img = RawImage::open(img_path).unwrap();
    let volume = Volume::open(Arc::new(img), 0).unwrap();
    let fs = FileSystem::new(volume);

    // Deleted directories are typically removed from `$I30`, so plain `resolve_path` should fail.
    // The `*_including_deleted` variant uses a parent-reference scan to recover names.
    assert!(fs.resolve_path("\\dir1").is_err());

    assert_eq!(fs.resolve_path_including_deleted("\\dir1").unwrap(), 33);
    assert_eq!(
        fs.resolve_path_including_deleted("\\dir1\\dir2").unwrap(),
        34
    );
    assert_eq!(
        fs.resolve_path_including_deleted("\\dir1\\mult2.dat")
            .unwrap(),
        36
    );
    assert_eq!(
        fs.resolve_path_including_deleted("\\dir1\\dir2\\frag3.dat")
            .unwrap(),
        35
    );
}
