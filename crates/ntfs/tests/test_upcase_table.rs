use ntfs::image::AffImage;
use ntfs::ntfs::name::UpcaseTable;
use ntfs::ntfs::name::upcase::UPCASE_TABLE_SIZE_BYTES;
use ntfs::ntfs::{FileSystem, Volume};
use std::sync::Arc;

mod common;

#[test]
fn test_read_upcase_table_from_fixture() {
    let path = common::ntfs_fixture_path("ntfs1-gen0.aff");
    if !common::ensure_fixture(&path) {
        return;
    }
    let img = AffImage::open(path).unwrap();
    let volume = Volume::open(Arc::new(img), 0).unwrap();
    let fs = FileSystem::new(volume);

    let raw = fs.read_file_default_stream(10).unwrap();
    assert_eq!(raw.len(), UPCASE_TABLE_SIZE_BYTES);

    let table = UpcaseTable::from_bytes(&raw).unwrap();
    assert_eq!(table.map_u16(b'a' as u16), b'A' as u16);
    assert_eq!(table.map_u16(b'Z' as u16), b'Z' as u16);
}
