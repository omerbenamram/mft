use ntfs::image::{AffImage, EwfImage};
use ntfs::ntfs::Volume;
use std::sync::Arc;

mod common;

fn assert_volume_can_read_mft_entry0(volume: &Volume) {
    assert_eq!(volume.header.bytes_per_sector, 512);
    assert!(volume.header.cluster_size > 0);
    assert!(volume.header.mft_entry_size > 0);

    let entry0 = volume.read_mft_entry(0).unwrap();
    assert!(entry0.header.is_valid());
    assert_eq!(entry0.header.record_number, 0);
}

#[test]
fn test_volume_from_aff_gen0_reads_mft_entry0() {
    let path = common::ntfs_fixture_path("ntfs1-gen0.aff");
    if !common::ensure_fixture(&path) {
        return;
    }
    let img = AffImage::open(path).unwrap();
    let volume = Volume::open(Arc::new(img), 0).unwrap();
    assert_volume_can_read_mft_entry0(&volume);
}

#[test]
fn test_volume_from_ewf_gen0_reads_mft_entry0() {
    let path = common::ntfs_fixture_path("ntfs1-gen0.E01");
    if !common::ensure_fixture(&path) {
        return;
    }
    let img = EwfImage::open(path).unwrap();
    let volume = Volume::open(Arc::new(img), 0).unwrap();
    assert_volume_can_read_mft_entry0(&volume);
}
