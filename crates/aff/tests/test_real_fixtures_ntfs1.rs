use aff::AffImage;
use forensic_image::ReadAt;

mod common;

fn assert_ntfs_boot_sector(image: &impl ReadAt) {
    let mut boot = [0u8; 512];
    image.read_exact_at(0, &mut boot).unwrap();
    assert_eq!(&boot[3..11], b"NTFS    ");
    assert_eq!(&boot[510..512], &[0x55, 0xAA]);
}

#[test]
fn test_open_ntfs1_gen0_aff_reads_ntfs_boot_sector() {
    let path = common::ntfs_fixture_path("ntfs1-gen0.aff");
    if !common::ensure_fixture(&path) {
        return;
    }
    let img = AffImage::open(path).unwrap();
    assert_ntfs_boot_sector(&img);
}

#[test]
fn test_open_ntfs1_gen1_aff_reads_ntfs_boot_sector() {
    let path = common::ntfs_fixture_path("ntfs1-gen1.aff");
    if !common::ensure_fixture(&path) {
        return;
    }
    let img = AffImage::open(path).unwrap();
    assert_ntfs_boot_sector(&img);
}
