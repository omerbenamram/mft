use ntfs::image::{AffImage, EwfImage, ReadAt};
mod common;

fn assert_ntfs_boot_sector(image: &impl ReadAt) {
    let mut boot = [0u8; 512];
    image.read_exact_at(0, &mut boot).unwrap();
    assert_eq!(&boot[3..11], b"NTFS    ");
    // Boot sector signature.
    assert_eq!(&boot[510..512], &[0x55, 0xAA]);
}

#[test]
fn test_aff_gen0_reads_ntfs_boot_sector() {
    let path = common::ntfs_fixture_path("ntfs1-gen0.aff");
    if !common::ensure_fixture(&path) {
        return;
    }
    let img = AffImage::open(path).unwrap();
    assert_ntfs_boot_sector(&img);
}

#[test]
fn test_gen0_aff_and_ewf_boot_sector_match() {
    let aff_path = common::ntfs_fixture_path("ntfs1-gen0.aff");
    if !common::ensure_fixture(&aff_path) {
        return;
    }
    let ewf_path = common::ntfs_fixture_path("ntfs1-gen0.E01");
    if !common::ensure_fixture(&ewf_path) {
        return;
    }

    let aff = AffImage::open(aff_path).unwrap();
    let ewf = EwfImage::open(ewf_path).unwrap();

    let mut boot_aff = [0u8; 512];
    let mut boot_ewf = [0u8; 512];
    aff.read_exact_at(0, &mut boot_aff).unwrap();
    ewf.read_exact_at(0, &mut boot_ewf).unwrap();
    assert_eq!(boot_aff, boot_ewf);
}

#[test]
fn test_aff_gen1_reads_ntfs_boot_sector() {
    let path = common::ntfs_fixture_path("ntfs1-gen1.aff");
    if !common::ensure_fixture(&path) {
        return;
    }
    let img = AffImage::open(path).unwrap();
    assert_ntfs_boot_sector(&img);
}

// EWF backend fixture tests live in the `ewf` crate now.
