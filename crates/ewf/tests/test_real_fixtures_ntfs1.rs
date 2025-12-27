use ewf::EwfReader;

mod common;

fn assert_ntfs_boot_sector(img: &EwfReader) {
    let mut boot = [0u8; 512];
    img.read_exact_at(0, &mut boot).unwrap();
    assert_eq!(&boot[3..11], b"NTFS    ");
    assert_eq!(&boot[510..512], &[0x55, 0xAA]);
}

#[test]
fn test_ewf_ntfs1_gen0_reads_boot_sector() {
    let path = common::ntfs_fixture_path("ntfs1-gen0.E01");
    if !common::ensure_fixture(&path) {
        return;
    }
    let img = EwfReader::open(&path).unwrap();
    assert_ntfs_boot_sector(&img);
}

#[test]
fn test_ewf_ntfs1_gen1_reads_boot_sector() {
    let path = common::ntfs_fixture_path("ntfs1-gen1.E01");
    if !common::ensure_fixture(&path) {
        return;
    }
    let img = EwfReader::open(&path).unwrap();
    assert_ntfs_boot_sector(&img);
}

#[test]
fn test_ewf_ntfs1_gen2_reads_boot_sector() {
    let path = common::ntfs_fixture_path("ntfs1-gen2.E01");
    if !common::ensure_fixture(&path) {
        return;
    }
    let img = EwfReader::open(&path).unwrap();
    assert_ntfs_boot_sector(&img);
}
