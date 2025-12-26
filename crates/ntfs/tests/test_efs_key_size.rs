use mft::attribute::header::ResidentialHeader;
use mft::attribute::MftAttributeType;
use ntfs::image::EwfImage;
use ntfs::ntfs::efs::{EfsMetadataV1, EfsRsaKeyBag};
use ntfs::ntfs::{FileSystem, Volume};
use std::sync::Arc;

mod common;

#[test]
fn test_efs_rsa_key_size_matches_ddf_ciphertext_size() {
    let img_path = common::ntfs_fixture_path("ntfs1-gen2.E01");
    if !common::ensure_fixture(&img_path) {
        return;
    }
    let img = EwfImage::open(img_path).unwrap();
    let volume = Volume::open(Arc::new(img), 0).unwrap();
    let fs = FileSystem::new(volume);

    let pfx_id = fs.resolve_path("\\EFS-key-no-password.pfx").unwrap();
    let pfx = fs.read_file_default_stream(pfx_id).unwrap();
    let keys = EfsRsaKeyBag::from_pkcs12_der(&pfx, None).unwrap();
    let rsa = keys.iter().next().unwrap();

    let encrypted_id = fs.resolve_path("\\Encrypted\\NIST_logo.jpg").unwrap();
    let entry = fs.volume().read_mft_entry(encrypted_id).unwrap();
    let attr = entry
        .iter_attributes_matching(Some(vec![MftAttributeType::LoggedUtilityStream]))
        .filter_map(std::result::Result::ok)
        .find(|a| a.header.name == "$EFS")
        .unwrap();

    let efs_blob = match &attr.header.residential_header {
        ResidentialHeader::Resident(rh) => {
            let start = attr.header.start_offset as usize + rh.data_offset as usize;
            let end = start + rh.data_size as usize;
            entry.data[start..end].to_vec()
        }
        ResidentialHeader::NonResident(nr) => {
            let runs = attr.data.clone().into_data_runs().unwrap().data_runs;
            let mut buf = vec![0u8; nr.file_size as usize];
            ntfs::ntfs::data_stream::read_from_data_runs(fs.volume(), &runs, 0, &mut buf)
                .unwrap();
            buf
        }
    };

    let meta = EfsMetadataV1::parse(&efs_blob, 0).unwrap();
    let first = meta.ddf.iter().find(|e| e.flags == 0).unwrap();

    assert_eq!(
        rsa.size() as u32,
        first.encrypted_fek_length,
        "RSA modulus size should match Encrypted FEK length"
    );
}
