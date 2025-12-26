use mft::attribute::header::ResidentialHeader;
use mft::attribute::MftAttributeType;
use ntfs::image::EwfImage;
use ntfs::ntfs::efs::{EfsMetadataV1, EfsRsaKeyBag};
use ntfs::ntfs::{FileSystem, Volume};
use std::sync::Arc;

mod common;

#[test]
fn test_efs_decrypt_reports_thumbprint_mismatch_against_fixture_pfx() {
    let img_path = common::ntfs_fixture_path("ntfs1-gen2.E01");
    if !common::ensure_fixture(&img_path) {
        return;
    }
    let img = EwfImage::open(img_path).unwrap();
    let volume = Volume::open(Arc::new(img), 0).unwrap();
    let fs = FileSystem::new(volume);

    // The fixture includes a PFX in the image root. The password is documented in
    // `EFS-key-info.txt`.
    let pfx_id = fs.resolve_path("\\EFS-key-password.pfx").unwrap();
    let pfx = fs.read_file_default_stream(pfx_id).unwrap();
    let keys = EfsRsaKeyBag::from_pkcs12_der(&pfx, Some("password")).unwrap();

    let encrypted_id = fs.resolve_path("\\Encrypted\\NIST_logo.jpg").unwrap();
    let entry = fs.volume().read_mft_entry(encrypted_id).unwrap();

    // Extract and parse `$EFS` metadata so we can compare the DDF thumbprint(s) with the PFX
    // thumbprint(s).
    let attr = entry
        .iter_attributes_matching(Some(vec![MftAttributeType::LoggedUtilityStream]))
        .filter_map(std::result::Result::ok)
        .find(|a| a.header.name == "$EFS")
        .expect("missing $EFS attribute");

    let efs_blob = match &attr.header.residential_header {
        ResidentialHeader::Resident(rh) => {
            let start = attr.header.start_offset as usize + rh.data_offset as usize;
            let end = start + rh.data_size as usize;
            entry.data[start..end].to_vec()
        }
        ResidentialHeader::NonResident(nr) => {
            let runs = attr.data.clone().into_data_runs().unwrap().data_runs;
            let mut buf = vec![0u8; nr.file_size as usize];
            ntfs::ntfs::data_stream::read_from_data_runs(fs.volume(), &runs, 0, &mut buf).unwrap();
            buf
        }
    };

    let meta = EfsMetadataV1::parse(&efs_blob, 0).unwrap();
    let ddf_tps = meta
        .ddf
        .iter()
        .filter_map(|e| e.cert_thumbprint_sha1)
        .map(hex::encode)
        .collect::<Vec<_>>();
    let pfx_tps = keys
        .thumbprints()
        .flatten()
        .map(hex::encode)
        .collect::<Vec<_>>();

    let err = fs
        .read_file_default_stream_decrypted(encrypted_id, &keys)
        .unwrap_err();
    let s = err.to_string();

    // The failure mode should be deterministic and include both the DDF and PFX thumbprints.
    for tp in ddf_tps {
        assert!(
            s.contains(&tp),
            "expected decrypt error to include DDF thumbprint {tp}, got:\n{s}"
        );
    }
    for tp in pfx_tps {
        assert!(
            s.contains(&tp),
            "expected decrypt error to include PFX thumbprint {tp}, got:\n{s}"
        );
    }
}

#[test]
fn test_efs_decrypt_logfile1_matches_raw_with_fixture_pfx() {
    let img_path = common::ntfs_fixture_path("ntfs1-gen2.E01");
    if !common::ensure_fixture(&img_path) {
        return;
    }
    let img = EwfImage::open(img_path).unwrap();
    let volume = Volume::open(Arc::new(img), 0).unwrap();
    let fs = FileSystem::new(volume);

    // The fixture includes a password-less PFX export in the image root.
    let pfx_id = fs.resolve_path("\\EFS-key-no-password.pfx").unwrap();
    let pfx = fs.read_file_default_stream(pfx_id).unwrap();
    let keys = EfsRsaKeyBag::from_pkcs12_der(&pfx, None).unwrap();

    // In gen2, `\\Encrypted\\logfile1.txt` uses the certificate whose SHA-1 thumbprint matches the
    // exported PFX. Validate the end-to-end decrypt path by comparing against the plaintext copy
    // in `\\Raw`.
    let encrypted_id = fs.resolve_path("\\Encrypted\\logfile1.txt").unwrap();
    let raw_id = fs.resolve_path("\\Raw\\logfile1.txt").unwrap();

    let raw = fs.read_file_default_stream(raw_id).unwrap();
    let decrypted = fs
        .read_file_default_stream_decrypted(encrypted_id, &keys)
        .unwrap();

    assert_eq!(decrypted, raw);
}
