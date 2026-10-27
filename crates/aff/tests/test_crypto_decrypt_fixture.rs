use aff::AffOpenOptions;
use forensic_image::ReadAt;

mod common;

#[test]
fn test_decrypt_afflib_encrypted_fixture_matches_raw() {
    // AFFLIBv3 fixture: encrypted.aff is encrypted with passphrase "password".
    let aff_path = common::afflib_fixture_path("encrypted.aff");
    let raw_path = common::afflib_fixture_path("encrypted.raw");
    if !common::ensure_fixture(&aff_path) || !common::ensure_fixture(&raw_path) {
        return;
    }

    let mut opts = AffOpenOptions::new();
    opts.passphrase = Some("password".to_string());
    opts.auto_decrypt = true;

    let img = opts.open(&aff_path).expect("open encrypted.aff");

    let raw = std::fs::read(&raw_path).expect("read encrypted.raw");
    assert_eq!(img.len(), raw.len() as u64);

    let mut out = vec![0u8; raw.len()];
    img.read_exact_at(0, &mut out)
        .expect("read decrypted bytes");
    assert_eq!(out, raw, "decrypted content mismatch");
}
