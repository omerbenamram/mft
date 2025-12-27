use aff::AffOpenOptions;
use forensic_image::ReadAt;

#[test]
fn test_decrypt_afflib_encrypted_fixture_matches_raw() {
    // AFFLIBv3 fixture: encrypted.aff is encrypted with passphrase "password".
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "../../external/refs/repos/sshock__AFFLIBv3@f6e51a8367cff73ea24c0adf09e533483c80ecd4/tests",
    );
    let aff_path = root.join("encrypted.aff");
    let raw_path = root.join("encrypted.raw");

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
