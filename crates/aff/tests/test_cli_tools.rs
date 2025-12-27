use assert_cmd::Command;
use predicates::prelude::*;

#[cfg(feature = "crypto")]
fn build_aff_with_signed_segment(segname: &str, arg: u32, data: &[u8]) -> Vec<u8> {
    use openssl::asn1::{Asn1Integer, Asn1Time};
    use openssl::bn::{BigNum, MsbOption};
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::sign::Signer;
    use openssl::x509::{X509NameBuilder, X509};

    fn aff_segment(name: &str, data: &[u8], arg: u32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"AFF\0");
        out.extend_from_slice(&(name.len() as u32).to_be_bytes());
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(&arg.to_be_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);
        out.extend_from_slice(b"ATT\0");
        let seg_len = (16 + name.len() + data.len() + 8) as u32;
        out.extend_from_slice(&seg_len.to_be_bytes());
        out
    }

    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();

    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "aff-test").unwrap();
    let name = name.build();

    let mut serial = BigNum::new().unwrap();
    serial.rand(64, MsbOption::MAYBE_ZERO, false).unwrap();
    let serial = Asn1Integer::from_bn(&serial).unwrap();

    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_serial_number(&serial).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&pkey).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();
    builder.sign(&pkey, MessageDigest::sha256()).unwrap();
    let cert = builder.build();
    let cert_pem = cert.to_pem().unwrap();

    let mut signer = Signer::new(MessageDigest::sha256(), &pkey).unwrap();
    signer.update(segname.as_bytes()).unwrap();
    signer.update(&[0]).unwrap();
    signer.update(&arg.to_be_bytes()).unwrap();
    signer.update(data).unwrap();
    let sig = signer.sign_to_vec().unwrap();

    let sigseg = format!("{segname}{}", aff::format::SIG256_SUFFIX);

    let mut out = Vec::new();
    out.extend_from_slice(b"AFF10\r\n\0");
    out.extend_from_slice(&aff_segment("pagesize", &[], 4096));
    out.extend_from_slice(&aff_segment(aff::format::SIGN256_CERT, &cert_pem, 0));
    out.extend_from_slice(&aff_segment(segname, data, arg));
    out.extend_from_slice(&aff_segment(&sigseg, &sig, aff::format::AF_SIGNATURE_MODE0));
    out
}

#[test]
fn test_aff_cat_decrypts_afflib_fixture() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../external/refs/repos/sshock__AFFLIBv3@f6e51a8367cff73ea24c0adf09e533483c80ecd4/tests");
    let aff_path = root.join("encrypted.aff");
    let raw_path = root.join("encrypted.raw");
    let raw = std::fs::read(&raw_path).unwrap();

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("aff-cat"));
    cmd.arg(&aff_path)
        .arg("--passphrase")
        .arg("password");

    cmd.assert()
        .success()
        .stdout(predicate::eq(raw));
}

#[test]
fn test_aff_info_runs_and_reports_len() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../external/refs/repos/sshock__AFFLIBv3@f6e51a8367cff73ea24c0adf09e533483c80ecd4/tests");
    let aff_path = root.join("encrypted.aff");

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("aff-info"));
    cmd.arg(&aff_path);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("len: 32"));
}

#[test]
fn test_aff_verify_exits_nonzero_on_bad_signature() {
    #[cfg(not(feature = "crypto"))]
    {
        return;
    }

    #[cfg(feature = "crypto")]
    {
        let good = build_aff_with_signed_segment("hello", 123, b"world");
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &good).unwrap();

        Command::new(assert_cmd::cargo::cargo_bin!("aff-verify"))
            .arg(tmp.path())
            .assert()
            .success();

        let mut bad = good;
        let pos = bad
            .windows(5)
            .position(|w| w == b"world")
            .expect("world present");
        bad[pos] ^= 0x01;
        std::fs::write(tmp.path(), &bad).unwrap();

        Command::new(assert_cmd::cargo::cargo_bin!("aff-verify"))
            .arg(tmp.path())
            .assert()
            .failure();
    }
}


