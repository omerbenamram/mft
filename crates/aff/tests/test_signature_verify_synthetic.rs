use aff::{AffOpenOptions, SignatureStatus, Verifier};

#[cfg(feature = "crypto")]
fn build_aff_with_signed_segment(segname: &str, arg: u32, data: &[u8]) -> Vec<u8> {
    use openssl::asn1::Asn1Integer;
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::sign::Signer;
    use openssl::x509::{X509, X509NameBuilder};

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

    // Generate a keypair and a self-signed cert.
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();

    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "aff-test").unwrap();
    let name = name.build();

    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    let mut serial = BigNum::new().unwrap();
    serial
        .rand(64, openssl::bn::MsbOption::MAYBE_ZERO, false)
        .unwrap();
    let serial = Asn1Integer::from_bn(&serial).unwrap();
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

    // Sign according to AFFLIB: sha256(segname + NUL + arg_be + data)
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

#[cfg(feature = "crypto")]
fn build_aff_with_signed_page_mode1(segname: &str, pagesize: u32, page0: &[u8]) -> Vec<u8> {
    use openssl::asn1::{Asn1Integer, Asn1Time};
    use openssl::bn::{BigNum, MsbOption};
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::sign::Signer;
    use openssl::x509::{X509, X509NameBuilder};

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

    // Generate a keypair and a self-signed cert.
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

    let imagesize = page0.len() as u64;
    let imagesize_quad = {
        let low = (imagesize & 0xffff_ffff) as u32;
        let high = (imagesize >> 32) as u32;
        let mut out = [0u8; 8];
        out[0..4].copy_from_slice(&low.to_be_bytes());
        out[4..8].copy_from_slice(&high.to_be_bytes());
        out
    };

    // MODE1: sha256(segname + NUL + 0_be + uncompressed_page_bytes)
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey).unwrap();
    signer.update(segname.as_bytes()).unwrap();
    signer.update(&[0]).unwrap();
    signer.update(&0u32.to_be_bytes()).unwrap();
    signer.update(page0).unwrap();
    let sig = signer.sign_to_vec().unwrap();

    let sigseg = format!("{segname}{}", aff::format::SIG256_SUFFIX);

    let mut out = Vec::new();
    out.extend_from_slice(b"AFF10\r\n\0");
    out.extend_from_slice(&aff_segment("pagesize", &[], pagesize));
    out.extend_from_slice(&aff_segment("imagesize", &imagesize_quad, 2));
    out.extend_from_slice(&aff_segment(aff::format::SIGN256_CERT, &cert_pem, 0));
    out.extend_from_slice(&aff_segment(segname, page0, 0));
    out.extend_from_slice(&aff_segment(&sigseg, &sig, aff::format::AF_SIGNATURE_MODE1));
    out
}

#[test]
fn test_verify_synthetic_signature_good_and_bad() {
    #[cfg(not(feature = "crypto"))]
    {
        return;
    }

    #[cfg(feature = "crypto")]
    {
        let bytes = build_aff_with_signed_segment("hello", 123, b"world");
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &bytes).unwrap();

        let img = AffOpenOptions::new().open(tmp.path()).unwrap();
        let v = Verifier::new(&img);
        assert_eq!(v.verify_segment("hello").unwrap(), SignatureStatus::Good);

        // Tamper: overwrite the segment data to break the signature.
        let mut tampered = bytes.clone();
        // Find the first occurrence of b"world" and flip a bit.
        let pos = tampered
            .windows(5)
            .position(|w| w == b"world")
            .expect("world present");
        tampered[pos] ^= 0x01;

        std::fs::write(tmp.path(), &tampered).unwrap();
        let img2 = AffOpenOptions::new().open(tmp.path()).unwrap();
        let v2 = Verifier::new(&img2);
        assert_eq!(v2.verify_segment("hello").unwrap(), SignatureStatus::Bad);
    }
}

#[test]
fn test_verify_mode1_page_signature() {
    #[cfg(not(feature = "crypto"))]
    {
        return;
    }

    #[cfg(feature = "crypto")]
    {
        let page0 = b"ABCDEFGH";
        // Regression: MODE1 hashes only the bytes returned by `af_get_page()`. For the final page,
        // that can be less than `pagesize` (no implicit zero-padding).
        let bytes = build_aff_with_signed_page_mode1("page0", 4096, page0);

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &bytes).unwrap();

        let img = AffOpenOptions::new().open(tmp.path()).unwrap();
        let v = Verifier::new(&img);
        assert_eq!(v.verify_segment("page0").unwrap(), SignatureStatus::Good);

        // Tamper with the page data and verify signature becomes Bad.
        let mut tampered = bytes;
        let pos = tampered
            .windows(page0.len())
            .position(|w| w == page0)
            .expect("page0 bytes present");
        tampered[pos] ^= 0x01;
        std::fs::write(tmp.path(), &tampered).unwrap();

        let img2 = AffOpenOptions::new().open(tmp.path()).unwrap();
        let v2 = Verifier::new(&img2);
        assert_eq!(v2.verify_segment("page0").unwrap(), SignatureStatus::Bad);
    }
}

#[test]
fn test_verify_mode1_page_signature_deprecated_seg_prefix() {
    #[cfg(not(feature = "crypto"))]
    {
        return;
    }

    #[cfg(feature = "crypto")]
    {
        let page0 = b"ABCDEFGH";
        let bytes = build_aff_with_signed_page_mode1("seg0", 4096, page0);

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &bytes).unwrap();

        let img = AffOpenOptions::new().open(tmp.path()).unwrap();
        let v = Verifier::new(&img);
        assert_eq!(v.verify_segment("seg0").unwrap(), SignatureStatus::Good);
    }
}
