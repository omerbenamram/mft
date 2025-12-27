use aff::AffOpenOptions;

#[cfg(feature = "crypto")]
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

#[cfg(feature = "crypto")]
fn aff_encrypt_segment_data(segname: &str, key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    use openssl::symm::{Cipher, Crypter, Mode};

    let mut iv = [0u8; 16];
    let name_bytes = segname.as_bytes();
    let take = name_bytes.len().min(iv.len());
    iv[..take].copy_from_slice(&name_bytes[..take]);

    // AFFLIB's segment encryption pads to a block boundary and then appends `extra` bytes so
    // ciphertext_len % 16 == plaintext_len % 16.
    let extra = plaintext.len() % 16;
    let pad = (16 - extra) % 16;

    let mut padded = Vec::with_capacity(plaintext.len() + pad);
    padded.extend_from_slice(plaintext);
    padded.extend(std::iter::repeat_n((pad + extra) as u8, pad));

    let mut enc = Crypter::new(Cipher::aes_256_cbc(), Mode::Encrypt, key, Some(&iv)).unwrap();
    enc.pad(false);
    let mut out = vec![0u8; padded.len() + 16];
    let mut n = enc.update(&padded, &mut out).unwrap();
    n += enc.finalize(&mut out[n..]).unwrap();
    out.truncate(n);

    if extra != 0 {
        out.extend(std::iter::repeat_n(0u8, extra));
    }
    out
}

#[test]
fn test_unseal_keyfile_derives_affkey_and_decrypts_aes256_segment() {
    #[cfg(not(feature = "crypto"))]
    {
        return;
    }

    #[cfg(feature = "crypto")]
    {
        use openssl::pkey::PKey;
        use openssl::rand::rand_bytes;
        use openssl::rsa::{Padding, Rsa};
        use openssl::symm::{Cipher, encrypt};

        // RSA keypair for sealing/unsealing.
        let rsa = Rsa::generate(2048).unwrap();
        let priv_pem = rsa.private_key_to_pem().unwrap();
        let pub_rsa = Rsa::public_key_from_pem(&rsa.public_key_to_pem().unwrap()).unwrap();
        let pub_pkey = PKey::from_rsa(pub_rsa).unwrap();

        // Real AFF key (what we want to recover via affkey_evp0).
        let mut affkey = [0u8; 32];
        rand_bytes(&mut affkey).unwrap();

        // Session key + IV used for the envelope payload.
        let mut session_key = [0u8; 32];
        rand_bytes(&mut session_key).unwrap();
        let mut iv = [0u8; 16];
        rand_bytes(&mut iv).unwrap();

        // Encrypt (seal) the session key with the public key (PKCS1).
        let mut ek = vec![0u8; rsa.size() as usize];
        let ek_len = pub_pkey
            .rsa()
            .unwrap()
            .public_encrypt(&session_key, &mut ek, Padding::PKCS1)
            .unwrap();
        ek.truncate(ek_len);

        // Encrypt the AFF key using AES-256-CBC with PKCS7 padding (like EVP_Seal* would do).
        let encrypted_affkey =
            encrypt(Cipher::aes_256_cbc(), &session_key, Some(&iv), &affkey).unwrap();

        // Build `affkey_evp0` segment data.
        let mut evp = Vec::new();
        evp.extend_from_slice(&1u32.to_be_bytes()); // version
        evp.extend_from_slice(&(ek.len() as u32).to_be_bytes());
        evp.extend_from_slice(&(encrypted_affkey.len() as u32).to_be_bytes());
        evp.extend_from_slice(&iv);
        evp.extend_from_slice(&ek);
        evp.extend_from_slice(&encrypted_affkey);

        // Add an encrypted segment we can decrypt with the recovered affkey.
        let plaintext = b"hello from aff";
        let encrypted = aff_encrypt_segment_data("hello", &affkey, plaintext);

        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"AFF10\r\n\0");
        bytes.extend_from_slice(&aff_segment("pagesize", &[], 4096));
        bytes.extend_from_slice(&aff_segment("affkey_evp0", &evp, 0));
        bytes.extend_from_slice(&aff_segment("hello/aes256", &encrypted, 0));

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &bytes).unwrap();

        let key = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(key.path(), &priv_pem).unwrap();

        let mut opts = AffOpenOptions::new();
        opts.unseal_keyfile = Some(key.path().to_path_buf());
        opts.auto_decrypt = true;

        let img = opts.open(tmp.path()).unwrap();
        let seg = img.read_segment("hello").unwrap().unwrap();
        assert_eq!(seg.data, plaintext);
    }
}
