//! EFS FEK unwrap + sector decryption.
//!
//! This module implements the cryptographic pieces needed for offline EFS reads:
//!
//! - **RSA unwrap** of the on-disk “Encrypted FEK” blob into the FEK plaintext structure
//!   (ref: `external/refs/specs/MS-EFSR.md` §2.2.2.1.5 “Encrypted FEK”; reference behavior:
//!   `external/refs/repos/ntfsprogs-plus__ntfsprogs-plus@*/src/deprecated/ntfsdecrypt.c`,
//!   function `ntfs_raw_fek_decrypt`).
//! - **Sector decryption** in 512-byte units with Windows’ IV derivation scheme
//!   (ref: `ntfsdecrypt.c` function `ntfs_fek_decrypt_sector`).
//! - **DESX key expansion** (MD5 + salts) matching Windows EFS
//!   (ref: `ntfsdecrypt.c` function `ntfs_desx_key_expand`).
//!
//! Important byte-order note: the on-disk RSA ciphertext bytes are stored byte-reversed
//! (“little-endian” as a byte array), and the reference implementation reverses them before RSA
//! math (ref: `ntfsdecrypt.c` `ntfs_raw_fek_decrypt` calls `ntfs_buffer_reverse`).
//!
//! ## Current limitations
//!
//! - Only `flags == 0` (RSA-wrapped FEK) is supported. Smartcard AES-wrapped FEKs (flags=1) are
//!   not yet supported (ref: `external/refs/specs/MS-EFSR.md` §2.2.2.1.2 “Flags”).

use crate::ntfs::{Error, Result};
use crate::parse::Reader;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use des::{Des, TdesEde3};
use md5::{Digest as _, Md5};
use openssl::pkey::Private;
use openssl::rsa::{Padding, Rsa};

use super::metadata::EfsMetadataV1;
use super::pfx::EfsRsaKeyBag;

/// Supported EFS FEK algorithms (ALG_ID).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EfsFekAlgorithm {
    /// CALG_DESX (`0x6604`) with the Windows EFS key expansion.
    Desx,
    /// CALG_3DES (`0x6603`) in CBC mode.
    Tdes,
    /// CALG_AES_256 (`0x6610`) in CBC mode.
    Aes256,
}

/// A parsed and expanded File Encryption Key (FEK) for decrypting file content.
#[derive(Debug, Clone)]
pub enum EfsFek {
    /// DESX keying material expanded into:
    /// - DES key (8 bytes)
    /// - input/output whitening (64-bit each)
    Desx {
        des_key: [u8; 8],
        out_whitening: u64,
        in_whitening: u64,
    },
    /// 3DES EDE key (24 bytes).
    Tdes { key: [u8; 24] },
    /// AES-256 key (32 bytes).
    Aes256 { key: [u8; 32] },
}

impl EfsFek {
    pub fn algorithm(&self) -> EfsFekAlgorithm {
        match self {
            Self::Desx { .. } => EfsFekAlgorithm::Desx,
            Self::Tdes { .. } => EfsFekAlgorithm::Tdes,
            Self::Aes256 { .. } => EfsFekAlgorithm::Aes256,
        }
    }

    /// Decrypt a buffer in-place, interpreting it as a sequence of 512-byte sectors.
    ///
    /// `start_offset` is the file offset (in bytes) corresponding to `buf[0]` in the stream being
    /// decrypted. For normal file reads starting at the beginning, this is `0`.
    pub fn decrypt_in_place(&self, buf: &mut [u8], start_offset: u64) -> Result<()> {
        if !buf.len().is_multiple_of(512) {
            return Err(Error::InvalidData {
                message: format!(
                    "EFS decrypt expects a whole number of 512-byte sectors, got len={}",
                    buf.len()
                ),
            });
        }

        for i in 0..(buf.len() / 512) {
            let off = start_offset.saturating_add((i as u64).saturating_mul(512));
            let sector = &mut buf[i * 512..(i + 1) * 512];
            self.decrypt_sector_in_place(sector, off)?;
        }

        Ok(())
    }

    /// Decrypt a single 512-byte sector in-place.
    pub fn decrypt_sector_in_place(&self, sector: &mut [u8], offset: u64) -> Result<()> {
        if sector.len() != 512 {
            return Err(Error::InvalidData {
                message: format!("expected 512-byte sector, got {}", sector.len()),
            });
        }

        match self {
            EfsFek::Desx {
                des_key,
                out_whitening,
                in_whitening,
            } => {
                // CBC-like chaining is handled manually (per 8-byte block) and the EFS per-sector IV
                // is applied after decryption to the first 8 bytes.
                let des = Des::new_from_slice(des_key).map_err(|_e| Error::InvalidData {
                    message: "invalid DES key length".to_string(),
                })?;

                let mut prev_blk: u64 = 0;
                for k in (0..512).step_by(8) {
                    let curr_blk = u64::from_le_bytes(sector[k..k + 8].try_into().unwrap());
                    let mut tmp = (curr_blk ^ *out_whitening).to_le_bytes();
                    des.encrypt_block((&mut tmp).into());
                    let plain = u64::from_le_bytes(tmp) ^ *in_whitening ^ prev_blk;
                    prev_blk = curr_blk;
                    sector[k..k + 8].copy_from_slice(&plain.to_le_bytes());
                }

                // Apply the IV (all non-AES algorithms share the same IV scheme).
                let iv = 0x1691_1962_9891_ad13_u64.wrapping_add(offset);
                let p0 = u64::from_le_bytes(sector[0..8].try_into().unwrap()) ^ iv;
                sector[0..8].copy_from_slice(&p0.to_le_bytes());
            }
            EfsFek::Tdes { key } => {
                let tdes = TdesEde3::new_from_slice(key).map_err(|_e| Error::InvalidData {
                    message: "invalid 3DES key length".to_string(),
                })?;

                let iv = 0x1691_1962_9891_ad13_u64.wrapping_add(offset).to_le_bytes();
                let mut prev = iv;

                for k in (0..512).step_by(8) {
                    let mut block = [0u8; 8];
                    block.copy_from_slice(&sector[k..k + 8]);
                    let cipher_block = block;

                    tdes.decrypt_block((&mut block).into());
                    for i in 0..8 {
                        block[i] ^= prev[i];
                    }

                    sector[k..k + 8].copy_from_slice(&block);
                    prev = cipher_block;
                }
            }
            EfsFek::Aes256 { key } => {
                let aes = aes::Aes256::new_from_slice(key).map_err(|_e| Error::InvalidData {
                    message: "invalid AES-256 key length".to_string(),
                })?;

                // AES uses a 16-byte IV derived from two 64-bit constants plus the sector offset.
                let iv0 = 0x5816_657b_e916_1312_u64.wrapping_add(offset).to_le_bytes();
                let iv1 = 0x1989_adbe_4491_8961_u64.wrapping_add(offset).to_le_bytes();
                let mut prev = [0u8; 16];
                prev[0..8].copy_from_slice(&iv0);
                prev[8..16].copy_from_slice(&iv1);

                for k in (0..512).step_by(16) {
                    let mut block = [0u8; 16];
                    block.copy_from_slice(&sector[k..k + 16]);
                    let cipher_block = block;

                    aes.decrypt_block((&mut block).into());
                    for i in 0..16 {
                        block[i] ^= prev[i];
                    }

                    sector[k..k + 16].copy_from_slice(&block);
                    prev = cipher_block;
                }
            }
        }

        Ok(())
    }
}

/// Helper that unwraps an FEK from `$EFS` metadata and decrypts file sectors.
#[derive(Debug, Clone)]
pub struct EfsFekDecryptor {
    fek: EfsFek,
}

impl EfsFekDecryptor {
    /// Unwrap the FEK from the DDF entries in the given `$EFS` metadata.
    ///
    /// This selects candidate RSA keys **by matching certificate thumbprints** (MS-EFSR
    /// §2.2.2.1.4), then attempts to unwrap the FEK for each entry.
    ///
    /// This is intentionally deterministic: we do not try RSA keys whose certificate thumbprints
    /// do not match the DDF thumbprint.
    pub fn from_metadata_v1(meta: &EfsMetadataV1, keys: &EfsRsaKeyBag) -> Result<Self> {
        for entry in &meta.ddf {
            if entry.flags != 0 {
                // Smartcard AES-wrapped FEKs are not supported yet.
                continue;
            }

            if let Some(tp) = entry.cert_thumbprint_sha1.as_ref() {
                // Try keys that match the thumbprint.
                let mut matched_any = false;
                for rsa in keys.iter_matching_thumbprint(tp) {
                    matched_any = true;
                    if let Some(fek) = try_unwrap_fek_rsa(&entry.encrypted_fek, rsa)? {
                        return Ok(Self { fek });
                    }
                }

                // If no key matched this entry's thumbprint, keep trying other DDF entries (other
                // users/recovery agents may be present in the list).
                if !matched_any {
                    continue;
                }
            } else {
                // Metadata without thumbprints is unexpected for v1, but keep a best-effort path:
                // try all keys.
                for rsa in keys.iter() {
                    if let Some(fek) = try_unwrap_fek_rsa(&entry.encrypted_fek, rsa)? {
                        return Ok(Self { fek });
                    }
                }
            }
        }

        Err(Error::NotFound {
            what: format_thumbprint_mismatch(meta, keys),
        })
    }

    pub fn fek(&self) -> &EfsFek {
        &self.fek
    }

    pub fn decrypt_in_place(&self, buf: &mut [u8], start_offset: u64) -> Result<()> {
        self.fek.decrypt_in_place(buf, start_offset)
    }
}

fn try_unwrap_fek_rsa(encrypted_fek: &[u8], rsa: &Rsa<Private>) -> Result<Option<EfsFek>> {
    // In on-disk `$EFS` metadata, the RSA ciphertext bytes are stored byte-reversed (little-endian).
    // Try the "Windows" direction first, then fall back to the raw order for robustness.
    let mut ct_rev = encrypted_fek.to_vec();
    ct_rev.reverse();

    if let Some(fek) = try_unwrap_fek_rsa_inner(&ct_rev, rsa)? {
        return Ok(Some(fek));
    }
    if let Some(fek) = try_unwrap_fek_rsa_inner(encrypted_fek, rsa)? {
        return Ok(Some(fek));
    }

    Ok(None)
}

fn try_unwrap_fek_rsa_inner(ciphertext: &[u8], rsa: &Rsa<Private>) -> Result<Option<EfsFek>> {
    // Use raw RSA (no padding) and strip PKCS#1 v1.5 padding ourselves.
    // This matches the behavior of common reference implementations.
    let mut out = vec![0u8; rsa.size() as usize];
    let n = match rsa.private_decrypt(ciphertext, &mut out, Padding::NONE) {
        Ok(n) => n,
        Err(_) => return Ok(None),
    };
    out.truncate(n);

    if let Some(pt) = strip_pkcs1v15(&out)
        && let Some(fek) = parse_fek_plaintext(pt)?
    {
        return Ok(Some(fek));
    }

    // Fallback: ntfsdecrypt.c-style stripping (less strict than PKCS#1 parsing).
    // Ref: `external/refs/repos/ntfsprogs-plus__ntfsprogs-plus@*/src/deprecated/ntfsdecrypt.c`,
    // `ntfs_raw_fek_decrypt` uses `strnlen()+1` to strip padding after MPI-to-bytes conversion.
    if let Some(pt) = strip_ntfsdecrypt_style(&out) {
        return parse_fek_plaintext(pt);
    }

    Ok(None)
}

fn strip_pkcs1v15(buf: &[u8]) -> Option<&[u8]> {
    // Accept both:
    // - 0x00 0x02 ... 0x00 <msg> (full-length RSA block)
    // - 0x02 ... 0x00 <msg>      (leading 0x00 dropped by integer-to-bytes conversion)
    if buf.len() < 3 {
        return None;
    }

    let (start, prefix_ok) = if buf[0] == 0x00 {
        (2usize, buf.get(1) == Some(&0x02))
    } else {
        (1usize, buf[0] == 0x02)
    };
    if !prefix_ok {
        return None;
    }

    let sep = buf[start..].iter().position(|&b| b == 0x00)? + start;
    buf.get(sep + 1..)
}

fn strip_ntfsdecrypt_style(buf: &[u8]) -> Option<&[u8]> {
    // Mimic libgcrypt MPI printing: drop leading zeros, then strip everything up to and including
    // the first NUL byte (ref: ntfsdecrypt.c `ntfs_raw_fek_decrypt`).
    let first_non_zero = buf.iter().position(|&b| b != 0)?;
    let stripped = &buf[first_non_zero..];
    let z = stripped.iter().position(|&b| b == 0)?;
    stripped.get(z + 1..)
}

fn format_thumbprint_mismatch(meta: &EfsMetadataV1, keys: &EfsRsaKeyBag) -> String {
    fn hex20(tp: &[u8; 20]) -> String {
        let mut s = String::with_capacity(40);
        for b in tp {
            use std::fmt::Write as _;
            let _ = write!(&mut s, "{:02x}", b);
        }
        s
    }

    let mut out = String::new();
    out.push_str(
        "no DDF entry could be decrypted with the provided RSA key(s) (thumbprint-first)\n",
    );

    out.push_str("ddf_entries:\n");
    for (i, e) in meta.ddf.iter().enumerate() {
        let tp = e
            .cert_thumbprint_sha1
            .as_ref()
            .map(hex20)
            .unwrap_or_else(|| "<missing>".to_string());
        out.push_str(&format!(
            "- ddf[{i}]: flags={} encrypted_fek_len={} cert_thumbprint_sha1={tp}\n",
            e.flags,
            e.encrypted_fek.len()
        ));
    }

    out.push_str("pfx_keys:\n");
    for (i, (rsa, tp)) in keys.iter_with_thumbprints().enumerate() {
        let tp = tp
            .map(|t| hex20(&t))
            .unwrap_or_else(|| "<missing>".to_string());
        out.push_str(&format!(
            "- key[{i}]: rsa_size={} cert_thumbprint_sha1={tp}\n",
            rsa.size()
        ));
    }

    out
}

fn parse_fek_plaintext(pt: &[u8]) -> Result<Option<EfsFek>> {
    // MS-EFSR 2.2.2.1.5: KeyLength, Entropy, Algorithm, Reserved, Key[..].
    if pt.len() < 16 {
        return Ok(None);
    }

    let mut r = Reader::new(pt);
    let key_len = r.u32_le("efs.fek.key_length")? as usize;
    let _entropy = r.u32_le("efs.fek.entropy")?;
    let alg = r.u32_le("efs.fek.algorithm")?;
    let reserved = r.u32_le("efs.fek.reserved")?;
    if reserved != 0 {
        return Ok(None);
    }

    let key_bytes = r.take("efs.fek.key", key_len)?;

    const CALG_DES: u32 = 0x6601;
    const CALG_3DES: u32 = 0x6603;
    const CALG_DESX: u32 = 0x6604;
    const CALG_AES_256: u32 = 0x6610;

    let fek = match alg {
        CALG_DESX => {
            if key_len != 16 {
                return Ok(None);
            }
            let on_disk_key: [u8; 16] = key_bytes.try_into().expect("len checked");
            let (des_key, out_whitening, in_whitening) = desx_expand_key(&on_disk_key);
            EfsFek::Desx {
                des_key,
                out_whitening,
                in_whitening,
            }
        }
        CALG_3DES => {
            if key_len != 24 {
                return Ok(None);
            }
            EfsFek::Tdes {
                key: key_bytes.try_into().expect("len checked"),
            }
        }
        CALG_AES_256 => {
            if key_len != 32 {
                return Ok(None);
            }
            EfsFek::Aes256 {
                key: key_bytes.try_into().expect("len checked"),
            }
        }
        CALG_DES => {
            // Explicitly unsupported: weak and uncommon in modern EFS.
            return Ok(None);
        }
        _ => return Ok(None),
    };

    Ok(Some(fek))
}

fn desx_expand_key(on_disk_key: &[u8; 16]) -> ([u8; 8], u64, u64) {
    // Matches the DESX expansion used by Windows EFS (as documented by reference implementations).
    //
    // Important: the salts include the trailing NUL byte (12 bytes total).
    const SALT1: &[u8; 12] = b"Dan Simon  \0";
    const SALT2: &[u8; 12] = b"Scott Field\0";

    let d1 = md5_concat(on_disk_key, SALT1);
    let w0 = u32::from_le_bytes(d1[0..4].try_into().unwrap());
    let w1 = u32::from_le_bytes(d1[4..8].try_into().unwrap());
    let w2 = u32::from_le_bytes(d1[8..12].try_into().unwrap());
    let w3 = u32::from_le_bytes(d1[12..16].try_into().unwrap());
    let des0 = w0 ^ w1;
    let des1 = w2 ^ w3;
    let mut des_key = [0u8; 8];
    des_key[0..4].copy_from_slice(&des0.to_le_bytes());
    des_key[4..8].copy_from_slice(&des1.to_le_bytes());

    let d2 = md5_concat(on_disk_key, SALT2);
    let out_whitening = u64::from_le_bytes(d2[0..8].try_into().unwrap());
    let in_whitening = u64::from_le_bytes(d2[8..16].try_into().unwrap());

    (des_key, out_whitening, in_whitening)
}

fn md5_concat(a: &[u8], b: &[u8]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(a);
    h.update(b);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkcs12::Pkcs12;
    use openssl::pkey::PKey;
    use openssl::x509::{X509, X509NameBuilder};

    fn build_fek_plaintext_aes256(key_byte: u8) -> Vec<u8> {
        let mut pt = Vec::new();
        pt.extend_from_slice(&(32u32).to_le_bytes()); // key len
        pt.extend_from_slice(&(256u32).to_le_bytes()); // entropy (ignored)
        pt.extend_from_slice(&(0x6610u32).to_le_bytes()); // CALG_AES_256
        pt.extend_from_slice(&(0u32).to_le_bytes()); // reserved
        pt.extend([key_byte; 32]);
        pt
    }

    fn build_pkcs12_with_rsa(password: &str) -> (Vec<u8>, EfsRsaKeyBag, [u8; 20]) {
        let rsa = Rsa::generate(1024).expect("RSA keygen");
        let pkey = PKey::from_rsa(rsa).expect("PKey::from_rsa");

        let mut name = X509NameBuilder::new().expect("X509NameBuilder");
        name.append_entry_by_nid(Nid::COMMONNAME, "ntfs-crypto-test")
            .unwrap();
        let name = name.build();

        let mut builder = X509::builder().expect("X509::builder");
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        let cert = builder.build();

        let digest = cert.digest(MessageDigest::sha1()).unwrap();
        let mut tp = [0u8; 20];
        tp.copy_from_slice(&digest);

        let p12 = Pkcs12::builder()
            .name("ntfs-crypto-test")
            .pkey(&pkey)
            .cert(&cert)
            .build2(password)
            .unwrap();
        let der = p12.to_der().unwrap();

        let keys = EfsRsaKeyBag::from_pkcs12_der(&der, Some(password)).unwrap();
        (der, keys, tp)
    }

    #[test]
    fn strip_pkcs1v15_accepts_full_block_prefix() {
        let buf = [0x00, 0x02, 0xAA, 0xBB, 0x00, 0x11, 0x22];
        assert_eq!(strip_pkcs1v15(&buf), Some(&buf[5..]));
    }

    #[test]
    fn strip_pkcs1v15_accepts_missing_leading_zero_prefix() {
        let buf = [0x02, 0xAA, 0xBB, 0x00, 0x11, 0x22];
        assert_eq!(strip_pkcs1v15(&buf), Some(&buf[4..]));
    }

    #[test]
    fn strip_ntfsdecrypt_style_drops_leading_zeros_and_splits_on_nul() {
        let buf = [0x00, 0x00, 0x11, 0x22, 0x00, 0xAA, 0xBB];
        assert_eq!(strip_ntfsdecrypt_style(&buf), Some(&buf[5..]));
    }

    #[test]
    fn parse_fek_plaintext_accepts_aes256() {
        let pt = build_fek_plaintext_aes256(0xAB);
        let fek = parse_fek_plaintext(&pt).unwrap().unwrap();
        assert_eq!(fek.algorithm(), EfsFekAlgorithm::Aes256);
        match fek {
            EfsFek::Aes256 { key } => assert!(key.iter().all(|&b| b == 0xAB)),
            _ => panic!("expected aes256"),
        }
    }

    #[test]
    fn try_unwrap_fek_rsa_succeeds_for_on_disk_reversed_ciphertext() {
        let (_der, keys, tp) = build_pkcs12_with_rsa("password");
        let rsa = keys.iter().next().unwrap();

        let pt = build_fek_plaintext_aes256(0x42);
        let mut ct = vec![0u8; rsa.size() as usize];
        let n = rsa
            .public_encrypt(&pt, &mut ct, Padding::PKCS1)
            .expect("public_encrypt");
        ct.truncate(n);
        assert_eq!(ct.len(), rsa.size() as usize);

        // Simulate on-disk byte-reversed ciphertext.
        let mut on_disk = ct.clone();
        on_disk.reverse();

        let fek = try_unwrap_fek_rsa(&on_disk, rsa).unwrap().unwrap();
        assert_eq!(fek.algorithm(), EfsFekAlgorithm::Aes256);

        // Smoke-check that metadata+thumbprint selection can succeed with this key.
        let entry = crate::ntfs::efs::metadata::KeyListEntry {
            length: 0,
            public_key_info_offset: 0,
            encrypted_fek_length: on_disk.len() as u32,
            encrypted_fek_offset: 0,
            flags: 0,
            encrypted_fek: on_disk,
            cert_thumbprint_sha1: Some(tp),
            owner_hint_sid: None,
            cert_container_name: None,
            cert_provider_name: None,
            cert_display_name: None,
        };
        let meta = crate::ntfs::efs::metadata::EfsMetadataV1 {
            length: 0,
            efs_version: 2,
            efs_id: [0u8; 16],
            efs_hash: [0u8; 16],
            ddf: vec![entry],
            drf: Vec::new(),
        };
        let dec = EfsFekDecryptor::from_metadata_v1(&meta, &keys).unwrap();
        assert_eq!(dec.fek().algorithm(), EfsFekAlgorithm::Aes256);
    }

    #[test]
    fn from_metadata_v1_errors_on_thumbprint_mismatch_and_includes_diagnostics() {
        let (_der, keys, tp) = build_pkcs12_with_rsa("password");
        let rsa = keys.iter().next().unwrap();

        let pt = build_fek_plaintext_aes256(0x42);
        let mut ct = vec![0u8; rsa.size() as usize];
        let n = rsa.public_encrypt(&pt, &mut ct, Padding::PKCS1).unwrap();
        ct.truncate(n);
        let mut on_disk = ct.clone();
        on_disk.reverse();

        let mut wrong_tp = tp;
        wrong_tp[0] ^= 0xff;

        let entry = crate::ntfs::efs::metadata::KeyListEntry {
            length: 0,
            public_key_info_offset: 0,
            encrypted_fek_length: on_disk.len() as u32,
            encrypted_fek_offset: 0,
            flags: 0,
            encrypted_fek: on_disk,
            cert_thumbprint_sha1: Some(wrong_tp),
            owner_hint_sid: None,
            cert_container_name: None,
            cert_provider_name: None,
            cert_display_name: None,
        };
        let meta = crate::ntfs::efs::metadata::EfsMetadataV1 {
            length: 0,
            efs_version: 2,
            efs_id: [0u8; 16],
            efs_hash: [0u8; 16],
            ddf: vec![entry],
            drf: Vec::new(),
        };

        let err = EfsFekDecryptor::from_metadata_v1(&meta, &keys).unwrap_err();
        let s = err.to_string();
        assert!(s.contains("no DDF entry could be decrypted"));
        // both thumbprints should appear, hex-encoded.
        assert!(s.contains(&hex::encode(wrong_tp)));
        assert!(s.contains(&hex::encode(tp)));
    }
}
