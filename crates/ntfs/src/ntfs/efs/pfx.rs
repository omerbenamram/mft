//! PKCS#12 (`.pfx`) handling for EFS private keys.
//!
//! In Windows EFS workflows, user/DRA private keys are commonly exported as PKCS#12 files. We
//! parse the `.pfx` and extract RSA private keys to unwrap the FEK from `$EFS` metadata.
//!
//! The on-disk `$EFS` metadata identifies the intended certificate via a **certificate thumbprint**
//! which is defined as `SHA1(DER(X.509 certificate))` (ref: `external/refs/specs/MS-EFSR.md`
//! §2.2.2.1.4 “Certificate Thumbprint”). Reference tooling extracts the same SHA‑1 fingerprint from
//! the PFX’s embedded certificate when selecting the matching key (ref:
//! `external/refs/repos/ntfsprogs-plus__ntfsprogs-plus@*/src/deprecated/ntfsdecrypt.c`,
//! function `ntfs_pkcs12_extract_rsa_key`).
//!
//! ## Current limitations
//!
//! - We currently extract only RSA keys.

use crate::ntfs::{Error, Result};
use openssl::hash::MessageDigest;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::Private;
use openssl::rsa::Rsa;

/// Collection of RSA private keys loaded from a PKCS#12/PFX.
///
/// This bag retains (when available) the SHA-1 thumbprint of the X.509 certificate associated
/// with each RSA key. This enables deterministic “thumbprint-first” selection against `$EFS`
/// metadata (ref: `external/refs/specs/MS-EFSR.md` §2.2.2.1.4).
#[derive(Debug, Clone)]
pub struct EfsRsaKeyBag {
    keys: Vec<EfsRsaKeyEntry>,
}

#[derive(Debug, Clone)]
struct EfsRsaKeyEntry {
    rsa: Rsa<Private>,
    cert_thumbprint_sha1: Option<[u8; 20]>,
}

impl EfsRsaKeyBag {
    /// Load RSA keys from a PKCS#12/PFX blob (`.pfx`).
    ///
    /// - `password`: pass `None` for a password-less PFX, or `Some("")` for an empty password.
    pub fn from_pkcs12_der(pfx: &[u8], password: Option<&str>) -> Result<Self> {
        let password = password.unwrap_or("");

        // OpenSSL 3.x disables several legacy algorithms (notably RC2) by default. Real-world PKCS#12
        // files (and our fixture) can still use these. Since we build with the vendored OpenSSL,
        // attempt to load the `legacy` provider to enable RC2-based PBE.
        let _legacy = openssl::provider::Provider::try_load(None, "legacy", true).map_err(|e| {
            Error::InvalidData {
                message: format!("failed to load OpenSSL legacy provider: {e}"),
            }
        })?;

        let parsed = Pkcs12::from_der(pfx)
            .and_then(|p12| p12.parse2(password))
            .map_err(|e| Error::InvalidData {
                message: format!("failed to parse PKCS#12/PFX: {e}"),
            })?;

        let cert_thumbprint_sha1 = if let Some(cert) = parsed.cert.as_ref() {
            let digest = cert
                .digest(MessageDigest::sha1())
                .map_err(|e| Error::InvalidData {
                    message: format!("failed to compute certificate SHA-1 thumbprint: {e}"),
                })?;
            if digest.len() != 20 {
                return Err(Error::InvalidData {
                    message: format!(
                        "unexpected certificate SHA-1 thumbprint length: {} (expected 20)",
                        digest.len()
                    ),
                });
            }
            let mut out = [0u8; 20];
            out.copy_from_slice(&digest);
            Some(out)
        } else {
            None
        };

        let mut keys = Vec::new();
        if let Some(pkey) = parsed.pkey {
            let rsa = pkey.rsa().map_err(|e| Error::InvalidData {
                message: format!("PKCS#12 private key is not usable as RSA: {e}"),
            })?;
            keys.push(EfsRsaKeyEntry {
                rsa,
                cert_thumbprint_sha1,
            });
        }

        if keys.is_empty() {
            return Err(Error::NotFound {
                what: "no RSA private keys found in PKCS#12/PFX".to_string(),
            });
        }

        Ok(Self { keys })
    }

    /// Iterate all RSA keys stored in this bag.
    pub fn iter(&self) -> impl Iterator<Item = &Rsa<Private>> {
        self.keys.iter().map(|k| &k.rsa)
    }

    /// Iterate the stored certificate SHA-1 thumbprints (if present) alongside their keys.
    pub fn iter_with_thumbprints(&self) -> impl Iterator<Item = (&Rsa<Private>, Option<[u8; 20]>)> {
        self.keys.iter().map(|k| (&k.rsa, k.cert_thumbprint_sha1))
    }

    /// Iterate the stored certificate SHA-1 thumbprints (if present).
    pub fn thumbprints(&self) -> impl Iterator<Item = Option<[u8; 20]>> + '_ {
        self.keys.iter().map(|k| k.cert_thumbprint_sha1)
    }

    /// Iterate RSA keys whose associated certificate thumbprint matches `thumbprint`.
    pub fn iter_matching_thumbprint<'a>(
        &'a self,
        thumbprint: &'a [u8; 20],
    ) -> impl Iterator<Item = &'a Rsa<Private>> + 'a {
        self.keys.iter().filter_map(move |k| {
            if k.cert_thumbprint_sha1.as_ref() == Some(thumbprint) {
                Some(&k.rsa)
            } else {
                None
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::asn1::Asn1Time;
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::x509::{X509, X509Name, X509NameBuilder};

    fn build_self_signed_rsa_pkcs12(password: &str) -> (Vec<u8>, [u8; 20]) {
        let rsa = Rsa::generate(1024).expect("RSA keygen");
        let pkey = PKey::from_rsa(rsa).expect("PKey::from_rsa");

        let mut name = X509NameBuilder::new().expect("X509NameBuilder");
        name.append_entry_by_nid(Nid::COMMONNAME, "ntfs-test")
            .expect("append CN");
        let name: X509Name = name.build();

        let mut builder = X509::builder().expect("X509::builder");
        builder.set_version(2).expect("set_version");
        builder.set_subject_name(&name).expect("set_subject_name");
        builder.set_issuer_name(&name).expect("set_issuer_name");
        builder.set_pubkey(&pkey).expect("set_pubkey");
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        builder
            .sign(&pkey, MessageDigest::sha256())
            .expect("sign cert");
        let cert: X509 = builder.build();

        let digest = cert
            .digest(MessageDigest::sha1())
            .expect("cert sha1 digest");
        let mut tp = [0u8; 20];
        tp.copy_from_slice(&digest);

        let p12 = Pkcs12::builder()
            .name("ntfs-test")
            .pkey(&pkey)
            .cert(&cert)
            .build2(password)
            .expect("build pkcs12");
        (p12.to_der().expect("to_der"), tp)
    }

    #[test]
    fn parses_pkcs12_and_exposes_cert_thumbprint() {
        let (der, expected_tp) = build_self_signed_rsa_pkcs12("password");
        let bag = EfsRsaKeyBag::from_pkcs12_der(&der, Some("password")).unwrap();

        let tps: Vec<Option<[u8; 20]>> = bag.thumbprints().collect();
        assert_eq!(tps, vec![Some(expected_tp)]);

        // Ensure the key is present and modulus size is as expected for 1024-bit RSA.
        let rsa = bag.iter().next().unwrap();
        assert_eq!(rsa.size(), 128);
    }

    #[test]
    fn iter_matching_thumbprint_filters_keys() {
        let (der, expected_tp) = build_self_signed_rsa_pkcs12("password");
        let bag = EfsRsaKeyBag::from_pkcs12_der(&der, Some("password")).unwrap();

        assert_eq!(bag.iter_matching_thumbprint(&expected_tp).count(), 1);
        assert_eq!(bag.iter_matching_thumbprint(&[0u8; 20]).count(), 0);
    }

    #[test]
    fn parses_pkcs12_even_if_cert_missing_sets_thumbprint_none() {
        // Create a PKCS#12 which contains only a private key (no certificate). OpenSSL allows this
        // via PKCS12_create with a NULL cert pointer (used internally by Pkcs12Builder::build2).
        let rsa = Rsa::generate(1024).expect("RSA keygen");
        let pkey = PKey::from_rsa(rsa).expect("PKey::from_rsa");

        let p12 = Pkcs12::builder()
            .name("ntfs-test")
            .pkey(&pkey)
            .build2("password")
            .expect("build pkcs12");
        let der = p12.to_der().expect("to_der");

        let bag = EfsRsaKeyBag::from_pkcs12_der(&der, Some("password")).unwrap();
        assert_eq!(bag.iter().count(), 1);
        assert_eq!(bag.thumbprints().collect::<Vec<_>>(), vec![None]);
    }
}
