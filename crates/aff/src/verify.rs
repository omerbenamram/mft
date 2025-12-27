//! Signature verification for AFF segments.
//!
//! AFFLIBv3 supports attaching SHA-256 RSA signatures to segments by writing a companion segment
//! named `"{segname}/sha256"`. The signing certificate is stored in the segment `cert-sha256` as
//! a PEM-encoded X.509 certificate.
//!
//! This module provides read-side signature verification matching AFFLIB semantics.
//!
//! ## Example
//!
//! ```no_run
//! use aff::{AffOpenOptions, Verifier};
//!
//! let img = AffOpenOptions::new().open("image.aff")?;
//! let v = Verifier::new(&img);
//! let status = v.verify_segment("pagesize")?;
//! println!("{status:?}");
//! # Ok::<(), aff::Error>(())
//! ```

use crate::{AffImage, Error, Result};
use forensic_image::ReadAt;

/// Signature verification outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureStatus {
    /// The segment verified successfully.
    Good,
    /// The signature segment is missing.
    MissingSignature,
    /// The signing certificate segment (`cert-sha256`) is missing.
    MissingCertificate,
    /// The segment being verified is missing.
    MissingSegment,
    /// The signature did not verify.
    Bad,
    /// Unsupported signature mode (unknown arg in the `*/sha256` segment).
    UnsupportedMode(u32),
    /// Signature verification requires the `crypto` feature.
    CryptoDisabled,
}

/// Signature verification helper bound to a specific [`AffImage`].
pub struct Verifier<'a> {
    img: &'a AffImage,
}

impl<'a> Verifier<'a> {
    /// Creates a verifier for an opened image.
    ///
    /// ## Example
    ///
    /// ```no_run
    /// use aff::{AffImage, Verifier};
    ///
    /// let img = AffImage::open("image.aff")?;
    /// let v = Verifier::new(&img);
    /// # Ok::<(), aff::Error>(())
    /// ```
    pub fn new(img: &'a AffImage) -> Self {
        Self { img }
    }

    /// Verifies a single segment against its companion `"{segname}/sha256"` signature segment.
    ///
    /// ## Example
    ///
    /// ```no_run
    /// use aff::{AffImage, SignatureStatus, Verifier};
    ///
    /// let img = AffImage::open("image.aff")?;
    /// let v = Verifier::new(&img);
    /// let status = v.verify_segment("page0")?;
    /// assert!(matches!(status, SignatureStatus::Good | SignatureStatus::MissingSignature));
    /// # Ok::<(), aff::Error>(())
    /// ```
    pub fn verify_segment(&self, segname: &str) -> Result<SignatureStatus> {
        self.verify_segment_impl(segname)
    }

    /// Verifies all signature segments present in the container.
    ///
    /// This method iterates `segment_names()`, finds segments ending with `/sha256`, and verifies
    /// their corresponding base segment.
    ///
    /// ## Example
    ///
    /// ```no_run
    /// use aff::{AffImage, Verifier};
    ///
    /// let img = AffImage::open("image.aff")?;
    /// let v = Verifier::new(&img);
    /// for (name, status) in v.verify_all()? {
    ///     println!("{status:?}\t{name}");
    /// }
    /// # Ok::<(), aff::Error>(())
    /// ```
    pub fn verify_all(&self) -> Result<Vec<(String, SignatureStatus)>> {
        let mut out = Vec::new();
        for name in self.img.segment_names() {
            if let Some(base) = name.strip_suffix(crate::format::SIG256_SUFFIX) {
                let status = self.verify_segment(base)?;
                out.push((base.to_string(), status));
            }
        }
        Ok(out)
    }

    fn verify_segment_impl(&self, segname: &str) -> Result<SignatureStatus> {
        #[cfg(not(feature = "crypto"))]
        {
            let _ = segname;
            return Ok(SignatureStatus::CryptoDisabled);
        }

        #[cfg(feature = "crypto")]
        {
            use openssl::hash::MessageDigest;
            use openssl::sign::Verifier as OpenSslVerifier;
            use openssl::x509::X509;

            let sigseg = format!("{segname}{}", crate::format::SIG256_SUFFIX);

            let Some(sig) = self.img.read_segment(&sigseg)? else {
                return Ok(SignatureStatus::MissingSignature);
            };

            let sigmode = sig.arg;
            if sigmode != crate::format::AF_SIGNATURE_MODE0
                && sigmode != crate::format::AF_SIGNATURE_MODE1
            {
                return Ok(SignatureStatus::UnsupportedMode(sigmode));
            }

            let Some(certseg) = self.img.read_segment(crate::format::SIGN256_CERT)? else {
                return Ok(SignatureStatus::MissingCertificate);
            };

            let cert = X509::from_pem(&certseg.data).map_err(|e| Error::InvalidData {
                message: format!("failed to parse cert-sha256 PEM: {e}"),
            })?;
            let pubkey = cert.public_key().map_err(|e| Error::InvalidData {
                message: format!("failed to extract public key: {e}"),
            })?;

            let mut verifier =
                OpenSslVerifier::new(MessageDigest::sha256(), &pubkey).map_err(|e| {
                    Error::InvalidData {
                        message: format!("OpenSSL verifier init failed: {e}"),
                    }
                })?;

            // AFFLIB signs/verifies with:
            // - segname including a terminating NUL byte
            // - arg in network byte order
            // - segment bytes
            verifier
                .update(segname.as_bytes())
                .map_err(|e| Error::InvalidData {
                    message: format!("verifier update(segname) failed: {e}"),
                })?;
            verifier.update(&[0]).map_err(|e| Error::InvalidData {
                message: format!("verifier update(NUL) failed: {e}"),
            })?;

            let (arg_net, bytes) = if sigmode == crate::format::AF_SIGNATURE_MODE1 {
                // Mode1: arg=0 and uncompressed page bytes for page segments.
                let page_index = segname
                    .strip_prefix("page")
                    .or_else(|| segname.strip_prefix("seg"))
                    .and_then(|r| r.parse::<u64>().ok())
                    .ok_or_else(|| Error::InvalidData {
                        message: format!("MODE1 signature for non-page segment: {segname}"),
                    })?;

                let page_size = self.img.page_size() as u64;
                let base = page_index.saturating_mul(page_size);
                let mut buf = vec![0u8; self.img.page_size()];
                if base < self.img.len() {
                    let take = (self.img.len() - base).min(page_size) as usize;
                    self.img
                        .read_exact_at(base, &mut buf[..take])
                        .map_err(Error::Io)?;
                }
                (0u32.to_be_bytes(), buf)
            } else {
                let Some(seg) = self.img.read_segment(segname)? else {
                    return Ok(SignatureStatus::MissingSegment);
                };
                (seg.arg.to_be_bytes(), seg.data)
            };

            verifier.update(&arg_net).map_err(|e| Error::InvalidData {
                message: format!("verifier update(arg) failed: {e}"),
            })?;
            verifier.update(&bytes).map_err(|e| Error::InvalidData {
                message: format!("verifier update(data) failed: {e}"),
            })?;

            let ok = verifier.verify(&sig.data).map_err(|e| Error::InvalidData {
                message: format!("signature verify failed: {e}"),
            })?;

            Ok(if ok {
                SignatureStatus::Good
            } else {
                SignatureStatus::Bad
            })
        }
    }
}
