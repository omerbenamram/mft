use crate::backends::AffOpenOptions;
use crate::backends::backend::Backend;
use crate::format;
use crate::format::AF_AFFKEY;
use crate::{ContainerKind, Segment};
use crate::{Error, Result};
use forensic_image::ReadAt;
use openssl::hash::{MessageDigest, hash};
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::symm::{Cipher, Crypter, Mode};
use std::io;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

pub(crate) fn wrap_backend(
    inner: Arc<dyn Backend>,
    opts: &AffOpenOptions,
) -> Result<Arc<dyn Backend>> {
    let mut state = CryptoState::new(inner.clone());

    if let Some(pass) = opts.passphrase.as_deref() {
        state.try_set_passphrase(&*inner, pass)?;
    }
    if let Some(keyfile) = opts.unseal_keyfile.as_deref() {
        state.try_set_unseal_keyfile(&*inner, keyfile)?;
    }

    Ok(Arc::new(CryptoBackend {
        inner,
        state,
        auto_decrypt: opts.auto_decrypt,
    }))
}

#[derive(Debug, Clone)]
struct CryptoState {
    aes_key: Option<[u8; 32]>,
}

impl CryptoState {
    fn new(_inner: Arc<dyn Backend>) -> Self {
        Self { aes_key: None }
    }

    fn try_set_passphrase(&mut self, inner: &dyn Backend, passphrase: &str) -> Result<()> {
        // Derive SHA256(passphrase)
        let hash = hash(MessageDigest::sha256(), passphrase.as_bytes()).map_err(|e| {
            Error::InvalidData {
                message: format!("sha256(passphrase): {e}"),
            }
        })?;

        let seg = match inner.read_segment(AF_AFFKEY).map_err(Error::Io)? {
            Some(s) => s,
            None => {
                return Err(Error::InvalidData {
                    message: "missing affkey_aes256 segment".to_string(),
                });
            }
        };

        // On-disk can be 52 bytes (correct) or 56 bytes (legacy packing bug).
        if seg.data.len() < 52 {
            return Err(Error::InvalidData {
                message: format!("affkey_aes256 too small: {}", seg.data.len()),
            });
        }

        let version = u32::from_be_bytes(seg.data[0..4].try_into().expect("len=4"));
        if version != 1 {
            return Err(Error::InvalidData {
                message: format!("affkey_aes256 wrong version: {version}"),
            });
        }

        let mut affkey_enc = [0u8; 32];
        affkey_enc.copy_from_slice(&seg.data[4..36]);
        let mut zeros_enc = [0u8; 16];
        zeros_enc.copy_from_slice(&seg.data[36..52]);

        fn aes256_ecb_decrypt_block(key: &[u8], block16: &[u8]) -> Result<[u8; 16]> {
            let cipher = Cipher::aes_256_ecb();
            let mut dec =
                Crypter::new(cipher, Mode::Decrypt, key, None).map_err(|e| Error::InvalidData {
                    message: format!("aes256-ecb init: {e}"),
                })?;
            dec.pad(false);

            let mut out = [0u8; 32];
            let mut n = dec
                .update(block16, &mut out)
                .map_err(|e| Error::InvalidData {
                    message: format!("aes update: {e}"),
                })?;
            n += dec
                .finalize(&mut out[n..])
                .map_err(|e| Error::InvalidData {
                    message: format!("aes finalize: {e}"),
                })?;
            if n != 16 {
                return Err(Error::InvalidData {
                    message: "aes ecb decrypt produced unexpected length".to_string(),
                });
            }

            Ok(out[..16].try_into().expect("len=16"))
        }

        let block0 = aes256_ecb_decrypt_block(hash.as_ref(), &affkey_enc[0..16])?;
        let block1 = aes256_ecb_decrypt_block(hash.as_ref(), &affkey_enc[16..32])?;
        let zeros = aes256_ecb_decrypt_block(hash.as_ref(), &zeros_enc)?;

        if zeros.iter().any(|&b| b != 0) {
            return Err(Error::InvalidData {
                message: "wrong passphrase (zeros check failed)".to_string(),
            });
        }

        let mut aes_key = [0u8; 32];
        aes_key[0..16].copy_from_slice(&block0);
        aes_key[16..32].copy_from_slice(&block1);
        self.aes_key = Some(aes_key);
        Ok(())
    }

    fn try_set_unseal_keyfile(
        &mut self,
        inner: &dyn Backend,
        private_keyfile: &Path,
    ) -> Result<()> {
        // Port of AFFLIB's `af_get_affkey_using_keyfile` rev-1 only.
        let pem = std::fs::read(private_keyfile)?;
        let rsa = Rsa::private_key_from_pem(&pem).map_err(|e| Error::InvalidData {
            message: format!("failed to parse PEM private key: {e}"),
        })?;
        let pkey = PKey::from_rsa(rsa).map_err(|e| Error::InvalidData {
            message: format!("failed to build PKey: {e}"),
        })?;

        for i in 0..1000u32 {
            let name = format!("affkey_evp{i}");
            let Some(seg) = inner.read_segment(&name).map_err(Error::Io)? else {
                // AFFLIB treats missing as failure; stop searching.
                break;
            };

            // Layout:
            // u32 version (BE) == 1
            // u32 ek_size (BE)
            // u32 total_encrypted_bytes (BE)
            // iv[EVP_MAX_IV_LENGTH==16]
            // ek[ek_size]
            // encrypted_affkey[total_encrypted_bytes]
            if seg.data.len() < 12 + 16 {
                continue;
            }
            let v = u32::from_be_bytes(seg.data[0..4].try_into().unwrap());
            if v != 1 {
                continue;
            }
            let ek_size = u32::from_be_bytes(seg.data[4..8].try_into().unwrap()) as usize;
            let total = u32::from_be_bytes(seg.data[8..12].try_into().unwrap()) as usize;
            let expected = 12 + 16 + ek_size + total;
            if seg.data.len() != expected {
                continue;
            }
            let iv = &seg.data[12..12 + 16];
            let ek = &seg.data[12 + 16..12 + 16 + ek_size];
            let encrypted = &seg.data[12 + 16 + ek_size..];

            // Use OpenSSL high-level decrypt: EVP_OpenInit/OpenUpdate/OpenFinal.
            // In Rust bindings we implement the same using `openssl::symm::Crypter` is not suitable here;
            // use `openssl::pkey` + `openssl::rsa` is not enough. We approximate with `openssl::symm::Crypter`
            // by decrypting the session key (ek) using RSA, then decrypting encrypted_affkey using AES-256-CBC.
            //
            // Note: In AFFLIB, `ek` is produced by EVP_SealInit and encrypted with the cert pubkey. With RSA,
            // we can recover it with private key decrypt.
            let rsa = pkey.rsa().map_err(|_| Error::InvalidData {
                message: "unseal key is not RSA".to_string(),
            })?;
            let mut session_key = vec![0u8; 256];
            let n = rsa
                .private_decrypt(ek, &mut session_key, openssl::rsa::Padding::PKCS1)
                .map_err(|e| Error::InvalidData {
                    message: format!("RSA private_decrypt failed: {e}"),
                })?;
            session_key.truncate(n);

            // Decrypt encrypted_affkey with AES-256-CBC using recovered session_key and IV.
            if session_key.len() != 32 {
                continue;
            }
            let cipher = Cipher::aes_256_cbc();
            let mut dec =
                Crypter::new(cipher, Mode::Decrypt, &session_key, Some(iv)).map_err(|e| {
                    Error::InvalidData {
                        message: format!("aes-256-cbc init failed: {e}"),
                    }
                })?;
            dec.pad(true);
            let mut out = vec![0u8; encrypted.len() + cipher.block_size()];
            let mut count = dec
                .update(encrypted, &mut out)
                .map_err(|e| Error::InvalidData {
                    message: format!("aes update failed: {e}"),
                })?;
            count += dec
                .finalize(&mut out[count..])
                .map_err(|e| Error::InvalidData {
                    message: format!("aes finalize failed: {e}"),
                })?;
            out.truncate(count);
            if out.len() < 32 {
                continue;
            }
            let mut aes_key = [0u8; 32];
            aes_key.copy_from_slice(&out[..32]);
            self.aes_key = Some(aes_key);
            return Ok(());
        }

        Err(Error::InvalidData {
            message: "failed to unseal affkey using private key".to_string(),
        })
    }

    // Signature verification lives in `crate::verify`.
}

/// Crypto wrapper backend.
#[derive(Clone)]
struct CryptoBackend {
    inner: Arc<dyn Backend>,
    state: CryptoState,
    auto_decrypt: bool,
}

impl std::fmt::Debug for CryptoBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoBackend")
            .field("kind", &self.kind())
            .field("auto_decrypt", &self.auto_decrypt)
            .finish()
    }
}

impl ReadAt for CryptoBackend {
    fn len(&self) -> u64 {
        self.inner.len()
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        if offset.saturating_add(buf.len() as u64) > self.len() {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        let page_size = self.page_size();
        if page_size == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "page_size is 0"));
        }

        let mut remaining = buf.len();
        let mut out_pos = 0usize;
        let mut cur = offset;

        while remaining > 0 {
            let page_index = cur / page_size as u64;
            let within = (cur % page_size as u64) as usize;
            let take = remaining.min(page_size - within);

            let page = self.read_page(page_index)?;
            buf[out_pos..out_pos + take].copy_from_slice(&page[within..within + take]);

            out_pos += take;
            remaining -= take;
            cur = cur.saturating_add(take as u64);
        }

        Ok(())
    }
}

impl Backend for CryptoBackend {
    fn kind(&self) -> ContainerKind {
        self.inner.kind()
    }

    fn page_size(&self) -> usize {
        self.inner.page_size()
    }

    fn segment_names(&self) -> Vec<String> {
        self.inner.segment_names()
    }

    fn read_segment(&self, name: &str) -> io::Result<Option<Segment>> {
        // Implement AFFLIB-style auto-decrypt:
        // - if auto_decrypt and key present: try "<name>/aes256" first; if found, decrypt and return as `name`.
        // - otherwise return plain segment.

        if self.auto_decrypt
            && let Some(_key) = self.state.aes_key
        {
            let enc_name = format!("{name}{}", format::AES256_SUFFIX);
            if let Some(mut enc) = self.inner.read_segment(&enc_name)? {
                // Decrypt in-place (CBC with IV derived from segname, padded with zeros).
                let mut data = enc.data;
                let mut datalen = data.len();
                // AFFLIB trims any extra bytes so that datalen is a multiple of 16.
                let extra = datalen % 16;
                let pad = (16 - extra) % 16;
                if extra != 0 && datalen < 16 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "encrypted segment too small",
                    ));
                }
                datalen -= extra;
                data.truncate(datalen);

                let mut iv = [0u8; 16];
                let n = name.len().min(16);
                iv[..n].copy_from_slice(&name.as_bytes()[..n]);

                let cipher = Cipher::aes_256_cbc();
                let key = self.state.aes_key.expect("checked");
                let mut dec = Crypter::new(cipher, Mode::Decrypt, &key, Some(&iv))
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                dec.pad(false);
                let mut out = vec![0u8; data.len() + 16];
                let mut count = dec
                    .update(&data, &mut out)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                count += dec
                    .finalize(&mut out[count..])
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                out.truncate(count);

                // Remove padding bytes (AFFLIB writes PKCS7-ish pad values into a padded block).
                if pad > 0 && out.len() >= pad {
                    out.truncate(out.len() - pad);
                }

                enc.name = name.to_string();
                enc.data = out;
                return Ok(Some(enc));
            }
        }

        self.inner.read_segment(name)
    }
}

impl CryptoBackend {
    fn read_page(&self, page_index: u64) -> io::Result<Vec<u8>> {
        let page_size = self.page_size();
        let mut out = vec![0u8; page_size];

        // AFFLIB supports both `page<N>` and the deprecated `seg<N>` nomenclature.
        let mut name = format!("page{page_index}");
        let mut seg = self.read_segment(&name)?;
        if seg.is_none() {
            name = format!("seg{page_index}");
            seg = self.read_segment(&name)?;
        }
        let Some(seg) = seg else {
            return Ok(out);
        };

        // Decode page bytes from the (possibly decrypted) segment data.
        if (seg.arg & format::AF_PAGE_COMPRESSED) == 0 {
            let take = seg.data.len().min(out.len());
            out[..take].copy_from_slice(&seg.data[..take]);
            return Ok(out);
        }

        match seg.arg & format::AF_PAGE_COMP_ALG_MASK {
            format::AF_PAGE_COMP_ALG_ZERO => {
                // ZERO compressor => page is all zero.
                Ok(out)
            }
            format::AF_PAGE_COMP_ALG_ZLIB => {
                let cursor = io::Cursor::new(seg.data);
                let mut decoder = flate2::read::ZlibDecoder::new(cursor);
                let mut written = 0usize;
                while written < out.len() {
                    let n = decoder.read(&mut out[written..])?;
                    if n == 0 {
                        break;
                    }
                    written += n;
                }
                Ok(out)
            }
            format::AF_PAGE_COMP_ALG_LZMA => {
                #[cfg(feature = "lzma")]
                {
                    let mut input = io::Cursor::new(seg.data);
                    let mut output = io::Cursor::new(&mut out[..]);
                    lzma_rs::lzma_decompress(&mut input, &mut output).map_err(|e| {
                        io::Error::new(io::ErrorKind::InvalidData, format!("LZMA: {e}"))
                    })?;
                    Ok(out)
                }
                #[cfg(not(feature = "lzma"))]
                {
                    let _ = seg;
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "LZMA page but feature `lzma` is disabled",
                    ))
                }
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported page compression",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io;

    #[derive(Debug)]
    struct MemBackend {
        kind: ContainerKind,
        page_size: usize,
        segments: HashMap<String, Segment>,
    }

    impl ReadAt for MemBackend {
        fn len(&self) -> u64 {
            0
        }

        fn read_exact_at(&self, _offset: u64, _buf: &mut [u8]) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::UnexpectedEof))
        }
    }

    impl Backend for MemBackend {
        fn kind(&self) -> ContainerKind {
            self.kind
        }

        fn page_size(&self) -> usize {
            self.page_size
        }

        fn segment_names(&self) -> Vec<String> {
            let mut out = self.segments.keys().cloned().collect::<Vec<_>>();
            out.sort();
            out
        }

        fn read_segment(&self, name: &str) -> io::Result<Option<Segment>> {
            Ok(self.segments.get(name).cloned())
        }
    }

    fn aff_encrypt_like_afflib(segname: &str, key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
        // Match `af_update_segf` + `af_aes_decrypt` behavior:
        // - derive IV from segname
        // - encrypt plaintext padded to a block boundary (pad bytes are value `pad+extra`)
        // - append `extra` bytes so ciphertext_len % 16 == plaintext_len % 16
        let extra = plaintext.len() % 16;
        let pad = (16 - extra) % 16;

        let mut padded = Vec::with_capacity(plaintext.len() + pad);
        padded.extend_from_slice(plaintext);
        padded.extend(std::iter::repeat_n((pad + extra) as u8, pad));

        let mut iv = [0u8; 16];
        let n = segname.len().min(16);
        iv[..n].copy_from_slice(&segname.as_bytes()[..n]);

        let cipher = Cipher::aes_256_cbc();
        let mut enc = Crypter::new(cipher, Mode::Encrypt, key, Some(&iv)).unwrap();
        enc.pad(false);

        let mut out = vec![0u8; padded.len() + 16];
        let mut count = enc.update(&padded, &mut out).unwrap();
        count += enc.finalize(&mut out[count..]).unwrap();
        out.truncate(count);

        if extra != 0 {
            out.extend(std::iter::repeat_n(0u8, extra));
        }
        out
    }

    #[test]
    fn test_auto_decrypt_aes256_segment_trims_extra_and_padding() {
        let segname = "hello";
        let plaintext = b"hello from aff"; // len=14 => extra=14, pad=2

        let key = [0x11u8; 32];
        let enc = aff_encrypt_like_afflib(segname, &key, plaintext);

        let mut segments = HashMap::new();
        segments.insert(
            format!("{segname}{}", format::AES256_SUFFIX),
            Segment {
                name: format!("{segname}{}", format::AES256_SUFFIX),
                arg: 0,
                data: enc,
            },
        );

        let inner = Arc::new(MemBackend {
            kind: ContainerKind::Aff1,
            page_size: 4096,
            segments,
        });

        let crypto = CryptoBackend {
            inner,
            state: CryptoState { aes_key: Some(key) },
            auto_decrypt: true,
        };

        let seg = crypto.read_segment(segname).unwrap().unwrap();
        assert_eq!(seg.name, segname);
        assert_eq!(seg.data, plaintext);
    }
}
