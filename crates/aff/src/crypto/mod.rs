//! AFF crypto (read-side).
//!
//! This module provides a wrapper layer around a container backend which can:
//! - derive an AFF AES key from `affkey_aes256` using a passphrase
//! - unseal `affkey_evp%d` using an RSA private key (PEM)
//! - auto-decrypt `/aes256` segments on read (CBC with IV derived from segment name)
//!
//! Signature verification is implemented in [`crate::verify`].
//!
//! The implementation is modeled after AFFLIBv3 (`lib/crypto.cpp` + `lib/afflib.cpp`).

mod wrapper;

pub(crate) use wrapper::wrap_backend;
