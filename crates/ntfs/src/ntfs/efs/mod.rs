//! Encrypting File System (EFS) support.
//!
//! This module implements **offline EFS decryption** for NTFS volumes:
//!
//! - Parse the on-disk `$EFS` metadata stored in the `LoggedUtilityStream` attribute
//!   (`$LOGGED_UTILITY_STREAM`, attribute type `0x100`) named `"$EFS"`.
//! - Unwrap the **File Encryption Key (FEK)** from the DDF/DRF entries using an RSA private key
//!   (typically supplied as a PKCS#12 / `.pfx` file).
//! - Decrypt file `$DATA` **by 512-byte sectors**, using the FEK and the per-sector IV scheme used
//!   by Windows NTFS.
//!
//! ## References
//!
//! - `external/refs/specs/MS-EFSR.md` (MS-EFSR): structures used for the `$EFS` metadata and the
//!   "Encrypted FEK" structure.
//! - Reference implementations (vendored for offline reading only):
//!   - `external/refs/repos/ntfsprogs-plus__ntfsprogs-plus@*/src/deprecated/ntfsdecrypt.c`
//!   - `external/refs/repos/tuxera__ntfs-3g@*/libntfs-3g/efs.c`
//!
//! **Important**: this crate does not compile or link any code from `external/refs/`.

pub mod crypto;
pub mod metadata;
pub mod pfx;

pub use crypto::{EfsFek, EfsFekAlgorithm, EfsFekDecryptor};
pub use metadata::{EfsMetadataV1, KeyListEntry};
pub use pfx::EfsRsaKeyBag;
