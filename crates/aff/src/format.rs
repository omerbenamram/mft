//! AFF format constants and well-known segment names.
//!
//! This module intentionally only defines **names and numeric constants**.
//! Parsing logic lives in the backend implementations under [`crate::backends`].

/// AFF1 file signature (first 4 bytes).
pub const AFF1_MAGIC: &[u8; 4] = b"AFF1";

/// AFF1 file header (8 bytes): `b"AFF10\\r\\n\\0"`.
pub const AFF1_HEADER: &[u8; 8] = b"AFF10\r\n\0";

/// Segment magic prefix.
pub const SEG_MAGIC: &[u8; 4] = b"AFF\0";

/// Segment trailer (AFFLIB calls this the segment tail magic).
pub const SEG_TRAILER: &[u8; 4] = b"ATT\0";

/// Segment name storing the page size (stored in `arg`, with `data_len == 0` in common writers).
pub const SEG_PAGESIZE: &str = "pagesize";

/// Deprecated alias for [`SEG_PAGESIZE`] used by early AFF writers (AFFLIB `AF_SEGSIZE_D`).
pub const SEG_SEGSIZE_DEPRECATED: &str = "segsize";

/// Segment name storing the logical image size as an AFFLIB `aff_quad` (8 bytes).
pub const SEG_IMAGESIZE: &str = "imagesize";

/// Segment name storing the sector size in bytes (stored in `arg`).
pub const SEG_SECTORSIZE: &str = "sectorsize";

/// Segment name storing the device sector count as an AFFLIB `aff_quad` (8 bytes).
pub const SEG_DEVICESECTORS: &str = "devicesectors";

/// Segment storing the split-raw file extension for AFM containers (3 bytes, e.g. `"000"`).
pub const AF_RAW_IMAGE_FILE_EXTENSION: &str = "raw_image_file_extension";

/// Segment storing pages-per-raw-file for AFM containers, as an AFFLIB `aff_quad` (8 bytes).
pub const AF_PAGES_PER_RAW_IMAGE_FILE: &str = "pages_per_raw_image_file";

/// Segment storing the AES-256 session key encrypted using SHA-256(passphrase).
pub const AF_AFFKEY: &str = "affkey_aes256";

/// `printf`-style name in AFFLIB; in this Rust port we model it as `format!("affkey_evp{n}")`.
pub const AF_AFFKEY_EVP_PREFIX: &str = "affkey_evp";

/// Suffix for encrypted segments.
pub const AES256_SUFFIX: &str = "/aes256";

/// Suffix for signature segments (SHA-256).
pub const SIG256_SUFFIX: &str = "/sha256";

/// Segment name storing the signing certificate for SHA-256 signatures.
pub const SIGN256_CERT: &str = "cert-sha256";

/// Signature mode 0: signature covers `(segname, arg, segment_data)`.
pub const AF_SIGNATURE_MODE0: u32 = 0x0000;

/// Signature mode 1: signature covers `(segname, 0, uncompressed_page_bytes)` for page segments.
pub const AF_SIGNATURE_MODE1: u32 = 0x0001;

// ---- Page flags (AFFLIBv3 `include/afflib/afflib.h`) ----

/// Page segment is compressed.
pub const AF_PAGE_COMPRESSED: u32 = 0x0001;

/// Mask for the compression algorithm bits.
pub const AF_PAGE_COMP_ALG_MASK: u32 = 0x00F0;

/// Zlib compression algorithm.
pub const AF_PAGE_COMP_ALG_ZLIB: u32 = 0x0000;

/// LZMA compression algorithm.
pub const AF_PAGE_COMP_ALG_LZMA: u32 = 0x0020;

/// ZERO compression algorithm: segment data is 4 bytes indicating the number of NUL bytes.
pub const AF_PAGE_COMP_ALG_ZERO: u32 = 0x0030;
