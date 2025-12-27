//! AFF (Advanced Forensic Format) image reader.
//!
//! This crate provides **read-only** access to AFF containers with behavior closely aligned to
//! **AFFLIBv3** (vendored under `external/refs/` for reference-only).
//!
//! Supported containers (this workspace):
//! - **AFF1** single-file (`.aff`)
//! - **AFM** (`.afm`) metadata + split-raw payload
//! - **AFD** directory container
//!
//! Supported page compression (AFF1 pages):
//! - **Uncompressed**
//! - **Zlib**
//! - **ZERO** (special compression storing a 4-byte count; page reads as all-zero)
//! - **LZMA** (LZMA-Alone framing; optional feature)
//!
//! Optional crypto/signature verification (feature `crypto`):
//! - Decrypt `/aes256` segments (read-side only)
//! - Verify `/sha256` signature segments using `cert-sha256` (read-side only)
//!
//! ## Quick start
//!
//! ```no_run
//! use aff::{AffImage, AffOpenOptions};
//! use forensic_image::ReadAt;
//!
//! let img = AffOpenOptions::new().open("image.aff")?;
//! let mut buf = [0u8; 512];
//! img.read_exact_at(0, &mut buf)?;
//! # Ok::<(), aff::Error>(())
//! ```
//!
//! ## Design notes
//!
//! - The primary API implements [`forensic_image::ReadAt`], so higher-level filesystems can
//!   consume an AFF image without pulling in AFF-specific dependencies.
//! - Missing pages in sparse containers are treated as **zero-filled regions**, matching typical
//!   forensic expectations and AFFLIB behavior.

#![forbid(unsafe_code)]
#![deny(unused_must_use)]
#![cfg_attr(not(debug_assertions), deny(clippy::dbg_macro))]

pub mod backends;
#[cfg(feature = "crypto")]
pub mod crypto;
pub mod error;
pub mod format;
pub mod verify;

pub use backends::AffImage;
pub use backends::AffOpenOptions;
pub use backends::{ContainerKind, Segment};
pub use error::{Error, Result};
pub use verify::{SignatureStatus, Verifier};
