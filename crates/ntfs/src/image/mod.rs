//! Abstractions for reading from disk images (raw, EWF/E01, AFF).

mod aff;
mod ewf;
mod raw;

use std::io;
use std::path::Path;

pub use aff::AffImage;
pub use ewf::EwfImage;
pub use raw::RawImage;

/// Random-access reading over an image-like source.
///
/// This is intentionally minimal: higher layers (NTFS, VFS) should not care how bytes are
/// retrieved (raw file, EWF, AFF, etc.).
pub trait ReadAt: Send + Sync {
    fn len(&self) -> u64;
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()>;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Debug)]
pub enum Image {
    Raw(RawImage),
    Ewf(EwfImage),
    Aff(AffImage),
}

impl Image {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        let lower = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();

        match lower.as_str() {
            "e01" => Ok(Image::Ewf(EwfImage::open(path)?)),
            "aff" => Ok(Image::Aff(AffImage::open(path)?)),
            _ => Ok(Image::Raw(RawImage::open(path)?)),
        }
    }

    pub fn len(&self) -> u64 {
        match self {
            Image::Raw(x) => x.len(),
            Image::Ewf(x) => x.len(),
            Image::Aff(x) => x.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl ReadAt for Image {
    fn len(&self) -> u64 {
        self.len()
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        match self {
            Image::Raw(x) => x.read_exact_at(offset, buf),
            Image::Ewf(x) => x.read_exact_at(offset, buf),
            Image::Aff(x) => x.read_exact_at(offset, buf),
        }
    }
}
