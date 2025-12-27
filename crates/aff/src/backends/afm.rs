//! AFM (`.afm`) backend.
//!
//! An AFM container is a **compound** format:
//! - Metadata is stored as an AFF1 file (segments) in the `.afm` path.
//! - The disk bytes are stored as one or more split-raw files, where the first file extension
//!   is given by the segment `raw_image_file_extension` (usually `"000"`).
//!
//! This backend is **read-only** in this workspace.

use super::aff1::Aff1Image;
use super::backend::{Backend, ContainerKind, Segment};
use super::split_raw::SplitRawImage;
use crate::format;
use crate::{Error, Result};
use forensic_image::ReadAt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug)]
pub(crate) struct AfmImage {
    meta: Arc<Aff1Image>,
    raw: SplitRawImage,
    page_size: usize,
    image_size: u64,
}

impl AfmImage {
    pub(crate) fn open_with(path: impl AsRef<Path>, page_cache_pages: usize) -> Result<Self> {
        let path = path.as_ref();

        let meta = Arc::new(Aff1Image::open_with(path, page_cache_pages)?);
        let page_size = meta.page_size();

        let ext = read_raw_extension(&meta)?;
        let raw_path = replace_extension(path, &ext)?;

        let raw = SplitRawImage::open(&raw_path).map_err(Error::Io)?;
        let image_size = raw.len();

        Ok(Self {
            meta,
            raw,
            page_size,
            image_size,
        })
    }

    fn read_page_segment(&self, page_index: u64) -> io::Result<Vec<u8>> {
        let page_size = self.page_size;
        let pos = page_index.saturating_mul(page_size as u64);
        if pos >= self.image_size {
            return Ok(Vec::new());
        }
        let take = (self.image_size - pos).min(page_size as u64) as usize;
        let mut buf = vec![0u8; take];
        self.raw.read_exact_at(pos, &mut buf)?;
        Ok(buf)
    }
}

impl ReadAt for AfmImage {
    fn len(&self) -> u64 {
        self.image_size
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        self.raw.read_exact_at(offset, buf)
    }
}

impl Backend for AfmImage {
    fn kind(&self) -> ContainerKind {
        ContainerKind::Afm
    }

    fn page_size(&self) -> usize {
        self.page_size
    }

    fn segment_names(&self) -> Vec<String> {
        // Metadata segments only (listing all page segments would be enormous).
        self.meta.segment_names()
    }

    fn read_segment(&self, name: &str) -> io::Result<Option<Segment>> {
        if let Some(seg) = self.meta.read_segment(name)? {
            return Ok(Some(seg));
        }

        // If the caller asks for `page<N>`, read it from the split-raw payload.
        if let Some(page_index) = name
            .strip_prefix("page")
            .and_then(|r| r.parse::<u64>().ok())
        {
            let data = self.read_page_segment(page_index)?;
            return Ok(Some(Segment {
                name: name.to_string(),
                arg: 0,
                data,
            }));
        }

        Ok(None)
    }
}

fn read_raw_extension(meta: &Aff1Image) -> Result<String> {
    let seg = meta
        .read_segment(format::AF_RAW_IMAGE_FILE_EXTENSION)
        .map_err(Error::Io)?
        .ok_or(Error::InvalidFormat {
            message: "AFM missing raw_image_file_extension segment",
        })?;

    let s = std::str::from_utf8(&seg.data).map_err(|_| Error::InvalidData {
        message: "AFM raw_image_file_extension is not UTF-8".to_string(),
    })?;
    let s = s.trim_matches(char::from(0)).trim();

    if s.is_empty() {
        return Err(Error::InvalidData {
            message: "AFM raw_image_file_extension is empty".to_string(),
        });
    }
    if s.len() != 3 {
        return Err(Error::InvalidData {
            message: "AFM raw_image_file_extension must be 3 characters".to_string(),
        });
    }
    if s.contains('.') || s.contains('/') || s.contains('\\') {
        return Err(Error::InvalidData {
            message: "AFM raw_image_file_extension contains invalid characters".to_string(),
        });
    }

    Ok(s.to_string())
}

fn replace_extension(path: &Path, new_ext: &str) -> Result<PathBuf> {
    let Some(old_ext) = path.extension().and_then(|e| e.to_str()) else {
        return Err(Error::InvalidData {
            message: "AFM path has no extension".to_string(),
        });
    };
    if old_ext.len() != 3 {
        return Err(Error::InvalidData {
            message: "AFM path extension must be 3 characters".to_string(),
        });
    }
    Ok(path.with_extension(new_ext))
}
