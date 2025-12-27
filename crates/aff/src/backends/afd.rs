//! AFD (AFF directory) backend.
//!
//! An AFD container is a directory containing multiple `.aff` files named like:
//! - `file_000.aff`
//! - `file_001.aff`
//! - ...
//!
//! Segment lookup follows AFFLIB’s semantics: the first subfile containing a segment wins.
//! Missing pages are treated as zero-filled regions.

use super::aff1::Aff1Image;
use super::backend::{Backend, ContainerKind, Segment};
use crate::{Error, Result};
use forensic_image::ReadAt;
use std::collections::{HashMap, HashSet};
use std::io;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug)]
pub(crate) struct AfdImage {
    files: Vec<Arc<Aff1Image>>,
    page_size: usize,
    image_size: u64,
    page_map: HashMap<u64, usize>, // page_index -> file index
}

impl AfdImage {
    pub(crate) fn open_with(path: impl AsRef<Path>, page_cache_pages: usize) -> Result<Self> {
        let path = path.as_ref();
        if !path.is_dir() {
            return Err(Error::InvalidFormat {
                message: "AFD path is not a directory",
            });
        }

        let mut found = Vec::new();
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let file_name = entry.file_name();
            let Some(s) = file_name.to_str() else {
                continue;
            };
            if let Some(idx) = parse_afd_file_index(s) {
                found.push((idx, entry.path()));
            }
        }
        found.sort_by_key(|(i, _)| *i);

        if found.is_empty() {
            return Err(Error::InvalidFormat {
                message: "AFD directory contains no file_###.aff entries",
            });
        }

        let mut files = Vec::new();
        for (_idx, p) in found {
            files.push(Arc::new(Aff1Image::open_with(p, page_cache_pages)?));
        }

        let page_size = files[0].page_size();
        if page_size == 0 {
            return Err(Error::InvalidData {
                message: "AFD pagesize cannot be 0".to_string(),
            });
        }
        for f in &files[1..] {
            if f.page_size() != page_size {
                return Err(Error::InvalidData {
                    message: "AFD pagesize mismatch across subfiles".to_string(),
                });
            }
        }

        let mut image_size = 0u64;
        for f in &files {
            image_size = image_size.max(f.len());
        }

        // Build a page -> file mapping (first file wins).
        let mut page_map: HashMap<u64, usize> = HashMap::new();
        for (file_idx, f) in files.iter().enumerate() {
            for page in f.page_indices() {
                page_map.entry(page).or_insert(file_idx);
            }
        }

        Ok(Self {
            files,
            page_size,
            image_size,
            page_map,
        })
    }
}

impl ReadAt for AfdImage {
    fn len(&self) -> u64 {
        self.image_size
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        if offset.saturating_add(buf.len() as u64) > self.len() {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }

        let mut remaining = buf.len();
        let mut out_pos = 0usize;
        let mut cur = offset;

        while remaining > 0 {
            let page_index = cur / self.page_size as u64;
            let within = (cur % self.page_size as u64) as usize;
            let take = remaining.min(self.page_size - within);

            if let Some(&file_idx) = self.page_map.get(&page_index) {
                let file = &self.files[file_idx];
                file.read_exact_at(cur, &mut buf[out_pos..out_pos + take])?;
            } else {
                buf[out_pos..out_pos + take].fill(0);
            }

            out_pos += take;
            remaining -= take;
            cur = cur.saturating_add(take as u64);
        }

        Ok(())
    }
}

impl Backend for AfdImage {
    fn kind(&self) -> ContainerKind {
        ContainerKind::Afd
    }

    fn page_size(&self) -> usize {
        self.page_size
    }

    fn segment_names(&self) -> Vec<String> {
        // Union across all subfiles (deduped + sorted).
        let mut seen = HashSet::new();
        for f in &self.files {
            for n in f.segment_names() {
                seen.insert(n);
            }
        }
        let mut out = seen.into_iter().collect::<Vec<_>>();
        out.sort();
        out
    }

    fn read_segment(&self, name: &str) -> io::Result<Option<Segment>> {
        for f in &self.files {
            if let Some(seg) = f.read_segment(name)? {
                return Ok(Some(seg));
            }
        }
        Ok(None)
    }
}

fn parse_afd_file_index(name: &str) -> Option<u32> {
    // Matches "file_###.aff"
    let (prefix, rest) = name.split_once('_')?;
    if prefix != "file" {
        return None;
    }
    let (digits, ext) = rest.split_once('.')?;
    if ext != "aff" {
        return None;
    }
    if digits.len() != 3 || !digits.as_bytes().iter().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u32>().ok()
}
