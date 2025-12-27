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
                // Important: do **not** delegate to `Aff1Image::read_exact_at(cur, ...)` here.
                //
                // In AFD, the global image size is the max across subfiles, but an individual
                // subfile may advertise a smaller `imagesize` (e.g. partial last page) while still
                // storing a full `page<N>` segment. AFFLIB satisfies AFD reads by fetching pages by
                // index via `af_get_page` / `af_get_seg` (see `lib/afflib_stream.cpp` +
                // `lib/vnode_afd.cpp` in the vendored AFFLIBv3 snapshot), not by performing a
                // per-subfile stream read with an `imagesize` bounds check.
                let page = file.read_page(page_index)?;
                buf[out_pos..out_pos + take].copy_from_slice(&page[within..within + take]);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format;

    fn aff_quad_u64(v: u64) -> [u8; 8] {
        let low = (v & 0xffff_ffff) as u32;
        let high = (v >> 32) as u32;
        let mut out = [0u8; 8];
        out[0..4].copy_from_slice(&low.to_be_bytes());
        out[4..8].copy_from_slice(&high.to_be_bytes());
        out
    }

    fn aff_segment(name: &str, data: &[u8], arg: u32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(format::SEG_MAGIC);
        out.extend_from_slice(&(name.len() as u32).to_be_bytes());
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(&arg.to_be_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);
        out.extend_from_slice(format::SEG_TRAILER);
        let seg_len = (16 + name.len() + data.len() + 8) as u32;
        out.extend_from_slice(&seg_len.to_be_bytes());
        out
    }

    fn build_aff1_file(segments: Vec<Vec<u8>>) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(format::AFF1_HEADER);
        for seg in segments {
            out.extend_from_slice(&seg);
        }
        out
    }

    #[test]
    fn test_read_exact_at_ignores_subfile_imagesize_when_page_exists() {
        // Regression test for a subtle AFD behavior:
        //
        // In AFFLIBv3, AFD reads are satisfied by fetching `page<N>` segments from whichever
        // subfile contains them, while the *overall* stream length is the max `imagesize`
        // across the directory (`afd_vstat` in `external/refs/repos/sshock__AFFLIBv3@.../lib/vnode_afd.cpp`).
        //
        // That means a subfile may advertise a smaller `imagesize` (partial last page) while still
        // storing a full `page<N>` segment; reads within that page are valid as long as the AFD's
        // global `imagesize` permits them.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("container.afd");
        std::fs::create_dir_all(&dir).unwrap();

        let page_size = 8usize;

        // file_000: claims imagesize=9 (partial last page), but stores a full page1 segment.
        let file0 = build_aff1_file(vec![
            aff_segment("pagesize", &[], page_size as u32),
            aff_segment("imagesize", &aff_quad_u64(9), 2),
            aff_segment("page0", b"AAAAAAAA", 0),
            aff_segment("page1", b"BBBBBBBB", 0),
        ]);

        // file_001: bumps the AFD global imagesize to 16 (2 full pages).
        let file1 = build_aff1_file(vec![
            aff_segment("pagesize", &[], page_size as u32),
            aff_segment("imagesize", &aff_quad_u64(16), 2),
        ]);

        std::fs::write(dir.join("file_000.aff"), file0).unwrap();
        std::fs::write(dir.join("file_001.aff"), file1).unwrap();

        let afd = AfdImage::open_with(&dir, 2).unwrap();
        assert_eq!(afd.page_size(), page_size);
        assert_eq!(afd.len(), 16);

        let mut page1 = [0u8; 8];
        afd.read_exact_at(8, &mut page1).unwrap();
        assert_eq!(&page1, b"BBBBBBBB");
    }
}
