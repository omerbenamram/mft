//! Page decoding shared by the page-based readers.
//!
//! A decoded page is kept as the bytes its segment really holds, which may be fewer than the page
//! size (a short last page, or a page that compresses a prefix). The rest of the page reads as
//! zeros. Nothing here allocates by the page size: that number comes from the `pagesize` segment
//! and can be anything up to 4 GiB.

use crate::format;
use flate2::read::ZlibDecoder;
use lru::LruCache;
use std::io::{self, Read};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

/// The page size AFFLIB writes by default. The page cache's memory budget is counted in pages
/// of this size.
const STANDARD_PAGE_BYTES: usize = 16 * 1024 * 1024;

/// Deflate cannot expand its input by more than about 1032:1.
const MAX_DEFLATE_EXPANSION: usize = 1040;

/// Decoded pages, shared between the cache and the reads that use them.
///
/// The cache holds at most the configured number of pages and at most that many standard
/// (16 MiB) pages' worth of bytes: the page size is a field of the image and can be anything up
/// to 4 GiB, so a count of pages alone does not bound the memory. The page decoded last is
/// always kept, whatever its size.
#[derive(Debug)]
pub(crate) struct PageCache {
    inner: Mutex<PageCacheInner>,
}

#[derive(Debug)]
struct PageCacheInner {
    pages: LruCache<u64, Arc<Vec<u8>>>,
    bytes: usize,
    budget: usize,
}

impl PageCache {
    pub(crate) fn new(pages: NonZeroUsize) -> Self {
        Self {
            inner: Mutex::new(PageCacheInner {
                pages: LruCache::new(pages),
                bytes: 0,
                budget: pages.get().saturating_mul(STANDARD_PAGE_BYTES),
            }),
        }
    }

    pub(crate) fn get(&self, page_index: u64) -> Option<Arc<Vec<u8>>> {
        let mut inner = self.inner.lock().expect("poisoned");
        inner.pages.get(&page_index).cloned()
    }

    /// Adds a decoded page and returns the shared handle to it.
    pub(crate) fn insert(&self, page_index: u64, mut page: Vec<u8>) -> Arc<Vec<u8>> {
        page.shrink_to_fit();
        let page = Arc::new(page);

        let mut inner = self.inner.lock().expect("poisoned");
        inner.bytes += page.len();
        if let Some((_, evicted)) = inner.pages.push(page_index, Arc::clone(&page)) {
            inner.bytes -= evicted.len();
        }
        while inner.bytes > inner.budget && inner.pages.len() > 1 {
            let Some((_, evicted)) = inner.pages.pop_lru() else {
                break;
            };
            inner.bytes -= evicted.len();
        }
        page
    }

    #[cfg(test)]
    fn cached_bytes(&self) -> usize {
        self.inner.lock().expect("poisoned").bytes
    }
}

/// Copies `buf.len()` bytes of a page into `buf`, starting `within` bytes into the page.
///
/// `page` holds the leading bytes of the page; everything past them is zero.
pub(crate) fn copy_page_bytes(page: &[u8], within: usize, buf: &mut [u8]) {
    let available = page.get(within..).unwrap_or(&[]);
    let take = available.len().min(buf.len());
    buf[..take].copy_from_slice(&available[..take]);
    buf[take..].fill(0);
}

/// Decodes a compressed page segment (`flags` has `AF_PAGE_COMPRESSED` set).
///
/// Returns the bytes the page holds, at most `page_size`. The buffer is sized by what the stored
/// bytes can decode to, never by `page_size` alone.
pub(crate) fn decode_compressed_page(
    flags: u32,
    stored: &[u8],
    page_size: usize,
) -> io::Result<Vec<u8>> {
    match flags & format::AF_PAGE_COMP_ALG_MASK {
        // The page is all zeros.
        format::AF_PAGE_COMP_ALG_ZERO => Ok(Vec::new()),
        format::AF_PAGE_COMP_ALG_ZLIB => {
            // A page normally decodes to exactly `page_size`: reserve that, as far as the stored
            // bytes can account for it, so the buffer neither grows in steps nor ends up with
            // spare capacity.
            let reserve = stored
                .len()
                .saturating_mul(MAX_DEFLATE_EXPANSION)
                .min(page_size);
            let mut out = Vec::new();
            out.try_reserve_exact(reserve).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::OutOfMemory,
                    "AFF page is too large to decode",
                )
            })?;
            ZlibDecoder::new(stored)
                .take(page_size as u64)
                .read_to_end(&mut out)?;
            Ok(out)
        }
        format::AF_PAGE_COMP_ALG_LZMA => {
            #[cfg(feature = "lzma")]
            {
                let mut input = io::Cursor::new(stored);
                let mut output = CappedWriter::new(page_size);
                lzma_rs::lzma_decompress(&mut input, &mut output).map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("LZMA: {e}"))
                })?;
                Ok(output.buf)
            }
            #[cfg(not(feature = "lzma"))]
            {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "AFF page uses LZMA compression but feature `lzma` is disabled",
                ))
            }
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported AFF page compression",
        )),
    }
}

/// Returns how many bytes a ZLIB or LZMA page segment decodes to (at most `page_size`), without
/// keeping the decoded bytes.
pub(crate) fn decoded_len_of_compressed_page(
    flags: u32,
    stored: &[u8],
    page_size: usize,
) -> io::Result<u64> {
    match flags & format::AF_PAGE_COMP_ALG_MASK {
        format::AF_PAGE_COMP_ALG_ZLIB => io::copy(
            &mut ZlibDecoder::new(stored).take(page_size as u64),
            &mut io::sink(),
        ),
        _ => decode_compressed_page(flags, stored, page_size).map(|page| page.len() as u64),
    }
}

/// A growing buffer that refuses to hold more than `cap` bytes.
#[cfg(feature = "lzma")]
struct CappedWriter {
    buf: Vec<u8>,
    cap: usize,
}

#[cfg(feature = "lzma")]
impl CappedWriter {
    fn new(cap: usize) -> Self {
        Self {
            buf: Vec::new(),
            cap,
        }
    }
}

#[cfg(feature = "lzma")]
impl io::Write for CappedWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.len() > self.cap - self.buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "page decodes to more than the page size",
            ));
        }
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_cache_is_bounded_in_bytes_and_keeps_the_last_page() {
        let cache = PageCache::new(NonZeroUsize::new(2).unwrap());

        // Ordinary pages: two fit.
        cache.insert(0, vec![1u8; 1024]);
        cache.insert(1, vec![2u8; 1024]);
        assert!(cache.get(0).is_some() && cache.get(1).is_some());
        assert_eq!(cache.cached_bytes(), 2048);

        // A third page pushes the least recently used one out by count.
        cache.insert(2, vec![3u8; 1024]);
        assert!(cache.get(0).is_none());
        assert_eq!(cache.cached_bytes(), 2048);

        // Pages of an oversized page size: the budget of two standard pages holds only one of
        // these, and the one decoded last is the one that stays.
        let big = STANDARD_PAGE_BYTES + STANDARD_PAGE_BYTES / 2;
        cache.insert(3, vec![0u8; big]);
        assert!(cache.get(3).is_some());
        assert!(cache.get(1).is_none());
        cache.insert(4, vec![0u8; big]);
        assert!(cache.get(4).is_some());
        assert!(cache.get(3).is_none());
        assert_eq!(cache.cached_bytes(), big);

        // Replacing a page does not count it twice.
        cache.insert(4, vec![0u8; 16]);
        assert_eq!(cache.cached_bytes(), 16);
    }

    #[test]
    fn decoded_zlib_page_has_no_spare_capacity() {
        use flate2::{Compression, write::ZlibEncoder};
        use std::io::Write as _;

        let page_size = 1024 * 1024;
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&vec![7u8; page_size]).unwrap();
        let stored = enc.finish().unwrap();

        let page =
            decode_compressed_page(format::AF_PAGE_COMP_ALG_ZLIB, &stored, page_size).unwrap();
        assert_eq!(page.len(), page_size);
        assert!(page.iter().all(|&b| b == 7));
        assert_eq!(page.capacity(), page_size);

        // A huge declared page size does not size the buffer.
        let page =
            decode_compressed_page(format::AF_PAGE_COMP_ALG_ZLIB, &stored, usize::MAX).unwrap();
        assert_eq!(page.len(), page_size);
    }
}
