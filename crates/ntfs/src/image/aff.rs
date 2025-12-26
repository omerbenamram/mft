use crate::image::ReadAt;
use flate2::read::ZlibDecoder;
use lru::LruCache;
use std::collections::BTreeMap;
use std::io::{self, Read};
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy)]
struct PageEntry {
    data_offset: usize,
    compressed_len: usize,
    is_zlib: bool,
}

/// Minimal AFF (AFF1) reader that supports page segments (`pageNNN`) compressed with zlib.
#[derive(Debug)]
pub struct AffImage {
    data: Arc<[u8]>,
    page_size: usize,
    pages: Vec<Option<PageEntry>>,
    cache: Mutex<LruCache<u64, Vec<u8>>>,
}

impl AffImage {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let data: Arc<[u8]> = std::fs::read(path)?.into();

        if data.len() < 8 || &data[0..4] != b"AFF1" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "missing AFF signature",
            ));
        }

        // Skip file signature: "AFF10\\r\\n\\0"
        let mut cursor = 8usize;

        let mut page_size: Option<usize> = None;
        let mut pages_map: BTreeMap<u64, PageEntry> = BTreeMap::new();

        // Parsing strategy:
        // - The first segment starts directly with magic "AFF\\0".
        // - Subsequent segments are preceded by a 4-byte prefix (ignored here), then "AFF\\0".
        let mut expect_prefix = false;
        while cursor + 4 <= data.len() {
            if expect_prefix {
                if cursor + 4 > data.len() {
                    break;
                }
                cursor += 4; // ignore prefix
            }

            if cursor + 4 > data.len() {
                break;
            }
            if &data[cursor..cursor + 4] != b"AFF\0" {
                // If we got desynced, stop early; callers can fall back to other formats.
                break;
            }
            cursor += 4;

            let name_len = read_u32_be(&data, &mut cursor)? as usize;
            let data_len = read_u32_be(&data, &mut cursor)? as usize;
            let arg = read_u32_be(&data, &mut cursor)?;

            let name_bytes = read_slice(&data, &mut cursor, name_len)?;
            let name = std::str::from_utf8(name_bytes)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-utf8 segment name"))?;

            let data_offset = cursor;
            cursor = cursor
                .checked_add(data_len)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "overflow"))?;
            if cursor > data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "segment data out of bounds",
                ));
            }

            // Segment type trailer (e.g. "ATT\\0")
            let trailer = read_slice(&data, &mut cursor, 4)?;
            let _trailer = trailer;

            if name == "pagesize" {
                // In our fixtures pagesize is stored in the arg field.
                page_size = Some(arg as usize);
            } else if let Some(page_index) = name.strip_prefix("page")
                && let Ok(page) = page_index.parse::<u64>()
            {
                let is_zlib = data_len >= 2
                    && data
                        .get(data_offset..data_offset + 2)
                        .is_some_and(|h| h[0] == 0x78 && matches!(h[1], 0x01 | 0x5e | 0x9c | 0xda));

                pages_map.insert(
                    page,
                    PageEntry {
                        data_offset,
                        compressed_len: data_len,
                        is_zlib,
                    },
                );
            }

            expect_prefix = true;
        }

        let page_size = page_size.ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "AFF missing pagesize segment")
        })?;
        if page_size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "AFF pagesize cannot be 0",
            ));
        }

        let max_page = pages_map.keys().copied().max().unwrap_or(0);
        let mut pages = vec![None; (max_page as usize).saturating_add(1)];
        for (idx, entry) in pages_map {
            if let Some(slot) = pages.get_mut(idx as usize) {
                *slot = Some(entry);
            }
        }

        Ok(Self {
            data,
            page_size,
            pages,
            // Pages are very large in our fixtures (16MiB), keep the cache small.
            cache: Mutex::new(LruCache::new(NonZeroUsize::new(2).expect("2 > 0"))),
        })
    }

    pub fn page_size(&self) -> usize {
        self.page_size
    }

    fn read_page(&self, page_index: u64) -> io::Result<Vec<u8>> {
        if let Some(hit) = self.cache.lock().expect("poisoned").get(&page_index) {
            return Ok(hit.clone());
        }

        let idx = usize::try_from(page_index)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "page index overflow"))?;
        let entry = self
            .pages
            .get(idx)
            .and_then(|x| *x)
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "page not present"))?;

        let compressed = self
            .data
            .get(entry.data_offset..entry.data_offset + entry.compressed_len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "page out of bounds"))?;

        let mut out = vec![0u8; self.page_size];
        if entry.is_zlib {
            let cursor = io::Cursor::new(compressed);
            let mut decoder = ZlibDecoder::new(cursor);
            decoder.read_exact(&mut out)?;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported AFF page compression",
            ));
        }

        self.cache
            .lock()
            .expect("poisoned")
            .put(page_index, out.clone());
        Ok(out)
    }
}

impl ReadAt for AffImage {
    fn len(&self) -> u64 {
        self.pages.len() as u64 * self.page_size as u64
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

            let page = self.read_page(page_index)?;
            let take = remaining.min(self.page_size - within);
            buf[out_pos..out_pos + take].copy_from_slice(&page[within..within + take]);

            out_pos += take;
            remaining -= take;
            cur = cur.saturating_add(take as u64);
        }

        Ok(())
    }
}

fn read_u32_be(data: &[u8], cursor: &mut usize) -> io::Result<u32> {
    let bytes = read_slice(data, cursor, 4)?;
    Ok(u32::from_be_bytes(bytes.try_into().expect("len=4")))
}

fn read_slice<'a>(data: &'a [u8], cursor: &mut usize, len: usize) -> io::Result<&'a [u8]> {
    let start = *cursor;
    let end = start
        .checked_add(len)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "overflow"))?;
    if end > data.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "out of bounds",
        ));
    }
    *cursor = end;
    Ok(&data[start..end])
}
