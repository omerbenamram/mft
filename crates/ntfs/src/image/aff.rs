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
    data_len: usize,
    flags: u32,
}

/// Minimal AFF (AFF1) reader.
///
/// Notes (per AFFLIBv3 semantics):
/// - Missing pages represent zero-filled regions.
/// - Pages may be stored uncompressed, zlib-compressed, or as a special "ZERO" compressor
///   (4-byte segment value indicating the number of NUL bytes).
#[derive(Debug)]
pub struct AffImage {
    data: Arc<[u8]>,
    page_size: usize,
    image_size: u64,
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
        let mut image_size: Option<u64> = None;
        let mut sector_size: Option<u32> = None;
        let mut device_sectors: Option<u64> = None;
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
            } else if name == "sectorsize" {
                sector_size = Some(arg);
            } else if name == "devicesectors" {
                if data_len != 8 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "AFF devicesectors segment must be 8 bytes",
                    ));
                }
                let quad = data
                    .get(data_offset..data_offset + data_len)
                    .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "segment data"))?;
                device_sectors = Some(read_aff_quad(quad)?);
            } else if name == "imagesize" {
                if data_len != 8 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "AFF imagesize segment must be 8 bytes",
                    ));
                }
                let quad = data
                    .get(data_offset..data_offset + data_len)
                    .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "segment data"))?;
                image_size = Some(read_aff_quad(quad)?);
            } else if let Some(page_index) = name.strip_prefix("page")
                && let Ok(page) = page_index.parse::<u64>()
            {
                pages_map.insert(
                    page,
                    PageEntry {
                        data_offset,
                        data_len,
                        flags: arg,
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

        let image_size = image_size
            .or_else(|| match (device_sectors, sector_size) {
                (Some(sectors), Some(bytes_per_sector)) => {
                    sectors.checked_mul(bytes_per_sector as u64)
                }
                _ => None,
            })
            .unwrap_or_else(|| pages.len() as u64 * page_size as u64);

        Ok(Self {
            data,
            page_size,
            image_size,
            pages,
            // Pages are very large in our fixtures (16MiB), keep the cache small.
            cache: Mutex::new(LruCache::new(NonZeroUsize::new(2).expect("2 > 0"))),
        })
    }

    pub fn page_size(&self) -> usize {
        self.page_size
    }

    fn blank_page(&self) -> Vec<u8> {
        vec![0u8; self.page_size]
    }

    fn read_page(&self, page_index: u64) -> io::Result<Vec<u8>> {
        if let Some(hit) = self.cache.lock().expect("poisoned").get(&page_index) {
            return Ok(hit.clone());
        }

        let idx = usize::try_from(page_index)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "page index overflow"))?;
        let Some(entry) = self.pages.get(idx).and_then(|x| *x) else {
            // Sparse / missing page => zero-filled region.
            let out = self.blank_page();
            self.cache
                .lock()
                .expect("poisoned")
                .put(page_index, out.clone());
            return Ok(out);
        };

        let seg = self
            .data
            .get(entry.data_offset..entry.data_offset + entry.data_len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "page out of bounds"))?;

        // AFFLIBv3 flags (see `include/afflib/afflib.h`)
        const AF_PAGE_COMPRESSED: u32 = 0x0001;
        const AF_PAGE_COMP_ALG_MASK: u32 = 0x00F0;
        const AF_PAGE_COMP_ALG_ZLIB: u32 = 0x0000;
        const AF_PAGE_COMP_ALG_LZMA: u32 = 0x0020;
        const AF_PAGE_COMP_ALG_ZERO: u32 = 0x0030;

        let mut out = self.blank_page();
        if (entry.flags & AF_PAGE_COMPRESSED) == 0 {
            // Uncompressed page data stored directly in the segment (possibly partial for the last page).
            let take = seg.len().min(out.len());
            out[..take].copy_from_slice(&seg[..take]);
        } else {
            match entry.flags & AF_PAGE_COMP_ALG_MASK {
                AF_PAGE_COMP_ALG_ZERO => {
                    // ZERO compressor: segment is a 4-byte count of NUL bytes (AFFLIB uses ntohl()).
                    // The page content is all zeros.
                    if seg.len() != 4 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "AFF ZERO-compressed page must have 4 bytes of data",
                        ));
                    }
                }
                AF_PAGE_COMP_ALG_ZLIB => {
                    let cursor = io::Cursor::new(seg);
                    let mut decoder = ZlibDecoder::new(cursor);
                    let mut written = 0usize;
                    while written < out.len() {
                        let n = decoder.read(&mut out[written..])?;
                        if n == 0 {
                            break;
                        }
                        written += n;
                    }
                }
                AF_PAGE_COMP_ALG_LZMA => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unsupported AFF page compression: LZMA",
                    ));
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unsupported AFF page compression",
                    ));
                }
            }
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

/// Reads an AFFLIB `aff_quad` (8 bytes) as `u64`.
///
/// The encoding is **little-endian in 32-bit words**:
/// - bytes `[0..4]` are the low 32 bits in network order (`htonl(low)`),
/// - bytes `[4..8]` are the high 32 bits in network order (`htonl(high)`).
fn read_aff_quad(bytes: &[u8]) -> io::Result<u64> {
    if bytes.len() != 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "AFF quad must be 8 bytes",
        ));
    }
    let low = u32::from_be_bytes(bytes[0..4].try_into().expect("len=4"));
    let high = u32::from_be_bytes(bytes[4..8].try_into().expect("len=4"));
    Ok(((high as u64) << 32) | (low as u64))
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
