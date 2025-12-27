//! AFF1 (`.aff`) single-file backend.
//!
//! This is a minimal, read-only implementation designed to match **AFFLIBv3** behavior:
//! - Segment framing: `AF_SEGHEAD` + header fields + name + data + `AF_SEGTAIL` + segment length
//! - Page addressing via `page<N>` segments
//! - Missing pages are treated as **zero-filled** regions
//! - Page compression flags follow `include/afflib/afflib.h`
//!
//! The current implementation loads the entire `.aff` file into memory. This keeps the logic
//! simple and deterministic while we harden correctness; it can be switched to a file-backed
//! reader later without changing the public [`forensic_image::ReadAt`] API.

use crate::format;
use crate::{Error, Result};
use flate2::read::ZlibDecoder;
use forensic_image::ReadAt;
use lru::LruCache;
use std::collections::HashMap;
use std::io::{self, Read};
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::{Arc, Mutex};

use super::backend::{Backend, ContainerKind, Segment};

#[derive(Debug, Clone, Copy)]
struct PageEntry {
    data_offset: usize,
    data_len: usize,
    flags: u32,
    is_aes256: bool,
}

#[derive(Debug, Clone, Copy)]
struct SegmentEntry {
    data_offset: usize,
    data_len: usize,
    arg: u32,
}

/// Read-only AFF1 backend.
#[derive(Debug)]
pub(crate) struct Aff1Image {
    data: Arc<[u8]>,
    page_size: usize,
    image_size: u64,
    segments: HashMap<String, SegmentEntry>,
    pages: HashMap<u64, PageEntry>,
    cache: Mutex<LruCache<u64, Vec<u8>>>,
}

impl Aff1Image {
    pub(crate) fn open_with(path: impl AsRef<Path>, page_cache_pages: usize) -> Result<Self> {
        let data: Arc<[u8]> = std::fs::read(path)?.into();

        if data.len() < format::AFF1_HEADER.len() || &data[0..8] != format::AFF1_HEADER {
            return Err(Error::InvalidFormat {
                message: "missing AFF1 header",
            });
        }

        let mut cursor = 8usize;

        let mut page_size: Option<usize> = None;
        let mut image_size: Option<u64> = None;

        let mut segments: HashMap<String, SegmentEntry> = HashMap::new();
        let mut pages: HashMap<u64, PageEntry> = HashMap::new();

        while cursor + 4 <= data.len() {
            // Segment header
            let magic = data
                .get(cursor..cursor + 4)
                .ok_or_else(|| Error::Io(io_eof()))?;
            if magic != format::SEG_MAGIC {
                break;
            }
            cursor += 4;

            let name_len = read_u32_be(&data, &mut cursor)? as usize;
            let data_len = read_u32_be(&data, &mut cursor)? as usize;
            let arg = read_u32_be(&data, &mut cursor)?;

            let name_bytes = read_slice(&data, &mut cursor, name_len)?;
            let name = std::str::from_utf8(name_bytes).map_err(|_| Error::InvalidData {
                message: "non-utf8 segment name".to_string(),
            })?;
            let is_aes256 = name.ends_with(format::AES256_SUFFIX);
            let logical_name = name.strip_suffix(format::AES256_SUFFIX).unwrap_or(name);

            let data_offset = cursor;
            cursor = cursor
                .checked_add(data_len)
                .ok_or_else(|| Error::InvalidData {
                    message: "segment overflow".to_string(),
                })?;
            if cursor > data.len() {
                return Err(Error::Io(io_eof()));
            }

            // Segment tail + segment_len
            let trailer = read_slice(&data, &mut cursor, 4)?;
            if trailer != format::SEG_TRAILER {
                return Err(Error::InvalidData {
                    message: "segment missing ATT\\0 trailer".to_string(),
                });
            }
            let seg_len = read_u32_be(&data, &mut cursor)? as usize;

            // Validate segment_len.
            let expected = 16usize
                .checked_add(name_len)
                .and_then(|v| v.checked_add(data_len))
                .and_then(|v| v.checked_add(8))
                .ok_or_else(|| Error::InvalidData {
                    message: "segment length overflow".to_string(),
                })?;
            if seg_len != expected {
                return Err(Error::InvalidData {
                    message: format!("segment length mismatch: expected {expected}, got {seg_len}"),
                });
            }

            // Record segment in the TOC (last write wins).
            segments.insert(
                name.to_string(),
                SegmentEntry {
                    data_offset,
                    data_len,
                    arg,
                },
            );

            // Parse well-known metadata segments.
            match logical_name {
                format::SEG_PAGESIZE | format::SEG_SEGSIZE_DEPRECATED => {
                    // AFFLIB stores the page size in the `arg` field and uses `data_len == 0`.
                    // (It also supports the deprecated alias `segsize`.)
                    if data_len != 0 {
                        return Err(Error::InvalidData {
                            message: "pagesize/segsize segment must have empty data".to_string(),
                        });
                    }
                    page_size = Some(arg as usize);
                }
                format::SEG_IMAGESIZE => {
                    // If this segment is encrypted (`imagesize/aes256`) we can't parse it
                    // without decryption; defer to the AFFLIB-style imagesize scan below.
                    if is_aes256 {
                        continue;
                    }
                    let quad = data
                        .get(data_offset..data_offset + data_len)
                        .ok_or_else(|| Error::Io(io_eof()))?;
                    if quad.len() != 8 {
                        return Err(Error::InvalidData {
                            message: "imagesize segment must be 8 bytes".to_string(),
                        });
                    }
                    image_size = Some(read_aff_quad(quad)?);
                }
                _ => {}
            }

            // Page segments: `page<N>` (new) or `seg<N>` (deprecated).
            if let Some(page_index) = parse_page_number(logical_name) {
                pages.insert(
                    page_index,
                    PageEntry {
                        data_offset,
                        data_len,
                        flags: arg,
                        is_aes256,
                    },
                );
            }
        }

        let page_size = page_size.ok_or(Error::InvalidFormat {
            message: "missing pagesize/segsize segment",
        })?;
        if page_size == 0 {
            return Err(Error::InvalidData {
                message: "pagesize cannot be 0".to_string(),
            });
        }

        let image_size = (|| -> Result<u64> {
            if let Some(v) = image_size {
                return Ok(v);
            }

            // AFFLIBv3 behavior (`af_read_sizes`): if `imagesize` is missing, compute it by
            // finding the highest present page number and then asking for that page’s logical
            // length (`af_get_page(..., data==NULL)`), which may require decompression.
            let Some(max_page) = pages.keys().copied().max() else {
                return Ok(0);
            };
            let base = max_page.saturating_mul(page_size as u64);
            let Some(last) = pages.get(&max_page).copied() else {
                return Ok(base);
            };

            let page_logical_len = |entry: PageEntry| -> Result<u64> {
                let seg = data
                    .get(entry.data_offset..entry.data_offset + entry.data_len)
                    .ok_or_else(|| Error::Io(io_eof()))?;

                // Uncompressed: the segment length is the logical length (for the last page this
                // may be shorter than `pagesize`).
                if (entry.flags & format::AF_PAGE_COMPRESSED) == 0 {
                    let mut len = entry.data_len as u64;
                    if entry.is_aes256 && !len.is_multiple_of(16) {
                        // AFFLIB `af_aes_decrypt(..., data==NULL)`: if ciphertext_len % 16 != 0,
                        // subtract one full AES block to recover the original length.
                        if len < 16 {
                            return Err(Error::InvalidData {
                                message: "encrypted page segment too small".to_string(),
                            });
                        }
                        len -= 16;
                    }
                    return Ok(len);
                }

                // Compressed: AFFLIB inflates the page even when just requesting the length.
                // We cannot do this for encrypted compressed pages without the decryption key.
                if entry.is_aes256 {
                    return Err(Error::InvalidData {
                        message: "cannot infer imagesize from encrypted+compressed last page (missing imagesize)".to_string(),
                    });
                }

                match entry.flags & format::AF_PAGE_COMP_ALG_MASK {
                    format::AF_PAGE_COMP_ALG_ZERO => {
                        if seg.len() != 4 {
                            return Err(Error::InvalidData {
                                message: "AFF ZERO-compressed page must have 4 bytes of data"
                                    .to_string(),
                            });
                        }
                        let count = u32::from_be_bytes(seg[0..4].try_into().expect("len=4")) as u64;
                        Ok(count.min(page_size as u64))
                    }
                    format::AF_PAGE_COMP_ALG_ZLIB => {
                        let cursor = io::Cursor::new(seg);
                        let mut decoder = ZlibDecoder::new(cursor);
                        let mut out = vec![0u8; page_size];
                        let mut written = 0usize;
                        while written < out.len() {
                            let n = decoder.read(&mut out[written..])?;
                            if n == 0 {
                                break;
                            }
                            written += n;
                        }
                        Ok(written as u64)
                    }
                    format::AF_PAGE_COMP_ALG_LZMA => {
                        #[cfg(feature = "lzma")]
                        {
                            let mut input = io::Cursor::new(seg);
                            let mut out = vec![0u8; page_size];
                            let mut output = io::Cursor::new(&mut out[..]);
                            lzma_rs::lzma_decompress(&mut input, &mut output).map_err(|e| {
                                Error::InvalidData {
                                    message: format!("LZMA: {e}"),
                                }
                            })?;
                            Ok(output.position())
                        }
                        #[cfg(not(feature = "lzma"))]
                        {
                            Err(Error::InvalidData {
                                message:
                                    "AFF page uses LZMA compression but feature `lzma` is disabled"
                                        .to_string(),
                            })
                        }
                    }
                    _ => Err(Error::InvalidData {
                        message: "unsupported AFF page compression".to_string(),
                    }),
                }
            };

            let last_len = page_logical_len(last)?;
            Ok(base.saturating_add(last_len))
        })()?;

        let cache_pages =
            NonZeroUsize::new(page_cache_pages).ok_or_else(|| Error::InvalidData {
                message: "page_cache_pages cannot be 0".to_string(),
            })?;

        Ok(Self {
            data,
            page_size,
            image_size,
            segments,
            pages,
            // Keep small: typical pages are large (MiBs).
            cache: Mutex::new(LruCache::new(cache_pages)),
        })
    }

    pub(crate) fn page_indices(&self) -> impl Iterator<Item = u64> + '_ {
        self.pages.keys().copied()
    }

    fn blank_page(&self) -> Vec<u8> {
        vec![0u8; self.page_size]
    }

    pub(crate) fn read_page(&self, page_index: u64) -> io::Result<Vec<u8>> {
        if let Some(hit) = self.cache.lock().expect("poisoned").get(&page_index) {
            return Ok(hit.clone());
        }

        let Some(entry) = self.pages.get(&page_index).copied() else {
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
            .ok_or_else(io_eof)?;

        let mut out = self.blank_page();
        if (entry.flags & format::AF_PAGE_COMPRESSED) == 0 {
            let take = seg.len().min(out.len());
            out[..take].copy_from_slice(&seg[..take]);
        } else {
            match entry.flags & format::AF_PAGE_COMP_ALG_MASK {
                format::AF_PAGE_COMP_ALG_ZERO => {
                    if seg.len() != 4 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "AFF ZERO-compressed page must have 4 bytes of data",
                        ));
                    }
                    // Output remains all-zero.
                }
                format::AF_PAGE_COMP_ALG_ZLIB => {
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
                format::AF_PAGE_COMP_ALG_LZMA => {
                    #[cfg(feature = "lzma")]
                    {
                        let mut input = io::Cursor::new(seg);
                        let mut output = io::Cursor::new(&mut out[..]);
                        lzma_rs::lzma_decompress(&mut input, &mut output).map_err(|e| {
                            io::Error::new(io::ErrorKind::InvalidData, format!("LZMA: {e}"))
                        })?;
                    }
                    #[cfg(not(feature = "lzma"))]
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "AFF page uses LZMA compression but feature `lzma` is disabled",
                        ));
                    }
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

impl ReadAt for Aff1Image {
    fn len(&self) -> u64 {
        self.image_size
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        if offset.saturating_add(buf.len() as u64) > self.len() {
            return Err(io_eof());
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

impl Backend for Aff1Image {
    fn kind(&self) -> ContainerKind {
        ContainerKind::Aff1
    }

    fn page_size(&self) -> usize {
        self.page_size
    }

    fn segment_names(&self) -> Vec<String> {
        let mut out = self.segments.keys().cloned().collect::<Vec<_>>();
        out.sort();
        out
    }

    fn read_segment(&self, name: &str) -> io::Result<Option<Segment>> {
        let Some(ent) = self.segments.get(name).copied() else {
            return Ok(None);
        };
        let data = self
            .data
            .get(ent.data_offset..ent.data_offset + ent.data_len)
            .ok_or_else(io_eof)?;
        Ok(Some(Segment {
            name: name.to_string(),
            arg: ent.arg,
            data: data.to_vec(),
        }))
    }
}

fn io_eof() -> io::Error {
    io::Error::from(io::ErrorKind::UnexpectedEof)
}

fn read_u32_be(data: &[u8], cursor: &mut usize) -> Result<u32> {
    let bytes = read_slice(data, cursor, 4)?;
    Ok(u32::from_be_bytes(bytes.try_into().expect("len=4")))
}

fn read_slice<'a>(data: &'a [u8], cursor: &mut usize, len: usize) -> Result<&'a [u8]> {
    let start = *cursor;
    let end = start.checked_add(len).ok_or_else(|| Error::InvalidData {
        message: "overflow".to_string(),
    })?;
    if end > data.len() {
        return Err(Error::Io(io_eof()));
    }
    *cursor = end;
    Ok(&data[start..end])
}

fn parse_page_number(name: &str) -> Option<u64> {
    name.strip_prefix("page")
        .or_else(|| name.strip_prefix("seg"))
        .and_then(|rest| rest.parse::<u64>().ok())
}

/// Reads an AFFLIB `aff_quad` (8 bytes) as `u64`.
///
/// The encoding is **little-endian in 32-bit words**:
/// - bytes `[0..4]` are the low 32 bits in network order (`htonl(low)`),
/// - bytes `[4..8]` are the high 32 bits in network order (`htonl(high)`).
fn read_aff_quad(bytes: &[u8]) -> Result<u64> {
    if bytes.len() != 8 {
        return Err(Error::InvalidData {
            message: "AFF quad must be 8 bytes".to_string(),
        });
    }
    let low = u32::from_be_bytes(bytes[0..4].try_into().expect("len=4"));
    let high = u32::from_be_bytes(bytes[4..8].try_into().expect("len=4"));
    Ok(((high as u64) << 32) | (low as u64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

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

    fn aff_segment_with_len(name: &str, data: &[u8], arg: u32, seg_len: u32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(format::SEG_MAGIC);
        out.extend_from_slice(&(name.len() as u32).to_be_bytes());
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(&arg.to_be_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);
        out.extend_from_slice(format::SEG_TRAILER);
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
    fn test_read_aff_quad_roundtrip() {
        let v = 0x11223344_55667788u64;
        let bytes = aff_quad_u64(v);
        assert_eq!(read_aff_quad(&bytes).unwrap(), v);
    }

    #[test]
    fn test_pagesize_deprecated_segsize_is_accepted() {
        let page_size = 8usize;
        let image_size = page_size as u64;

        let bytes = build_aff1_file(vec![
            aff_segment(format::SEG_SEGSIZE_DEPRECATED, &[], page_size as u32),
            aff_segment("imagesize", &aff_quad_u64(image_size), 2),
            aff_segment("page0", b"ABCDEFGH", 0),
        ]);

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), bytes).unwrap();
        let img = Aff1Image::open_with(tmp.path(), 2).unwrap();

        assert_eq!(img.page_size(), page_size);
        assert_eq!(img.len(), image_size);

        let mut out = [0u8; 8];
        img.read_exact_at(0, &mut out).unwrap();
        assert_eq!(&out, b"ABCDEFGH");
    }

    #[test]
    fn test_page_segment_deprecated_seg_prefix_is_accepted() {
        let page_size = 8usize;
        let image_size = page_size as u64;

        let bytes = build_aff1_file(vec![
            aff_segment("pagesize", &[], page_size as u32),
            aff_segment("imagesize", &aff_quad_u64(image_size), 2),
            aff_segment("seg0", b"ABCDEFGH", 0),
        ]);

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), bytes).unwrap();
        let img = Aff1Image::open_with(tmp.path(), 2).unwrap();

        let mut out = [0u8; 8];
        img.read_exact_at(0, &mut out).unwrap();
        assert_eq!(&out, b"ABCDEFGH");
    }

    #[test]
    fn test_open_rejects_bad_segment_len() {
        let good = 16u32 + "pagesize".len() as u32 + 8;
        let bad = good + 1;
        let bytes = build_aff1_file(vec![aff_segment_with_len("pagesize", &[], 4096, bad)]);

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), bytes).unwrap();

        let err = Aff1Image::open_with(tmp.path(), 2).unwrap_err();
        let msg = match err {
            Error::InvalidData { message } => message,
            other => panic!("expected InvalidData, got {other:?}"),
        };
        assert!(msg.contains("segment length mismatch"));
    }

    #[test]
    fn test_imagesize_inferred_adjusts_aes256_extra_len_like_afflib() {
        // Mimic AFFLIB `af_aes_decrypt(..., data==0)`: if ciphertext_len % 16 != 0, logical length
        // is reduced by one AES block (16).
        let page_size = 16usize;
        let ciphertext_len = 17usize; // extra=1 => subtract 16

        let mut payload = vec![0xABu8; ciphertext_len];
        // Ensure the file has enough bytes for the segment.
        payload[0] = 0xCD;

        let bytes = build_aff1_file(vec![
            aff_segment("pagesize", &[], page_size as u32),
            aff_segment(&format!("page1{}", format::AES256_SUFFIX), &payload, 0),
        ]);

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), bytes).unwrap();
        let img = Aff1Image::open_with(tmp.path(), 2).unwrap();

        assert_eq!(img.page_size(), page_size);
        assert_eq!(img.len(), 17);
    }

    #[test]
    fn test_imagesize_inferred_from_last_page_len_when_missing() {
        // Mirrors AFFLIB `af_read_sizes` behavior: if `imagesize` is missing, infer it from the
        // highest page number + the logical length of that page.
        let page_size = 8usize;

        let page0 = b"ABC";
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(page0).unwrap();
        let page0_z = enc.finish().unwrap();

        let bytes = build_aff1_file(vec![
            aff_segment("pagesize", &[], page_size as u32),
            // Intentionally omit `imagesize`.
            aff_segment(
                "page0",
                &page0_z,
                format::AF_PAGE_COMPRESSED | format::AF_PAGE_COMP_ALG_ZLIB,
            ),
        ]);

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), bytes).unwrap();
        let img = Aff1Image::open_with(tmp.path(), 2).unwrap();

        assert_eq!(img.len(), page0.len() as u64);
    }

    #[test]
    fn test_imagesize_inferred_from_zero_page_count_when_missing() {
        let page_size = 8usize;
        let count = 3u32;
        let bytes = build_aff1_file(vec![
            aff_segment("pagesize", &[], page_size as u32),
            // Intentionally omit `imagesize`.
            aff_segment(
                "page0",
                &count.to_be_bytes(),
                format::AF_PAGE_COMPRESSED | format::AF_PAGE_COMP_ALG_ZERO,
            ),
        ]);

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), bytes).unwrap();
        let img = Aff1Image::open_with(tmp.path(), 2).unwrap();

        assert_eq!(img.len(), count as u64);
    }

    #[test]
    #[cfg(feature = "lzma")]
    fn test_lzma_page_decompression_roundtrip() {
        let page_size = 64usize;
        let image_size = page_size as u64;

        let mut page = [0u8; 64];
        for (i, b) in page.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7);
        }

        let mut input = std::io::BufReader::new(std::io::Cursor::new(page));
        let mut compressed = Vec::new();
        lzma_rs::lzma_compress(&mut input, &mut compressed).unwrap();

        let bytes = build_aff1_file(vec![
            aff_segment("pagesize", &[], page_size as u32),
            aff_segment("imagesize", &aff_quad_u64(image_size), 2),
            aff_segment(
                "page0",
                &compressed,
                format::AF_PAGE_COMPRESSED | format::AF_PAGE_COMP_ALG_LZMA,
            ),
        ]);

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), bytes).unwrap();
        let img = Aff1Image::open_with(tmp.path(), 2).unwrap();

        let mut out = vec![0u8; page_size];
        img.read_exact_at(0, &mut out).unwrap();
        assert_eq!(out.as_slice(), page.as_slice());
    }

    #[test]
    fn test_zero_page_reads_as_zeros() {
        let page_size = 8usize;
        let image_size = page_size as u64;

        let zero_len = (page_size as u32).to_be_bytes();
        let bytes = build_aff1_file(vec![
            aff_segment("pagesize", &[], page_size as u32),
            aff_segment("imagesize", &aff_quad_u64(image_size), 2),
            aff_segment(
                "page0",
                &zero_len,
                format::AF_PAGE_COMPRESSED | format::AF_PAGE_COMP_ALG_ZERO,
            ),
        ]);

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), bytes).unwrap();
        let img = Aff1Image::open_with(tmp.path(), 2).unwrap();

        let mut out = vec![0xAAu8; page_size];
        img.read_exact_at(0, &mut out).unwrap();
        assert_eq!(out, vec![0u8; page_size]);
    }

    #[test]
    fn test_zlib_page_decompression_roundtrip() {
        let page_size = 32usize;
        let image_size = page_size as u64;

        let mut page = [0u8; 32];
        for (i, b) in page.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(13);
        }

        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&page).unwrap();
        let compressed = enc.finish().unwrap();

        let bytes = build_aff1_file(vec![
            aff_segment("pagesize", &[], page_size as u32),
            aff_segment("imagesize", &aff_quad_u64(image_size), 2),
            aff_segment(
                "page0",
                &compressed,
                format::AF_PAGE_COMPRESSED | format::AF_PAGE_COMP_ALG_ZLIB,
            ),
        ]);

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), bytes).unwrap();
        let img = Aff1Image::open_with(tmp.path(), 2).unwrap();

        let mut out = vec![0u8; page_size];
        img.read_exact_at(0, &mut out).unwrap();
        assert_eq!(out.as_slice(), page.as_slice());
    }
}
