//! Page decoding shared by the page-based readers.
//!
//! A decoded page is kept as the bytes its segment really holds, which may be fewer than the page
//! size (a short last page, or a page that compresses a prefix). The rest of the page reads as
//! zeros. Nothing here allocates by the page size: that number comes from the `pagesize` segment
//! and can be anything up to 4 GiB.

use crate::format;
use flate2::read::ZlibDecoder;
use std::io::{self, Read};

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
/// Returns the bytes the page holds, at most `page_size`. The buffer grows with the decoded
/// data; it is never sized by `page_size` up front.
pub(crate) fn decode_compressed_page(
    flags: u32,
    stored: &[u8],
    page_size: usize,
) -> io::Result<Vec<u8>> {
    match flags & format::AF_PAGE_COMP_ALG_MASK {
        // The page is all zeros.
        format::AF_PAGE_COMP_ALG_ZERO => Ok(Vec::new()),
        format::AF_PAGE_COMP_ALG_ZLIB => {
            let mut out = Vec::new();
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
