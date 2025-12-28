//! Small, shared utilities used across EWF parsers and writers.
//!
//! This module intentionally stays lightweight and dependency-free. It exists to avoid duplicating
//! common low-level helpers (checksums, fixed-offset file reads, etc.) across the EWF1/EWF2 reader
//! and writer implementations.

use std::fs::File;
use std::io;

use crate::{Error, Result};

/// Reads exactly `buf.len()` bytes from `file` at a given absolute `offset`.
///
/// This is a cross-platform wrapper around `FileExt` (pread/seek_read semantics).
pub(crate) fn read_exact_at(file: &File, offset: u64, mut buf: &mut [u8]) -> io::Result<()> {
    #[cfg(unix)]
    use std::os::unix::fs::FileExt as _;
    #[cfg(windows)]
    use std::os::windows::fs::FileExt as _;

    let mut cur = offset;
    while !buf.is_empty() {
        #[cfg(unix)]
        let n = file.read_at(buf, cur)?;
        #[cfg(windows)]
        let n = file.seek_read(buf, cur)?;

        if n == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        cur = cur.saturating_add(n as u64);
        buf = &mut buf[n..];
    }
    Ok(())
}

/// Reads a file range into memory (half-open interval: `[start, end)`).
pub(crate) fn read_file_range(file: &File, file_len: u64, start: u64, end: u64) -> Result<Vec<u8>> {
    if end > file_len || start >= end {
        return Err(Error::Invalid("file range out of bounds".to_string()));
    }
    let len = usize::try_from(end - start)
        .map_err(|_| Error::Invalid("range length overflow".to_string()))?;
    let mut buf = vec![0u8; len];
    read_exact_at(file, start, &mut buf)?;
    Ok(buf)
}

/// Parses an ASCII NUL-terminated string from a fixed-width byte field.
pub(crate) fn parse_ascii_nul_terminated(bytes: &[u8]) -> String {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).to_string()
}

/// Computes an Adler-32 checksum as defined by RFC1950 (zlib wrapper).
pub(crate) fn adler32_rfc1950(data: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a = (a + u32::from(byte)) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }
    (b << 16) | a
}
