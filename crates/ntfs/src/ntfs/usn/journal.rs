//! USN change journal (`$Extend\\$UsnJrnl:$J`) record reader.
//!
//! This is the *block-based* reader layer modeled after upstream
//! - Reads fixed-size **journal blocks** (default 0x1000 bytes)
//! - Interprets the first 4 bytes at the current block offset as `record_len` (LE u32)
//! - Treats `record_len == 0` as **end-of-block** and advances to the next block
//! - Rejects invalid sizes **strictly** (no skipping, no placeholders)
//!
//! It intentionally does **not** parse record semantics. Use [`super::UsnRecord::parse`] (or
//! [`super::UsnRecordV2::parse`]) on the returned bytes.

use crate::image::ReadAt;
use crate::ntfs::{Error, Result};
use std::sync::Arc;

/// Default journal block size.
///
pub const DEFAULT_USN_JOURNAL_BLOCK_SIZE: usize = 0x1000;

/// Minimum USN record size in bytes (fixed fields before variable-length name).
///
/// This is the size of a minimal `USN_RECORD_V2` with an empty file name.
pub const MIN_USN_RECORD_SIZE: usize = 60;

/// A raw USN record read from `$UsnJrnl:$J`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsnRawRecord {
    /// Logical stream offset where this record begins (relative to `$J` start).
    pub offset: u64,
    /// Record bytes (`record_len` bytes, starting with `record_len` itself).
    pub bytes: Vec<u8>,
}

/// Stateful `$J` reader yielding one record at a time.
#[derive(Clone)]
pub struct UsnChangeJournal {
    stream: Arc<dyn ReadAt>,
    journal_block_size: usize,

    // Current logical stream offset (relative to `$J` start).
    offset: u64,

    // Cached block.
    block_start: u64,
    block_valid_len: usize,
    block: Vec<u8>,
    block_loaded: bool,
}

impl UsnChangeJournal {
    /// Create a new journal reader over the provided `$J` stream.
    pub fn new(stream: Arc<dyn ReadAt>, journal_block_size: usize) -> Result<Self> {
        if journal_block_size < MIN_USN_RECORD_SIZE {
            return Err(Error::InvalidData {
                message: format!(
                    "invalid USN journal block size: {journal_block_size} (min {MIN_USN_RECORD_SIZE})"
                ),
            });
        }
        if journal_block_size > usize::MAX / 2 {
            // Defensive: avoid absurd allocations.
            return Err(Error::InvalidData {
                message: format!("invalid USN journal block size: {journal_block_size}"),
            });
        }

        Ok(Self {
            stream,
            journal_block_size,
            offset: 0,
            block_start: 0,
            block_valid_len: 0,
            block: vec![0u8; journal_block_size],
            block_loaded: false,
        })
    }

    /// Returns the logical `$J` stream length in bytes.
    pub fn len(&self) -> u64 {
        self.stream.len()
    }

    /// Returns `true` if the `$J` stream length is 0.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the current logical offset within `$J` (relative to `$J` start).
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Returns the journal block size in bytes.
    pub fn journal_block_size(&self) -> usize {
        self.journal_block_size
    }

    /// Reads the next USN record.
    ///
    /// - Returns `Ok(None)` on EOF.
    /// - Returns an error on invalid record layout (strict).
    pub fn read_record_bytes(&mut self) -> Result<Option<UsnRawRecord>> {
        loop {
            let stream_len = self.stream.len();
            if self.offset >= stream_len {
                return Ok(None);
            }

            let block_size_u64 = self.journal_block_size as u64;
            let within = (self.offset % block_size_u64) as usize;
            let block_start = self.offset - within as u64;

            if !self.block_loaded || self.block_start != block_start {
                self.load_block(block_start)?;
            }

            let remaining_in_block = self.journal_block_size.saturating_sub(within);

            // If there is not enough room for even the smallest record, skip to next block.
            // (Matches upstream intent; records are not expected to straddle blocks.)
            if remaining_in_block < MIN_USN_RECORD_SIZE {
                self.offset = block_start.saturating_add(block_size_u64);
                continue;
            }

            let record_len =
                u32::from_le_bytes(self.block[within..within + 4].try_into().expect("4 bytes"))
                    as usize;

            if record_len == 0 {
                // End-of-block marker.
                self.offset = block_start.saturating_add(block_size_u64);
                continue;
            }

            if record_len < MIN_USN_RECORD_SIZE {
                return Err(Error::InvalidData {
                    message: format!(
                        "invalid USN record size: len={record_len} at stream_offset=0x{:x}",
                        block_start + within as u64
                    ),
                });
            }
            if record_len > remaining_in_block {
                return Err(Error::InvalidData {
                    message: format!(
                        "invalid USN record size: len={record_len} overflows journal block at stream_offset=0x{:x}",
                        block_start + within as u64
                    ),
                });
            }

            let record_end = (block_start + within as u64)
                .checked_add(record_len as u64)
                .ok_or_else(|| Error::InvalidData {
                    message: "USN record end offset overflow".to_string(),
                })?;
            if record_end > stream_len {
                return Err(Error::InvalidData {
                    message: format!(
                        "USN record extends beyond end of $J stream: record_end=0x{:x} stream_len=0x{:x}",
                        record_end, stream_len
                    ),
                });
            }

            // Note: `block_valid_len` is only smaller than `journal_block_size` on the final block.
            // If the record is within `stream_len`, it must be within `block_valid_len` as well.
            if within
                .saturating_add(record_len)
                .saturating_sub(self.block_valid_len)
                > 0
            {
                return Err(Error::InvalidData {
                    message: format!(
                        "USN record extends beyond readable bytes in journal block: len={record_len} at stream_offset=0x{:x}",
                        block_start + within as u64
                    ),
                });
            }

            let bytes = self.block[within..within + record_len].to_vec();
            let record_offset = block_start + within as u64;

            self.offset = self.offset.saturating_add(record_len as u64);

            return Ok(Some(UsnRawRecord {
                offset: record_offset,
                bytes,
            }));
        }
    }

    /// Returns an iterator over raw USN records (as owned `Vec<u8>`).
    pub fn iter_record_bytes(&mut self) -> UsnRawRecordIter<'_> {
        UsnRawRecordIter {
            j: self,
            done: false,
        }
    }

    fn load_block(&mut self, block_start: u64) -> Result<()> {
        let stream_len = self.stream.len();
        if block_start >= stream_len {
            // Should be handled by caller, but keep this robust.
            self.block_loaded = true;
            self.block_start = block_start;
            self.block_valid_len = 0;
            self.block.fill(0);
            return Ok(());
        }

        let to_read = (stream_len - block_start)
            .min(self.journal_block_size as u64)
            .try_into()
            .map_err(|_| Error::InvalidData {
                message: "journal block read length overflow".to_string(),
            })?;

        self.block.fill(0);
        self.stream
            .read_exact_at(block_start, &mut self.block[..to_read])
            .map_err(Error::Io)?;

        self.block_loaded = true;
        self.block_start = block_start;
        self.block_valid_len = to_read;
        Ok(())
    }
}

pub struct UsnRawRecordIter<'a> {
    j: &'a mut UsnChangeJournal,
    done: bool,
}

impl Iterator for UsnRawRecordIter<'_> {
    type Item = Result<UsnRawRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match self.j.read_record_bytes() {
            Ok(Some(r)) => Some(Ok(r)),
            Ok(None) => {
                self.done = true;
                None
            }
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::Arc;

    #[derive(Debug)]
    struct MemReadAt {
        data: Arc<[u8]>,
    }

    impl MemReadAt {
        fn new(data: Vec<u8>) -> Self {
            Self { data: data.into() }
        }
    }

    impl ReadAt for MemReadAt {
        fn len(&self) -> u64 {
            self.data.len() as u64
        }

        fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
            let end = offset
                .checked_add(buf.len() as u64)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "offset overflow"))?;
            if end > self.len() {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            }
            let start = usize::try_from(offset)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "offset overflow"))?;
            let end = usize::try_from(end)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "offset overflow"))?;
            buf.copy_from_slice(&self.data[start..end]);
            Ok(())
        }
    }

    #[test]
    fn reader_yields_records_and_skips_end_of_block_marker() {
        let block_size = 0x1000usize;
        let mut data = vec![0u8; block_size * 2];

        // Block 0: record(60) + end-of-block marker (0).
        data[0..4].copy_from_slice(&(60u32).to_le_bytes());
        // Next record header at offset 60: record_len == 0 => end of block.
        data[60..64].copy_from_slice(&0u32.to_le_bytes());

        // Block 1: record(60) + end-of-block.
        let b1 = block_size;
        data[b1..b1 + 4].copy_from_slice(&(60u32).to_le_bytes());
        data[b1 + 60..b1 + 64].copy_from_slice(&0u32.to_le_bytes());

        let stream: Arc<dyn ReadAt> = Arc::new(MemReadAt::new(data));
        let mut j = UsnChangeJournal::new(stream, block_size).unwrap();

        let recs = j.iter_record_bytes().collect::<Result<Vec<_>>>().unwrap();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].offset, 0);
        assert_eq!(recs[0].bytes.len(), 60);
        assert_eq!(recs[1].offset, block_size as u64);
        assert_eq!(recs[1].bytes.len(), 60);
    }

    #[test]
    fn reader_errors_on_record_overflowing_block() {
        let block_size = 0x1000usize;
        let mut data = vec![0u8; block_size];

        // Place record header at the last possible start for a minimal record (60 bytes remain).
        let off = block_size - MIN_USN_RECORD_SIZE;
        data[off..off + 4].copy_from_slice(&(256u32).to_le_bytes()); // too large for remaining

        let stream: Arc<dyn ReadAt> = Arc::new(MemReadAt::new(data));
        let mut j = UsnChangeJournal::new(stream, block_size).unwrap();
        j.offset = off as u64;

        let err = j.read_record_bytes().unwrap_err();
        assert!(matches!(err, Error::InvalidData { .. }));
    }
}
