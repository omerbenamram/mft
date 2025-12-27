//! Delta (shadow) file support for copy-on-write modifications.
//!
//! libewf supports read/write access using "delta (or shadow) files". The on-disk format used by
//! libewf is not documented in the EWF specifications. This module implements a pragmatic,
//! append-only, chunk-granular copy-on-write overlay that provides the same *capability*:
//! non-destructive modifications layered on top of a base EWF image set.
//!
//! The delta file format used here is specific to this crate:
//! - fixed-size header (64 bytes)
//! - append-only records: (chunk_index, data_len, flags, data_bytes)
//! - the last record for a chunk wins; the in-memory index is rebuilt by scanning the file

use crate::{Error, Result};
use md5::{Digest as _, Md5};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::FileExt as _;
#[cfg(windows)]
use std::os::windows::fs::FileExt as _;

const DELTA_MAGIC: [u8; 8] = *b"EWFDELTA";
const DELTA_VERSION: u32 = 1;
const DELTA_HEADER_SIZE: usize = 64;
const RECORD_HEADER_SIZE: usize = 16;

#[derive(Debug, Clone, Copy)]
struct RecordLoc {
    data_offset: u64,
    data_len: u32,
    flags: u32,
}

#[derive(Debug)]
struct ShadowFile {
    #[allow(dead_code)]
    path: PathBuf,
    file: File,
    chunk_size: usize,
    #[allow(dead_code)]
    media_size: u64,
    #[allow(dead_code)]
    fingerprint: [u8; 16],
    index: HashMap<u64, RecordLoc>,
    end_offset: u64,
}

impl ShadowFile {
    fn open_or_create(
        path: &Path,
        chunk_size: usize,
        media_size: u64,
        fingerprint: [u8; 16],
    ) -> Result<Self> {
        let exists = path.exists();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;

        if !exists {
            write_delta_header(&mut file, chunk_size, media_size, fingerprint)?;
            file.flush()?;
        }

        let (stored_chunk_size, stored_media_size, stored_fp) = read_delta_header(&file)?;
        if stored_chunk_size != chunk_size {
            return Err(Error::Invalid(format!(
                "delta file chunk_size mismatch: expected={chunk_size} got={stored_chunk_size}"
            )));
        }
        if stored_media_size != media_size {
            return Err(Error::Invalid(format!(
                "delta file media_size mismatch: expected={media_size} got={stored_media_size}"
            )));
        }
        if stored_fp != fingerprint {
            return Err(Error::Invalid(
                "delta file base fingerprint mismatch".to_string(),
            ));
        }

        let (index, end_offset) = scan_delta_records(&file)?;
        let file_len = file.metadata()?.len();
        if end_offset < file_len {
            // Truncate any partial/corrupt tail so future appends don't accidentally "complete" it.
            file.set_len(end_offset)?;
        }

        Ok(Self {
            path: path.to_path_buf(),
            file,
            chunk_size,
            media_size,
            fingerprint,
            index,
            end_offset,
        })
    }

    fn read_chunk(&self, chunk_index: u64) -> Result<Option<Vec<u8>>> {
        let Some(loc) = self.index.get(&chunk_index).copied() else {
            return Ok(None);
        };

        let data_len: usize = loc
            .data_len
            .try_into()
            .map_err(|_| Error::Invalid("delta record size overflow".to_string()))?;

        if data_len != self.chunk_size {
            return Err(Error::Invalid(format!(
                "unexpected delta chunk size: expected={} got={data_len}",
                self.chunk_size
            )));
        }
        if loc.flags != 0 {
            return Err(Error::Unsupported(
                "delta record flags are not supported yet".to_string(),
            ));
        }

        let mut buf = vec![0u8; data_len];
        read_exact_at(&self.file, loc.data_offset, &mut buf)?;
        Ok(Some(buf))
    }

    fn write_chunk(&mut self, chunk_index: u64, chunk: &[u8]) -> Result<()> {
        if chunk.len() != self.chunk_size {
            return Err(Error::Invalid("chunk size mismatch".to_string()));
        }
        if chunk.len() > u32::MAX as usize {
            return Err(Error::Invalid("chunk too large".to_string()));
        }

        let record_offset = self.end_offset;
        self.file.seek(SeekFrom::Start(record_offset))?;

        let mut hdr = [0u8; RECORD_HEADER_SIZE];
        hdr[0..8].copy_from_slice(&chunk_index.to_le_bytes());
        hdr[8..12].copy_from_slice(&(chunk.len() as u32).to_le_bytes());
        hdr[12..16].copy_from_slice(&0u32.to_le_bytes()); // flags

        self.file.write_all(&hdr)?;
        self.file.write_all(chunk)?;

        let data_offset = record_offset
            .checked_add(RECORD_HEADER_SIZE as u64)
            .ok_or_else(|| Error::Invalid("delta file offset overflow".to_string()))?;
        self.index.insert(
            chunk_index,
            RecordLoc {
                data_offset,
                data_len: chunk.len() as u32,
                flags: 0,
            },
        );

        self.end_offset = data_offset
            .checked_add(chunk.len() as u64)
            .ok_or_else(|| Error::Invalid("delta file offset overflow".to_string()))?;

        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        self.file.flush()?;
        Ok(())
    }
}

/// A copy-on-write overlay on top of a base EWF image set.
#[derive(Debug)]
pub struct EwfDelta {
    base: crate::EwfReader,
    shadow: ShadowFile,
}

impl EwfDelta {
    /// Opens (or creates) a delta file overlaying the provided base image set.
    ///
    /// The delta file is append-only and can be re-opened to resume a previous overlay.
    pub fn open(base_path: impl AsRef<Path>, delta_path: impl AsRef<Path>) -> Result<Self> {
        let base = crate::EwfReader::open(base_path)?;
        let fp = fingerprint_base(&base)?;

        let shadow =
            ShadowFile::open_or_create(delta_path.as_ref(), base.chunk_size(), base.len(), fp)?;
        Ok(Self { base, shadow })
    }

    pub fn len(&self) -> u64 {
        self.base.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn chunk_size(&self) -> usize {
        self.base.chunk_size()
    }

    pub fn chunk_count(&self) -> u64 {
        self.base.chunk_count()
    }

    pub fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        if offset.saturating_add(buf.len() as u64) > self.len() {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }

        let mut remaining = buf.len();
        let mut out_pos = 0usize;
        let mut cur = offset;
        let chunk_size = self.chunk_size();

        while remaining > 0 {
            let chunk_index = cur / chunk_size as u64;
            let within = (cur % chunk_size as u64) as usize;

            let chunk = self.read_chunk_filled(chunk_index)?;
            let take = remaining.min(chunk_size - within);
            buf[out_pos..out_pos + take].copy_from_slice(&chunk[within..within + take]);

            out_pos += take;
            remaining -= take;
            cur = cur.saturating_add(take as u64);
        }

        Ok(())
    }

    pub fn write_exact_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        if offset.saturating_add(buf.len() as u64) > self.len() {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }

        let mut remaining = buf.len();
        let mut in_pos = 0usize;
        let mut cur = offset;
        let chunk_size = self.chunk_size();

        while remaining > 0 {
            let chunk_index = cur / chunk_size as u64;
            let within = (cur % chunk_size as u64) as usize;
            let take = remaining.min(chunk_size - within);

            let mut chunk = self.read_chunk_filled(chunk_index)?;
            chunk[within..within + take].copy_from_slice(&buf[in_pos..in_pos + take]);

            self.shadow.write_chunk(chunk_index, &chunk)?;

            in_pos += take;
            remaining -= take;
            cur = cur.saturating_add(take as u64);
        }

        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        self.shadow.flush()
    }

    fn read_chunk_filled(&self, chunk_index: u64) -> Result<Vec<u8>> {
        if let Some(chunk) = self.shadow.read_chunk(chunk_index)? {
            return Ok(chunk);
        }

        let chunk_size = self.chunk_size();
        let mut out = vec![0u8; chunk_size];
        let offset = chunk_index.saturating_mul(chunk_size as u64);
        if offset >= self.len() {
            return Ok(out);
        }

        let available = (self.len() - offset).min(chunk_size as u64) as usize;
        if available > 0 {
            self.base.read_exact_at(offset, &mut out[..available])?;
        }
        Ok(out)
    }
}

fn fingerprint_base(base: &crate::EwfReader) -> Result<[u8; 16]> {
    let sample_len: usize = base
        .len()
        .min(1024 * 1024)
        .try_into()
        .map_err(|_| Error::Invalid("base image too large".to_string()))?;

    let mut hasher = Md5::new();
    if sample_len != 0 {
        let mut buf = vec![0u8; sample_len];
        base.read_exact_at(0, &mut buf)?;
        hasher.update(&buf);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..]);
    Ok(out)
}

fn write_delta_header(
    file: &mut File,
    chunk_size: usize,
    media_size: u64,
    fingerprint: [u8; 16],
) -> Result<()> {
    if chunk_size > u32::MAX as usize {
        return Err(Error::Invalid("chunk_size too large".to_string()));
    }

    let chunk_count = div_ceil_u64(media_size, chunk_size as u64);

    let mut hdr = [0u8; DELTA_HEADER_SIZE];
    hdr[0..8].copy_from_slice(&DELTA_MAGIC);
    hdr[8..12].copy_from_slice(&DELTA_VERSION.to_le_bytes());
    hdr[12..16].copy_from_slice(&(chunk_size as u32).to_le_bytes());
    hdr[16..24].copy_from_slice(&media_size.to_le_bytes());
    hdr[24..32].copy_from_slice(&chunk_count.to_le_bytes());
    hdr[32..48].copy_from_slice(&fingerprint);
    // hdr[48..64] reserved zeros

    file.seek(SeekFrom::Start(0))?;
    file.write_all(&hdr)?;
    Ok(())
}

fn read_delta_header(file: &File) -> Result<(usize, u64, [u8; 16])> {
    let mut hdr = [0u8; DELTA_HEADER_SIZE];
    read_exact_at(file, 0, &mut hdr)?;

    if hdr[0..8] != DELTA_MAGIC {
        return Err(Error::Invalid("invalid delta magic".to_string()));
    }
    let version = u32::from_le_bytes(hdr[8..12].try_into().expect("len=4"));
    if version != DELTA_VERSION {
        return Err(Error::Unsupported(format!(
            "unsupported delta version: {version}"
        )));
    }

    let chunk_size_u32 = u32::from_le_bytes(hdr[12..16].try_into().expect("len=4"));
    let media_size = u64::from_le_bytes(hdr[16..24].try_into().expect("len=8"));
    let _chunk_count = u64::from_le_bytes(hdr[24..32].try_into().expect("len=8"));
    let mut fp = [0u8; 16];
    fp.copy_from_slice(&hdr[32..48]);

    Ok((chunk_size_u32 as usize, media_size, fp))
}

fn scan_delta_records(file: &File) -> Result<(HashMap<u64, RecordLoc>, u64)> {
    let file_len = file.metadata()?.len();
    if file_len < DELTA_HEADER_SIZE as u64 {
        return Err(Error::Invalid("delta file too small".to_string()));
    }

    let mut index: HashMap<u64, RecordLoc> = HashMap::new();
    let mut off: u64 = DELTA_HEADER_SIZE as u64;

    while off.saturating_add(RECORD_HEADER_SIZE as u64) <= file_len {
        let mut hdr = [0u8; RECORD_HEADER_SIZE];
        if let Err(e) = read_exact_at(file, off, &mut hdr) {
            // Corrupt/truncated tail: stop scanning.
            if e.kind() == io::ErrorKind::UnexpectedEof {
                break;
            }
            return Err(e.into());
        }

        let chunk_index = u64::from_le_bytes(hdr[0..8].try_into().expect("len=8"));
        let data_len = u32::from_le_bytes(hdr[8..12].try_into().expect("len=4"));
        let flags = u32::from_le_bytes(hdr[12..16].try_into().expect("len=4"));

        let data_offset = off
            .checked_add(RECORD_HEADER_SIZE as u64)
            .ok_or_else(|| Error::Invalid("delta file offset overflow".to_string()))?;
        let next = data_offset.saturating_add(data_len as u64);
        if next > file_len {
            break;
        }

        index.insert(
            chunk_index,
            RecordLoc {
                data_offset,
                data_len,
                flags,
            },
        );
        off = next;
    }

    Ok((index, off))
}

fn read_exact_at(file: &File, offset: u64, buf: &mut [u8]) -> io::Result<()> {
    let mut done = 0usize;
    while done < buf.len() {
        let n = file.read_at(&mut buf[done..], offset + done as u64)?;
        if n == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        done += n;
    }
    Ok(())
}

fn div_ceil_u64(n: u64, d: u64) -> u64 {
    if d == 0 {
        return 0;
    }
    let q = n / d;
    let r = n % d;
    if r == 0 { q } else { q + 1 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::writer::{Ewf1Format, EwfWriterOptions};
    use crate::{EwfReader, EwfWriter};

    #[test]
    fn test_delta_overlay_roundtrip_ewf1() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let base_path = dir.path().join("base.E01");
        let delta_path = dir.path().join("shadow.ewfdelta");

        // Base media: 2 chunks of 512 bytes.
        let mut media = vec![0u8; 1024];
        media[..].copy_from_slice(&std::iter::repeat_n(0xAAu8, 1024).collect::<Vec<u8>>());
        media[512..].copy_from_slice(&std::iter::repeat_n(0xBBu8, 512).collect::<Vec<u8>>());

        let mut opts = EwfWriterOptions::new(Ewf1Format::E01, media.len() as u64);
        opts.bytes_per_sector = 512;
        opts.sectors_per_chunk = 1;
        opts.segment_file_size = 10 * 1024 * 1024;
        let mut w = EwfWriter::create(&base_path, opts)?;
        let mut written = 0usize;
        while written < media.len() {
            let n = w.write(&media[written..])?;
            if n == 0 {
                return Err(Error::Invalid("writer made no progress".to_string()));
            }
            written += n;
        }
        w.finish()?;

        // Sanity: base reads back.
        let base = EwfReader::open(&base_path)?;
        let mut buf = vec![0u8; media.len()];
        base.read_exact_at(0, &mut buf)?;
        assert_eq!(buf, media);

        // Create overlay and apply modifications spanning chunk boundary.
        let mut overlay = EwfDelta::open(&base_path, &delta_path)?;
        overlay.write_exact_at(10, b"XYZ")?;
        overlay.write_exact_at(510, b"0123456789")?; // crosses into the second chunk
        overlay.flush()?;

        let mut out = vec![0u8; media.len()];
        overlay.read_exact_at(0, &mut out)?;
        let mut expected = media.clone();
        expected[10..13].copy_from_slice(b"XYZ");
        expected[510..520].copy_from_slice(b"0123456789");
        assert_eq!(out, expected);

        // Base must be unchanged.
        let base2 = EwfReader::open(&base_path)?;
        let mut buf2 = vec![0u8; media.len()];
        base2.read_exact_at(0, &mut buf2)?;
        assert_eq!(buf2, media);

        // Re-open overlay and ensure changes persist.
        drop(overlay);
        let overlay2 = EwfDelta::open(&base_path, &delta_path)?;
        let mut out2 = vec![0u8; media.len()];
        overlay2.read_exact_at(0, &mut out2)?;
        assert_eq!(out2, expected);

        Ok(())
    }
}
