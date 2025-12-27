//! Read support for EWF images.
//!
//! This module currently implements a random-access reader for **EWF1** segment sets, matching the
//! semantics of the reference implementation (libewf) as closely as possible:
//! - Section descriptor and table checksums are verified (Adler32 / RFC1950).
//! - The EWF1 chunk table "wraparound" offset encoding is handled the same way libewf does.
//! - Multi-segment image sets are discovered using the format-specific extension naming scheme
//!   (e.g. `.E01`..`.E99` then `.EAA`..`.ZZZ`).
//!
//! EWF2 (`.Ex01`, `.Lx01`) and logical evidence (`.L01`) are wired in later in this task series.

use crate::{Error, EwfCompression, EwfFormat, EwfInfo, Result};
use flate2::read::ZlibDecoder;
use lru::LruCache;
use md5::{Digest as _, Md5};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[cfg(unix)]
use std::os::unix::fs::FileExt as _;

#[cfg(windows)]
use std::os::windows::fs::FileExt as _;

// --- EWF signatures (file header; first 8 bytes) ---
const EWF1_EVF_SIGNATURE: [u8; 8] = [0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00]; // "EVF\t\r\n\xff\0"
const EWF1_LVF_SIGNATURE: [u8; 8] = [0x4c, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00]; // "LVF\t\r\n\xff\0" (logical evidence)
const EWF2_EVF_SIGNATURE: [u8; 8] = [0x45, 0x56, 0x46, 0x32, 0x0d, 0x0a, 0x81, 0x00]; // "EVF2\r\n\x81\0"
const EWF2_LEF_SIGNATURE: [u8; 8] = [0x4c, 0x45, 0x46, 0x32, 0x0d, 0x0a, 0x81, 0x00]; // "LEF2\r\n\x81\0"
const ADCRYPT_SIGNATURE: [u8; 8] = [0x41, 0x44, 0x43, 0x52, 0x59, 0x50, 0x54, 0x00]; // "ADCRYPT\0"

// --- EWF1 constants ---
const EWF1_FILE_HEADER_SIZE: usize = 8 + 1 + 2 + 2; // 13
const EWF1_SECTION_DESCRIPTOR_SIZE: usize = 16 + 8 + 8 + 40 + 4; // 76
const EWF1_TABLE_HEADER_SIZE: usize = 4 + 4 + 8 + 4 + 4; // 24

/// Random-access reader over an EWF image set.
///
/// This is a thin, format-detecting wrapper around format-specific readers (EWF1, EWF2, ...).
#[derive(Debug)]
pub struct EwfReader {
    inner: InnerReader,
}

/// Verification options for [`EwfReader::verify`].
#[derive(Debug, Clone, Copy)]
pub struct VerifyOptions {
    /// Verify chunk decoding by reading every chunk.
    pub verify_chunks: bool,
    /// Verify EWF2 per-section MD5 integrity hashes (skips `SECTOR_DATA` unless explicitly enabled).
    pub verify_section_md5: bool,
    /// When verifying section MD5, also verify the `SECTOR_DATA` section MD5 (can be very slow).
    pub verify_sector_data_section_md5: bool,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            verify_chunks: true,
            verify_section_md5: false,
            verify_sector_data_section_md5: false,
        }
    }
}

#[derive(Debug)]
enum InnerReader {
    Ewf1(Ewf1Reader),
    Ewf2(Ewf2Reader),
}

#[derive(Debug)]
struct Ewf1Reader {
    /// Logical media size in bytes.
    media_size: u64,

    /// Logical chunk size in bytes (sectors_per_chunk * bytes_per_sector).
    chunk_size: usize,

    /// Total number of chunks in the logical media.
    chunk_count: u64,

    /// Segment files in ascending `segment_number` order.
    segments: Vec<Ewf1Segment>,

    /// In-memory LRU cache of decoded chunks (keyed by global chunk index).
    cache: Mutex<LruCache<u64, Vec<u8>>>,
}

#[derive(Debug)]
struct Ewf2Reader {
    /// Logical media size in bytes.
    media_size: u64,

    /// Logical chunk size in bytes (sectors_per_chunk * bytes_per_sector).
    chunk_size: usize,

    /// Total number of chunks in the logical media.
    chunk_count: u64,

    /// Segment-set compression method (from the EWF2 file header).
    compression_method: u16,

    /// Segment files in ascending `segment_number` order.
    segments: Vec<Ewf2Segment>,

    /// Sector table groups in ascending `first_chunk_index` order.
    groups: Vec<Ewf2ChunkGroup>,

    /// In-memory LRU cache of decoded chunks (keyed by global chunk index).
    cache: Mutex<LruCache<u64, Vec<u8>>>,
}

#[derive(Debug)]
struct Ewf1Segment {
    // Kept for debugging and future features (writer/resume, delta/shadow, etc.).
    #[allow(dead_code)]
    path: PathBuf,
    file: File,
    file_len: u64,
    #[allow(dead_code)]
    segment_number: u16,

    /// Global chunk index of the first chunk stored in this segment.
    first_chunk_index: u64,
    /// Number of chunks stored in this segment.
    #[allow(dead_code)]
    chunk_count: u64,

    /// Chunk tables in this segment.
    ///
    /// Some writers emit multiple `sectors` + `table`/`table2` groups within the same segment.
    chunk_groups: Vec<Ewf1ChunkGroup>,
}

#[derive(Debug)]
struct Ewf1ChunkGroup {
    /// Global chunk index of the first entry in this group.
    first_chunk_index: u64,

    /// Base file offset for this group's entries.
    chunk_base: u64,

    /// Table entries for this group (v1 `table` / `table2`) storing per-chunk offsets and the
    /// compression flag (MSB).
    chunk_entries: Vec<u32>,

    /// Absolute file offset where the chunk data region for this group ends.
    chunk_data_end: u64,
}

// --- EWF2 constants ---
const EWF2_FILE_HEADER_SIZE: usize = 32;
const EWF2_SECTION_DESCRIPTOR_SIZE: usize = 64;
const EWF2_TABLE_HEADER_SIZE: usize = 32; // 20 bytes header + 12 bytes alignment padding
const EWF2_TABLE_ENTRY_SIZE: usize = 16;
const EWF2_TABLE_FOOTER_SIZE: usize = 16; // 4 bytes footer + 12 bytes alignment padding

const EWF2_SECTION_TYPE_DEVICE_INFORMATION: u32 = 0x0000_0001;
const EWF2_SECTION_TYPE_CASE_DATA: u32 = 0x0000_0002;
const EWF2_SECTION_TYPE_SECTOR_DATA: u32 = 0x0000_0003;
const EWF2_SECTION_TYPE_SECTOR_TABLE: u32 = 0x0000_0004;
const EWF2_SECTION_TYPE_NEXT: u32 = 0x0000_000d;
const EWF2_SECTION_TYPE_DONE: u32 = 0x0000_000f;
const EWF2_SECTION_TYPE_SINGLE_FILES_DATA: u32 = 0x0000_0020;

const EWF2_SECTION_DATA_FLAG_MD5HASHED: u32 = 0x0000_0001;
const EWF2_SECTION_DATA_FLAG_ENCRYPTED: u32 = 0x0000_0002;

const EWF2_CHUNK_DATA_FLAG_COMPRESSED: u32 = 0x0000_0001;
const EWF2_CHUNK_DATA_FLAG_CHECKSUMED: u32 = 0x0000_0002;
const EWF2_CHUNK_DATA_FLAG_PATTERNFILL: u32 = 0x0000_0004;

const EWF2_COMPRESSION_NONE: u16 = 0;
const EWF2_COMPRESSION_LZ: u16 = 1;
const EWF2_COMPRESSION_BZIP2: u16 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ewf2Kind {
    Ex01,
    Lx01,
}

#[derive(Debug)]
struct Ewf2FileHeader {
    kind: Ewf2Kind,
    #[allow(dead_code)]
    major: u8,
    #[allow(dead_code)]
    minor: u8,
    compression_method: u16,
    segment_number: u32,
    set_id: [u8; 16],
}

#[derive(Debug, Clone)]
struct Ewf2Section {
    section_type: u32,
    data_flags: u32,
    previous_offset: u64,
    #[allow(dead_code)]
    data_size: u64,
    #[allow(dead_code)]
    descriptor_size: u32,
    padding_size: u32,
    #[allow(dead_code)]
    data_integrity_hash: [u8; 16],

    /// Offset of the section descriptor (the descriptor is stored *at the end* of the section).
    #[allow(dead_code)]
    descriptor_offset: u64,

    /// Start offset of the section data (relative to the start of the segment file).
    data_start: u64,

    /// Length of the section data that is considered valid by `data_size`.
    ///
    /// Some tools may append extra bytes beyond `data_size` (e.g., after abort/restart scenarios).
    data_len: u64,
}

#[derive(Debug)]
struct Ewf2Segment {
    #[allow(dead_code)]
    path: PathBuf,
    file: File,
    file_len: u64,
    #[allow(dead_code)]
    segment_number: u32,
    sections: Vec<Ewf2Section>,
}

#[derive(Debug, Clone)]
struct Ewf2TableEntry {
    offset_raw: [u8; 8],
    size: u32,
    flags: u32,
}

#[derive(Debug)]
struct Ewf2ChunkGroup {
    segment_idx: usize,
    first_chunk_index: u64,
    entries: Vec<Ewf2TableEntry>,
}

impl EwfReader {
    /// Opens an existing EWF image set (EWF1 and EWF2 are auto-detected).
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let file = File::open(path)?;

        let mut sig = [0u8; 8];
        read_exact_at(&file, 0, &mut sig)?;
        drop(file);

        if sig == ADCRYPT_SIGNATURE {
            return Err(Error::Unsupported(
                "AccessData AD encryption container (ADCRYPT) is not supported".to_string(),
            ));
        }

        if sig == EWF1_EVF_SIGNATURE {
            return Ok(Self {
                inner: InnerReader::Ewf1(Ewf1Reader::open(path)?),
            });
        }
        if sig == EWF1_LVF_SIGNATURE {
            return Err(Error::Unsupported(
                "EWF-L01 (LVF) is a logical evidence file; use `LefReader`".to_string(),
            ));
        }
        if sig == EWF2_EVF_SIGNATURE {
            return Ok(Self {
                inner: InnerReader::Ewf2(Ewf2Reader::open(path)?),
            });
        }
        if sig == EWF2_LEF_SIGNATURE {
            return Err(Error::Unsupported(
                "EWF2-Lx01 (LEF2) is a logical evidence file; use `LefReader`".to_string(),
            ));
        }

        // If we were pointed at a *non-first* segment of an ADCRYPT container, its signature will be
        // ciphertext, not `ADCRYPT\0`. Try to detect this by probing a likely first segment.
        if is_related_adcrypt_set(path)? {
            return Err(Error::Unsupported(
                "AccessData AD encryption container (ADCRYPT) is not supported".to_string(),
            ));
        }

        Err(Error::Invalid("unsupported EWF signature".to_string()))
    }

    /// Returns the logical length of the image set in bytes.
    pub fn len(&self) -> u64 {
        match &self.inner {
            InnerReader::Ewf1(r) => r.len(),
            InnerReader::Ewf2(r) => r.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the logical chunk size in bytes.
    pub fn chunk_size(&self) -> usize {
        match &self.inner {
            InnerReader::Ewf1(r) => r.chunk_size(),
            InnerReader::Ewf2(r) => r.chunk_size(),
        }
    }

    /// Returns the number of chunks in the logical media.
    pub fn chunk_count(&self) -> u64 {
        match &self.inner {
            InnerReader::Ewf1(r) => r.chunk_count(),
            InnerReader::Ewf2(r) => r.chunk_count(),
        }
    }

    /// Returns the detected image format.
    pub fn format(&self) -> EwfFormat {
        match &self.inner {
            InnerReader::Ewf1(r) => r.format(),
            InnerReader::Ewf2(r) => r.format(),
        }
    }

    /// Returns a small metadata summary of the image set.
    pub fn info(&self) -> EwfInfo {
        match &self.inner {
            InnerReader::Ewf1(r) => r.info(),
            InnerReader::Ewf2(r) => r.info(),
        }
    }

    /// Verifies the image set according to `opts`.
    ///
    /// By default this verifies chunk decoding (it will read and decode every chunk).
    pub fn verify(&self, opts: VerifyOptions) -> Result<()> {
        match &self.inner {
            InnerReader::Ewf1(r) => r.verify(opts),
            InnerReader::Ewf2(r) => r.verify(opts),
        }
    }

    /// Reads exactly `buf.len()` bytes from the logical image at `offset`.
    pub fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        match &self.inner {
            InnerReader::Ewf1(r) => r.read_exact_at(offset, buf),
            InnerReader::Ewf2(r) => r.read_exact_at(offset, buf),
        }
    }
}

impl Ewf2Reader {
    fn open(path: &Path) -> Result<Self> {
        Self::open_kind(path, Ewf2Kind::Ex01)
    }

    fn open_lx01(path: &Path) -> Result<Self> {
        Self::open_kind(path, Ewf2Kind::Lx01)
    }

    fn open_kind(path: &Path, expected_kind: Ewf2Kind) -> Result<Self> {
        let base_path = remove_extension(path);
        let naming = Ewf2Naming::from_path(path, expected_kind)?;

        let segment_paths = discover_segment_paths_ewf2(&base_path, naming)?;
        if segment_paths.is_empty() {
            return Err(Error::Invalid(format!(
                "no segment files found for `{}`",
                path.display()
            )));
        }

        // Parse headers + sections for all segments, validating set-id and compression method.
        let mut segments: Vec<Ewf2Segment> = Vec::with_capacity(segment_paths.len());
        let mut compression_method: Option<u16> = None;
        let mut set_id: Option<[u8; 16]> = None;

        for (i, seg_path) in segment_paths.iter().enumerate() {
            let expected_segment_number: u32 =
                u32::try_from(i.saturating_add(1)).map_err(|_| {
                    Error::Invalid("segment count overflow (too many segments)".to_string())
                })?;

            let file = File::open(seg_path)?;
            let file_len = file.metadata()?.len();
            let hdr = parse_ewf2_file_header(&file)?;

            if hdr.kind != expected_kind {
                return Err(Error::Invalid(format!(
                    "unexpected EWF2 kind in `{}`: expected={expected_kind:?} got={:?}",
                    seg_path.display(),
                    hdr.kind
                )));
            }
            if hdr.segment_number != expected_segment_number {
                return Err(Error::Invalid(format!(
                    "segment `{}` header segment_number mismatch: expected={expected_segment_number} got={}",
                    seg_path.display(),
                    hdr.segment_number
                )));
            }

            if let Some(cm) = compression_method {
                if hdr.compression_method != cm {
                    return Err(Error::Invalid(format!(
                        "segment `{}` compression method mismatch: expected={cm} got={}",
                        seg_path.display(),
                        hdr.compression_method
                    )));
                }
            } else {
                compression_method = Some(hdr.compression_method);
            }

            if let Some(id) = set_id {
                if hdr.set_id != id {
                    return Err(Error::Invalid(format!(
                        "segment `{}` set identifier mismatch",
                        seg_path.display()
                    )));
                }
            } else {
                set_id = Some(hdr.set_id);
            }

            let sections = parse_ewf2_section_descriptors(&file, file_len)?;
            if sections
                .iter()
                .any(|s| (s.data_flags & EWF2_SECTION_DATA_FLAG_ENCRYPTED) != 0)
            {
                return Err(Error::Unsupported(
                    "EWF2 encrypted images are not supported (matches libewf)".to_string(),
                ));
            }

            segments.push(Ewf2Segment {
                path: seg_path.clone(),
                file,
                file_len,
                segment_number: hdr.segment_number,
                sections,
            });
        }

        let compression_method = compression_method.unwrap_or(EWF2_COMPRESSION_LZ);

        // Basic structural validation: non-last segments should end with `next`, and the last
        // segment should end with `done`.
        for (i, seg) in segments.iter().enumerate() {
            let is_last = i + 1 == segments.len();
            let Some(last) = seg.sections.last() else {
                return Err(Error::Invalid("EWF2 segment has no sections".to_string()));
            };
            if is_last {
                if last.section_type != EWF2_SECTION_TYPE_DONE {
                    return Err(Error::Invalid(
                        "EWF2 last segment does not end with done section".to_string(),
                    ));
                }
            } else if last.section_type != EWF2_SECTION_TYPE_NEXT {
                return Err(Error::Invalid(
                    "EWF2 non-last segment does not end with next section".to_string(),
                ));
            }
        }

        // The sector tables point at sector data chunks; having no sector data sections is usually a
        // strong indicator of a non-disk image or a corrupt file.
        let any_sector_data = segments.iter().any(|seg| {
            seg.sections
                .iter()
                .any(|s| s.section_type == EWF2_SECTION_TYPE_SECTOR_DATA)
        });
        if !any_sector_data {
            return Err(Error::Invalid(
                "EWF2 image has no sector data sections".to_string(),
            ));
        }

        // Read device information + case data from the first segment to establish media geometry.
        let first = segments
            .first()
            .ok_or_else(|| Error::Invalid("missing first segment".to_string()))?;

        let device_section = first
            .sections
            .iter()
            .find(|s| s.section_type == EWF2_SECTION_TYPE_DEVICE_INFORMATION)
            .ok_or_else(|| Error::Invalid("missing EWF2 device information section".to_string()))?;
        let case_section = first
            .sections
            .iter()
            .find(|s| s.section_type == EWF2_SECTION_TYPE_CASE_DATA)
            .ok_or_else(|| Error::Invalid("missing EWF2 case data section".to_string()))?;

        let device_tags = parse_ewf2_main_object_tags(&read_ewf2_compressed_object_string(
            first,
            device_section,
            compression_method,
        )?)?;
        let case_tags = parse_ewf2_main_object_tags(&read_ewf2_compressed_object_string(
            first,
            case_section,
            compression_method,
        )?)?;

        let bytes_per_sector = parse_tag_u32(&device_tags, "bp")?;
        let number_of_sectors = parse_tag_u64(&device_tags, "ts")?;
        let sectors_per_chunk = parse_tag_u32(&case_tags, "sb")?;
        let chunk_count = parse_tag_u64(&case_tags, "tb")?;

        // EWF2 chunk geometry must be valid before we compute `chunk_size`. Otherwise `chunk_size`
        // can become 0 and later reads will panic on division-by-zero.
        //
        // This mirrors the EWF1 validation in `parse_volume_like_section_v1`, and matches libewf's
        // behavior (it rejects a 0 chunk size when initializing its chunk data structures).
        if bytes_per_sector == 0 || sectors_per_chunk == 0 {
            return Err(Error::Invalid(format!(
                "invalid EWF2 chunk geometry: bp={bytes_per_sector} sb={sectors_per_chunk}"
            )));
        }

        let media_size = number_of_sectors
            .checked_mul(bytes_per_sector as u64)
            .ok_or_else(|| Error::Invalid("media size overflow".to_string()))?;

        let chunk_size_u64 = (bytes_per_sector as u64)
            .checked_mul(sectors_per_chunk as u64)
            .ok_or_else(|| Error::Invalid("chunk size overflow".to_string()))?;
        let chunk_size = usize::try_from(chunk_size_u64)
            .map_err(|_| Error::Invalid("chunk size exceeds usize".to_string()))?;

        let expected_chunk_count = div_ceil_u64(media_size, chunk_size as u64);
        if expected_chunk_count != chunk_count {
            return Err(Error::Invalid(format!(
                "media size/chunk size mismatch: media_size={} chunk_size={} expected_chunks={} case_chunks={chunk_count}",
                media_size, chunk_size, expected_chunk_count
            )));
        }

        // Parse sector table sections across all segments.
        let mut groups: Vec<Ewf2ChunkGroup> = Vec::new();
        for (seg_idx, seg) in segments.iter().enumerate() {
            for section in &seg.sections {
                if section.section_type == EWF2_SECTION_TYPE_SECTOR_TABLE {
                    let (first_chunk, entries) = parse_ewf2_sector_table_section(seg, section)?;
                    groups.push(Ewf2ChunkGroup {
                        segment_idx: seg_idx,
                        first_chunk_index: first_chunk,
                        entries,
                    });
                }
            }
        }

        if groups.is_empty() {
            return Err(Error::Invalid(
                "missing EWF2 sector table sections".to_string(),
            ));
        }

        groups.sort_by_key(|g| g.first_chunk_index);

        // Validate that groups cover exactly [0..chunk_count) contiguously (common EWF2 layout).
        let mut next_first = 0u64;
        for g in &groups {
            if g.first_chunk_index != next_first {
                return Err(Error::Invalid(format!(
                    "EWF2 sector table groups are not contiguous: expected first chunk {next_first} got {}",
                    g.first_chunk_index
                )));
            }
            let n = u64::try_from(g.entries.len())
                .map_err(|_| Error::Invalid("entry count overflow".to_string()))?;
            next_first = next_first.saturating_add(n);
        }
        if next_first != chunk_count {
            return Err(Error::Invalid(format!(
                "EWF2 chunk count mismatch: case_chunks={chunk_count} table_chunks={next_first}"
            )));
        }

        Ok(Self {
            media_size,
            chunk_size,
            chunk_count,
            compression_method,
            segments,
            groups,
            cache: Mutex::new(LruCache::new(NonZeroUsize::new(256).expect("256 > 0"))),
        })
    }

    fn len(&self) -> u64 {
        self.media_size
    }

    fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    fn chunk_count(&self) -> u64 {
        self.chunk_count
    }

    fn format(&self) -> EwfFormat {
        // For now `EwfReader` only exposes EVF2/Ex01 as a disk image reader.
        // (LEF2/Lx01 is handled by `LefReader`.)
        EwfFormat::Ex01
    }

    fn info(&self) -> EwfInfo {
        let compression = match self.compression_method {
            EWF2_COMPRESSION_NONE => EwfCompression::None,
            EWF2_COMPRESSION_LZ => EwfCompression::Zlib,
            EWF2_COMPRESSION_BZIP2 => EwfCompression::Bzip2,
            other => EwfCompression::Unknown(other),
        };

        EwfInfo {
            format: self.format(),
            media_size: self.media_size,
            chunk_size: self.chunk_size,
            chunk_count: self.chunk_count,
            segment_count: self.segments.len(),
            compression,
        }
    }

    fn verify(&self, opts: VerifyOptions) -> Result<()> {
        if opts.verify_section_md5 {
            self.verify_section_md5(opts.verify_sector_data_section_md5)?;
        }
        if opts.verify_chunks {
            for idx in 0..self.chunk_count() {
                // `read_chunk` validates CHECKSUMED chunks and decompresses compressed chunks.
                let _ = self.read_chunk(idx)?;
            }
        }
        Ok(())
    }

    fn verify_section_md5(&self, include_sector_data: bool) -> Result<()> {
        for seg in &self.segments {
            for section in &seg.sections {
                let has_md5 = (section.data_flags & EWF2_SECTION_DATA_FLAG_MD5HASHED) != 0;
                if !has_md5 {
                    continue;
                }
                if !include_sector_data && section.section_type == EWF2_SECTION_TYPE_SECTOR_DATA {
                    continue;
                }
                let digest = md5_file_range(
                    &seg.file,
                    seg.file_len,
                    section.data_start,
                    section.data_len,
                )?;
                if digest != section.data_integrity_hash {
                    return Err(Error::Corrupt(format!(
                        "EWF2 section MD5 mismatch (type=0x{:08x})",
                        section.section_type
                    )));
                }
            }
        }
        Ok(())
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        if offset.saturating_add(buf.len() as u64) > self.len() {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }

        let mut remaining = buf.len();
        let mut out_pos = 0usize;
        let mut cur = offset;

        while remaining > 0 {
            let chunk_index = cur / self.chunk_size as u64;
            let within = (cur % self.chunk_size as u64) as usize;

            let chunk = self.read_chunk(chunk_index)?;
            let take = remaining.min(self.chunk_size - within);
            buf[out_pos..out_pos + take].copy_from_slice(&chunk[within..within + take]);

            out_pos += take;
            remaining -= take;
            cur = cur.saturating_add(take as u64);
        }

        Ok(())
    }

    fn read_chunk(&self, chunk_index: u64) -> Result<Vec<u8>> {
        if let Some(hit) = self.cache.lock().expect("poisoned").get(&chunk_index) {
            return Ok(hit.clone());
        }
        if chunk_index >= self.chunk_count() {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }

        let (segment, group, idx) = self.group_for_chunk(chunk_index)?;
        let entry = group.entries.get(idx).ok_or_else(|| {
            Error::Invalid("chunk index out of range in sector table".to_string())
        })?;

        let is_compressed = (entry.flags & EWF2_CHUNK_DATA_FLAG_COMPRESSED) != 0;
        let is_checksumed = (entry.flags & EWF2_CHUNK_DATA_FLAG_CHECKSUMED) != 0;
        let is_pattern_fill =
            is_compressed && (entry.flags & EWF2_CHUNK_DATA_FLAG_PATTERNFILL) != 0;

        let mut out = vec![0u8; self.chunk_size];

        if is_pattern_fill {
            // Pattern fill: the "offset" field stores an 8-byte fill pattern.
            for (i, b) in out.iter_mut().enumerate() {
                *b = entry.offset_raw[i % 8];
            }
            self.cache
                .lock()
                .expect("poisoned")
                .put(chunk_index, out.clone());
            return Ok(out);
        }

        let data_offset = u64::from_le_bytes(entry.offset_raw);
        let data_size = usize::try_from(entry.size)
            .map_err(|_| Error::Invalid("chunk data size overflow".to_string()))?;
        if data_size == 0 {
            return Err(Error::Invalid("chunk data size is 0".to_string()));
        }

        let slice = read_file_range(
            &segment.file,
            segment.file_len,
            data_offset,
            data_offset.saturating_add(data_size as u64),
        )?;

        if is_compressed {
            if is_checksumed {
                return Err(Error::Invalid(
                    "invalid EWF2 chunk flags: compressed + checksumed".to_string(),
                ));
            }

            match self.compression_method {
                EWF2_COMPRESSION_LZ => {
                    let cursor = io::Cursor::new(slice);
                    let mut decoder = ZlibDecoder::new(cursor);
                    decoder.read_exact(&mut out)?;
                }
                EWF2_COMPRESSION_NONE => {
                    return Err(Error::Invalid(
                        "chunk marked compressed but compression method is NONE".to_string(),
                    ));
                }
                EWF2_COMPRESSION_BZIP2 => {
                    return Err(Error::Unsupported(
                        "EWF2 bzip2 compression is not implemented yet".to_string(),
                    ));
                }
                other => {
                    return Err(Error::Unsupported(format!(
                        "unsupported EWF2 compression method: {other}"
                    )));
                }
            }
        } else if is_checksumed {
            if slice.len() < 4 {
                return Err(
                    io::Error::new(io::ErrorKind::UnexpectedEof, "short checksumed chunk").into(),
                );
            }
            let data_part = &slice[..slice.len() - 4];
            let checksum_part = &slice[slice.len() - 4..];
            let stored = u32::from_le_bytes(checksum_part.try_into().expect("len=4"));
            let calculated = adler32_rfc1950(data_part);

            if stored != calculated {
                return Err(Error::Corrupt("EWF2 chunk checksum mismatch".to_string()));
            }
            if data_part.len() > out.len() {
                return Err(Error::Invalid("EWF2 chunk data too large".to_string()));
            }
            out[..data_part.len()].copy_from_slice(data_part);
        } else {
            // Uncompressed chunk without checksum (uncommon but allowed by the spec).
            if slice.len() > out.len() {
                return Err(Error::Invalid("EWF2 chunk data too large".to_string()));
            }
            out[..slice.len()].copy_from_slice(&slice);
        }

        self.cache
            .lock()
            .expect("poisoned")
            .put(chunk_index, out.clone());
        Ok(out)
    }

    fn group_for_chunk(&self, chunk_index: u64) -> Result<(&Ewf2Segment, &Ewf2ChunkGroup, usize)> {
        let pos = self
            .groups
            .partition_point(|g| g.first_chunk_index <= chunk_index);
        let group_idx = pos
            .checked_sub(1)
            .ok_or_else(|| Error::Invalid("chunk index out of range".to_string()))?;
        let group = &self.groups[group_idx];

        let segment = self
            .segments
            .get(group.segment_idx)
            .ok_or_else(|| Error::Invalid("segment index out of range".to_string()))?;

        let local_u64 = chunk_index.saturating_sub(group.first_chunk_index);
        let local = usize::try_from(local_u64)
            .map_err(|_| Error::Invalid("chunk index overflow".to_string()))?;
        if local >= group.entries.len() {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }

        Ok((segment, group, local))
    }
}

// --- EWF2 parsing helpers ---

fn parse_ewf2_file_header(file: &File) -> Result<Ewf2FileHeader> {
    let mut buf = [0u8; EWF2_FILE_HEADER_SIZE];
    read_exact_at(file, 0, &mut buf)?;

    let signature: [u8; 8] = buf[0..8].try_into().expect("len=8");
    let kind = if signature == EWF2_EVF_SIGNATURE {
        Ewf2Kind::Ex01
    } else if signature == EWF2_LEF_SIGNATURE {
        Ewf2Kind::Lx01
    } else {
        return Err(Error::Invalid("not an EWF2 segment file".to_string()));
    };

    let major = buf[8];
    let minor = buf[9];
    if major != 2 {
        return Err(Error::Invalid(format!(
            "unsupported EWF2 major version: {major}"
        )));
    }

    let compression_method = u16::from_le_bytes(buf[10..12].try_into().expect("len=2"));
    let segment_number = u32::from_le_bytes(buf[12..16].try_into().expect("len=4"));
    let set_id: [u8; 16] = buf[16..32].try_into().expect("len=16");

    Ok(Ewf2FileHeader {
        kind,
        major,
        minor,
        compression_method,
        segment_number,
        set_id,
    })
}

fn parse_ewf2_section_descriptors(file: &File, file_len: u64) -> Result<Vec<Ewf2Section>> {
    let min_len =
        (EWF2_FILE_HEADER_SIZE as u64).saturating_add(EWF2_SECTION_DESCRIPTOR_SIZE as u64);
    if file_len < min_len {
        return Err(Error::Invalid("file too small for EWF2".to_string()));
    }

    let mut sections_rev: Vec<Ewf2Section> = Vec::new();
    let mut desc_off = file_len
        .checked_sub(EWF2_SECTION_DESCRIPTOR_SIZE as u64)
        .ok_or_else(|| Error::Invalid("file too small for EWF2".to_string()))?;

    // Hard guard against loops on corrupt inputs.
    for _ in 0..1_000_000u32 {
        let section = parse_ewf2_section_descriptor_at(file, file_len, desc_off)?;
        let prev = section.previous_offset;
        sections_rev.push(section);

        if prev == 0 {
            break;
        }
        if prev >= desc_off {
            return Err(Error::Invalid(
                "EWF2 previous section offset does not move backwards".to_string(),
            ));
        }
        desc_off = prev;
    }

    if sections_rev.is_empty() {
        return Err(Error::Invalid("no EWF2 sections found".to_string()));
    }

    sections_rev.reverse();
    Ok(sections_rev)
}

fn parse_ewf2_section_descriptor_at(
    file: &File,
    file_len: u64,
    descriptor_offset: u64,
) -> Result<Ewf2Section> {
    let _ = file_len;
    let mut buf = [0u8; EWF2_SECTION_DESCRIPTOR_SIZE];
    read_exact_at(file, descriptor_offset, &mut buf)?;

    let stored = u32::from_le_bytes(buf[60..64].try_into().expect("len=4"));
    let calculated = adler32_rfc1950(&buf[0..60]);
    if stored != calculated {
        return Err(Error::Corrupt(
            "EWF2 section descriptor checksum mismatch".to_string(),
        ));
    }

    let section_type = u32::from_le_bytes(buf[0..4].try_into().expect("len=4"));
    let data_flags = u32::from_le_bytes(buf[4..8].try_into().expect("len=4"));
    // If the section has an MD5 integrity hash, the hash covers the (possibly encrypted) section data.
    // We currently do not verify it during open; chunk-level checksums and section descriptor checksums
    // provide basic corruption detection already.
    let _has_md5_integrity_hash = (data_flags & EWF2_SECTION_DATA_FLAG_MD5HASHED) != 0;
    let previous_offset = u64::from_le_bytes(buf[8..16].try_into().expect("len=8"));
    let data_size = u64::from_le_bytes(buf[16..24].try_into().expect("len=8"));
    let descriptor_size = u32::from_le_bytes(buf[24..28].try_into().expect("len=4"));
    let padding_size = u32::from_le_bytes(buf[28..32].try_into().expect("len=4"));
    let data_integrity_hash: [u8; 16] = buf[32..48].try_into().expect("len=16");

    if descriptor_size as usize != EWF2_SECTION_DESCRIPTOR_SIZE {
        return Err(Error::Invalid(format!(
            "unsupported EWF2 section descriptor size: {descriptor_size}"
        )));
    }

    // The descriptor links to the previous section descriptor (by offset). The section data begins
    // after the previous descriptor (or after the file header for the first section).
    let data_start = if previous_offset == 0 {
        EWF2_FILE_HEADER_SIZE as u64
    } else {
        previous_offset.saturating_add(descriptor_size as u64)
    };

    if data_start > descriptor_offset {
        return Err(Error::Invalid(
            "EWF2 section data start offset out of bounds".to_string(),
        ));
    }

    // `data_size` is the amount of data considered part of the section (including any padding
    // described by `padding_size`). If tools appended extra bytes between sections, we ignore them.
    let max_len = descriptor_offset.saturating_sub(data_start);
    let data_len = data_size.min(max_len);

    Ok(Ewf2Section {
        section_type,
        data_flags,
        previous_offset,
        data_size,
        descriptor_size,
        padding_size,
        data_integrity_hash,
        descriptor_offset,
        data_start,
        data_len,
    })
}

fn read_ewf2_compressed_object_string(
    segment: &Ewf2Segment,
    section: &Ewf2Section,
    compression_method: u16,
) -> Result<String> {
    if (section.data_flags & EWF2_SECTION_DATA_FLAG_ENCRYPTED) != 0 {
        return Err(Error::Unsupported(
            "EWF2 encrypted metadata sections are not supported yet".to_string(),
        ));
    }

    let mut compressed_len = section.data_len;
    if (section.padding_size as u64) <= compressed_len {
        compressed_len = compressed_len.saturating_sub(section.padding_size as u64);
    }
    if compressed_len == 0 {
        return Err(Error::Invalid(
            "EWF2 compressed string is empty".to_string(),
        ));
    }

    let compressed = read_file_range(
        &segment.file,
        segment.file_len,
        section.data_start,
        section.data_start.saturating_add(compressed_len),
    )?;

    let uncompressed = match compression_method {
        EWF2_COMPRESSION_NONE => compressed,
        EWF2_COMPRESSION_LZ => {
            let cursor = io::Cursor::new(compressed);
            let mut decoder = ZlibDecoder::new(cursor);
            let mut out = Vec::new();
            decoder.read_to_end(&mut out)?;
            out
        }
        EWF2_COMPRESSION_BZIP2 => {
            return Err(Error::Unsupported(
                "EWF2 bzip2 compression is not implemented yet".to_string(),
            ));
        }
        other => {
            return Err(Error::Unsupported(format!(
                "unsupported EWF2 compression method: {other}"
            )));
        }
    };

    decode_utf16_with_bom(&uncompressed)
}

fn decode_utf16_with_bom(bytes: &[u8]) -> Result<String> {
    if bytes.len() < 2 {
        return Err(Error::Invalid("short UTF-16 string".to_string()));
    }
    if !bytes.len().is_multiple_of(2) {
        return Err(Error::Invalid("UTF-16 string has odd length".to_string()));
    }

    let (le, start) = if bytes.starts_with(&[0xff, 0xfe]) {
        (true, 2)
    } else if bytes.starts_with(&[0xfe, 0xff]) {
        (false, 2)
    } else {
        // Commonly little-endian even without BOM (per libewf docs).
        (true, 0)
    };

    let mut u16s = Vec::with_capacity((bytes.len() - start) / 2);
    for chunk in bytes[start..].chunks_exact(2) {
        let v = if le {
            u16::from_le_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], chunk[1]])
        };
        u16s.push(v);
    }

    Ok(String::from_utf16_lossy(&u16s))
}

fn parse_ewf2_main_object_tags(s: &str) -> Result<HashMap<String, String>> {
    // Minimal parser for the common "single main object" serialization used in device information
    // and case data sections:
    //  line 1: number of objects (usually "1")
    //  line 2: object name (usually "main")
    //  line 3: tab-separated attribute tags
    //  line 4: tab-separated attribute values
    let mut lines = s.split('\n');
    let _num_objects = lines.next().unwrap_or_default();
    let _object_name = lines.next().unwrap_or_default();
    let tags_line = lines
        .next()
        .ok_or_else(|| Error::Invalid("EWF2 object string missing tags line".to_string()))?;
    let values_line = lines
        .next()
        .ok_or_else(|| Error::Invalid("EWF2 object string missing values line".to_string()))?;

    let tags: Vec<&str> = tags_line.trim_end_matches('\r').split('\t').collect();
    let values: Vec<&str> = values_line.trim_end_matches('\r').split('\t').collect();
    if tags.len() != values.len() {
        return Err(Error::Invalid(
            "EWF2 object tags/values column count mismatch".to_string(),
        ));
    }

    let mut out = HashMap::new();
    for (t, v) in tags.into_iter().zip(values) {
        if t.is_empty() {
            continue;
        }
        out.insert(t.to_string(), unescape_ewf2_value(v));
    }
    Ok(out)
}

fn unescape_ewf2_value(value: &str) -> String {
    // The object serialization uses:
    // - U+0001 for escaped line feed
    // - U+0002 for escaped carriage return
    // - U+0003 for escaped tab
    // The actual delimiters are U+000A (line) and U+0009 (tab).
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\u{1}' => out.push('\n'),
            '\u{2}' => out.push('\r'),
            '\u{3}' => out.push('\t'),
            other => out.push(other),
        }
    }
    out
}

fn parse_tag_u64(map: &HashMap<String, String>, tag: &str) -> Result<u64> {
    let v = map
        .get(tag)
        .ok_or_else(|| Error::Invalid(format!("missing EWF2 tag `{tag}`")))?;
    v.trim()
        .parse::<u64>()
        .map_err(|_| Error::Invalid(format!("invalid EWF2 `{tag}` value: `{v}`")))
}

fn parse_tag_u32(map: &HashMap<String, String>, tag: &str) -> Result<u32> {
    let v = map
        .get(tag)
        .ok_or_else(|| Error::Invalid(format!("missing EWF2 tag `{tag}`")))?;
    v.trim()
        .parse::<u32>()
        .map_err(|_| Error::Invalid(format!("invalid EWF2 `{tag}` value: `{v}`")))
}

fn parse_ewf2_sector_table_section(
    segment: &Ewf2Segment,
    section: &Ewf2Section,
) -> Result<(u64, Vec<Ewf2TableEntry>)> {
    if (section.data_flags & EWF2_SECTION_DATA_FLAG_ENCRYPTED) != 0 {
        return Err(Error::Unsupported(
            "EWF2 encrypted sector tables are not supported yet".to_string(),
        ));
    }

    let required_min = (EWF2_TABLE_HEADER_SIZE + EWF2_TABLE_FOOTER_SIZE) as u64;
    if section.data_len < required_min {
        return Err(Error::Invalid(
            "short EWF2 sector table section".to_string(),
        ));
    }

    let header = read_file_range(
        &segment.file,
        segment.file_len,
        section.data_start,
        section
            .data_start
            .saturating_add(EWF2_TABLE_HEADER_SIZE as u64),
    )?;

    let first_chunk = u64::from_le_bytes(header[0..8].try_into().expect("len=8"));
    let number_of_entries = u32::from_le_bytes(header[8..12].try_into().expect("len=4"));
    let stored_header_checksum = u32::from_le_bytes(header[16..20].try_into().expect("len=4"));
    let calc_header_checksum = adler32_rfc1950(&header[0..16]);
    if stored_header_checksum != calc_header_checksum {
        return Err(Error::Corrupt(
            "EWF2 sector table header checksum mismatch".to_string(),
        ));
    }

    let entries_len = (number_of_entries as u64)
        .checked_mul(EWF2_TABLE_ENTRY_SIZE as u64)
        .ok_or_else(|| Error::Invalid("sector table entries size overflow".to_string()))?;

    let entries_start = section
        .data_start
        .saturating_add(EWF2_TABLE_HEADER_SIZE as u64);
    let entries_end = entries_start.saturating_add(entries_len);
    let footer_end = entries_end.saturating_add(EWF2_TABLE_FOOTER_SIZE as u64);

    let section_end = section.data_start.saturating_add(section.data_len);
    if footer_end > section_end {
        return Err(Error::Invalid(
            "EWF2 sector table entries out of bounds".to_string(),
        ));
    }

    let entries_bytes =
        read_file_range(&segment.file, segment.file_len, entries_start, entries_end)?;
    let footer = read_file_range(&segment.file, segment.file_len, entries_end, footer_end)?;
    let stored_footer_checksum = u32::from_le_bytes(footer[0..4].try_into().expect("len=4"));
    let calc_footer_checksum = adler32_rfc1950(&entries_bytes);
    if stored_footer_checksum != calc_footer_checksum {
        return Err(Error::Corrupt(
            "EWF2 sector table footer checksum mismatch".to_string(),
        ));
    }

    let mut entries: Vec<Ewf2TableEntry> = Vec::with_capacity(number_of_entries as usize);
    for chunk in entries_bytes.chunks_exact(EWF2_TABLE_ENTRY_SIZE) {
        let offset_raw: [u8; 8] = chunk[0..8].try_into().expect("len=8");
        let size = u32::from_le_bytes(chunk[8..12].try_into().expect("len=4"));
        let flags = u32::from_le_bytes(chunk[12..16].try_into().expect("len=4"));
        entries.push(Ewf2TableEntry {
            offset_raw,
            size,
            flags,
        });
    }

    Ok((first_chunk, entries))
}

impl Ewf1Reader {
    /// Opens an existing EWF image set.
    ///
    /// For EWF1 this will discover sibling segment files using the naming schema described in the
    /// libewf EWF specification (e.g. `.E01`..`.E99` then `.EAA`..`.ZZZ`), starting at segment 1.
    fn open(path: &Path) -> Result<Self> {
        // Read enough of the file header to classify the image set and decide discovery rules.
        let first_file = File::open(path)?;
        let header = Ewf1FileHeader::parse(&first_file)?;

        match header.signature {
            EwfSignature::Ewf1Evf => Self::open_ewf1(path, header.segment_number),
            EwfSignature::Ewf1Lvf => Err(Error::Unsupported(
                "EWF-L01 (LVF) is not implemented yet (planned in LEF todo)".to_string(),
            )),
            EwfSignature::Ewf2Evf | EwfSignature::Ewf2Lef => Err(Error::Unsupported(
                "EWF2 (EVF2/LEF2) is not implemented yet (planned in EWF2 todo)".to_string(),
            )),
            EwfSignature::Unknown => Err(Error::Invalid("unsupported EWF signature".to_string())),
        }
    }

    /// Returns the logical length of the image set in bytes.
    pub fn len(&self) -> u64 {
        self.media_size
    }

    /// Returns the logical chunk size in bytes.
    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    /// Returns the number of chunks in the logical media.
    pub fn chunk_count(&self) -> u64 {
        self.chunk_count
    }

    fn format(&self) -> EwfFormat {
        // Determine E01 vs S01 from the first segment file extension.
        // This mirrors how we choose the naming scheme on open.
        let Some(seg1) = self.segments.first() else {
            return EwfFormat::E01;
        };
        let ext = seg1
            .path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if ext.starts_with('s') {
            EwfFormat::S01
        } else {
            EwfFormat::E01
        }
    }

    fn info(&self) -> EwfInfo {
        EwfInfo {
            format: self.format(),
            media_size: self.media_size,
            chunk_size: self.chunk_size,
            chunk_count: self.chunk_count,
            segment_count: self.segments.len(),
            compression: EwfCompression::Zlib,
        }
    }

    fn verify(&self, opts: VerifyOptions) -> Result<()> {
        if opts.verify_section_md5 || opts.verify_sector_data_section_md5 {
            // EWF1 does not define section MD5 integrity hashes the way EWF2 does.
        }
        if opts.verify_chunks {
            for idx in 0..self.chunk_count() {
                let _ = self.read_chunk(idx)?;
            }
        }
        Ok(())
    }

    /// Reads exactly `buf.len()` bytes from the logical image at `offset`.
    pub fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        if offset.saturating_add(buf.len() as u64) > self.len() {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }

        let mut remaining = buf.len();
        let mut out_pos = 0usize;
        let mut cur = offset;

        while remaining > 0 {
            let chunk_index = cur / self.chunk_size as u64;
            let within = (cur % self.chunk_size as u64) as usize;

            let chunk = self.read_chunk(chunk_index)?;
            let take = remaining.min(self.chunk_size - within);
            buf[out_pos..out_pos + take].copy_from_slice(&chunk[within..within + take]);

            out_pos += take;
            remaining -= take;
            cur = cur.saturating_add(take as u64);
        }

        Ok(())
    }

    fn open_ewf1(path: &Path, hinted_segment_number: u16) -> Result<Self> {
        // Determine segment naming scheme from the file extension.
        // The EWF1 file header signature (EVF) does not distinguish EnCase (`.E01`) from SMART
        // (`.s01`) images, so we follow the format-specific naming schema based on the extension.
        let naming = EwfxNaming::from_path(path)?;
        let base_path = remove_extension(path);

        let segment_paths = discover_segment_paths(&base_path, naming)?;
        if segment_paths.is_empty() {
            return Err(Error::Invalid(format!(
                "no segment files found for `{}`",
                path.display()
            )));
        }

        // If the caller opened a non-first segment, we still expect to discover segment 1 and open
        // from there. `hinted_segment_number` is used only as a sanity check: the provided file
        // must be part of the discovered set.
        if hinted_segment_number == 0 {
            return Err(Error::Invalid("segment number 0 is invalid".to_string()));
        }

        // First pass: open files, validate headers, and parse section descriptors for each segment.
        let mut parsed: Vec<Ewf1SegmentParsed> = Vec::with_capacity(segment_paths.len());
        let mut any_table2 = false;

        for (i, seg_path) in segment_paths.iter().enumerate() {
            let expected_segment_number: u16 =
                u16::try_from(i.saturating_add(1)).map_err(|_| {
                    Error::Invalid("segment count overflow (too many segments)".to_string())
                })?;

            let file = File::open(seg_path)?;
            let file_len = file.metadata()?.len();

            let hdr = Ewf1FileHeader::parse(&file)?;
            if hdr.signature != EwfSignature::Ewf1Evf {
                return Err(Error::Invalid(format!(
                    "segment `{}` has unexpected signature: {hdr:?}",
                    seg_path.display()
                )));
            }
            if hdr.segment_number != expected_segment_number {
                return Err(Error::Invalid(format!(
                    "segment `{}` header segment_number mismatch: expected={expected_segment_number} got={}",
                    seg_path.display(),
                    hdr.segment_number
                )));
            }

            let sections =
                parse_ewf1_section_descriptors(&file, file_len, hdr.sections_start_offset())?;
            any_table2 |= sections.iter().any(|s| s.type_string == "table2");

            parsed.push(Ewf1SegmentParsed {
                path: seg_path.clone(),
                file,
                file_len,
                segment_number: hdr.segment_number,
                sections,
            });
        }

        // Second pass: extract volume parameters and build chunk group mapping.
        let table_type = if any_table2 { "table2" } else { "table" };

        let volume = parsed
            .first()
            .ok_or_else(|| Error::Invalid("missing first segment".to_string()))
            .and_then(|first| parse_volume_like_section_v1(&first.file, &first.sections))?;

        let mut segments: Vec<Ewf1Segment> = Vec::with_capacity(parsed.len());
        let mut global_chunk_index: u64 = 0;

        for seg in parsed {
            let (chunk_groups, seg_chunk_count) = parse_chunk_groups_v1(
                &seg.file,
                seg.file_len,
                &seg.sections,
                table_type,
                global_chunk_index,
            )?;

            segments.push(Ewf1Segment {
                path: seg.path,
                file: seg.file,
                file_len: seg.file_len,
                segment_number: seg.segment_number,
                first_chunk_index: global_chunk_index,
                chunk_count: seg_chunk_count,
                chunk_groups,
            });

            global_chunk_index = global_chunk_index.saturating_add(seg_chunk_count);
        }

        if segments.is_empty() {
            return Err(Error::Invalid("no segments".to_string()));
        }

        // Global validation against volume parameters.
        let chunk_count = global_chunk_index;
        if volume.number_of_chunks as u64 != chunk_count {
            return Err(Error::Invalid(format!(
                "volume/table chunk count mismatch: volume={} table={chunk_count}",
                volume.number_of_chunks
            )));
        }

        let expected_chunks_from_media = div_ceil_u64(volume.media_size, volume.chunk_size as u64);
        if expected_chunks_from_media != chunk_count {
            return Err(Error::Invalid(format!(
                "media size/chunk size mismatch: media_size={} chunk_size={} expected_chunks={} table_chunks={}",
                volume.media_size, volume.chunk_size, expected_chunks_from_media, chunk_count
            )));
        }

        Ok(Self {
            media_size: volume.media_size,
            chunk_size: volume.chunk_size,
            chunk_count,
            segments,
            cache: Mutex::new(LruCache::new(NonZeroUsize::new(256).expect("256 > 0"))),
        })
    }

    fn read_chunk(&self, chunk_index: u64) -> Result<Vec<u8>> {
        if let Some(hit) = self.cache.lock().expect("poisoned").get(&chunk_index) {
            return Ok(hit.clone());
        }
        if chunk_index >= self.chunk_count() {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }

        let (segment, group, idx) = self.group_for_chunk(chunk_index)?;
        let (start, end, is_compressed) = chunk_range_v1(group, idx)?;

        let slice = read_file_range(&segment.file, segment.file_len, start, end)?;
        let mut out = vec![0u8; self.chunk_size];

        if is_compressed {
            // Compressed chunks contain a zlib stream that expands to exactly `chunk_size` bytes.
            // (EWF1 uses zlib/deflate for chunk compression.)
            let cursor = io::Cursor::new(slice);
            let mut decoder = ZlibDecoder::new(cursor);
            decoder.read_exact(&mut out)?;
        } else {
            // Uncompressed chunks are stored as: [chunk bytes][u32 adler32 checksum].
            let required = self
                .chunk_size
                .checked_add(4)
                .ok_or_else(|| Error::Invalid("chunk size overflow".to_string()))?;
            if slice.len() < required {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "short uncompressed chunk",
                )
                .into());
            }

            let data_part = &slice[..self.chunk_size];
            let checksum_part = &slice[self.chunk_size..self.chunk_size + 4];
            let stored = u32::from_le_bytes(checksum_part.try_into().expect("len=4"));
            let calculated = adler32_rfc1950(data_part);

            if stored != calculated {
                return Err(Error::Corrupt(
                    "uncompressed chunk checksum mismatch".to_string(),
                ));
            }
            out.copy_from_slice(data_part);
        }

        self.cache
            .lock()
            .expect("poisoned")
            .put(chunk_index, out.clone());

        Ok(out)
    }

    fn group_for_chunk(&self, chunk_index: u64) -> Result<(&Ewf1Segment, &Ewf1ChunkGroup, usize)> {
        // Find the last segment whose `first_chunk_index` is <= chunk_index.
        let pos = self
            .segments
            .partition_point(|s| s.first_chunk_index <= chunk_index);
        let seg_idx = pos
            .checked_sub(1)
            .ok_or_else(|| Error::Invalid("chunk index out of range".to_string()))?;
        let segment = &self.segments[seg_idx];

        // Find the last group whose `first_chunk_index` is <= chunk_index.
        let pos = segment
            .chunk_groups
            .partition_point(|g| g.first_chunk_index <= chunk_index);
        let group_idx = pos
            .checked_sub(1)
            .ok_or_else(|| Error::Invalid("chunk index out of range".to_string()))?;
        let group = &segment.chunk_groups[group_idx];

        let local_u64 = chunk_index.saturating_sub(group.first_chunk_index);
        let local = usize::try_from(local_u64)
            .map_err(|_| Error::Invalid("chunk index overflow".to_string()))?;
        if local >= group.chunk_entries.len() {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }

        Ok((segment, group, local))
    }
}

// --- EWF1 parsing (file-backed) ---

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EwfSignature {
    Ewf1Evf,
    Ewf1Lvf,
    Ewf2Evf,
    Ewf2Lef,
    Unknown,
}

#[derive(Debug, Clone, Copy)]
struct Ewf1FileHeader {
    signature: EwfSignature,
    segment_number: u16,
}

impl Ewf1FileHeader {
    fn parse(file: &File) -> Result<Self> {
        let mut buf = [0u8; EWF1_FILE_HEADER_SIZE];
        read_exact_at(file, 0, &mut buf)?;

        let sig: [u8; 8] = buf[0..8].try_into().expect("len=8");
        let signature = if sig == EWF1_EVF_SIGNATURE {
            EwfSignature::Ewf1Evf
        } else if sig == EWF1_LVF_SIGNATURE {
            EwfSignature::Ewf1Lvf
        } else if sig == EWF2_EVF_SIGNATURE {
            EwfSignature::Ewf2Evf
        } else if sig == EWF2_LEF_SIGNATURE {
            EwfSignature::Ewf2Lef
        } else {
            EwfSignature::Unknown
        };

        if matches!(signature, EwfSignature::Unknown) {
            return Ok(Self {
                signature,
                segment_number: 0,
            });
        }

        // Field layout per libewf spec:
        // - byte 8 = 0x01 start of fields
        // - bytes 9..11 = segment number (LE u16)
        // - bytes 11..13 = 0x0000 end of fields
        let segment_number = u16::from_le_bytes(buf[9..11].try_into().expect("len=2"));

        Ok(Self {
            signature,
            segment_number,
        })
    }

    fn sections_start_offset(&self) -> u64 {
        // EWF1 sections start immediately after the fixed-size v1 file header.
        EWF1_FILE_HEADER_SIZE as u64
    }
}

#[derive(Debug, Clone)]
struct Ewf1SectionDescriptor {
    start_offset: u64,
    type_string: String,
    size: u64,
}

impl Ewf1SectionDescriptor {
    fn parse_at(file: &File, file_len: u64, start_offset: u64) -> Result<Self> {
        if start_offset >= file_len {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }

        let mut raw = [0u8; EWF1_SECTION_DESCRIPTOR_SIZE];
        read_exact_at(file, start_offset, &mut raw)?;

        let stored_checksum = u32::from_le_bytes(
            raw[EWF1_SECTION_DESCRIPTOR_SIZE - 4..]
                .try_into()
                .expect("len=4"),
        );
        let calculated_checksum = adler32_rfc1950(&raw[..EWF1_SECTION_DESCRIPTOR_SIZE - 4]);
        if stored_checksum != calculated_checksum {
            return Err(Error::Corrupt(
                "section descriptor checksum mismatch".to_string(),
            ));
        }

        let type_string = parse_ascii_nul_terminated(&raw[0..16]);
        let next_offset = u64::from_le_bytes(raw[16..24].try_into().expect("len=8"));
        let mut size = u64::from_le_bytes(raw[24..32].try_into().expect("len=8"));

        // libewf behavior: some writers leave size = 0, but set next_offset; infer size from that.
        if size == 0 && next_offset != start_offset && next_offset >= start_offset {
            size = next_offset - start_offset;
        }

        Ok(Self {
            start_offset,
            type_string,
            size,
        })
    }

    fn data_range(&self) -> Result<(u64, u64)> {
        let start = self
            .start_offset
            .checked_add(EWF1_SECTION_DESCRIPTOR_SIZE as u64)
            .ok_or_else(|| Error::Invalid("section range overflow".to_string()))?;
        let end = self
            .start_offset
            .checked_add(self.size)
            .ok_or_else(|| Error::Invalid("section range overflow".to_string()))?;
        Ok((start, end))
    }
}

fn parse_ewf1_section_descriptors(
    file: &File,
    file_len: u64,
    first_section_offset: u64,
) -> Result<Vec<Ewf1SectionDescriptor>> {
    let mut sections = Vec::new();
    let mut offset = first_section_offset;

    // Hard safety cap: avoid pathological scans on corrupted inputs.
    for _ in 0..100_000 {
        if offset == 0 || offset >= file_len {
            break;
        }

        let desc = Ewf1SectionDescriptor::parse_at(file, file_len, offset)?;
        let is_last = desc.type_string == "next" || desc.type_string == "done";

        let advance = if desc.size != 0 {
            desc.size
        } else {
            // libewf: for last sections (`next`/`done`) some writers set size=0; advance by descriptor size.
            EWF1_SECTION_DESCRIPTOR_SIZE as u64
        };

        if advance == 0 {
            return Err(Error::Invalid(
                "zero advance while scanning sections".to_string(),
            ));
        }

        sections.push(desc);
        if is_last {
            break;
        }

        offset = offset.saturating_add(advance);
    }

    if sections.is_empty() {
        return Err(Error::Invalid("no EWF sections found".to_string()));
    }

    Ok(sections)
}

#[derive(Debug, Clone, Copy)]
struct VolumeV1 {
    number_of_chunks: u32,
    chunk_size: usize,
    media_size: u64,
}

fn parse_volume_like_section_v1(
    file: &File,
    sections: &[Ewf1SectionDescriptor],
) -> Result<VolumeV1> {
    // Some writers store volume parameters in a `disk` section (not `volume`).
    // For multi-segment EWF1, non-first segments may contain a `data` section that mirrors volume.
    let volume_desc = sections
        .iter()
        .find(|s| s.type_string == "volume" || s.type_string == "disk" || s.type_string == "data")
        .ok_or_else(|| {
            Error::Invalid("missing required section `volume` (or `disk`/`data`)".to_string())
        })?;

    let (start, end) = volume_desc.data_range()?;
    if end <= start {
        return Err(Error::Invalid("invalid volume section range".to_string()));
    }
    let mut buf = [0u8; 24];
    read_exact_at(file, start, &mut buf)?;

    let number_of_chunks = u32::from_le_bytes(buf[4..8].try_into().expect("len=4"));
    let sectors_per_chunk = u32::from_le_bytes(buf[8..12].try_into().expect("len=4"));
    let bytes_per_sector = u32::from_le_bytes(buf[12..16].try_into().expect("len=4"));

    // NOTE: In EWF1 the sector count is 32-bit in older variants and 64-bit in newer ones.
    // Our current NTFS fixtures use the 64-bit encoding.
    let number_of_sectors = u64::from_le_bytes(buf[16..24].try_into().expect("len=8"));

    if number_of_chunks == 0 || sectors_per_chunk == 0 || bytes_per_sector == 0 {
        return Err(Error::Invalid("invalid volume parameters".to_string()));
    }

    let chunk_size = sectors_per_chunk
        .checked_mul(bytes_per_sector)
        .ok_or_else(|| Error::Invalid("chunk size overflow".to_string()))?
        as usize;

    let media_size = number_of_sectors
        .checked_mul(bytes_per_sector as u64)
        .ok_or_else(|| Error::Invalid("media size overflow".to_string()))?;

    Ok(VolumeV1 {
        number_of_chunks,
        chunk_size,
        media_size,
    })
}

#[derive(Debug, Clone)]
struct TableV1 {
    base_offset: u64,
    entries: Vec<u32>,
}

fn parse_table_section_v1(
    file: &File,
    file_len: u64,
    table_desc: &Ewf1SectionDescriptor,
) -> Result<TableV1> {
    let (data_start, data_end) = table_desc.data_range()?;
    if data_end > file_len {
        return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
    }
    let section_data_len = data_end.saturating_sub(data_start);
    if section_data_len < EWF1_TABLE_HEADER_SIZE as u64 {
        return Err(Error::Invalid("table header too small".to_string()));
    }

    let mut header = [0u8; EWF1_TABLE_HEADER_SIZE];
    read_exact_at(file, data_start, &mut header)?;

    let stored_header_checksum = u32::from_le_bytes(
        header[EWF1_TABLE_HEADER_SIZE - 4..]
            .try_into()
            .expect("len=4"),
    );
    let calculated_header_checksum = adler32_rfc1950(&header[..EWF1_TABLE_HEADER_SIZE - 4]);
    if stored_header_checksum != calculated_header_checksum {
        return Err(Error::Corrupt("table header checksum mismatch".to_string()));
    }

    let number_of_entries = u32::from_le_bytes(header[0..4].try_into().expect("len=4"));
    let base_offset = u64::from_le_bytes(header[8..16].try_into().expect("len=8"));

    if number_of_entries == 0 {
        return Err(Error::Invalid("table number_of_entries is 0".to_string()));
    }

    let entries_len = usize::try_from(number_of_entries)
        .map_err(|_| Error::Invalid("table entry count overflow".to_string()))?;
    let entries_bytes = entries_len
        .checked_mul(4)
        .ok_or_else(|| Error::Invalid("entries size overflow".to_string()))?;

    let entries_offset = data_start
        .checked_add(EWF1_TABLE_HEADER_SIZE as u64)
        .ok_or_else(|| Error::Invalid("entries offset overflow".to_string()))?;
    let entries_end = entries_offset
        .checked_add(entries_bytes as u64)
        .ok_or_else(|| Error::Invalid("entries end overflow".to_string()))?;

    if entries_end > data_end {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated table entries").into());
    }

    let mut entries_data = vec![0u8; entries_bytes];
    read_exact_at(file, entries_offset, &mut entries_data)?;

    // Optional entries checksum (footer): immediately follows entries.
    let footer_size_ok = data_end.saturating_sub(entries_end).saturating_sub(0); // keep the computation explicit
    if footer_size_ok >= 4 {
        let mut footer = [0u8; 4];
        read_exact_at(file, entries_end, &mut footer)?;
        let stored_entries_checksum = u32::from_le_bytes(footer);
        let calculated_entries_checksum = adler32_rfc1950(&entries_data);
        if stored_entries_checksum != calculated_entries_checksum {
            return Err(Error::Corrupt(
                "table entries checksum mismatch".to_string(),
            ));
        }
    }

    let mut out = Vec::with_capacity(entries_len);
    for chunk in entries_data.chunks_exact(4) {
        out.push(u32::from_le_bytes(chunk.try_into().expect("len=4")));
    }

    Ok(TableV1 {
        base_offset,
        entries: out,
    })
}

fn parse_chunk_groups_v1(
    file: &File,
    file_len: u64,
    sections: &[Ewf1SectionDescriptor],
    table_type: &str,
    segment_first_chunk_index: u64,
) -> Result<(Vec<Ewf1ChunkGroup>, u64)> {
    let mut chunk_groups: Vec<Ewf1ChunkGroup> = Vec::new();
    let mut chunk_count: u64 = 0;
    let mut pending_sectors_end: Option<u64> = None;

    for desc in sections {
        match desc.type_string.as_str() {
            // Chunk data section. The table that follows describes offsets into this region.
            "sectors" | "sector" => {
                let end = desc.start_offset.saturating_add(desc.size);
                pending_sectors_end = Some(end);
            }
            x if x == table_type => {
                let table = parse_table_section_v1(file, file_len, desc)?;
                if table.entries.is_empty() {
                    return Err(Error::Invalid("table has no entries".to_string()));
                }

                let last_entry = *table.entries.last().expect("non-empty");
                let chunk_data_end = match pending_sectors_end.take() {
                    Some(end) => end,
                    None => compute_chunk_data_end_offset_v1(desc, table.base_offset, last_entry)?,
                };

                if chunk_data_end > file_len {
                    return Err(Error::Invalid("chunk data end out of bounds".to_string()));
                }

                let entries_len_u64 = u64::try_from(table.entries.len())
                    .map_err(|_| Error::Invalid("table entry count overflow".to_string()))?;

                chunk_groups.push(Ewf1ChunkGroup {
                    first_chunk_index: segment_first_chunk_index.saturating_add(chunk_count),
                    chunk_base: table.base_offset,
                    chunk_entries: table.entries,
                    chunk_data_end,
                });

                chunk_count = chunk_count.saturating_add(entries_len_u64);
            }
            _ => {}
        }
    }

    if chunk_groups.is_empty() {
        return Err(Error::Invalid(format!("no `{table_type}` sections found")));
    }

    Ok((chunk_groups, chunk_count))
}

fn chunk_range_v1(group: &Ewf1ChunkGroup, idx: usize) -> Result<(u64, u64, bool)> {
    let current = group
        .chunk_entries
        .get(idx)
        .copied()
        .ok_or_else(|| Error::Invalid("chunk entry index out of range".to_string()))?;
    let next = group.chunk_entries.get(idx + 1).copied();

    let is_compressed = (current >> 31) != 0;
    let current_off = current & 0x7fff_ffff;

    let start = group.chunk_base.saturating_add(current_off as u64);

    let end = if let Some(next) = next {
        let next_off = next & 0x7fff_ffff;

        // libewf: if next_off < current_off, compute size from the *stored* (unmasked) next entry.
        let size = if next_off < current_off {
            if next < current_off {
                return Err(Error::Invalid("table offsets out of order".to_string()));
            }
            (next - current_off) as u64
        } else {
            (next_off - current_off) as u64
        };

        start
            .checked_add(size)
            .ok_or_else(|| Error::Invalid("chunk end overflow".to_string()))?
    } else {
        // There is no indication how large the last chunk is. It is derived from the offset of
        // the next section, following libewf v1 behavior.
        group.chunk_data_end
    };

    if end <= start {
        return Err(Error::Invalid("invalid chunk range".to_string()));
    }

    Ok((start, end, is_compressed))
}

fn compute_chunk_data_end_offset_v1(
    table_desc: &Ewf1SectionDescriptor,
    base_offset: u64,
    last_entry: u32,
) -> Result<u64> {
    let last_chunk_data_offset = base_offset.saturating_add((last_entry & 0x7fff_ffff) as u64);

    let end = if table_desc.type_string == "table2" {
        // libewf: For table2 the chunk data is stored 2 sections before the table2 section.
        table_desc.start_offset.saturating_sub(table_desc.size)
    } else if last_chunk_data_offset < table_desc.start_offset {
        // Chunk data stored before the table section.
        table_desc.start_offset
    } else {
        // Chunk data stored inside the table section.
        table_desc.start_offset.saturating_add(table_desc.size)
    };

    if end <= last_chunk_data_offset {
        return Err(Error::Invalid(
            "last chunk end offset out of bounds".to_string(),
        ));
    }

    Ok(end)
}

// --- Segment discovery (EWF2 naming schema) ---

#[derive(Debug, Clone, Copy)]
struct Ewf2Naming {
    first_character: char,
    additional_characters: char,
    maximum_number_of_segments: u32,
}

impl Ewf2Naming {
    fn from_path(path: &Path, kind: Ewf2Kind) -> Result<Self> {
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or_default();

        let default_first = match kind {
            Ewf2Kind::Ex01 => 'E',
            Ewf2Kind::Lx01 => 'L',
        };

        let first = ext.chars().next().unwrap_or(default_first);
        let additional = if first.is_ascii_uppercase() { 'A' } else { 'a' };

        Ok(Self {
            first_character: first,
            additional_characters: additional,
            maximum_number_of_segments: 2127, // libewf supports up to .EzZZ / .LzZZ
        })
    }

    fn extension_for_segment(&self, segment_number: u32) -> Result<String> {
        if segment_number == 0 || segment_number > self.maximum_number_of_segments {
            return Err(Error::Invalid(format!(
                "segment number {segment_number} out of bounds"
            )));
        }

        let mut out = [0u8; 4];
        out[0] = self.first_character as u8;

        if segment_number <= 99 {
            out[1] = b'x';
            out[3] = b'0' + (segment_number % 10) as u8;
            out[2] = b'0' + (segment_number / 10) as u8;
        } else {
            let mut n = segment_number.saturating_sub(100);
            let hi = n / (26 * 26);
            n %= 26 * 26;

            let second = b'x'.saturating_add(hi as u8);
            if second > b'z' {
                return Err(Error::Unsupported(
                    "more than 2127 segments are not supported".to_string(),
                ));
            }
            out[1] = second;
            out[2] = (self.additional_characters as u8) + ((n / 26) as u8);
            out[3] = (self.additional_characters as u8) + ((n % 26) as u8);
        }

        Ok(String::from_utf8_lossy(&out).to_string())
    }
}

fn discover_segment_paths_ewf2(base_path: &Path, naming: Ewf2Naming) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for seg in 1..=naming.maximum_number_of_segments {
        let ext = naming.extension_for_segment(seg)?;
        let candidate = base_path.with_extension(ext);
        if candidate.exists() {
            out.push(candidate);
        } else {
            break;
        }
    }
    Ok(out)
}

// --- Segment discovery (EWF1 naming schema) ---

#[derive(Debug, Clone, Copy)]
struct EwfxNaming {
    first_character: char,
    additional_characters: char,
    maximum_number_of_segments: u32,
}

impl EwfxNaming {
    fn from_path(path: &Path) -> Result<Self> {
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        let Some(first) = ext.chars().next() else {
            // Default to EnCase E01 naming.
            return Ok(Self {
                first_character: 'E',
                additional_characters: 'A',
                maximum_number_of_segments: 14971,
            });
        };

        // Follow the libewf naming rules:
        // - EWF1 EnCase: `.E01`..`.E99` then `.EAA`..`.ZZZ` (max 14971)
        // - EWF1 SMART:  `.s01`..`.s99` then `.saa`..`.zzz` (max 5507)
        let is_smart = first.eq_ignore_ascii_case(&'s');
        let additional = if first.is_ascii_uppercase() { 'A' } else { 'a' };
        Ok(Self {
            first_character: first,
            additional_characters: additional,
            maximum_number_of_segments: if is_smart { 5507 } else { 14971 },
        })
    }

    fn extension_for_segment(&self, mut segment_number: u32) -> Result<String> {
        if segment_number == 0 || segment_number > self.maximum_number_of_segments {
            return Err(Error::Invalid(format!(
                "segment number {segment_number} out of bounds"
            )));
        }

        let mut out = [0u8; 3];
        out[0] = self.first_character as u8;

        if segment_number <= 99 {
            out[2] = b'0' + (segment_number % 10) as u8;
            out[1] = b'0' + (segment_number / 10) as u8;
        } else {
            segment_number -= 100;

            out[2] = (self.additional_characters as u8) + (segment_number % 26) as u8;
            segment_number /= 26;

            out[1] = (self.additional_characters as u8) + (segment_number % 26) as u8;
            segment_number /= 26;

            // For EWF1 the first extension character increases from E..Z (or s..z).
            if segment_number > 25 {
                return Err(Error::Unsupported(
                    "more than 14971 segments are not supported".to_string(),
                ));
            }
            out[0] = out[0].saturating_add(segment_number as u8);
        }

        Ok(String::from_utf8_lossy(&out).to_string())
    }
}

fn remove_extension(path: &Path) -> PathBuf {
    let mut base = path.to_path_buf();
    base.set_extension("");
    base
}

fn discover_segment_paths(base_path: &Path, naming: EwfxNaming) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for seg in 1..=naming.maximum_number_of_segments {
        let ext = naming.extension_for_segment(seg)?;
        let candidate = base_path.with_extension(ext);
        if candidate.exists() {
            out.push(candidate);
        } else {
            break;
        }
    }
    Ok(out)
}

// --- File IO helpers ---

fn read_exact_at(file: &File, offset: u64, mut buf: &mut [u8]) -> io::Result<()> {
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

fn read_file_range(file: &File, file_len: u64, start: u64, end: u64) -> Result<Vec<u8>> {
    if end > file_len || start >= end {
        return Err(Error::Invalid("file range out of bounds".to_string()));
    }
    let len = usize::try_from(end - start)
        .map_err(|_| Error::Invalid("range length overflow".to_string()))?;
    let mut buf = vec![0u8; len];
    read_exact_at(file, start, &mut buf)?;
    Ok(buf)
}

fn md5_file_range(file: &File, file_len: u64, start: u64, len: u64) -> Result<[u8; 16]> {
    if start >= file_len {
        return Err(Error::Invalid("file range out of bounds".to_string()));
    }
    let end = start
        .checked_add(len)
        .ok_or_else(|| Error::Invalid("range length overflow".to_string()))?;
    if end > file_len {
        return Err(Error::Invalid("file range out of bounds".to_string()));
    }

    let mut h = Md5::new();
    let mut off: u64 = 0;
    let mut buf = vec![0u8; 1024 * 1024];

    while off < len {
        let remaining = (len - off) as usize;
        let take = remaining.min(buf.len());
        let slice = &mut buf[..take];
        read_exact_at(file, start.saturating_add(off), slice)?;
        h.update(slice);
        off = off.saturating_add(take as u64);
    }

    Ok(h.finalize().into())
}

// --- Parsing helpers ---

fn parse_ascii_nul_terminated(bytes: &[u8]) -> String {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).to_string()
}

fn div_ceil_u64(a: u64, b: u64) -> u64 {
    if b == 0 {
        return 0;
    }
    a / b + u64::from(!a.is_multiple_of(b))
}

fn adler32_rfc1950(data: &[u8]) -> u32 {
    // RFC1950 adler32; same as zlib's adler32.
    const MOD_ADLER: u32 = 65521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;

    for &byte in data {
        a = (a + u32::from(byte)) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }

    (b << 16) | a
}

#[derive(Debug)]
struct Ewf1SegmentParsed {
    path: PathBuf,
    file: File,
    file_len: u64,
    segment_number: u16,
    sections: Vec<Ewf1SectionDescriptor>,
}

// === Logical evidence (EWF-L01 / EWF2-Lx01) ===
//
// These formats store *logical* file evidence rather than a block device image. The segment set
// still contains a chunked "media data" stream (addressable by offset), plus a serialized file tree
// (EnCase 7 style) that maps file entries to extents within that stream.

/// A contiguous extent within the logical evidence "media data" stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LefExtent {
    /// Offset (in bytes) relative to the start of the media data stream.
    pub offset: u64,
    /// Extent length (in bytes).
    pub size: u64,
}

/// A logical evidence entry (file or directory).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LefEntry {
    /// Normalized path using `/` separators.
    pub path: String,
    pub is_dir: bool,
    /// Logical file size (0 for directories).
    pub size: u64,
    /// Data extents (empty for directories).
    pub extents: Vec<LefExtent>,
}

#[derive(Debug)]
pub struct LefReader {
    inner: LefInner,
}

#[derive(Debug)]
enum LefInner {
    L01(LefL01),
    Lx01(LefLx01),
}

#[derive(Debug)]
struct LefL01 {
    media: Ewf1Reader,
    entries: Vec<LefEntry>,
}

#[derive(Debug)]
struct LefLx01 {
    media: Ewf2Reader,
    entries: Vec<LefEntry>,
}

impl LefReader {
    /// Opens an EWF logical evidence set (`.L01` / `.Lx01`) and parses its file tree.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let mut file = File::open(path)?;
        let mut sig = [0u8; 8];
        file.read_exact(&mut sig)?;

        if sig == ADCRYPT_SIGNATURE {
            return Err(Error::Unsupported(
                "AccessData AD encryption container (ADCRYPT) is not supported".to_string(),
            ));
        }
        if is_related_adcrypt_set(path)? {
            return Err(Error::Unsupported(
                "AccessData AD encryption container (ADCRYPT) is not supported".to_string(),
            ));
        }

        if sig == EWF1_LVF_SIGNATURE {
            return Ok(Self {
                inner: LefInner::L01(open_l01(path)?),
            });
        }

        if sig == EWF2_LEF_SIGNATURE {
            return Ok(Self {
                inner: LefInner::Lx01(open_lx01(path)?),
            });
        }

        Err(Error::Invalid("unsupported LEF signature".to_string()))
    }

    pub fn entries(&self) -> &[LefEntry] {
        match &self.inner {
            LefInner::L01(r) => &r.entries,
            LefInner::Lx01(r) => &r.entries,
        }
    }

    pub fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        let want = normalize_lef_path(path);
        let entry = self
            .entries()
            .iter()
            .find(|e| e.path == want)
            .ok_or_else(|| Error::Invalid(format!("file not found in LEF: `{path}`")))?;
        self.read_entry(entry)
    }

    pub fn read_entry(&self, entry: &LefEntry) -> Result<Vec<u8>> {
        if entry.is_dir {
            return Err(Error::Invalid("cannot read directory entry".to_string()));
        }
        if entry.size > usize::MAX as u64 {
            return Err(Error::Invalid(
                "file too large for in-memory read".to_string(),
            ));
        }
        if entry.extents.is_empty() && entry.size != 0 {
            return Err(Error::Invalid("file has no data extents".to_string()));
        }

        let mut out = vec![0u8; entry.size as usize];
        let mut written: u64 = 0;

        for ext in &entry.extents {
            if written >= entry.size {
                break;
            }
            let take = (entry.size - written).min(ext.size);
            let start = written as usize;
            let end = start + (take as usize);

            match &self.inner {
                LefInner::L01(r) => r.media.read_exact_at(ext.offset, &mut out[start..end])?,
                LefInner::Lx01(r) => r.media.read_exact_at(ext.offset, &mut out[start..end])?,
            }
            written = written.saturating_add(take);
        }

        if written != entry.size {
            return Err(Error::Invalid(
                "file extents do not cover file size".to_string(),
            ));
        }

        Ok(out)
    }
}

fn is_related_adcrypt_set(path: &Path) -> Result<bool> {
    let base = remove_extension(path);
    let candidates = [
        "E01", "e01", "s01", "S01", "Ex01", "ex01", "L01", "l01", "Lx01", "lx01",
    ];
    for ext in candidates {
        let p = base.with_extension(ext);
        if !p.exists() {
            continue;
        }
        let f = File::open(&p)?;
        let mut sig = [0u8; 8];
        read_exact_at(&f, 0, &mut sig)?;
        if sig == ADCRYPT_SIGNATURE {
            return Ok(true);
        }
        return Ok(false);
    }
    Ok(false)
}

fn normalize_lef_path(path: &str) -> String {
    // EnCase/LEF paths are Windows-centric; normalize to forward slashes.
    let p = path.replace('\\', "/");
    // Avoid leading "./" surprises.
    p.trim_start_matches("./").to_string()
}

fn open_l01(path: &Path) -> Result<LefL01> {
    let naming = EwfxNaming::from_path(path)?;
    let base_path = remove_extension(path);
    let segment_paths = discover_segment_paths(&base_path, naming)?;
    if segment_paths.is_empty() {
        return Err(Error::Invalid(format!(
            "no segment files found for `{}`",
            path.display()
        )));
    }

    // Parse headers and section descriptors.
    let mut parsed: Vec<Ewf1SegmentParsed> = Vec::with_capacity(segment_paths.len());
    let mut any_table2 = false;

    for (i, seg_path) in segment_paths.iter().enumerate() {
        let expected_segment_number: u16 = u16::try_from(i.saturating_add(1)).map_err(|_| {
            Error::Invalid("segment count overflow (too many segments)".to_string())
        })?;

        let file = File::open(seg_path)?;
        let file_len = file.metadata()?.len();

        let hdr = Ewf1FileHeader::parse(&file)?;
        if hdr.signature != EwfSignature::Ewf1Lvf {
            return Err(Error::Invalid(format!(
                "segment `{}` has unexpected signature: {hdr:?}",
                seg_path.display()
            )));
        }
        if hdr.segment_number != expected_segment_number {
            return Err(Error::Invalid(format!(
                "segment `{}` header segment_number mismatch: expected={expected_segment_number} got={}",
                seg_path.display(),
                hdr.segment_number
            )));
        }

        let sections =
            parse_ewf1_section_descriptors(&file, file_len, hdr.sections_start_offset())?;
        any_table2 |= sections.iter().any(|s| s.type_string == "table2");

        parsed.push(Ewf1SegmentParsed {
            path: seg_path.clone(),
            file,
            file_len,
            segment_number: hdr.segment_number,
            sections,
        });
    }

    let table_type = if any_table2 { "table2" } else { "table" };

    let first = parsed
        .first()
        .ok_or_else(|| Error::Invalid("missing first segment".to_string()))?;
    let chunk_size = parse_chunk_geometry_v1_allow_zero_chunks(&first.file, &first.sections)?;

    // ltree lives in (typically) the last segment.
    let last = parsed
        .last()
        .ok_or_else(|| Error::Invalid("missing last segment".to_string()))?;
    let (total_bytes, entries) = parse_ewf1_ltree(&last.file, last.file_len, &last.sections)?;

    let expected_chunk_count = div_ceil_u64(total_bytes, chunk_size as u64);

    // Build chunk mapping for the media data stream.
    let mut segments: Vec<Ewf1Segment> = Vec::with_capacity(parsed.len());
    let mut global_chunk_index: u64 = 0;

    for seg in parsed {
        let (chunk_groups, seg_chunk_count) = parse_chunk_groups_v1(
            &seg.file,
            seg.file_len,
            &seg.sections,
            table_type,
            global_chunk_index,
        )?;

        segments.push(Ewf1Segment {
            path: seg.path,
            file: seg.file,
            file_len: seg.file_len,
            segment_number: seg.segment_number,
            first_chunk_index: global_chunk_index,
            chunk_count: seg_chunk_count,
            chunk_groups,
        });

        global_chunk_index = global_chunk_index.saturating_add(seg_chunk_count);
    }

    if expected_chunk_count > global_chunk_index {
        return Err(Error::Invalid(
            "ltree total bytes exceed available chunk mapping".to_string(),
        ));
    }

    let cache = Mutex::new(LruCache::new(NonZeroUsize::new(8).expect("nonzero")));

    Ok(LefL01 {
        media: Ewf1Reader {
            media_size: total_bytes,
            chunk_size,
            chunk_count: expected_chunk_count,
            segments,
            cache,
        },
        entries,
    })
}

fn open_lx01(path: &Path) -> Result<LefLx01> {
    let mut media = Ewf2Reader::open_lx01(path)?;

    let last = media
        .segments
        .last()
        .ok_or_else(|| Error::Invalid("missing last segment".to_string()))?;

    let section = last
        .sections
        .iter()
        .find(|s| s.section_type == EWF2_SECTION_TYPE_SINGLE_FILES_DATA)
        .ok_or_else(|| {
            Error::Invalid("missing EWF2 single files data section (0x20)".to_string())
        })?;

    let (total_bytes, entries) = parse_lx01_single_files_data_section(last, section)?;

    if total_bytes <= media.media_size {
        media.media_size = total_bytes;
    }

    Ok(LefLx01 { media, entries })
}

fn parse_lx01_single_files_data_section(
    segment: &Ewf2Segment,
    section: &Ewf2Section,
) -> Result<(u64, Vec<LefEntry>)> {
    // IMPORTANT: use `data_len`, not `data_size`.
    //
    // `data_len` is clamped to the actual space between `data_start` and the section descriptor
    // offset. Using `data_size` directly could make us read beyond the section bounds in malformed
    // files (and accidentally ingest bytes from the descriptor or the next section).
    let mut raw_len = section.data_len;
    if (section.padding_size as u64) <= raw_len {
        raw_len = raw_len.saturating_sub(section.padding_size as u64);
    }
    let raw_len: usize = raw_len
        .try_into()
        .map_err(|_| Error::Invalid("single files data length overflow".to_string()))?;

    let bytes = read_file_range(
        &segment.file,
        segment.file_len,
        section.data_start,
        section.data_start.saturating_add(raw_len as u64),
    )?;

    let ltree_text = decode_utf16le_maybe_bom(&bytes)?;
    parse_encase7_tree(&ltree_text)
}

fn parse_chunk_geometry_v1_allow_zero_chunks(
    file: &File,
    sections: &[Ewf1SectionDescriptor],
) -> Result<usize> {
    // In EWF-L01 the `data` section's number_of_chunks is often 0, but sectors_per_chunk and
    // bytes_per_sector still describe the chunk size.
    let candidate = ["data", "disk", "volume"]
        .into_iter()
        .find_map(|name| sections.iter().find(|s| s.type_string == name));

    let sec =
        candidate.ok_or_else(|| Error::Invalid("missing data/disk/volume section".to_string()))?;
    let (start, end) = sec.data_range()?;
    if end.saturating_sub(start) < 24 {
        return Err(Error::Invalid("short data/disk/volume section".to_string()));
    }

    let bytes = read_file_range(file, file.metadata()?.len(), start, start + 24)?;
    let sectors_per_chunk = u32::from_le_bytes(bytes[8..12].try_into().expect("len=4"));
    let bytes_per_sector = u32::from_le_bytes(bytes[12..16].try_into().expect("len=4"));

    if sectors_per_chunk == 0 || bytes_per_sector == 0 {
        return Err(Error::Invalid(
            "invalid chunk geometry in data/disk/volume".to_string(),
        ));
    }

    let chunk_size_u64 = (sectors_per_chunk as u64)
        .checked_mul(bytes_per_sector as u64)
        .ok_or_else(|| Error::Invalid("chunk size overflow".to_string()))?;

    usize::try_from(chunk_size_u64).map_err(|_| Error::Invalid("chunk size overflow".to_string()))
}

fn parse_ewf1_ltree(
    file: &File,
    file_len: u64,
    sections: &[Ewf1SectionDescriptor],
) -> Result<(u64, Vec<LefEntry>)> {
    let ltree = sections
        .iter()
        .find(|s| s.type_string == "ltree")
        .ok_or_else(|| Error::Invalid("missing ltree section".to_string()))?;
    let (start, end) = ltree.data_range()?;
    if end.saturating_sub(start) < 48 {
        return Err(Error::Invalid("short ltree section".to_string()));
    }

    let mut header = [0u8; 48];
    read_exact_at(file, start, &mut header)?;

    let mut stored_md5 = [0u8; 16];
    stored_md5.copy_from_slice(&header[0..16]);
    let data_size = u64::from_le_bytes(header[16..24].try_into().expect("len=8"));
    let stored_checksum = u32::from_le_bytes(header[24..28].try_into().expect("len=4"));

    let mut header_for_checksum = header;
    header_for_checksum[24..28].fill(0);
    let calc_checksum = adler32_rfc1950(&header_for_checksum);
    if stored_checksum != calc_checksum {
        return Err(Error::Corrupt("ltree header checksum mismatch".to_string()));
    }

    let data_start = start.saturating_add(48);
    let data_end = data_start.saturating_add(data_size);
    if data_end > end {
        return Err(Error::Invalid("ltree data out of bounds".to_string()));
    }

    let data = read_file_range(file, file_len, data_start, data_end)?;
    let calc_md5 = {
        let mut h = Md5::new();
        h.update(&data);
        let digest = h.finalize();
        let mut out = [0u8; 16];
        out.copy_from_slice(&digest[..]);
        out
    };
    if calc_md5 != stored_md5 {
        return Err(Error::Corrupt("ltree data MD5 mismatch".to_string()));
    }

    let text = decode_utf16le_no_bom_lossy(&data)?;
    parse_encase7_tree(&text)
}

fn decode_utf16le_no_bom_lossy(bytes: &[u8]) -> Result<String> {
    if !bytes.len().is_multiple_of(2) {
        return Err(Error::Invalid("UTF-16LE byte length is odd".to_string()));
    }
    let mut units: Vec<u16> = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks_exact(2) {
        units.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    Ok(String::from_utf16_lossy(&units))
}

fn decode_utf16le_maybe_bom(bytes: &[u8]) -> Result<String> {
    if bytes.len() >= 2 && (bytes[0..2] == [0xff, 0xfe] || bytes[0..2] == [0xfe, 0xff]) {
        return decode_utf16_with_bom(bytes);
    }
    decode_utf16le_no_bom_lossy(bytes)
}

fn parse_encase7_tree(text: &str) -> Result<(u64, Vec<LefEntry>)> {
    // Parse categories separated by an empty line.
    let mut lines: Vec<&str> = text.split('\n').collect();
    for line in &mut lines {
        *line = line.trim_end_matches('\r');
    }

    if lines.is_empty() {
        return Err(Error::Invalid("empty LEF tree".to_string()));
    }

    // Line 1 is "number of categories" (we don't rely on it).
    let mut i = 1usize;
    let mut categories: HashMap<&str, Vec<&str>> = HashMap::new();

    while i < lines.len() {
        if lines[i].is_empty() {
            i += 1;
            continue;
        }

        let name = lines[i];
        i += 1;
        let mut cat: Vec<&str> = Vec::new();
        cat.push(name);

        while i < lines.len() && !lines[i].is_empty() {
            cat.push(lines[i]);
            i += 1;
        }

        categories.insert(name, cat);

        while i < lines.len() && lines[i].is_empty() {
            i += 1;
        }
    }

    let total_bytes = parse_encase7_total_bytes(categories.get("rec"))?;
    let entries = parse_encase7_entries(categories.get("entry"))?;
    Ok((total_bytes, entries))
}

fn parse_encase7_total_bytes(cat: Option<&Vec<&str>>) -> Result<u64> {
    let cat = cat.ok_or_else(|| Error::Invalid("missing rec category".to_string()))?;
    if cat.len() < 3 {
        return Err(Error::Invalid("short rec category".to_string()));
    }
    let type_inds: Vec<&str> = cat[1].split('\t').collect();
    let values: Vec<&str> = cat[2].split('\t').collect();

    for (idx, ind) in type_inds.iter().enumerate() {
        if *ind == "tb" {
            let v = values.get(idx).copied().unwrap_or_default();
            return v
                .trim()
                .parse::<u64>()
                .map_err(|_| Error::Invalid("invalid rec.tb value".to_string()));
        }
    }

    Err(Error::Invalid("rec category missing tb".to_string()))
}

#[derive(Debug)]
struct EncaseNode {
    values: HashMap<String, String>,
    children: Vec<EncaseNode>,
}

fn parse_encase7_entries(cat: Option<&Vec<&str>>) -> Result<Vec<LefEntry>> {
    let cat = cat.ok_or_else(|| Error::Invalid("missing entry category".to_string()))?;
    if cat.len() < 5 {
        return Err(Error::Invalid("short entry category".to_string()));
    }

    // cat[0] = "entry"
    // cat[1] = "<count>\t<unknown>"
    // cat[2] = type indicators
    let type_inds: Vec<&str> = cat[2].split('\t').collect();

    let mut idx = 3usize;
    let root_children = parse_encase7_count_line(cat[idx])?;
    idx += 1;
    let _root_values = parse_encase7_values_line(&type_inds, cat[idx]);
    idx += 1;

    let mut root = EncaseNode {
        values: HashMap::new(),
        children: Vec::new(),
    };

    for _ in 0..root_children {
        root.children
            .push(parse_encase7_node(cat, &type_inds, &mut idx)?);
    }

    let mut out: Vec<LefEntry> = Vec::new();
    for child in &root.children {
        flatten_encase7_node(child, "", &mut out);
    }
    Ok(out)
}

fn parse_encase7_count_line(line: &str) -> Result<usize> {
    let parts: Vec<&str> = line.split('\t').collect();
    if parts.len() < 2 {
        return Err(Error::Invalid("invalid entry count line".to_string()));
    }
    parts[1]
        .trim()
        .parse::<usize>()
        .map_err(|_| Error::Invalid("invalid entry count line".to_string()))
}

fn parse_encase7_values_line(type_inds: &[&str], line: &str) -> HashMap<String, String> {
    let values: Vec<&str> = line.split('\t').collect();
    let mut out: HashMap<String, String> = HashMap::new();

    for (idx, ind) in type_inds.iter().enumerate() {
        let v = values.get(idx).copied().unwrap_or_default();
        if !ind.is_empty() {
            out.insert((*ind).to_string(), v.to_string());
        }
    }
    out
}

fn parse_encase7_node(cat: &[&str], type_inds: &[&str], idx: &mut usize) -> Result<EncaseNode> {
    if *idx + 1 >= cat.len() {
        return Err(Error::Invalid(
            "unexpected end of entry category".to_string(),
        ));
    }

    let children = parse_encase7_count_line(cat[*idx])?;
    *idx += 1;
    let values = parse_encase7_values_line(type_inds, cat[*idx]);
    *idx += 1;

    let mut node = EncaseNode {
        values,
        children: Vec::new(),
    };

    for _ in 0..children {
        node.children.push(parse_encase7_node(cat, type_inds, idx)?);
    }

    Ok(node)
}

fn flatten_encase7_node(node: &EncaseNode, prefix: &str, out: &mut Vec<LefEntry>) {
    let name = node.values.get("n").map(|s| s.as_str()).unwrap_or_default();

    let is_parent = node.values.get("p").map(|s| s == "1").unwrap_or(false);
    let is_dir = is_parent || !node.children.is_empty();

    let this_prefix = if name.is_empty() {
        prefix.to_string()
    } else if prefix.is_empty() {
        name.to_string()
    } else {
        format!("{prefix}/{name}")
    };

    if is_dir {
        for child in &node.children {
            flatten_encase7_node(child, &this_prefix, out);
        }
        return;
    }

    let size = node
        .values
        .get("ls")
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0);

    let mut extents: Vec<LefExtent> = Vec::new();
    if let Some(be) = node
        .values
        .get("be")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        && let Ok(parsed) = parse_binary_extents(be)
    {
        extents = parsed;
    }

    // Duplicate offset, if present, can be used as a single extent.
    if extents.is_empty()
        && let Some(du) = node
            .values
            .get("du")
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
        && let Ok(off) = du.parse::<u64>()
        && size != 0
    {
        extents.push(LefExtent { offset: off, size });
    }

    out.push(LefEntry {
        path: normalize_lef_path(&this_prefix),
        is_dir: false,
        size,
        extents,
    });
}

fn parse_binary_extents(value: &str) -> Result<Vec<LefExtent>> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() < 3 {
        return Err(Error::Invalid("invalid binary extents value".to_string()));
    }

    // Format: <unknown> <offset_hex> <size_hex> [<offset_hex> <size_hex> ...]
    let mut out: Vec<LefExtent> = Vec::new();
    let mut i = 1usize;
    while i + 1 < parts.len() {
        let off_str = parts[i].trim_start_matches("0x");
        let size_str = parts[i + 1].trim_start_matches("0x");
        let offset = u64::from_str_radix(off_str, 16)
            .map_err(|_| Error::Invalid("invalid extent offset".to_string()))?;
        let size = u64::from_str_radix(size_str, 16)
            .map_err(|_| Error::Invalid("invalid extent size".to_string()))?;
        out.push(LefExtent { offset, size });
        i += 2;
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn make_section_descriptor(
        type_string: &str,
        start_offset: u64,
        size: u64,
    ) -> [u8; EWF1_SECTION_DESCRIPTOR_SIZE] {
        let mut raw = [0u8; EWF1_SECTION_DESCRIPTOR_SIZE];

        // type string (ASCII, NUL-terminated)
        let mut type_bytes = [0u8; 16];
        let src = type_string.as_bytes();
        let copy_len = src.len().min(type_bytes.len().saturating_sub(1));
        type_bytes[..copy_len].copy_from_slice(&src[..copy_len]);
        raw[..16].copy_from_slice(&type_bytes);

        // next_offset (best-effort; not used by our scanner if size != 0)
        let next_offset = start_offset.saturating_add(size);
        raw[16..24].copy_from_slice(&next_offset.to_le_bytes());

        // size
        raw[24..32].copy_from_slice(&size.to_le_bytes());

        let checksum = adler32_rfc1950(&raw[..EWF1_SECTION_DESCRIPTOR_SIZE - 4]);
        raw[EWF1_SECTION_DESCRIPTOR_SIZE - 4..].copy_from_slice(&checksum.to_le_bytes());
        raw
    }

    fn make_table_header(number_of_entries: u32, base_offset: u64) -> [u8; EWF1_TABLE_HEADER_SIZE] {
        let mut hdr = [0u8; EWF1_TABLE_HEADER_SIZE];
        hdr[0..4].copy_from_slice(&number_of_entries.to_le_bytes());
        hdr[8..16].copy_from_slice(&base_offset.to_le_bytes());
        let checksum = adler32_rfc1950(&hdr[..EWF1_TABLE_HEADER_SIZE - 4]);
        hdr[EWF1_TABLE_HEADER_SIZE - 4..].copy_from_slice(&checksum.to_le_bytes());
        hdr
    }

    fn write_ewf1_header(file: &mut Vec<u8>, segment_number: u16) {
        file.extend_from_slice(&EWF1_EVF_SIGNATURE);
        file.push(0x01); // start of fields
        file.extend_from_slice(&segment_number.to_le_bytes());
        file.extend_from_slice(&0u16.to_le_bytes()); // end of fields
        assert_eq!(file.len(), EWF1_FILE_HEADER_SIZE);
    }

    fn write_lvf_header(file: &mut Vec<u8>, segment_number: u16) {
        file.extend_from_slice(&EWF1_LVF_SIGNATURE);
        file.push(0x01); // start of fields
        file.extend_from_slice(&segment_number.to_le_bytes());
        file.extend_from_slice(&0u16.to_le_bytes()); // end of fields
        assert_eq!(file.len(), EWF1_FILE_HEADER_SIZE);
    }

    fn write_ewf2_header(
        file: &mut Vec<u8>,
        segment_number: u32,
        compression_method: u16,
        set_id: [u8; 16],
    ) {
        file.extend_from_slice(&EWF2_EVF_SIGNATURE);
        file.push(2); // major
        file.push(1); // minor
        file.extend_from_slice(&compression_method.to_le_bytes());
        file.extend_from_slice(&segment_number.to_le_bytes());
        file.extend_from_slice(&set_id);
        assert_eq!(file.len(), EWF2_FILE_HEADER_SIZE);
    }

    fn write_lef2_header(
        file: &mut Vec<u8>,
        segment_number: u32,
        compression_method: u16,
        set_id: [u8; 16],
    ) {
        file.extend_from_slice(&EWF2_LEF_SIGNATURE);
        file.push(2); // major
        file.push(1); // minor
        file.extend_from_slice(&compression_method.to_le_bytes());
        file.extend_from_slice(&segment_number.to_le_bytes());
        file.extend_from_slice(&set_id);
        assert_eq!(file.len(), EWF2_FILE_HEADER_SIZE);
    }

    fn encode_utf16le_with_bom(s: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + s.len() * 2);
        out.extend_from_slice(&[0xff, 0xfe]);
        for u in s.encode_utf16() {
            out.extend_from_slice(&u.to_le_bytes());
        }
        out
    }

    fn encode_utf16le_no_bom(s: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(s.len() * 2);
        for u in s.encode_utf16() {
            out.extend_from_slice(&u.to_le_bytes());
        }
        out
    }

    fn zlib_compress(bytes: &[u8]) -> Vec<u8> {
        use flate2::{Compression, write::ZlibEncoder};
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(bytes).unwrap();
        enc.finish().unwrap()
    }

    fn pad16(data: &mut Vec<u8>) -> u32 {
        let pad = (16 - (data.len() % 16)) % 16;
        data.extend(std::iter::repeat_n(0u8, pad));
        pad as u32
    }

    fn make_ewf2_section_descriptor(
        section_type: u32,
        data_flags: u32,
        previous_offset: u64,
        data_size: u64,
        padding_size: u32,
    ) -> [u8; EWF2_SECTION_DESCRIPTOR_SIZE] {
        let mut raw = [0u8; EWF2_SECTION_DESCRIPTOR_SIZE];
        raw[0..4].copy_from_slice(&section_type.to_le_bytes());
        raw[4..8].copy_from_slice(&data_flags.to_le_bytes());
        raw[8..16].copy_from_slice(&previous_offset.to_le_bytes());
        raw[16..24].copy_from_slice(&data_size.to_le_bytes());
        raw[24..28].copy_from_slice(&(EWF2_SECTION_DESCRIPTOR_SIZE as u32).to_le_bytes());
        raw[28..32].copy_from_slice(&padding_size.to_le_bytes());
        // data_integrity_hash (16) + padding (12) left as zeros
        let checksum = adler32_rfc1950(&raw[..EWF2_SECTION_DESCRIPTOR_SIZE - 4]);
        raw[EWF2_SECTION_DESCRIPTOR_SIZE - 4..].copy_from_slice(&checksum.to_le_bytes());
        raw
    }

    fn append_ewf2_section_with_flags(
        file: &mut Vec<u8>,
        section_type: u32,
        data_flags: u32,
        previous_offset: u64,
        data: Vec<u8>,
        padding_size_field: u32,
    ) -> u64 {
        file.extend_from_slice(&data);
        let desc_off = file.len() as u64;
        let desc = make_ewf2_section_descriptor(
            section_type,
            data_flags,
            previous_offset,
            data.len() as u64,
            padding_size_field,
        );
        file.extend_from_slice(&desc);
        desc_off
    }

    fn ewf2_main_object(pairs: &[(&str, u64)]) -> String {
        let mut tags = String::new();
        let mut values = String::new();

        for (i, (tag, value)) in pairs.iter().enumerate() {
            if i != 0 {
                tags.push('\t');
                values.push('\t');
            }
            tags.push_str(tag);
            values.push_str(&value.to_string());
        }

        format!("1\nmain\n{tags}\n{values}")
    }

    #[derive(Debug, Clone, Copy)]
    struct Ewf2SectorTableEntrySpec {
        offset: u64,
        size: u32,
        flags: u32,
    }

    fn build_ewf2_sector_table(first_chunk: u64, entries: &[Ewf2SectorTableEntrySpec]) -> Vec<u8> {
        let number_of_entries: u32 = entries.len().try_into().expect("entries fit u32");

        let mut table = Vec::new();

        // Header (16 bytes + checksum + 12 bytes alignment padding) = 32 bytes total.
        table.extend_from_slice(&first_chunk.to_le_bytes());
        table.extend_from_slice(&number_of_entries.to_le_bytes());
        table.extend_from_slice(&0u32.to_le_bytes()); // unknown/padding
        let header_checksum = adler32_rfc1950(&table[..16]);
        table.extend_from_slice(&header_checksum.to_le_bytes());
        table.extend(std::iter::repeat_n(0u8, 12));

        // Entries.
        let mut entries_bytes =
            Vec::with_capacity(entries.len().saturating_mul(EWF2_TABLE_ENTRY_SIZE));
        for e in entries {
            entries_bytes.extend_from_slice(&e.offset.to_le_bytes());
            entries_bytes.extend_from_slice(&e.size.to_le_bytes());
            entries_bytes.extend_from_slice(&e.flags.to_le_bytes());
        }
        table.extend_from_slice(&entries_bytes);

        // Footer: checksum of the entries + 12 bytes alignment padding.
        let footer_checksum = adler32_rfc1950(&entries_bytes);
        table.extend_from_slice(&footer_checksum.to_le_bytes());
        table.extend(std::iter::repeat_n(0u8, 12));

        table
    }

    #[derive(Debug, Clone, Copy)]
    struct Ewf2WrittenSection {
        desc_off: u64,
        unpadded_len: u64,
        pad: u32,
    }

    /// Small builder for EWF2 segment fixtures in tests.
    ///
    /// The goal is **legible** tests that read like the on-disk layout:
    /// header → device information → case data → sector data → sector table → ... → done.
    #[derive(Debug)]
    struct Ewf2TestFile {
        bytes: Vec<u8>,
        prev_desc_off: u64,
    }

    impl Ewf2TestFile {
        fn new_ex01(set_id: [u8; 16]) -> Self {
            let mut bytes = Vec::new();
            write_ewf2_header(&mut bytes, 1, EWF2_COMPRESSION_LZ, set_id);
            Self {
                bytes,
                prev_desc_off: 0,
            }
        }

        fn new_lx01(set_id: [u8; 16]) -> Self {
            let mut bytes = Vec::new();
            write_lef2_header(&mut bytes, 1, EWF2_COMPRESSION_LZ, set_id);
            Self {
                bytes,
                prev_desc_off: 0,
            }
        }

        fn push_section_with_flags(
            &mut self,
            section_type: u32,
            data_flags: u32,
            data: Vec<u8>,
            padding_size_field: u32,
        ) -> u64 {
            let desc_off = append_ewf2_section_with_flags(
                &mut self.bytes,
                section_type,
                data_flags,
                self.prev_desc_off,
                data,
                padding_size_field,
            );
            self.prev_desc_off = desc_off;
            desc_off
        }

        fn push_section(
            &mut self,
            section_type: u32,
            data: Vec<u8>,
            padding_size_field: u32,
        ) -> u64 {
            self.push_section_with_flags(section_type, 0, data, padding_size_field)
        }

        fn push_compressed_main_object(
            &mut self,
            section_type: u32,
            data_flags: u32,
            pairs: &[(&str, u64)],
        ) -> u64 {
            let s = ewf2_main_object(pairs);
            let utf16 = encode_utf16le_with_bom(&s);
            let mut data = zlib_compress(&utf16);
            let pad = pad16(&mut data);
            self.push_section_with_flags(section_type, data_flags, data, pad)
        }

        fn device_information(&mut self, bytes_per_sector: u32, number_of_sectors: u64) -> u64 {
            let pairs = [
                ("bp", u64::from(bytes_per_sector)),
                ("ts", number_of_sectors),
            ];
            self.push_compressed_main_object(EWF2_SECTION_TYPE_DEVICE_INFORMATION, 0, &pairs)
        }

        fn device_information_with_flags(
            &mut self,
            bytes_per_sector: u32,
            number_of_sectors: u64,
            data_flags: u32,
        ) -> u64 {
            let pairs = [
                ("bp", u64::from(bytes_per_sector)),
                ("ts", number_of_sectors),
            ];
            self.push_compressed_main_object(
                EWF2_SECTION_TYPE_DEVICE_INFORMATION,
                data_flags,
                &pairs,
            )
        }

        fn case_data(&mut self, sectors_per_chunk: u32, chunk_count: u64) -> u64 {
            let pairs = [("sb", u64::from(sectors_per_chunk)), ("tb", chunk_count)];
            self.push_compressed_main_object(EWF2_SECTION_TYPE_CASE_DATA, 0, &pairs)
        }

        fn sector_data_uncompressed_chunk(&mut self, chunk: &[u8]) -> (u64, u32) {
            // Capture the file offset where the chunk bytes will begin.
            let chunk_offset = self.bytes.len() as u64;

            assert!(
                chunk.len() <= (u32::MAX as usize).saturating_sub(4),
                "chunk too large for test fixture"
            );

            let mut sector_data = Vec::new();
            sector_data.extend_from_slice(chunk);
            let checksum = adler32_rfc1950(chunk);
            sector_data.extend_from_slice(&checksum.to_le_bytes());

            let chunk_data_size = sector_data.len() as u32;
            let pad = pad16(&mut sector_data);

            self.push_section(EWF2_SECTION_TYPE_SECTOR_DATA, sector_data, pad);
            (chunk_offset, chunk_data_size)
        }

        fn sector_table(&mut self, first_chunk: u64, entries: &[Ewf2SectorTableEntrySpec]) -> u64 {
            let table = build_ewf2_sector_table(first_chunk, entries);
            // libewf uses padding_size=24 for sector tables (12 after header + 12 after footer).
            self.push_section(EWF2_SECTION_TYPE_SECTOR_TABLE, table, 24)
        }

        fn utf16le_no_bom_section(&mut self, section_type: u32, text: &str) -> Ewf2WrittenSection {
            let mut data = encode_utf16le_no_bom(text);
            let unpadded_len = data.len() as u64;
            let pad = pad16(&mut data);
            let desc_off = self.push_section(section_type, data, pad);
            Ewf2WrittenSection {
                desc_off,
                unpadded_len,
                pad,
            }
        }

        fn single_files_data(&mut self, ltree_text: &str) -> Ewf2WrittenSection {
            self.utf16le_no_bom_section(EWF2_SECTION_TYPE_SINGLE_FILES_DATA, ltree_text)
        }

        fn done(&mut self) -> u64 {
            self.push_section(EWF2_SECTION_TYPE_DONE, Vec::new(), 0)
        }

        fn patch_descriptor_data_size(&mut self, desc_off: u64, data_size: u64) -> Result<()> {
            let desc_start: usize = desc_off
                .try_into()
                .map_err(|_| Error::Invalid("descriptor offset overflow".to_string()))?;
            let desc_end = desc_start
                .checked_add(EWF2_SECTION_DESCRIPTOR_SIZE)
                .ok_or_else(|| Error::Invalid("descriptor offset overflow".to_string()))?;

            self.bytes[desc_start + 16..desc_start + 24].copy_from_slice(&data_size.to_le_bytes());
            let checksum = adler32_rfc1950(&self.bytes[desc_start..desc_end - 4]);
            self.bytes[desc_end - 4..desc_end].copy_from_slice(&checksum.to_le_bytes());
            Ok(())
        }

        fn into_bytes(self) -> Vec<u8> {
            self.bytes
        }
    }

    /// Minimal EnCase 7 `rec` + `entry` tree describing a single file `hello.txt` (5 bytes) at
    /// extent `(chunk=1, offset=0, size=5)`.
    const ENCASE7_TREE_SINGLE_HELLO_TXT: &str = "2\nrec\ntb\n5\n\nentry\n1\t1\np\tn\tls\tbe\n0\t1\n1\t\t0\t\n0\t0\n\thello.txt\t5\t1 0 5\n\n";

    fn hello_chunk_512() -> Vec<u8> {
        let mut chunk = vec![0u8; 512];
        chunk[..5].copy_from_slice(b"hello");
        chunk
    }

    #[test]
    fn test_open_disk_section_and_multi_table2_groups_single_segment() -> Result<()> {
        // Minimal EWF v1 EVF file with:
        // - `disk` section (instead of `volume`)
        // - two `sectors` + `table2` groups (each group contains one chunk)
        // - `done` terminator
        //
        // Each chunk is zlib-compressed and should decompress to 512 bytes.
        let chunk_size = 512usize;
        let chunk0 = vec![b'A'; chunk_size];
        let chunk1 = vec![b'B'; chunk_size];
        let chunk0_z = {
            use flate2::{Compression, write::ZlibEncoder};
            let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
            enc.write_all(&chunk0).unwrap();
            enc.finish().unwrap()
        };
        let chunk1_z = {
            use flate2::{Compression, write::ZlibEncoder};
            let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
            enc.write_all(&chunk1).unwrap();
            enc.finish().unwrap()
        };

        let mut file: Vec<u8> = Vec::new();
        write_ewf1_header(&mut file, 1);

        // Helper to append a section: descriptor + body, returning its start_offset.
        let mut append_section = |typ: &str, body: &[u8]| -> u64 {
            let start_offset = file.len() as u64;
            let size = (EWF1_SECTION_DESCRIPTOR_SIZE + body.len()) as u64;
            let desc = make_section_descriptor(typ, start_offset, size);
            file.extend_from_slice(&desc);
            file.extend_from_slice(body);
            start_offset
        };

        // disk section body: layout matches parse_volume_like_section_v1 (fields starting at offset 4).
        let mut disk_body = vec![0u8; 24];
        disk_body[0..4].copy_from_slice(&1u32.to_le_bytes()); // version/unknown
        disk_body[4..8].copy_from_slice(&2u32.to_le_bytes()); // number_of_chunks
        disk_body[8..12].copy_from_slice(&1u32.to_le_bytes()); // sectors_per_chunk
        disk_body[12..16].copy_from_slice(&512u32.to_le_bytes()); // bytes_per_sector
        disk_body[16..24].copy_from_slice(&2u64.to_le_bytes()); // number_of_sectors
        append_section("disk", &disk_body);

        // group 0: sectors (chunk0_z) + table2 (1 entry)
        let sectors0_start = append_section("sectors", &chunk0_z);
        let chunk0_file_off = (sectors0_start + EWF1_SECTION_DESCRIPTOR_SIZE as u64) as u32;

        let mut table2_0_body: Vec<u8> = Vec::new();
        table2_0_body.extend_from_slice(&make_table_header(1, 0));
        table2_0_body.extend_from_slice(&(chunk0_file_off | 0x8000_0000).to_le_bytes());
        append_section("table2", &table2_0_body);

        // group 1: sectors (chunk1_z) + table2 (1 entry)
        let sectors1_start = append_section("sectors", &chunk1_z);
        let chunk1_file_off = (sectors1_start + EWF1_SECTION_DESCRIPTOR_SIZE as u64) as u32;

        let mut table2_1_body: Vec<u8> = Vec::new();
        table2_1_body.extend_from_slice(&make_table_header(1, 0));
        table2_1_body.extend_from_slice(&(chunk1_file_off | 0x8000_0000).to_le_bytes());
        append_section("table2", &table2_1_body);

        append_section("done", &[]);

        // Write to a temp file so we exercise the real open path.
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("test.E01");
        std::fs::write(&path, &file)?;

        let img = EwfReader::open(&path)?;
        assert_eq!(img.len(), 1024);
        assert_eq!(img.chunk_size(), 512);
        assert_eq!(img.chunk_count(), 2);

        let mut buf = vec![0u8; 1024];
        img.read_exact_at(0, &mut buf)?;
        assert_eq!(&buf[..512], &chunk0[..]);
        assert_eq!(&buf[512..], &chunk1[..]);

        // Cross-chunk read.
        let mut mid = vec![0u8; 40];
        img.read_exact_at(500, &mut mid)?;
        assert_eq!(&mid[..12], &vec![b'A'; 12]);
        assert_eq!(&mid[12..], &vec![b'B'; 28]);

        Ok(())
    }

    #[test]
    fn test_ewf2_minimal_ex01_single_chunk_uncompressed() -> Result<()> {
        // Minimal EWF2 Ex01 file with:
        // - device information (compressed UTF-16 string)
        // - case data (compressed UTF-16 string)
        // - sector data (1 uncompressed chunk + Adler32, padded to 16-byte alignment)
        // - sector table (1 entry pointing at the chunk)
        // - done terminator
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("out.Ex01");

        let set_id = [0x11u8; 16];
        let chunk = vec![b'Z'; 512];

        let mut f = Ewf2TestFile::new_ex01(set_id);
        f.device_information(512, 1);
        f.case_data(1, 1);
        let (chunk_data_offset, chunk_data_size) = f.sector_data_uncompressed_chunk(&chunk);
        f.sector_table(
            0,
            &[Ewf2SectorTableEntrySpec {
                offset: chunk_data_offset,
                size: chunk_data_size,
                flags: EWF2_CHUNK_DATA_FLAG_CHECKSUMED,
            }],
        );
        f.done();

        std::fs::write(&path, &f.into_bytes())?;

        let img = EwfReader::open(&path)?;
        assert_eq!(img.len(), 512);

        let mut buf = vec![0u8; 512];
        img.read_exact_at(0, &mut buf)?;
        assert_eq!(buf, chunk);

        Ok(())
    }

    #[test]
    fn test_ewf2_ex01_rejects_zero_sectors_per_chunk() -> Result<()> {
        // Regression test: EWF2 parsing must reject sb=0 (sectors per chunk).
        //
        // Prior to the fix, this could yield `chunk_size == 0`, allowing open() to succeed and
        // causing a division-by-zero panic later in read_exact_at().
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("bad.Ex01");

        let set_id = [0x33u8; 16];
        let chunk = vec![b'Z'; 512];

        let mut f = Ewf2TestFile::new_ex01(set_id);
        f.device_information(512, 1);
        f.case_data(0, 0);
        let _ = f.sector_data_uncompressed_chunk(&chunk);
        f.sector_table(0, &[]);
        f.done();

        std::fs::write(&path, &f.into_bytes())?;

        let err = EwfReader::open(&path).unwrap_err();
        assert!(matches!(err, Error::Invalid(_)));
        Ok(())
    }

    #[test]
    fn test_ewf2_ex01_rejects_zero_bytes_per_sector() -> Result<()> {
        // Regression test: EWF2 parsing must reject bp=0 (bytes per sector).
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("bad-bp0.Ex01");

        let set_id = [0x34u8; 16];
        let chunk = vec![b'Z'; 512];

        let mut f = Ewf2TestFile::new_ex01(set_id);
        f.device_information(0, 1);
        f.case_data(1, 0);
        let _ = f.sector_data_uncompressed_chunk(&chunk);
        f.sector_table(0, &[]);
        f.done();

        std::fs::write(&path, &f.into_bytes())?;

        let err = EwfReader::open(&path).unwrap_err();
        assert!(matches!(err, Error::Invalid(_)));
        Ok(())
    }

    #[test]
    fn test_ewf2_encrypted_section_is_rejected() -> Result<()> {
        // EWF2 supports encrypted sections, but libewf currently rejects them; we mirror that.
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("out.Ex01");

        let set_id = [0x22u8; 16];
        let chunk = vec![b'Z'; 512];

        let mut f = Ewf2TestFile::new_ex01(set_id);
        f.device_information_with_flags(512, 1, EWF2_SECTION_DATA_FLAG_ENCRYPTED);
        f.case_data(1, 1);
        let (chunk_data_offset, chunk_data_size) = f.sector_data_uncompressed_chunk(&chunk);
        f.sector_table(
            0,
            &[Ewf2SectorTableEntrySpec {
                offset: chunk_data_offset,
                size: chunk_data_size,
                flags: EWF2_CHUNK_DATA_FLAG_CHECKSUMED,
            }],
        );
        f.done();

        std::fs::write(&path, &f.into_bytes())?;

        let err = EwfReader::open(&path).unwrap_err();
        match err {
            Error::Unsupported(_) => Ok(()),
            other => Err(Error::Invalid(format!(
                "expected Unsupported for encrypted EWF2 section, got: {other:?}"
            ))),
        }
    }

    #[test]
    fn test_adcrypt_container_is_rejected() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("enc.E01");
        std::fs::write(&path, ADCRYPT_SIGNATURE)?;
        let err = EwfReader::open(&path).unwrap_err();
        match err {
            Error::Unsupported(_) => Ok(()),
            other => Err(Error::Invalid(format!(
                "expected Unsupported for ADCRYPT, got: {other:?}"
            ))),
        }
    }

    #[test]
    fn test_adcrypt_container_is_rejected_when_opening_non_first_segment() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let base = dir.path().join("case");
        let p1 = base.with_extension("E01");
        let p2 = base.with_extension("E02");

        std::fs::write(&p1, ADCRYPT_SIGNATURE)?;
        std::fs::write(&p2, [0u8; 8])?;

        let err = EwfReader::open(&p2).unwrap_err();
        match err {
            Error::Unsupported(_) => Ok(()),
            other => Err(Error::Invalid(format!(
                "expected Unsupported for ADCRYPT when opening .E02, got: {other:?}"
            ))),
        }
    }

    #[test]
    fn test_multi_segment_discovery_and_read() -> Result<()> {
        // Two-segment EWF1 set:
        // - segment 1 has 1 chunk and ends with `next`
        // - segment 2 has 1 chunk and ends with `done`
        // Verify that discovery reads both `.E01` and `.E02` and that the logical address space is
        // contiguous across segments.

        let chunk_size = 512usize;
        let chunk0 = vec![b'A'; chunk_size];
        let chunk1 = vec![b'B'; chunk_size];
        let chunk0_z = {
            use flate2::{Compression, write::ZlibEncoder};
            let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
            enc.write_all(&chunk0).unwrap();
            enc.finish().unwrap()
        };
        let chunk1_z = {
            use flate2::{Compression, write::ZlibEncoder};
            let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
            enc.write_all(&chunk1).unwrap();
            enc.finish().unwrap()
        };

        let dir = tempfile::tempdir()?;
        let base = dir.path().join("case");

        // --- segment 1 (.E01) ---
        let mut seg1: Vec<u8> = Vec::new();
        write_ewf1_header(&mut seg1, 1);
        let mut append1 = |typ: &str, body: &[u8]| -> u64 {
            let start_offset = seg1.len() as u64;
            let size = (EWF1_SECTION_DESCRIPTOR_SIZE + body.len()) as u64;
            let desc = make_section_descriptor(typ, start_offset, size);
            seg1.extend_from_slice(&desc);
            seg1.extend_from_slice(body);
            start_offset
        };

        // disk section describes the full 2-chunk media.
        let mut disk_body = vec![0u8; 24];
        disk_body[0..4].copy_from_slice(&1u32.to_le_bytes());
        disk_body[4..8].copy_from_slice(&2u32.to_le_bytes()); // chunk_count across all segments
        disk_body[8..12].copy_from_slice(&1u32.to_le_bytes());
        disk_body[12..16].copy_from_slice(&512u32.to_le_bytes());
        disk_body[16..24].copy_from_slice(&2u64.to_le_bytes()); // sector_count across all segments
        append1("disk", &disk_body);

        let sectors1_start = append1("sectors", &chunk0_z);
        let chunk0_file_off = (sectors1_start + EWF1_SECTION_DESCRIPTOR_SIZE as u64) as u32;

        let mut table2_body = Vec::new();
        table2_body.extend_from_slice(&make_table_header(1, 0));
        table2_body.extend_from_slice(&(chunk0_file_off | 0x8000_0000).to_le_bytes());
        append1("table2", &table2_body);

        append1("next", &[]);

        // --- segment 2 (.E02) ---
        let mut seg2: Vec<u8> = Vec::new();
        write_ewf1_header(&mut seg2, 2);
        let mut append2 = |typ: &str, body: &[u8]| -> u64 {
            let start_offset = seg2.len() as u64;
            let size = (EWF1_SECTION_DESCRIPTOR_SIZE + body.len()) as u64;
            let desc = make_section_descriptor(typ, start_offset, size);
            seg2.extend_from_slice(&desc);
            seg2.extend_from_slice(body);
            start_offset
        };

        let sectors2_start = append2("sectors", &chunk1_z);
        let chunk1_file_off = (sectors2_start + EWF1_SECTION_DESCRIPTOR_SIZE as u64) as u32;

        let mut table2_body2 = Vec::new();
        table2_body2.extend_from_slice(&make_table_header(1, 0));
        table2_body2.extend_from_slice(&(chunk1_file_off | 0x8000_0000).to_le_bytes());
        append2("table2", &table2_body2);

        append2("done", &[]);

        let p1 = base.with_extension("E01");
        let p2 = base.with_extension("E02");
        std::fs::write(&p1, &seg1)?;
        std::fs::write(&p2, &seg2)?;

        let img = EwfReader::open(&p2)?; // open from non-first segment should still discover the set
        assert_eq!(img.len(), 1024);

        let mut buf = vec![0u8; 1024];
        img.read_exact_at(0, &mut buf)?;
        assert_eq!(&buf[..512], &chunk0[..]);
        assert_eq!(&buf[512..], &chunk1[..]);

        Ok(())
    }

    #[test]
    fn test_lef_l01_single_file_read() -> Result<()> {
        let chunk = hello_chunk_512();

        let mut file: Vec<u8> = Vec::new();
        write_lvf_header(&mut file, 1);

        let mut append_section = |typ: &str, body: &[u8]| -> u64 {
            let start_offset = file.len() as u64;
            let size = (EWF1_SECTION_DESCRIPTOR_SIZE + body.len()) as u64;
            let desc = make_section_descriptor(typ, start_offset, size);
            file.extend_from_slice(&desc);
            file.extend_from_slice(body);
            start_offset
        };

        // data section: number_of_chunks is 0 for L01, but chunk geometry is still present.
        let mut data_body = vec![0u8; 24];
        data_body[0..4].copy_from_slice(&1u32.to_le_bytes()); // version/unknown
        data_body[4..8].copy_from_slice(&0u32.to_le_bytes()); // number_of_chunks (often 0)
        data_body[8..12].copy_from_slice(&1u32.to_le_bytes()); // sectors_per_chunk
        data_body[12..16].copy_from_slice(&512u32.to_le_bytes()); // bytes_per_sector
        data_body[16..24].copy_from_slice(&1u64.to_le_bytes()); // number_of_sectors
        append_section("data", &data_body);

        // sectors: uncompressed chunk + Adler32 of chunk bytes
        let mut sectors_body = Vec::new();
        sectors_body.extend_from_slice(&chunk);
        let checksum = adler32_rfc1950(&chunk);
        sectors_body.extend_from_slice(&checksum.to_le_bytes());
        let sectors_start = append_section("sectors", &sectors_body);
        let chunk_file_off = (sectors_start + EWF1_SECTION_DESCRIPTOR_SIZE as u64) as u32;

        // table2: one entry, base_offset=0, no compression flag.
        let mut table2_body: Vec<u8> = Vec::new();
        table2_body.extend_from_slice(&make_table_header(1, 0));
        table2_body.extend_from_slice(&chunk_file_off.to_le_bytes());
        append_section("table2", &table2_body);

        // ltree: EnCase 7 style serialized tree (UTF-16LE without BOM).
        let ltree_text = ENCASE7_TREE_SINGLE_HELLO_TXT;
        let ltree_data = encode_utf16le_no_bom(ltree_text);

        let mut ltree_hdr = [0u8; 48];
        let md5 = {
            let mut h = Md5::new();
            h.update(&ltree_data);
            let d = h.finalize();
            let mut out = [0u8; 16];
            out.copy_from_slice(&d[..]);
            out
        };
        ltree_hdr[0..16].copy_from_slice(&md5);
        ltree_hdr[16..24].copy_from_slice(&(ltree_data.len() as u64).to_le_bytes());
        // checksum at 24..28 filled later
        let mut hdr_for_checksum = ltree_hdr;
        hdr_for_checksum[24..28].fill(0);
        let hdr_checksum = adler32_rfc1950(&hdr_for_checksum);
        ltree_hdr[24..28].copy_from_slice(&hdr_checksum.to_le_bytes());

        let mut ltree_body = Vec::new();
        ltree_body.extend_from_slice(&ltree_hdr);
        ltree_body.extend_from_slice(&ltree_data);
        append_section("ltree", &ltree_body);

        append_section("done", &[]);

        let dir = tempfile::tempdir()?;
        let path = dir.path().join("case.L01");
        std::fs::write(&path, &file)?;

        let lef = LefReader::open(&path)?;
        let data = lef.read_file("hello.txt")?;
        assert_eq!(data, b"hello");
        Ok(())
    }

    #[test]
    fn test_lef_lx01_single_file_read() -> Result<()> {
        let chunk = hello_chunk_512();

        let dir = tempfile::tempdir()?;
        let path = dir.path().join("case.Lx01");

        let set_id = [9u8; 16];
        let mut f = Ewf2TestFile::new_lx01(set_id);
        f.device_information(512, 1);
        f.case_data(1, 1);
        let (chunk_data_offset, chunk_data_size) = f.sector_data_uncompressed_chunk(&chunk);
        f.sector_table(
            0,
            &[Ewf2SectorTableEntrySpec {
                offset: chunk_data_offset,
                size: chunk_data_size,
                flags: EWF2_CHUNK_DATA_FLAG_CHECKSUMED,
            }],
        );
        let _ = f.single_files_data(ENCASE7_TREE_SINGLE_HELLO_TXT);
        f.done();

        std::fs::write(&path, &f.into_bytes())?;

        let lef = LefReader::open(&path)?;
        let data = lef.read_file("hello.txt")?;
        assert_eq!(data, b"hello");
        Ok(())
    }

    #[test]
    fn test_lef_lx01_single_files_data_read_is_clamped_to_section_bounds() -> Result<()> {
        let chunk = hello_chunk_512();

        let dir = tempfile::tempdir()?;
        let path = dir.path().join("case-malformed-size.Lx01");

        let set_id = [0x55u8; 16];
        let mut f = Ewf2TestFile::new_lx01(set_id);
        f.device_information(512, 1);
        f.case_data(1, 1);

        let (chunk_data_offset, chunk_data_size) = f.sector_data_uncompressed_chunk(&chunk);
        f.sector_table(
            0,
            &[Ewf2SectorTableEntrySpec {
                offset: chunk_data_offset,
                size: chunk_data_size,
                flags: EWF2_CHUNK_DATA_FLAG_CHECKSUMED,
            }],
        );

        // Single files data (0x20): EnCase 7 style tree (UTF-16LE without BOM).
        let single = f.single_files_data(ENCASE7_TREE_SINGLE_HELLO_TXT);

        // Add a "poison" section whose bytes look like a new (invalid) `rec` category. If we
        // over-read beyond the single-files section bounds, parsing will fail.
        let poison_text = "\n\nrec\nx\n";
        let poison = f.utf16le_no_bom_section(0xdead_beefu32, poison_text);

        // Corrupt the single-files section descriptor's `data_size` to claim the section extends
        // past its descriptor and into the following section.
        //
        // `open_lx01` must clamp reads using `data_len` (which is bounded by the descriptor offset),
        // otherwise it can read bytes from the descriptor/next section.
        // Inflate `data_size` enough that a buggy `data_size - padding_size` read would include:
        // - the section's own padding bytes,
        // - the section descriptor,
        // - and the full poison payload.
        //
        // We add `pad` twice so the buggy read length includes the original padding (otherwise it
        // might only read a prefix of `poison`, which makes the regression less deterministic).
        let inflated_data_size = single
            .unpadded_len
            .saturating_add(u64::from(single.pad).saturating_mul(2))
            .saturating_add(EWF2_SECTION_DESCRIPTOR_SIZE as u64)
            .saturating_add(poison.unpadded_len);
        f.patch_descriptor_data_size(single.desc_off, inflated_data_size)?;

        f.done();
        std::fs::write(&path, &f.into_bytes())?;

        let lef = LefReader::open(&path)?;
        let data = lef.read_file("hello.txt")?;
        assert_eq!(data, b"hello");
        Ok(())
    }

    #[test]
    fn test_lef_lx01_rejects_zero_sectors_per_chunk() -> Result<()> {
        // Regression test: EWF2-Lx01 parsing must reject sb=0 (sectors per chunk).
        //
        // Prior to the fix, this could yield `chunk_size == 0`, allowing `LefReader::open()` to
        // succeed and causing a division-by-zero panic later when reading file contents.
        let chunk = hello_chunk_512();

        let dir = tempfile::tempdir()?;
        let path = dir.path().join("bad.Lx01");

        let set_id = [0x44u8; 16];
        let mut f = Ewf2TestFile::new_lx01(set_id);
        f.device_information(512, 1);
        f.case_data(0, 0);
        let _ = f.sector_data_uncompressed_chunk(&chunk);
        f.sector_table(0, &[]);
        let _ = f.single_files_data(ENCASE7_TREE_SINGLE_HELLO_TXT);
        f.done();
        std::fs::write(&path, &f.into_bytes())?;

        let err = LefReader::open(&path).unwrap_err();
        assert!(matches!(err, Error::Invalid(_)));
        Ok(())
    }

    #[test]
    fn test_lef_lx01_rejects_zero_bytes_per_sector() -> Result<()> {
        // Regression test: EWF2-Lx01 parsing must reject bp=0 (bytes per sector).
        let chunk = hello_chunk_512();

        let dir = tempfile::tempdir()?;
        let path = dir.path().join("bad-bp0.Lx01");

        let set_id = [0x45u8; 16];
        let mut f = Ewf2TestFile::new_lx01(set_id);
        f.device_information(0, 1);
        f.case_data(1, 0);
        let _ = f.sector_data_uncompressed_chunk(&chunk);
        f.sector_table(0, &[]);
        let _ = f.single_files_data(ENCASE7_TREE_SINGLE_HELLO_TXT);
        f.done();

        std::fs::write(&path, &f.into_bytes())?;

        let err = LefReader::open(&path).unwrap_err();
        assert!(matches!(err, Error::Invalid(_)));
        Ok(())
    }
}
