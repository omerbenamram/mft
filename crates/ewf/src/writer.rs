//! Write support for EWF images.
//!
//! The design goal is functional parity with libewf’s write capabilities for EWF1 formats:
//! - `.E01` (EnCase EWF-E01) **read+write**
//! - `.S01` (SMART EWF-S01) **read+write**
//!
//! Writer behavior intentionally mirrors the libewf conventions:
//! - E01: chunk data is stored in a `sectors` section; chunk offsets are stored in a `table`
//!   section and mirrored in a `table2` section.
//! - S01: chunk data is stored in the `table` section itself (no `sectors`, no `table2`);
//!   chunks are always stored **compressed** (zlib), matching libewf’s `FORCE_COMPRESSION` behavior
//!   for SMART.
//! - For E01, `next`/`done` sections use a 0 size field in the descriptor (EnCase quirk).
//! - Checksums are Adler32 (RFC1950), matching the EWF spec and libewf.
//!
//! NOTE: This module writes a *conservative* subset of the metadata sections required by common
//! tooling (header2/header, volume/data, table/tables). More metadata surface area is added as part
//! of the later EWF2/LEF/delta work.

use crate::ewf1_volume;
use crate::ewf2::file_header::{EWF2_FILE_HEADER_SIZE, Ewf2FileHeader, Ewf2Kind};
use crate::{Error, Result};
use flate2::{Compression, write::ZlibEncoder};
use md5::{Digest as _, Md5};
use rand::RngCore as _;
use sha1::Sha1;
use std::fs::File;
use std::io::{self, Read as _, Seek, SeekFrom, Write as _};
use std::path::{Path, PathBuf};

// EWF1 file header signature ("EVF\t\r\n\xff\0")
const EWF1_EVF_SIGNATURE: [u8; 8] = [0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00];

const EWF1_FILE_HEADER_SIZE: usize = 8 + 1 + 2 + 2; // 13
const EWF1_SECTION_DESCRIPTOR_SIZE: usize = 16 + 8 + 8 + 40 + 4; // 76
const EWF1_TABLE_HEADER_SIZE: usize = 4 + 4 + 8 + 4 + 4; // 24

// --- EWF2 constants (EnCase 7 "EVF2"/".Ex01") ---
const EWF2_SECTION_DESCRIPTOR_SIZE: usize = 64;
const EWF2_TABLE_HEADER_SIZE: usize = 32; // 20 bytes header + 12 bytes alignment padding
const EWF2_TABLE_ENTRY_SIZE: usize = 16;
const EWF2_TABLE_FOOTER_SIZE: usize = 16; // 4 bytes footer + 12 bytes alignment padding

const EWF2_SECTION_TYPE_DEVICE_INFORMATION: u32 = 0x0000_0001;
const EWF2_SECTION_TYPE_CASE_DATA: u32 = 0x0000_0002;
const EWF2_SECTION_TYPE_SECTOR_DATA: u32 = 0x0000_0003;
const EWF2_SECTION_TYPE_SECTOR_TABLE: u32 = 0x0000_0004;
const EWF2_SECTION_TYPE_MD5_HASH: u32 = 0x0000_0008;
const EWF2_SECTION_TYPE_SHA1_HASH: u32 = 0x0000_0009;
const EWF2_SECTION_TYPE_NEXT: u32 = 0x0000_000d;
const EWF2_SECTION_TYPE_DONE: u32 = 0x0000_000f;

const EWF2_SECTION_DATA_FLAG_MD5HASHED: u32 = 0x0000_0001;
#[allow(dead_code)]
const EWF2_SECTION_DATA_FLAG_ENCRYPTED: u32 = 0x0000_0002;

const EWF2_CHUNK_DATA_FLAG_COMPRESSED: u32 = 0x0000_0001;
const EWF2_CHUNK_DATA_FLAG_CHECKSUMED: u32 = 0x0000_0002;
const EWF2_CHUNK_DATA_FLAG_PATTERNFILL: u32 = 0x0000_0004;

/// EWF1 writer format (segment file naming + structural differences).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ewf1Format {
    /// EnCase `.E01` / `.E02` / ...
    E01,
    /// SMART `.s01` / `.s02` / ...
    S01,
}

/// Compression level exposed in the EWF1 volume/header metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Ewf1CompressionLevel {
    None,
    #[default]
    Fast,
    Best,
}

impl Ewf1CompressionLevel {
    fn as_volume_byte(self) -> u8 {
        match self {
            Ewf1CompressionLevel::None => 0x00,
            Ewf1CompressionLevel::Fast => 0x01,
            Ewf1CompressionLevel::Best => 0x02,
        }
    }

    fn as_flate2(self) -> Compression {
        match self {
            Ewf1CompressionLevel::None => Compression::none(),
            Ewf1CompressionLevel::Fast => Compression::fast(),
            Ewf1CompressionLevel::Best => Compression::best(),
        }
    }
}

/// Minimal set of human-oriented header fields we write into the header sections.
///
/// These are not required for byte-level correctness, but they make the output much more
/// interoperable with existing forensic tooling.
#[derive(Debug, Clone, Default)]
pub struct EwfHeaderValues {
    pub case_number: String,
    pub evidence_number: String,
    pub description: String,
    pub examiner_name: String,
    pub notes: String,
    pub acquisition_datetime: String,
    pub system_datetime: String,
    pub acquisition_software: String,
    pub acquisition_software_version: String,
    pub acquisition_os: String,
}

/// Options for creating or resuming an EWF1 writer.
#[derive(Debug, Clone)]
pub struct EwfWriterOptions {
    pub format: Ewf1Format,
    /// Logical media size in bytes.
    pub media_size: u64,
    /// Bytes per sector (typically 512).
    pub bytes_per_sector: u32,
    /// Sectors per chunk/block (typically 64, so chunk_size is 32768).
    pub sectors_per_chunk: u32,
    /// The number of sectors to use as error granularity.
    ///
    /// If not set, this defaults to `sectors_per_chunk` (mirrors libewf’s acquisition tooling).
    pub error_granularity: Option<u32>,
    /// Maximum size of a segment file in bytes (libewf default is 1500 MiB).
    pub segment_file_size: u64,
    /// Chunk compression level (E01 uses “compress if smaller”; S01 forces compression).
    pub compression_level: Ewf1CompressionLevel,
    /// If set, empty chunks (all zeros) are compressed using a precomputed zero-block deflate stream.
    pub empty_block_compression: bool,
    /// Header fields (written into header/header2 sections for E01, and header for S01).
    pub header_values: EwfHeaderValues,
    /// Optional 16-byte set identifier written into the E01 volume/data sections.
    pub set_identifier: Option<[u8; 16]>,
}

impl EwfWriterOptions {
    pub fn new(format: Ewf1Format, media_size: u64) -> Self {
        Self {
            format,
            media_size,
            bytes_per_sector: 512,
            sectors_per_chunk: 64,
            error_granularity: None,
            segment_file_size: 1500 * 1024 * 1024, // libewf default
            compression_level: Ewf1CompressionLevel::default(),
            empty_block_compression: true,
            header_values: EwfHeaderValues::default(),
            set_identifier: None,
        }
    }
}

/// EWF2 compression method (as stored in the EWF2 file header / case data).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ewf2CompressionMethod {
    None,
    Zlib,
    Bzip2,
}

impl Ewf2CompressionMethod {
    fn to_u16(self) -> u16 {
        match self {
            Ewf2CompressionMethod::None => 0,
            Ewf2CompressionMethod::Zlib => 1,
            Ewf2CompressionMethod::Bzip2 => 2,
        }
    }
}

/// Options for creating an EWF2-Ex01 writer.
#[derive(Debug, Clone)]
pub struct Ewf2WriterOptions {
    /// Logical media size in bytes.
    pub media_size: u64,
    /// Bytes per sector (typically 512).
    pub bytes_per_sector: u32,
    /// Sectors per chunk/block (typically 64, so chunk_size is 32768).
    pub sectors_per_chunk: u32,
    /// The number of sectors to use as error granularity.
    ///
    /// If not set, this defaults to `sectors_per_chunk` (mirrors libewf’s acquisition tooling).
    pub error_granularity: Option<u32>,
    /// Maximum size of a segment file in bytes.
    pub segment_file_size: u64,
    /// Segment-set compression method.
    pub compression_method: Ewf2CompressionMethod,
    /// If set, all-zero chunks are written using PATTERNFILL (no stored bytes).
    pub pattern_fill: bool,
    /// Header fields used to populate basic device/case metadata.
    pub header_values: EwfHeaderValues,
    /// Optional 16-byte set identifier written into the EWF2 file header (all segments).
    pub set_identifier: Option<[u8; 16]>,
}

impl Ewf2WriterOptions {
    pub fn new(media_size: u64) -> Self {
        Self {
            media_size,
            bytes_per_sector: 512,
            sectors_per_chunk: 64,
            error_granularity: None,
            segment_file_size: 1500 * 1024 * 1024,
            compression_method: Ewf2CompressionMethod::Zlib,
            pattern_fill: true,
            header_values: EwfHeaderValues::default(),
            set_identifier: None,
        }
    }
}

/// Writer for EWF image sets (EWF1 for now).
#[derive(Debug)]
pub struct EwfWriter {
    opts: EwfWriterOptions,
    base_path: PathBuf,
    naming: Ewf1Naming,

    // Media geometry (EWF1 volume/data sections).
    bytes_per_sector: u32,
    sectors_per_chunk: u32,
    error_granularity: u32,
    number_of_sectors: u64,
    chunk_size: usize,
    chunk_count: u64,

    // Global progress.
    bytes_written: u64,
    chunks_written: u64,

    // Hashing of logical media bytes.
    md5: Md5,
    sha1: Sha1,

    // Current segment state.
    segment_number: u32,
    file: Option<File>,
    file_offset: u64,
    segment_target_chunks: u64,
    segment_chunks_written: u64,

    // Chunk table entries for the current segment.
    table_entries: Vec<u32>,

    // E01: sectors section tracking.
    sectors_section_start: Option<u64>,
    sectors_section_desc_offset: Option<u64>,

    // S01: table section tracking + prefix reservation.
    table_section_start: Option<u64>,
    table_section_desc_offset: Option<u64>,
    table_section_prefix_len: usize,
    table_entries_file_offset: Option<u64>,

    // Chunk buffering for streaming writes.
    chunk_buf: Vec<u8>,
    chunk_buf_len: usize,

    // Cached compressed zero block for empty-block compression.
    compressed_zero_block: Option<Vec<u8>>,

    // E01 set identifier (volume/data sections).
    set_identifier: [u8; 16],
}

impl EwfWriter {
    /// Creates a new EWF1 image set.
    ///
    /// `path` is the path of (or adjacent to) the first segment file, e.g. `out.E01` or `out.s01`.
    /// The writer will create sibling segment files using the format-specific naming schema.
    pub fn create(path: impl AsRef<Path>, opts: EwfWriterOptions) -> Result<Self> {
        Self::create_internal(path.as_ref(), opts, None)
    }

    /// Resumes writing an incomplete EWF1 image set.
    ///
    /// Resume is conservative: if the last segment does not parse cleanly we discard it (and any
    /// later segments) and resume at the next segment boundary. This mirrors libewf’s behavior of
    /// backtracking to a known-good “chunks section” boundary.
    pub fn resume(path: impl AsRef<Path>, opts: EwfWriterOptions) -> Result<Self> {
        let path = path.as_ref();

        let base_path = remove_extension(path);
        let naming = Ewf1Naming::from_path(path, opts.format)?;
        let segment_paths = discover_segment_paths(&base_path, naming)?;
        if segment_paths.is_empty() {
            return Err(Error::Invalid(format!(
                "no segment files found for `{}`",
                path.display()
            )));
        }

        // Parse segments until we hit an incomplete/unparseable one.
        let mut parsed_segments: Vec<Ewf1ParsedSegment> = Vec::new();
        let mut resume_segment_number: u32 = 1;

        for (i, seg_path) in segment_paths.iter().enumerate() {
            let expected = u32::try_from(i + 1).unwrap_or(u32::MAX);
            match parse_segment_for_resume(seg_path, opts.format) {
                Ok(seg) => {
                    parsed_segments.push(seg);
                    resume_segment_number = expected.saturating_add(1);
                }
                Err(_) => {
                    // Resume will discard this segment and everything after it.
                    resume_segment_number = expected;
                    break;
                }
            }
        }

        // If the last fully parsed segment ends with `done`, we consider the set finalized.
        if let Some(last) = parsed_segments.last()
            && last.last_section_type == Some("done".to_string())
        {
            return Err(Error::Invalid(
                "cannot resume: image set is already finalized (done section present)".to_string(),
            ));
        }

        let chunk_size = checked_chunk_size(opts.sectors_per_chunk, opts.bytes_per_sector)?;
        let bytes_per_sector = opts.bytes_per_sector;
        let number_of_sectors = checked_number_of_sectors(opts.media_size, bytes_per_sector)?;
        let chunk_count = div_ceil_u64(number_of_sectors, opts.sectors_per_chunk as u64);

        let chunks_written = parsed_segments
            .iter()
            .map(|s| s.chunk_count)
            .sum::<u64>()
            .min(chunk_count);

        let bytes_written = (chunks_written as u128)
            .saturating_mul(chunk_size as u128)
            .min(opts.media_size as u128) as u64;

        // Recompute MD5/SHA1 of the already-written prefix by reading back from the parsed segments.
        let (md5, sha1) = hash_prefix_from_parsed_segments(
            &parsed_segments,
            chunk_size,
            bytes_written,
            opts.format,
        )?;

        Self::create_internal(
            path,
            opts,
            Some(ResumeState {
                resume_segment_number,
                bytes_written,
                chunks_written,
                md5,
                sha1,
            }),
        )
    }

    /// Writes bytes of the logical media.
    ///
    /// Callers can stream data in arbitrary chunking; the writer will buffer into EWF chunks
    /// internally.
    pub fn write(&mut self, mut buf: &[u8]) -> Result<usize> {
        if self.bytes_written >= self.opts.media_size {
            return Ok(0);
        }

        let mut total = 0usize;
        while !buf.is_empty() && self.bytes_written < self.opts.media_size {
            let remaining_media = (self.opts.media_size - self.bytes_written) as usize;
            let take = buf.len().min(remaining_media);
            let take_slice = &buf[..take];

            // Buffer into the next chunk.
            let free = self.chunk_size.saturating_sub(self.chunk_buf_len);
            let copy = free.min(take);

            // Safety: ensure this loop always makes progress.
            if copy == 0 {
                if self.chunk_buf_len == self.chunk_size {
                    // Flush to make room and try again.
                    self.flush_full_chunk()?;
                    continue;
                }
                return Err(Error::Invalid("writer.write made no progress".to_string()));
            }

            // Feed hashes only for *logical* bytes that we actually consume (no padding).
            self.md5.update(&take_slice[..copy]);
            self.sha1.update(&take_slice[..copy]);

            self.bytes_written = self.bytes_written.saturating_add(copy as u64);

            self.chunk_buf[self.chunk_buf_len..self.chunk_buf_len + copy]
                .copy_from_slice(&take_slice[..copy]);
            self.chunk_buf_len += copy;

            total += copy;
            buf = &buf[copy..];

            if self.chunk_buf_len == self.chunk_size {
                self.flush_full_chunk()?;
            }
        }

        Ok(total)
    }

    /// Finalizes the image set (writes tables, hash/digest sections, and the final `done` marker).
    pub fn finish(mut self) -> Result<()> {
        // If the caller did not provide enough input, fail loudly: media size is part of the EWF metadata.
        if self.bytes_written != self.opts.media_size {
            return Err(Error::Invalid(format!(
                "media size mismatch: expected={} wrote={}",
                self.opts.media_size, self.bytes_written
            )));
        }

        // Flush a final partial chunk (padded with zeros on disk).
        if self.chunk_buf_len != 0 {
            self.chunk_buf[self.chunk_buf_len..].fill(0);
            self.flush_full_chunk()?;
        }

        if self.chunks_written != self.chunk_count {
            return Err(Error::Invalid(format!(
                "chunk count mismatch at finalize: expected={} wrote={}",
                self.chunk_count, self.chunks_written
            )));
        }

        // Finalize the last segment’s chunk section (sectors+tables or table-with-data).
        self.finalize_current_segment_chunks_section(true)?;

        // Write hash sections for the last segment (digest + hash for E01; hash for S01).
        self.write_hash_sections()?;

        // Write `done` section.
        self.write_last_section(true)?;

        Ok(())
    }

    // --- internals ---

    fn create_internal(
        path: &Path,
        opts: EwfWriterOptions,
        resume: Option<ResumeState>,
    ) -> Result<Self> {
        if opts.media_size == 0 {
            return Err(Error::Invalid("media_size must be > 0".to_string()));
        }
        if opts.segment_file_size < 1024 {
            return Err(Error::Invalid(
                "segment_file_size is too small (must be >= 1024 bytes)".to_string(),
            ));
        }

        let bytes_per_sector = opts.bytes_per_sector;
        let sectors_per_chunk = opts.sectors_per_chunk;
        let chunk_size = checked_chunk_size(sectors_per_chunk, bytes_per_sector)?;
        let number_of_sectors = checked_number_of_sectors(opts.media_size, bytes_per_sector)?;
        let chunk_count = div_ceil_u64(number_of_sectors, sectors_per_chunk as u64);
        let mut error_granularity = opts.error_granularity.unwrap_or(sectors_per_chunk);
        if error_granularity == 0 || error_granularity > sectors_per_chunk {
            error_granularity = sectors_per_chunk;
        }

        let base_path = remove_extension(path);
        let naming = Ewf1Naming::from_path(path, opts.format)?;

        // Segment set identifier (EnCase5+ volume/data sections).
        let mut set_identifier = [0u8; 16];
        if let Some(id) = opts.set_identifier {
            set_identifier = id;
        } else {
            rand::rng().fill_bytes(&mut set_identifier);
        }

        let mut w = Self {
            opts,
            base_path,
            naming,
            bytes_per_sector,
            sectors_per_chunk,
            error_granularity,
            number_of_sectors,
            chunk_size,
            chunk_count,
            bytes_written: 0,
            chunks_written: 0,
            md5: Md5::new(),
            sha1: Sha1::new(),
            segment_number: 0,
            file: None,
            file_offset: 0,
            segment_target_chunks: 0,
            segment_chunks_written: 0,
            table_entries: Vec::new(),
            sectors_section_start: None,
            sectors_section_desc_offset: None,
            table_section_start: None,
            table_section_desc_offset: None,
            table_section_prefix_len: 0,
            table_entries_file_offset: None,
            chunk_buf: vec![0u8; chunk_size],
            chunk_buf_len: 0,
            compressed_zero_block: None,
            set_identifier,
        };

        if let Some(resume) = resume {
            w.bytes_written = resume.bytes_written;
            w.chunks_written = resume.chunks_written;
            w.md5 = resume.md5;
            w.sha1 = resume.sha1;

            // Resume always starts on a chunk boundary and with an empty chunk buffer.
            w.chunk_buf.fill(0);
            w.chunk_buf_len = 0;

            // Open the resume segment.
            w.open_new_segment(resume.resume_segment_number, false)?;
        } else {
            // Fresh write starts at segment 1.
            w.open_new_segment(1, false)?;
        }

        Ok(w)
    }

    fn file_mut(&mut self) -> Result<&mut File> {
        self.file
            .as_mut()
            .ok_or_else(|| Error::Invalid("segment file is not open".to_string()))
    }

    fn open_new_segment(&mut self, segment_number: u32, is_last_segment: bool) -> Result<()> {
        self.segment_number = segment_number;
        self.segment_chunks_written = 0;
        self.table_entries.clear();
        self.sectors_section_start = None;
        self.sectors_section_desc_offset = None;
        self.table_section_start = None;
        self.table_section_desc_offset = None;
        self.table_section_prefix_len = 0;
        self.table_entries_file_offset = None;

        let ext = self.naming.extension_for_segment(segment_number)?;
        let path = self.base_path.with_extension(ext);
        self.file = Some(File::create(&path)?);
        self.file_offset = 0;

        // --- file header ---
        self.write_ewf1_file_header(segment_number)?;

        // --- header sections + volume/data ---
        match (self.opts.format, segment_number) {
            (Ewf1Format::E01, 1) => {
                self.write_e01_header_sections()?;
                self.write_e01_volume_section()?;
            }
            (Ewf1Format::E01, _) => {
                self.write_e01_data_section()?;
            }
            (Ewf1Format::S01, 1) => {
                self.write_s01_header_section()?;
                self.write_s01_volume_section()?;
            }
            (Ewf1Format::S01, _) => {}
        }

        // Determine how many chunks this segment should hold (conservative, worst-case sizing).
        let chunks_remaining = self.chunk_count.saturating_sub(self.chunks_written);
        if chunks_remaining == 0 {
            // Nothing more to write; this can happen when finalizing an already-complete set.
            self.segment_target_chunks = 0;
            return Ok(());
        }

        let available = self.opts.segment_file_size.saturating_sub(self.file_offset);
        let max_chunks_here = self.max_chunks_for_segment(available, is_last_segment)?;
        self.segment_target_chunks = chunks_remaining.min(max_chunks_here.max(1));

        // --- chunks section start ---
        match self.opts.format {
            Ewf1Format::E01 => self.start_e01_sectors_section()?,
            Ewf1Format::S01 => self.start_s01_table_section()?,
        }

        Ok(())
    }

    fn max_chunks_for_segment(&self, available: u64, is_last_segment: bool) -> Result<u64> {
        let _ = is_last_segment;
        match self.opts.format {
            Ewf1Format::E01 => {
                // Reserve space for:
                // - sectors descriptor
                // - table + table2 descriptors + headers + footers
                // - next/done descriptor
                let reserved_fixed =
                    (EWF1_SECTION_DESCRIPTOR_SIZE as u64) /*sectors*/ +
                    2 * (EWF1_SECTION_DESCRIPTOR_SIZE as u64 + EWF1_TABLE_HEADER_SIZE as u64 + 4) /*table+table2*/ +
                    (EWF1_SECTION_DESCRIPTOR_SIZE as u64) /*next/done*/;

                // Worst-case per chunk stored size: uncompressed (chunk_size + adler32).
                let per_chunk_data = (self.chunk_size as u64).saturating_add(4);
                // Per chunk table overhead: 4 bytes in table + 4 bytes in table2.
                let per_chunk_table = 8u64;
                let per_chunk_total = per_chunk_data.saturating_add(per_chunk_table);

                if available <= reserved_fixed.saturating_add(per_chunk_total) {
                    return Ok(1);
                }
                Ok((available - reserved_fixed) / per_chunk_total)
            }
            Ewf1Format::S01 => {
                // SMART stores chunk data inside the table section. We must reserve the descriptor,
                // the table header/footer, and the terminal next/done descriptor.
                let reserved_fixed =
                    (EWF1_SECTION_DESCRIPTOR_SIZE as u64) /*table*/ +
                    (EWF1_TABLE_HEADER_SIZE as u64) +
                    4 /*footer*/ +
                    (EWF1_SECTION_DESCRIPTOR_SIZE as u64) /*next/done*/;

                // libewf uses `chunk_size + 16` as an “average” expansion factor for zlib.
                let per_chunk_data = (self.chunk_size as u64).saturating_add(16);
                let per_chunk_table = 4u64;
                let per_chunk_total = per_chunk_data.saturating_add(per_chunk_table);

                if available <= reserved_fixed.saturating_add(per_chunk_total) {
                    return Ok(1);
                }
                Ok((available - reserved_fixed) / per_chunk_total)
            }
        }
    }

    fn flush_full_chunk(&mut self) -> Result<()> {
        debug_assert_eq!(self.chunk_buf_len, self.chunk_size);

        // Ensure the current segment exists (it might not if resume opened at the end).
        if self.segment_target_chunks == 0 {
            self.open_new_segment(self.segment_number.max(1), false)?;
        }

        // Write chunk bytes to the current chunks section and record the table entry.
        //
        // NOTE: We copy the chunk buffer into a local Vec to satisfy the borrow checker: the
        // chunk write paths mutate `self` and also need a stable slice of the chunk bytes.
        let chunk = self.chunk_buf.clone();
        match self.opts.format {
            Ewf1Format::E01 => self.write_e01_chunk(&chunk)?,
            Ewf1Format::S01 => self.write_s01_chunk(&chunk)?,
        }

        self.chunk_buf_len = 0;
        self.chunks_written = self.chunks_written.saturating_add(1);
        self.segment_chunks_written = self.segment_chunks_written.saturating_add(1);

        // If we filled the current segment, finalize it and open the next one.
        if self.segment_chunks_written == self.segment_target_chunks {
            let more_segments_needed = self.chunks_written < self.chunk_count;

            if more_segments_needed {
                self.finalize_current_segment_chunks_section(false)?;
                self.write_last_section(false)?;

                let next = self.segment_number.saturating_add(1);
                self.open_new_segment(next, false)?;
            }
        }

        Ok(())
    }

    fn write_ewf1_file_header(&mut self, segment_number: u32) -> Result<()> {
        if segment_number == 0 || segment_number > u16::MAX as u32 {
            return Err(Error::Invalid("segment number out of bounds".to_string()));
        }
        let file = self.file_mut()?;
        file.write_all(&EWF1_EVF_SIGNATURE)?;
        file.write_all(&[0x01])?; // start of fields
        file.write_all(&(segment_number as u16).to_le_bytes())?;
        file.write_all(&0u16.to_le_bytes())?; // end of fields
        self.file_offset += EWF1_FILE_HEADER_SIZE as u64;
        Ok(())
    }

    fn write_e01_header_sections(&mut self) -> Result<()> {
        // EnCase 4–7: header2 twice, then header once (all zlib-compressed).
        let header2 = build_header2_utf16le(&self.opts.header_values);
        let header2_z = zlib_compress(&header2, Compression::default())?;
        self.write_section_with_descriptor_v1("header2", &header2_z)?;
        self.write_section_with_descriptor_v1("header2", &header2_z)?;

        let header = build_header_ascii(&self.opts.header_values, self.opts.compression_level);
        let header_z = zlib_compress(header.as_bytes(), Compression::default())?;
        self.write_section_with_descriptor_v1("header", &header_z)?;
        Ok(())
    }

    fn write_s01_header_section(&mut self) -> Result<()> {
        // SMART: a single header section, compressed using the same compression level as chunks.
        let header = build_header_ascii(&self.opts.header_values, self.opts.compression_level);
        let header_z = zlib_compress(header.as_bytes(), self.opts.compression_level.as_flate2())?;
        self.write_section_with_descriptor_v1("header", &header_z)?;
        Ok(())
    }

    fn write_e01_volume_section(&mut self) -> Result<()> {
        let data = ewf1_volume::build_volume_section_e01_1052(
            self.chunk_count,
            self.sectors_per_chunk,
            self.error_granularity,
            self.bytes_per_sector,
            self.number_of_sectors,
            self.opts.compression_level.as_volume_byte(),
            self.set_identifier,
        );
        self.write_section_with_descriptor_v1("volume", &data)?;
        Ok(())
    }

    fn write_e01_data_section(&mut self) -> Result<()> {
        let data = ewf1_volume::build_volume_section_e01_1052(
            self.chunk_count,
            self.sectors_per_chunk,
            self.error_granularity,
            self.bytes_per_sector,
            self.number_of_sectors,
            self.opts.compression_level.as_volume_byte(),
            self.set_identifier,
        );
        self.write_section_with_descriptor_v1("data", &data)?;
        Ok(())
    }

    fn write_s01_volume_section(&mut self) -> Result<()> {
        let data = ewf1_volume::build_volume_section_s01_94(
            self.chunk_count,
            self.sectors_per_chunk,
            self.bytes_per_sector,
            self.number_of_sectors,
        );
        self.write_section_with_descriptor_v1("volume", &data)?;
        Ok(())
    }

    fn start_e01_sectors_section(&mut self) -> Result<()> {
        let start = self.file_offset;
        let desc = make_section_descriptor_v1("sectors", start, start, 0);
        self.file_mut()?.write_all(&desc)?;
        self.sectors_section_start = Some(start);
        self.sectors_section_desc_offset = Some(start);
        self.file_offset = self
            .file_offset
            .saturating_add(EWF1_SECTION_DESCRIPTOR_SIZE as u64);
        Ok(())
    }

    fn start_s01_table_section(&mut self) -> Result<()> {
        let start = self.file_offset;
        // Placeholder descriptor (fixed at finalize, once we know the total chunk data size).
        let desc = make_section_descriptor_v1("table", start, start, 0);
        self.file_mut()?.write_all(&desc)?;
        self.file_offset = self
            .file_offset
            .saturating_add(EWF1_SECTION_DESCRIPTOR_SIZE as u64);

        // Reserve space for header + entries + footer, so chunk data can follow immediately.
        let entries_len = usize::try_from(self.segment_target_chunks)
            .map_err(|_| Error::Invalid("segment entry count overflow".to_string()))?;
        let entries_bytes = entries_len
            .checked_mul(4)
            .ok_or_else(|| Error::Invalid("entries size overflow".to_string()))?;

        let header = make_table_header_v1(entries_len as u32, 0);
        let entries = vec![0u8; entries_bytes];
        let footer = adler32_rfc1950(&entries).to_le_bytes();

        let prefix_len = header.len() + entries.len() + footer.len();
        let file = self.file_mut()?;
        file.write_all(&header)?;
        file.write_all(&entries)?;
        file.write_all(&footer)?;
        self.file_offset = self.file_offset.saturating_add(prefix_len as u64);

        self.table_section_start = Some(start);
        self.table_section_desc_offset = Some(start);
        self.table_section_prefix_len = prefix_len;
        self.table_entries_file_offset =
            Some(start + EWF1_SECTION_DESCRIPTOR_SIZE as u64 + EWF1_TABLE_HEADER_SIZE as u64);

        Ok(())
    }

    fn write_e01_chunk(&mut self, chunk: &[u8]) -> Result<()> {
        let Some(sectors_start) = self.sectors_section_start else {
            return Err(Error::Invalid("missing sectors section start".to_string()));
        };

        // Decide whether to store this chunk compressed.
        let (stored, compressed_flag) = pack_chunk_e01(
            chunk,
            self.opts.compression_level,
            self.opts.empty_block_compression,
            &mut self.compressed_zero_block,
        )?;

        // Table entries are relative to the sectors section start offset for EnCase6-style base offsets.
        let rel_off = self
            .file_offset
            .checked_sub(sectors_start)
            .ok_or_else(|| Error::Invalid("negative chunk offset".to_string()))?;
        let rel_u32 = u32::try_from(rel_off)
            .map_err(|_| Error::Invalid("chunk offset overflow".to_string()))?;
        if (rel_u32 & 0x8000_0000) != 0 {
            return Err(Error::Invalid(
                "chunk offset exceeds 31-bit limit".to_string(),
            ));
        }

        let entry = rel_u32 | if compressed_flag { 0x8000_0000 } else { 0 };
        self.table_entries.push(entry);

        self.file_mut()?.write_all(&stored)?;
        self.file_offset = self.file_offset.saturating_add(stored.len() as u64);
        Ok(())
    }

    fn write_s01_chunk(&mut self, chunk: &[u8]) -> Result<()> {
        let Some(table_entries_off) = self.table_entries_file_offset else {
            return Err(Error::Invalid(
                "missing table entries file offset".to_string(),
            ));
        };
        let Some(table_start) = self.table_section_start else {
            return Err(Error::Invalid("missing table section start".to_string()));
        };

        // SMART forces compression (zlib) for all chunks.
        let stored = zlib_compress(chunk, self.opts.compression_level.as_flate2())?;

        // Record absolute offset (base_offset=0 for SMART), with compression flag set.
        let start_off_u32 = u32::try_from(self.file_offset)
            .map_err(|_| Error::Invalid("chunk offset overflow".to_string()))?;
        let entry = start_off_u32 | 0x8000_0000;
        self.table_entries.push(entry);

        // Fill the corresponding table entry in-place (makes the file more resumable mid-write).
        let entry_pos = table_entries_off
            .checked_add(self.segment_chunks_written * 4)
            .ok_or_else(|| Error::Invalid("table entry position overflow".to_string()))?;

        let return_pos = self.file_offset;
        let file = self.file_mut()?;
        file.seek(SeekFrom::Start(entry_pos))?;
        file.write_all(&entry.to_le_bytes())?;
        file.seek(SeekFrom::Start(return_pos))?;

        // Write chunk data into the table section body (after header+entries+footer prefix).
        self.file_mut()?.write_all(&stored)?;
        self.file_offset = self.file_offset.saturating_add(stored.len() as u64);

        // Safety: ensure we didn't overwrite the reserved prefix region.
        let prefix_end = table_start
            + EWF1_SECTION_DESCRIPTOR_SIZE as u64
            + self.table_section_prefix_len as u64;
        if return_pos < prefix_end {
            return Err(Error::Invalid(
                "chunk data overlapped table prefix".to_string(),
            ));
        }

        Ok(())
    }

    fn finalize_current_segment_chunks_section(&mut self, is_last_segment: bool) -> Result<()> {
        if self.segment_chunks_written == 0 {
            return Ok(());
        }

        match self.opts.format {
            Ewf1Format::E01 => {
                self.finalize_e01_sectors_and_tables()?;
                let _ = is_last_segment;
            }
            Ewf1Format::S01 => {
                self.finalize_s01_table_section()?;
                let _ = is_last_segment;
            }
        }
        Ok(())
    }

    fn finalize_e01_sectors_and_tables(&mut self) -> Result<()> {
        let Some(sectors_desc_off) = self.sectors_section_desc_offset else {
            return Err(Error::Invalid(
                "missing sectors section descriptor offset".to_string(),
            ));
        };
        let Some(sectors_start) = self.sectors_section_start else {
            return Err(Error::Invalid("missing sectors section start".to_string()));
        };

        // Fix up the sectors section descriptor now that we know its final size.
        let sectors_total_size = self
            .file_offset
            .checked_sub(sectors_start)
            .ok_or_else(|| Error::Invalid("invalid sectors size".to_string()))?;
        let sectors_desc = make_section_descriptor_v1(
            "sectors",
            sectors_start,
            sectors_start.saturating_add(sectors_total_size),
            sectors_total_size,
        );
        self.write_descriptor_at(sectors_desc_off, &sectors_desc)?;

        // Write table section (then table2 mirror).
        let base_offset = sectors_start; // EnCase6 base offset semantics (see libewf_write_io_handle.c)

        let table_data = build_table_section_v1(base_offset, &self.table_entries)?;

        self.write_section_with_descriptor_v1("table", &table_data)?;
        self.write_section_with_descriptor_v1("table2", &table_data)?;

        Ok(())
    }

    fn finalize_s01_table_section(&mut self) -> Result<()> {
        let Some(table_start) = self.table_section_start else {
            return Err(Error::Invalid("missing table section start".to_string()));
        };
        let Some(table_desc_off) = self.table_section_desc_offset else {
            return Err(Error::Invalid(
                "missing table section descriptor offset".to_string(),
            ));
        };

        // Rewrite table header (checksum depends on number_of_entries, base_offset, etc).
        let entries_len = u32::try_from(self.table_entries.len())
            .map_err(|_| Error::Invalid("table entry count overflow".to_string()))?;
        let header = make_table_header_v1(entries_len, 0);

        let header_off = table_start + EWF1_SECTION_DESCRIPTOR_SIZE as u64;
        let entries_off = header_off + EWF1_TABLE_HEADER_SIZE as u64;
        let footer_off = entries_off
            .checked_add((entries_len as u64) * 4)
            .ok_or_else(|| Error::Invalid("footer offset overflow".to_string()))?;

        self.write_bytes_at(header_off, &header)?;

        // Rewrite entries (in case resume filled them partially) and compute footer checksum.
        let mut entries_bytes = Vec::with_capacity(self.table_entries.len() * 4);
        for e in &self.table_entries {
            entries_bytes.extend_from_slice(&e.to_le_bytes());
        }
        self.write_bytes_at(entries_off, &entries_bytes)?;
        let footer = adler32_rfc1950(&entries_bytes).to_le_bytes();
        self.write_bytes_at(footer_off, &footer)?;

        // Fix the section descriptor size and next_offset.
        let table_section_size = self
            .file_offset
            .checked_sub(table_start)
            .ok_or_else(|| Error::Invalid("invalid table section size".to_string()))?;
        let desc = make_section_descriptor_v1(
            "table",
            table_start,
            table_start.saturating_add(table_section_size),
            table_section_size,
        );
        self.write_descriptor_at(table_desc_off, &desc)?;

        Ok(())
    }

    fn write_hash_sections(&mut self) -> Result<()> {
        // Hash the logical media data (not including any chunk padding beyond media_size).
        let md5: [u8; 16] = self.md5.clone().finalize().into();
        let sha1: [u8; 20] = self.sha1.clone().finalize().into();

        match self.opts.format {
            Ewf1Format::E01 => {
                // Digest section: MD5 + SHA1 + padding + checksum.
                let digest_data = build_digest_section(&md5, &sha1);
                self.write_section_with_descriptor_v1("digest", &digest_data)?;
                // Hash section: MD5 + unknown (zeros) + checksum.
                let hash_data = build_hash_section(&md5);
                self.write_section_with_descriptor_v1("hash", &hash_data)?;
            }
            Ewf1Format::S01 => {
                let hash_data = build_hash_section(&md5);
                self.write_section_with_descriptor_v1("hash", &hash_data)?;
            }
        }
        Ok(())
    }

    fn write_last_section(&mut self, last_segment: bool) -> Result<()> {
        let typ = if last_segment { "done" } else { "next" };
        let start = self.file_offset;

        // EnCase E01 leaves the size field empty (0) for next/done; SMART uses a 76-byte size.
        let size_field = match self.opts.format {
            Ewf1Format::E01 => 0u64,
            Ewf1Format::S01 => EWF1_SECTION_DESCRIPTOR_SIZE as u64,
        };

        let desc = make_section_descriptor_v1(typ, start, start, size_field);
        self.file_mut()?.write_all(&desc)?;
        self.file_offset = self
            .file_offset
            .saturating_add(EWF1_SECTION_DESCRIPTOR_SIZE as u64);
        Ok(())
    }

    fn write_section_with_descriptor_v1(&mut self, typ: &str, data: &[u8]) -> Result<()> {
        let start = self.file_offset;
        let size = (EWF1_SECTION_DESCRIPTOR_SIZE + data.len()) as u64;
        let next = start.saturating_add(size);
        let desc = make_section_descriptor_v1(typ, start, next, size);
        let file = self.file_mut()?;
        file.write_all(&desc)?;
        file.write_all(data)?;
        self.file_offset = next;
        Ok(())
    }

    fn write_descriptor_at(
        &mut self,
        offset: u64,
        raw: &[u8; EWF1_SECTION_DESCRIPTOR_SIZE],
    ) -> Result<()> {
        let return_pos = self.file_offset;
        let file = self.file_mut()?;
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(raw)?;
        file.seek(SeekFrom::Start(return_pos))?;
        Ok(())
    }

    fn write_bytes_at(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        let return_pos = self.file_offset;
        let file = self.file_mut()?;
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(data)?;
        file.seek(SeekFrom::Start(return_pos))?;
        Ok(())
    }
}

// --- Resume helpers (internal) ---

#[derive(Debug)]
struct ResumeState {
    resume_segment_number: u32,
    bytes_written: u64,
    chunks_written: u64,
    md5: Md5,
    sha1: Sha1,
}

#[derive(Debug)]
struct Ewf1ParsedSegment {
    #[allow(dead_code)]
    path: PathBuf,
    file: File,
    file_len: u64,
    chunk_groups: Vec<Ewf1ChunkGroup>,
    chunk_count: u64,
    last_section_type: Option<String>,
}

#[derive(Debug)]
struct Ewf1ChunkGroup {
    #[allow(dead_code)]
    first_chunk_index: u64,
    chunk_base: u64,
    chunk_entries: Vec<u32>,
    chunk_data_end: u64,
}

fn parse_segment_for_resume(path: &Path, format: Ewf1Format) -> Result<Ewf1ParsedSegment> {
    let file = File::open(path)?;
    let file_len = file.metadata()?.len();

    // Basic EVF signature check.
    let mut header = [0u8; EWF1_FILE_HEADER_SIZE];
    read_exact_at(&file, 0, &mut header)?;
    if header[0..8] != EWF1_EVF_SIGNATURE {
        return Err(Error::Invalid("unsupported EWF1 signature".to_string()));
    }

    let sections = parse_ewf1_section_descriptors(&file, file_len, EWF1_FILE_HEADER_SIZE as u64)?;
    let last_section_type = sections.last().map(|s| s.type_string.clone());

    let table_type = match format {
        Ewf1Format::E01 => "table2",
        Ewf1Format::S01 => "table",
    };

    let (chunk_groups, chunk_count) =
        parse_chunk_groups_v1(&file, file_len, &sections, table_type, 0)?;

    Ok(Ewf1ParsedSegment {
        path: path.to_path_buf(),
        file,
        file_len,
        chunk_groups,
        chunk_count,
        last_section_type,
    })
}

fn hash_prefix_from_parsed_segments(
    segments: &[Ewf1ParsedSegment],
    chunk_size: usize,
    bytes_to_hash: u64,
    _format: Ewf1Format,
) -> Result<(Md5, Sha1)> {
    let mut md5 = Md5::new();
    let mut sha1 = Sha1::new();

    let mut remaining = bytes_to_hash;
    for seg in segments {
        for group in &seg.chunk_groups {
            for (i, _) in group.chunk_entries.iter().enumerate() {
                if remaining == 0 {
                    return Ok((md5, sha1));
                }
                let (start, end, is_compressed) = chunk_range_v1(group, i)?;
                let slice = read_file_range(&seg.file, seg.file_len, start, end)?;
                let mut out = vec![0u8; chunk_size];

                if is_compressed {
                    let cursor = io::Cursor::new(slice);
                    let mut decoder = flate2::read::ZlibDecoder::new(cursor);
                    decoder.read_exact(&mut out)?;
                } else {
                    if slice.len() < chunk_size + 4 {
                        return Err(Error::Invalid("short uncompressed chunk".to_string()));
                    }
                    let data_part = &slice[..chunk_size];
                    let checksum_part = &slice[chunk_size..chunk_size + 4];
                    let stored = u32::from_le_bytes(checksum_part.try_into().expect("len=4"));
                    let calculated = adler32_rfc1950(data_part);
                    if stored != calculated {
                        return Err(Error::Corrupt(
                            "uncompressed chunk checksum mismatch".to_string(),
                        ));
                    }
                    out.copy_from_slice(data_part);
                }

                let take = (remaining as usize).min(out.len());
                md5.update(&out[..take]);
                sha1.update(&out[..take]);
                remaining = remaining.saturating_sub(take as u64);
            }
        }
    }

    Ok((md5, sha1))
}

// --- Low-level EWF1 encoders ---

#[derive(Debug, Clone, Copy)]
struct Ewf1Naming {
    first_character: char,
    additional_characters: char,
    maximum_number_of_segments: u32,
}

impl Ewf1Naming {
    fn from_path(path: &Path, format: Ewf1Format) -> Result<Self> {
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        let first = ext.chars().next().unwrap_or(match format {
            Ewf1Format::E01 => 'E',
            Ewf1Format::S01 => 's',
        });
        let additional = if first.is_ascii_uppercase() { 'A' } else { 'a' };
        Ok(Self {
            first_character: first,
            additional_characters: additional,
            maximum_number_of_segments: match format {
                Ewf1Format::E01 => 14971,
                Ewf1Format::S01 => 5507,
            },
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

            if segment_number > 25 {
                return Err(Error::Unsupported("too many segments".to_string()));
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

fn discover_segment_paths(base_path: &Path, naming: Ewf1Naming) -> Result<Vec<PathBuf>> {
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

fn checked_chunk_size(sectors_per_chunk: u32, bytes_per_sector: u32) -> Result<usize> {
    let chunk_size_u32 = sectors_per_chunk
        .checked_mul(bytes_per_sector)
        .ok_or_else(|| Error::Invalid("chunk size overflow".to_string()))?;
    usize::try_from(chunk_size_u32).map_err(|_| Error::Invalid("chunk size overflow".to_string()))
}

fn checked_number_of_sectors(media_size: u64, bytes_per_sector: u32) -> Result<u64> {
    let bps = bytes_per_sector as u64;
    if bps == 0 {
        return Err(Error::Invalid("bytes_per_sector must be > 0".to_string()));
    }
    if !media_size.is_multiple_of(bps) {
        return Err(Error::Invalid(format!(
            "media_size ({media_size}) is not a multiple of bytes_per_sector ({bytes_per_sector})"
        )));
    }
    Ok(media_size / bps)
}

fn div_ceil_u64(a: u64, b: u64) -> u64 {
    if b == 0 {
        return 0;
    }
    a / b + u64::from(!a.is_multiple_of(b))
}

fn make_section_descriptor_v1(
    type_string: &str,
    _start_offset: u64,
    next_offset: u64,
    size: u64,
) -> [u8; EWF1_SECTION_DESCRIPTOR_SIZE] {
    let mut raw = [0u8; EWF1_SECTION_DESCRIPTOR_SIZE];

    let mut type_bytes = [0u8; 16];
    let src = type_string.as_bytes();
    let copy_len = src.len().min(type_bytes.len().saturating_sub(1));
    type_bytes[..copy_len].copy_from_slice(&src[..copy_len]);
    raw[..16].copy_from_slice(&type_bytes);

    raw[16..24].copy_from_slice(&next_offset.to_le_bytes());
    raw[24..32].copy_from_slice(&size.to_le_bytes());

    // padding [32..72] left zero
    let checksum = adler32_rfc1950(&raw[..EWF1_SECTION_DESCRIPTOR_SIZE - 4]);
    raw[EWF1_SECTION_DESCRIPTOR_SIZE - 4..].copy_from_slice(&checksum.to_le_bytes());
    raw
}

fn make_table_header_v1(number_of_entries: u32, base_offset: u64) -> [u8; EWF1_TABLE_HEADER_SIZE] {
    let mut hdr = [0u8; EWF1_TABLE_HEADER_SIZE];
    hdr[0..4].copy_from_slice(&number_of_entries.to_le_bytes());
    hdr[8..16].copy_from_slice(&base_offset.to_le_bytes());
    let checksum = adler32_rfc1950(&hdr[..EWF1_TABLE_HEADER_SIZE - 4]);
    hdr[EWF1_TABLE_HEADER_SIZE - 4..].copy_from_slice(&checksum.to_le_bytes());
    hdr
}

fn build_table_section_v1(base_offset: u64, entries: &[u32]) -> Result<Vec<u8>> {
    let entries_len = u32::try_from(entries.len())
        .map_err(|_| Error::Invalid("table entry count overflow".to_string()))?;

    let mut out = Vec::with_capacity(EWF1_TABLE_HEADER_SIZE + entries.len() * 4 + 4);
    out.extend_from_slice(&make_table_header_v1(entries_len, base_offset));

    let mut entries_bytes = Vec::with_capacity(entries.len() * 4);
    for e in entries {
        entries_bytes.extend_from_slice(&e.to_le_bytes());
    }
    out.extend_from_slice(&entries_bytes);
    out.extend_from_slice(&adler32_rfc1950(&entries_bytes).to_le_bytes());
    Ok(out)
}

fn zlib_compress(bytes: &[u8], level: Compression) -> io::Result<Vec<u8>> {
    let mut enc = ZlibEncoder::new(Vec::new(), level);
    enc.write_all(bytes)?;
    enc.finish()
}

fn pack_chunk_e01(
    chunk: &[u8],
    level: Ewf1CompressionLevel,
    empty_block_compression: bool,
    cached_zero: &mut Option<Vec<u8>>,
) -> Result<(Vec<u8>, bool)> {
    // Decide if the chunk is an empty block.
    if empty_block_compression && chunk.iter().all(|&b| b == 0) {
        if cached_zero.is_none() {
            *cached_zero = Some(zlib_compress(chunk, level.as_flate2())?);
        }
        return Ok((cached_zero.clone().expect("cached"), true));
    }

    if level == Ewf1CompressionLevel::None {
        let mut out = Vec::with_capacity(chunk.len() + 4);
        out.extend_from_slice(chunk);
        out.extend_from_slice(&adler32_rfc1950(chunk).to_le_bytes());
        return Ok((out, false));
    }

    let compressed = zlib_compress(chunk, level.as_flate2())?;
    if compressed.len() < chunk.len() {
        Ok((compressed, true))
    } else {
        let mut out = Vec::with_capacity(chunk.len() + 4);
        out.extend_from_slice(chunk);
        out.extend_from_slice(&adler32_rfc1950(chunk).to_le_bytes());
        Ok((out, false))
    }
}

fn build_digest_section(md5: &[u8; 16], sha1: &[u8; 20]) -> Vec<u8> {
    let mut out = vec![0u8; 80];
    out[0..16].copy_from_slice(md5);
    out[16..36].copy_from_slice(sha1);
    // padding [36..76] already zero
    let checksum = adler32_rfc1950(&out[..76]).to_le_bytes();
    out[76..80].copy_from_slice(&checksum);
    out
}

fn build_hash_section(md5: &[u8; 16]) -> Vec<u8> {
    let mut out = vec![0u8; 36];
    out[0..16].copy_from_slice(md5);
    // unknown [16..32] left zero (matches SMART + older EnCase variants)
    let checksum = adler32_rfc1950(&out[..32]).to_le_bytes();
    out[32..36].copy_from_slice(&checksum);
    out
}

fn build_header_ascii(values: &EwfHeaderValues, compression: Ewf1CompressionLevel) -> String {
    // Minimal EnCase-like header structure:
    // - 1 category (“main”)
    // - identifiers line + values line
    // Lines end with CRLF in EnCase-style headers.
    //
    // We keep the value set small but stable; tooling generally treats these as informational.
    let mut s = String::new();
    s.push_str("1\r\n");
    s.push_str("main\r\n");
    s.push_str("c\tn\ta\te\tt\tav\tov\tm\tu\tp\tr\r\n");
    s.push_str(&format!(
        "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\r\n",
        values.case_number,
        values.evidence_number,
        values.description,
        values.examiner_name,
        values.notes,
        values.acquisition_software_version,
        values.acquisition_os,
        values.acquisition_datetime,
        values.system_datetime,
        "0", // password hash placeholder (no encryption for EWF1)
        match compression {
            Ewf1CompressionLevel::None => "n",
            Ewf1CompressionLevel::Fast => "f",
            Ewf1CompressionLevel::Best => "b",
        }
    ));
    s.push_str("\r\n");
    s
}

fn build_header2_utf16le(values: &EwfHeaderValues) -> Vec<u8> {
    // Minimal EnCase 5–7 style header2: UTF-16LE text with BOM and LF line endings.
    //
    // The full header2 semantics are extensive (categories, sources, subjects). We generate a
    // structurally valid, minimal variant with empty categories beyond “main”.
    let mut s = String::new();
    s.push_str("3\n");
    s.push_str("main\n");
    s.push_str("a\tc\tn\te\tt\tmd\tsn\tav\tov\tm\tu\tp\n");
    s.push_str(&format!(
        "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t0\n",
        values.description,
        values.case_number,
        values.evidence_number,
        values.examiner_name,
        values.notes,
        "", // media model
        "", // serial
        values.acquisition_software,
        values.acquisition_os,
        values.acquisition_datetime,
        values.system_datetime,
    ));
    s.push('\n');

    // srce category placeholder
    s.push_str("srce\n");
    s.push_str("0 1\n");
    s.push_str("p\tn\tid\tev\ttb\tlo\tpo\tah\tsh\tgu\taq\n");
    s.push_str("0 0\n");
    s.push('\n');

    // sub category placeholder
    s.push_str("sub\n");
    s.push_str("0 1\n");
    s.push_str("p\tn\tid\tnu\tco\tgu\n");
    s.push_str("0 0\n");
    s.push('\n');

    // UTF-16LE with BOM.
    let mut out = Vec::with_capacity(2 + s.len() * 2);
    out.extend_from_slice(&[0xff, 0xfe]);
    for u in s.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
}

fn adler32_rfc1950(data: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a = (a + u32::from(byte)) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }
    (b << 16) | a
}

// --- Minimal parsing utilities reused by resume hashing ---

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

        let stored = u32::from_le_bytes(
            raw[EWF1_SECTION_DESCRIPTOR_SIZE - 4..]
                .try_into()
                .expect("len=4"),
        );
        let calculated = adler32_rfc1950(&raw[..EWF1_SECTION_DESCRIPTOR_SIZE - 4]);
        if stored != calculated {
            return Err(Error::Corrupt(
                "section descriptor checksum mismatch".to_string(),
            ));
        }

        let type_string = parse_ascii_nul_terminated(&raw[0..16]);
        let next_offset = u64::from_le_bytes(raw[16..24].try_into().expect("len=8"));
        let mut size = u64::from_le_bytes(raw[24..32].try_into().expect("len=8"));
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
        let start = self.start_offset + EWF1_SECTION_DESCRIPTOR_SIZE as u64;
        let end = self.start_offset + self.size;
        Ok((start, end))
    }
}

fn parse_ewf1_section_descriptors(
    file: &File,
    file_len: u64,
    first_offset: u64,
) -> Result<Vec<Ewf1SectionDescriptor>> {
    let mut sections = Vec::new();
    let mut offset = first_offset;
    for _ in 0..100_000 {
        if offset == 0 || offset >= file_len {
            break;
        }
        let desc = Ewf1SectionDescriptor::parse_at(file, file_len, offset)?;
        let is_last = desc.type_string == "next" || desc.type_string == "done";
        let advance = if desc.size != 0 {
            desc.size
        } else {
            EWF1_SECTION_DESCRIPTOR_SIZE as u64
        };
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

#[derive(Debug, Clone)]
struct TableV1 {
    base_offset: u64,
    entries: Vec<u32>,
}

fn parse_table_section_v1(
    file: &File,
    file_len: u64,
    desc: &Ewf1SectionDescriptor,
) -> Result<TableV1> {
    let (data_start, data_end) = desc.data_range()?;
    if data_end > file_len {
        return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
    }
    if data_end - data_start < EWF1_TABLE_HEADER_SIZE as u64 {
        return Err(Error::Invalid("table header too small".to_string()));
    }
    let mut header = [0u8; EWF1_TABLE_HEADER_SIZE];
    read_exact_at(file, data_start, &mut header)?;

    let stored = u32::from_le_bytes(
        header[EWF1_TABLE_HEADER_SIZE - 4..]
            .try_into()
            .expect("len=4"),
    );
    let calculated = adler32_rfc1950(&header[..EWF1_TABLE_HEADER_SIZE - 4]);
    if stored != calculated {
        return Err(Error::Corrupt("table header checksum mismatch".to_string()));
    }

    let number_of_entries = u32::from_le_bytes(header[0..4].try_into().expect("len=4"));
    let base_offset = u64::from_le_bytes(header[8..16].try_into().expect("len=8"));

    let entries_len = usize::try_from(number_of_entries)
        .map_err(|_| Error::Invalid("table entry count overflow".to_string()))?;
    let entries_bytes = entries_len
        .checked_mul(4)
        .ok_or_else(|| Error::Invalid("entries size overflow".to_string()))?;

    let entries_offset = data_start + EWF1_TABLE_HEADER_SIZE as u64;
    let entries_end = entries_offset + entries_bytes as u64;
    if entries_end > data_end {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated table entries").into());
    }

    let mut entries_data = vec![0u8; entries_bytes];
    read_exact_at(file, entries_offset, &mut entries_data)?;
    let mut entries = Vec::with_capacity(entries_len);
    for c in entries_data.chunks_exact(4) {
        entries.push(u32::from_le_bytes(c.try_into().expect("len=4")));
    }
    Ok(TableV1 {
        base_offset,
        entries,
    })
}

fn parse_chunk_groups_v1(
    file: &File,
    file_len: u64,
    sections: &[Ewf1SectionDescriptor],
    table_type: &str,
    segment_first_chunk_index: u64,
) -> Result<(Vec<Ewf1ChunkGroup>, u64)> {
    let mut groups = Vec::new();
    let mut chunk_count = 0u64;
    let mut pending_sectors_end: Option<u64> = None;

    for desc in sections {
        match desc.type_string.as_str() {
            "sectors" | "sector" => {
                pending_sectors_end = Some(desc.start_offset.saturating_add(desc.size));
            }
            x if x == table_type => {
                let table = parse_table_section_v1(file, file_len, desc)?;
                let chunk_data_end = pending_sectors_end
                    .take()
                    .unwrap_or(desc.start_offset.saturating_add(desc.size));
                let entries_len_u64 = u64::try_from(table.entries.len())
                    .map_err(|_| Error::Invalid("table entry count overflow".to_string()))?;
                groups.push(Ewf1ChunkGroup {
                    first_chunk_index: segment_first_chunk_index + chunk_count,
                    chunk_base: table.base_offset,
                    chunk_entries: table.entries,
                    chunk_data_end,
                });
                chunk_count += entries_len_u64;
            }
            _ => {}
        }
    }
    if groups.is_empty() {
        return Err(Error::Invalid(format!("no `{table_type}` sections found")));
    }
    Ok((groups, chunk_count))
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
        let size = if next_off < current_off {
            if next < current_off {
                return Err(Error::Invalid("table offsets out of order".to_string()));
            }
            (next - current_off) as u64
        } else {
            (next_off - current_off) as u64
        };
        start + size
    } else {
        group.chunk_data_end
    };
    Ok((start, end, is_compressed))
}

fn read_exact_at(file: &File, offset: u64, mut buf: &mut [u8]) -> io::Result<()> {
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
        cur += n as u64;
        buf = &mut buf[n..];
    }
    Ok(())
}

fn read_file_range(file: &File, file_len: u64, start: u64, end: u64) -> Result<Vec<u8>> {
    if end > file_len || start >= end {
        return Err(Error::Invalid("file range out of bounds".to_string()));
    }
    let len =
        usize::try_from(end - start).map_err(|_| Error::Invalid("range overflow".to_string()))?;
    let mut buf = vec![0u8; len];
    read_exact_at(file, start, &mut buf)?;
    Ok(buf)
}

fn parse_ascii_nul_terminated(bytes: &[u8]) -> String {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).to_string()
}

// === EWF2 writer (EWF2-Ex01 / EVF2) ===

#[derive(Debug, Clone, Copy)]
struct Ewf2Naming {
    first_character: char,
    additional_characters: char,
    maximum_number_of_segments: u32,
}

impl Ewf2Naming {
    fn from_path(path: &Path) -> Result<Self> {
        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        let first = ext.chars().next().unwrap_or('E');
        let additional = if first.is_ascii_uppercase() { 'A' } else { 'a' };

        Ok(Self {
            first_character: first,
            additional_characters: additional,
            maximum_number_of_segments: 2127, // .Ex01 .. .EzZZ
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

#[derive(Debug, Clone)]
struct Ewf2TableEntry {
    offset_raw: [u8; 8],
    size: u32,
    flags: u32,
}

/// Streaming writer for EWF2-Ex01 images.
///
/// This is a minimal, spec-driven writer intended to match libewf behavior for common Ex01 images:
/// - Sections are written in-order; section descriptors are written at the end of each section.
/// - A sector data section is followed by a sector table section in each segment.
/// - Non-last segments end with a `next` section; the last segment ends with `done`.
/// - The last segment also contains the global MD5 and SHA1 hash sections.
#[derive(Debug)]
pub struct Ewf2Writer {
    opts: Ewf2WriterOptions,
    base_path: PathBuf,
    naming: Ewf2Naming,

    bytes_per_sector: u32,
    sectors_per_chunk: u32,
    error_granularity: u32,
    number_of_sectors: u64,
    chunk_size: usize,
    chunk_count: u64,

    // Global progress.
    bytes_written: u64,
    chunks_written: u64,

    // Global hash of logical media bytes.
    md5: Md5,
    sha1: Sha1,

    // EWF2 set identifier (file header GUID-ish bytes).
    set_identifier: [u8; 16],

    // Current segment state.
    segment_number: u32,
    segment_first_chunk_index: u64,
    segment_target_chunks: u64,
    segment_chunks_written: u64,

    file: Option<File>,
    file_offset: u64,
    last_desc_offset: u64,

    // Current sector data section state (open while writing chunks).
    sector_data_start: u64,
    sector_data_md5: Md5,
    sector_data_padding_total: u32,

    // Sector table entries for this segment.
    table_entries: Vec<Ewf2TableEntry>,

    // Chunk buffering.
    chunk_buf: Vec<u8>,
    chunk_buf_len: usize,
}

impl Ewf2Writer {
    pub fn create(path: impl AsRef<Path>, opts: Ewf2WriterOptions) -> Result<Self> {
        let path = path.as_ref();
        if opts.media_size == 0 {
            return Err(Error::Invalid("media_size must be > 0".to_string()));
        }
        if opts.segment_file_size < 1024 {
            return Err(Error::Invalid(
                "segment_file_size is too small (must be >= 1024 bytes)".to_string(),
            ));
        }

        let bytes_per_sector = opts.bytes_per_sector;
        let sectors_per_chunk = opts.sectors_per_chunk;
        let chunk_size = checked_chunk_size(sectors_per_chunk, bytes_per_sector)?;
        let mut error_granularity = opts.error_granularity.unwrap_or(sectors_per_chunk);
        if error_granularity == 0 || error_granularity > sectors_per_chunk {
            error_granularity = sectors_per_chunk;
        }

        if !opts.media_size.is_multiple_of(bytes_per_sector as u64) {
            return Err(Error::Invalid(
                "EWF2 writer currently requires media_size to be a multiple of bytes_per_sector"
                    .to_string(),
            ));
        }

        let number_of_sectors = opts.media_size / bytes_per_sector as u64;
        let chunk_count = div_ceil_u64(number_of_sectors, sectors_per_chunk as u64);

        let base_path = remove_extension(path);
        let naming = Ewf2Naming::from_path(path)?;

        // Segment set identifier.
        let mut set_identifier = [0u8; 16];
        if let Some(id) = opts.set_identifier {
            set_identifier = id;
        } else {
            rand::rng().fill_bytes(&mut set_identifier);
        }

        let mut w = Self {
            opts,
            base_path,
            naming,
            bytes_per_sector,
            sectors_per_chunk,
            error_granularity,
            number_of_sectors,
            chunk_size,
            chunk_count,
            bytes_written: 0,
            chunks_written: 0,
            md5: Md5::new(),
            sha1: Sha1::new(),
            set_identifier,
            segment_number: 0,
            segment_first_chunk_index: 0,
            segment_target_chunks: 0,
            segment_chunks_written: 0,
            file: None,
            file_offset: 0,
            last_desc_offset: 0,
            sector_data_start: 0,
            sector_data_md5: Md5::new(),
            sector_data_padding_total: 0,
            table_entries: Vec::new(),
            chunk_buf: vec![0u8; chunk_size],
            chunk_buf_len: 0,
        };

        w.open_new_segment(1)?;
        Ok(w)
    }

    pub fn write(&mut self, mut buf: &[u8]) -> Result<usize> {
        if self.bytes_written >= self.opts.media_size {
            return Ok(0);
        }

        let mut total = 0usize;
        while !buf.is_empty() && self.bytes_written < self.opts.media_size {
            let remaining_media = (self.opts.media_size - self.bytes_written) as usize;
            let take = buf.len().min(remaining_media);
            let take_slice = &buf[..take];

            // Buffer into chunk buffer.
            let free = self.chunk_size.saturating_sub(self.chunk_buf_len);
            let copy = free.min(take);

            if copy == 0 {
                if self.chunk_buf_len == self.chunk_size {
                    self.flush_full_chunk()?;
                    continue;
                }
                return Err(Error::Invalid("ewf2 writer made no progress".to_string()));
            }

            // Hash only the bytes we actually consume.
            self.md5.update(&take_slice[..copy]);
            self.sha1.update(&take_slice[..copy]);
            self.bytes_written = self.bytes_written.saturating_add(copy as u64);

            self.chunk_buf[self.chunk_buf_len..self.chunk_buf_len + copy]
                .copy_from_slice(&take_slice[..copy]);
            self.chunk_buf_len += copy;

            total += copy;
            buf = &buf[copy..];

            if self.chunk_buf_len == self.chunk_size {
                self.flush_full_chunk()?;
            }
        }

        Ok(total)
    }

    pub fn finish(mut self) -> Result<()> {
        if self.bytes_written != self.opts.media_size {
            return Err(Error::Invalid(format!(
                "media size mismatch: expected={} wrote={}",
                self.opts.media_size, self.bytes_written
            )));
        }

        // Flush final partial chunk (padded with zeros on disk).
        if self.chunk_buf_len != 0 {
            self.chunk_buf[self.chunk_buf_len..].fill(0);
            self.chunk_buf_len = self.chunk_size;
            self.flush_full_chunk()?;
        }

        if self.chunks_written != self.chunk_count {
            return Err(Error::Invalid(format!(
                "chunk count mismatch at finalize: expected={} wrote={}",
                self.chunk_count, self.chunks_written
            )));
        }

        self.finalize_current_segment(true)?;
        Ok(())
    }

    // --- internals ---

    fn file_mut(&mut self) -> Result<&mut File> {
        self.file
            .as_mut()
            .ok_or_else(|| Error::Invalid("segment file is not open".to_string()))
    }

    fn open_new_segment(&mut self, segment_number: u32) -> Result<()> {
        self.segment_number = segment_number;
        self.segment_first_chunk_index = self.chunks_written;
        self.segment_chunks_written = 0;
        self.segment_target_chunks = 0;
        self.last_desc_offset = 0;
        self.table_entries.clear();
        self.sector_data_md5 = Md5::new();
        self.sector_data_padding_total = 0;

        let ext = self.naming.extension_for_segment(segment_number)?;
        let path = self.base_path.with_extension(ext);
        self.file = Some(File::create(&path)?);
        self.file_offset = 0;

        self.write_ewf2_file_header(segment_number)?;

        // Write device information + case data sections (compressed UTF-16 strings).
        self.write_ewf2_device_information_section()?;
        self.write_ewf2_case_data_section()?;

        // Start sector data section at current offset.
        self.sector_data_start = self.file_offset;

        // Determine how many chunks to put in this segment.
        let chunks_remaining = self.chunk_count.saturating_sub(self.chunks_written);
        if chunks_remaining == 0 {
            self.segment_target_chunks = 0;
            return Ok(());
        }

        let available = self.opts.segment_file_size.saturating_sub(self.file_offset);
        let max_here = self.max_chunks_for_segment(available, false)?;
        self.segment_target_chunks = chunks_remaining.min(max_here.max(1));

        Ok(())
    }

    fn max_chunks_for_segment(&self, available: u64, is_last_segment: bool) -> Result<u64> {
        // Reserve space for:
        // - sector data descriptor
        // - sector table section (header+footer+descriptor)
        // - next/done descriptor
        // - (optional) md5+sha1 sections on the last segment
        let mut reserved_fixed = (EWF2_SECTION_DESCRIPTOR_SIZE as u64) + // sector data descriptor
            (EWF2_TABLE_HEADER_SIZE as u64 + EWF2_TABLE_FOOTER_SIZE as u64) + // sector table data fixed
            (EWF2_SECTION_DESCRIPTOR_SIZE as u64) + // sector table descriptor
            (EWF2_SECTION_DESCRIPTOR_SIZE as u64); // next/done descriptor

        if is_last_segment {
            reserved_fixed = reserved_fixed
                .saturating_add((32 + EWF2_SECTION_DESCRIPTOR_SIZE) as u64) // md5 section (32 data + 64 desc)
                .saturating_add((32 + EWF2_SECTION_DESCRIPTOR_SIZE) as u64); // sha1 section
        }

        // Worst-case chunk storage sizing:
        // - zlib can expand slightly; use a conservative overhead
        // - add up to 15 bytes of alignment padding
        let per_chunk_data = (self.chunk_size as u64).saturating_add(80);
        let per_chunk_table = EWF2_TABLE_ENTRY_SIZE as u64;
        let per_chunk_total = per_chunk_data.saturating_add(per_chunk_table);

        if available <= reserved_fixed.saturating_add(per_chunk_total) {
            return Ok(1);
        }
        Ok((available - reserved_fixed) / per_chunk_total)
    }

    fn flush_full_chunk(&mut self) -> Result<()> {
        debug_assert_eq!(self.chunk_buf_len, self.chunk_size);

        if self.segment_target_chunks == 0 {
            self.open_new_segment(self.segment_number.max(1))?;
        }

        let chunk = self.chunk_buf.clone();
        self.write_ewf2_chunk(&chunk)?;

        self.chunk_buf_len = 0;
        self.chunks_written = self.chunks_written.saturating_add(1);
        self.segment_chunks_written = self.segment_chunks_written.saturating_add(1);

        // If we filled this segment and more chunks remain, finalize and open the next segment.
        if self.segment_chunks_written == self.segment_target_chunks
            && self.chunks_written < self.chunk_count
        {
            self.finalize_current_segment(false)?;
            let next = self.segment_number.saturating_add(1);
            self.open_new_segment(next)?;
        }

        Ok(())
    }

    fn write_ewf2_file_header(&mut self, segment_number: u32) -> Result<()> {
        let set_id = self.set_identifier;
        let compression_method = self.opts.compression_method.to_u16();
        let hdr = Ewf2FileHeader::new(Ewf2Kind::Ex01, compression_method, segment_number, set_id);

        let file = self.file_mut()?;
        file.write_all(&hdr.to_bytes())?;
        self.file_offset += EWF2_FILE_HEADER_SIZE as u64;
        Ok(())
    }

    fn write_ewf2_device_information_section(&mut self) -> Result<()> {
        let device_string = build_ewf2_device_information_string(
            self.number_of_sectors,
            self.bytes_per_sector,
            &self.opts.header_values,
        );
        let utf16 = encode_utf16le_with_bom(&device_string);
        let mut data = match self.opts.compression_method {
            Ewf2CompressionMethod::None => utf16,
            Ewf2CompressionMethod::Zlib => zlib_compress_bytes(&utf16)?,
            Ewf2CompressionMethod::Bzip2 => {
                return Err(Error::Unsupported(
                    "EWF2 bzip2 compression is not implemented yet".to_string(),
                ));
            }
        };
        let pad = pad16_bytes(&mut data);
        self.write_ewf2_section_with_descriptor(
            EWF2_SECTION_TYPE_DEVICE_INFORMATION,
            EWF2_SECTION_DATA_FLAG_MD5HASHED,
            pad,
            &data,
        )?;
        Ok(())
    }

    fn write_ewf2_case_data_section(&mut self) -> Result<()> {
        let case_string = build_ewf2_case_data_string(
            self.chunk_count,
            self.sectors_per_chunk,
            self.error_granularity,
            self.opts.compression_method.to_u16(),
            &self.opts.header_values,
        );
        let utf16 = encode_utf16le_with_bom(&case_string);
        let mut data = match self.opts.compression_method {
            Ewf2CompressionMethod::None => utf16,
            Ewf2CompressionMethod::Zlib => zlib_compress_bytes(&utf16)?,
            Ewf2CompressionMethod::Bzip2 => {
                return Err(Error::Unsupported(
                    "EWF2 bzip2 compression is not implemented yet".to_string(),
                ));
            }
        };
        let pad = pad16_bytes(&mut data);
        self.write_ewf2_section_with_descriptor(
            EWF2_SECTION_TYPE_CASE_DATA,
            EWF2_SECTION_DATA_FLAG_MD5HASHED,
            pad,
            &data,
        )?;
        Ok(())
    }

    fn write_ewf2_chunk(&mut self, chunk: &[u8]) -> Result<()> {
        // PATTERNFILL (for all-zero chunks) is a common EWF2 optimization.
        if self.opts.pattern_fill && chunk.iter().all(|&b| b == 0) {
            self.table_entries.push(Ewf2TableEntry {
                offset_raw: [0u8; 8], // pattern = 0
                size: 0,
                flags: EWF2_CHUNK_DATA_FLAG_COMPRESSED | EWF2_CHUNK_DATA_FLAG_PATTERNFILL,
            });
            return Ok(());
        }

        let data_offset = self.file_offset;

        let (stored, flags): (Vec<u8>, u32) = match self.opts.compression_method {
            Ewf2CompressionMethod::None => {
                // Uncompressed + Adler32 checksum.
                let mut v = Vec::with_capacity(self.chunk_size + 4);
                v.extend_from_slice(chunk);
                let checksum = adler32_rfc1950(chunk);
                v.extend_from_slice(&checksum.to_le_bytes());
                (v, EWF2_CHUNK_DATA_FLAG_CHECKSUMED)
            }
            Ewf2CompressionMethod::Zlib => {
                // Always compress; this matches libewf's behavior for formats that force compression.
                let z = zlib_compress_bytes(chunk)?;
                (z, EWF2_CHUNK_DATA_FLAG_COMPRESSED)
            }
            Ewf2CompressionMethod::Bzip2 => {
                return Err(Error::Unsupported(
                    "EWF2 bzip2 compression is not implemented yet".to_string(),
                ));
            }
        };

        let stored_len_u32: u32 = u32::try_from(stored.len())
            .map_err(|_| Error::Invalid("chunk stored size overflow".to_string()))?;

        // Write stored bytes to the sector data section.
        self.file_mut()?.write_all(&stored)?;
        self.sector_data_md5.update(&stored);
        self.file_offset = self.file_offset.saturating_add(stored.len() as u64);

        // Align each stored chunk to 16 bytes.
        let pad = ((16 - (stored.len() % 16)) % 16) as u32;
        if pad != 0 {
            let zeros = vec![0u8; pad as usize];
            self.file_mut()?.write_all(&zeros)?;
            self.sector_data_md5.update(&zeros);
            self.file_offset = self.file_offset.saturating_add(pad as u64);
            self.sector_data_padding_total = self.sector_data_padding_total.saturating_add(pad);
        }

        self.table_entries.push(Ewf2TableEntry {
            offset_raw: data_offset.to_le_bytes(),
            size: stored_len_u32,
            flags,
        });

        Ok(())
    }

    fn finalize_current_segment(&mut self, last_segment: bool) -> Result<()> {
        if self.file.is_none() {
            return Ok(());
        }

        // Close sector data section by writing its descriptor.
        let sector_data_size = self
            .file_offset
            .checked_sub(self.sector_data_start)
            .ok_or_else(|| Error::Invalid("invalid sector data size".to_string()))?;

        let sector_md5: [u8; 16] = self.sector_data_md5.clone().finalize().into();
        self.write_ewf2_section_descriptor_only(
            EWF2_SECTION_TYPE_SECTOR_DATA,
            EWF2_SECTION_DATA_FLAG_MD5HASHED,
            self.sector_data_padding_total,
            sector_data_size,
            sector_md5,
        )?;

        // Write sector table section.
        let table_data = build_ewf2_sector_table_section_data(
            self.segment_first_chunk_index,
            &self.table_entries,
        )?;
        self.write_ewf2_section_with_descriptor(
            EWF2_SECTION_TYPE_SECTOR_TABLE,
            EWF2_SECTION_DATA_FLAG_MD5HASHED,
            24, // libewf convention: 12 bytes after header + 12 bytes after footer
            &table_data,
        )?;

        if last_segment {
            self.write_ewf2_hash_sections()?;
            // Done marker (no data).
            self.write_ewf2_empty_section(EWF2_SECTION_TYPE_DONE)?;
        } else {
            self.write_ewf2_empty_section(EWF2_SECTION_TYPE_NEXT)?;
        }

        // Close file.
        self.file = None;
        Ok(())
    }

    fn write_ewf2_hash_sections(&mut self) -> Result<()> {
        let md5: [u8; 16] = self.md5.clone().finalize().into();
        let sha1: [u8; 20] = self.sha1.clone().finalize().into();

        let md5_data = build_ewf2_md5_section_data(&md5);
        self.write_ewf2_section_with_descriptor(
            EWF2_SECTION_TYPE_MD5_HASH,
            EWF2_SECTION_DATA_FLAG_MD5HASHED,
            12,
            &md5_data,
        )?;

        let sha1_data = build_ewf2_sha1_section_data(&sha1);
        self.write_ewf2_section_with_descriptor(
            EWF2_SECTION_TYPE_SHA1_HASH,
            EWF2_SECTION_DATA_FLAG_MD5HASHED,
            8,
            &sha1_data,
        )?;

        Ok(())
    }

    fn write_ewf2_empty_section(&mut self, section_type: u32) -> Result<()> {
        let empty_md5: [u8; 16] = Md5::new().finalize().into();
        self.write_ewf2_section_descriptor_only(section_type, 0, 0, 0, empty_md5)
    }

    fn write_ewf2_section_with_descriptor(
        &mut self,
        section_type: u32,
        data_flags: u32,
        padding_size_field: u32,
        data: &[u8],
    ) -> Result<()> {
        let md5_hash: [u8; 16] = if (data_flags & EWF2_SECTION_DATA_FLAG_MD5HASHED) != 0 {
            let mut h = Md5::new();
            h.update(data);
            h.finalize().into()
        } else {
            [0u8; 16]
        };

        self.file_mut()?.write_all(data)?;
        let desc_off = self.file_offset.saturating_add(data.len() as u64);
        self.file_offset = desc_off;

        let desc = make_ewf2_section_descriptor(
            section_type,
            data_flags,
            self.last_desc_offset,
            data.len() as u64,
            padding_size_field,
            md5_hash,
        );
        self.file_mut()?.write_all(&desc)?;
        self.last_desc_offset = desc_off;
        self.file_offset = self
            .file_offset
            .saturating_add(EWF2_SECTION_DESCRIPTOR_SIZE as u64);
        Ok(())
    }

    fn write_ewf2_section_descriptor_only(
        &mut self,
        section_type: u32,
        data_flags: u32,
        padding_size_field: u32,
        data_size: u64,
        md5_hash: [u8; 16],
    ) -> Result<()> {
        let desc_off = self.file_offset;
        let desc = make_ewf2_section_descriptor(
            section_type,
            data_flags,
            self.last_desc_offset,
            data_size,
            padding_size_field,
            md5_hash,
        );
        self.file_mut()?.write_all(&desc)?;
        self.last_desc_offset = desc_off;
        self.file_offset = self
            .file_offset
            .saturating_add(EWF2_SECTION_DESCRIPTOR_SIZE as u64);
        Ok(())
    }
}

fn make_ewf2_section_descriptor(
    section_type: u32,
    data_flags: u32,
    previous_offset: u64,
    data_size: u64,
    padding_size: u32,
    data_integrity_hash: [u8; 16],
) -> [u8; EWF2_SECTION_DESCRIPTOR_SIZE] {
    let mut raw = [0u8; EWF2_SECTION_DESCRIPTOR_SIZE];
    raw[0..4].copy_from_slice(&section_type.to_le_bytes());
    raw[4..8].copy_from_slice(&data_flags.to_le_bytes());
    raw[8..16].copy_from_slice(&previous_offset.to_le_bytes());
    raw[16..24].copy_from_slice(&data_size.to_le_bytes());
    raw[24..28].copy_from_slice(&(EWF2_SECTION_DESCRIPTOR_SIZE as u32).to_le_bytes());
    raw[28..32].copy_from_slice(&padding_size.to_le_bytes());
    raw[32..48].copy_from_slice(&data_integrity_hash);
    // raw[48..60] padding is left as zeros.
    let checksum = adler32_rfc1950(&raw[..EWF2_SECTION_DESCRIPTOR_SIZE - 4]);
    raw[EWF2_SECTION_DESCRIPTOR_SIZE - 4..].copy_from_slice(&checksum.to_le_bytes());
    raw
}

fn encode_utf16le_with_bom(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + s.len() * 2);
    out.extend_from_slice(&[0xff, 0xfe]);
    for u in s.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
}

fn zlib_compress_bytes(data: &[u8]) -> Result<Vec<u8>> {
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    enc.write_all(data)?;
    Ok(enc.finish()?)
}

fn pad16_bytes(data: &mut Vec<u8>) -> u32 {
    let pad = (16 - (data.len() % 16)) % 16;
    data.extend(std::iter::repeat_n(0u8, pad));
    pad as u32
}

fn build_ewf2_device_information_string(
    number_of_sectors: u64,
    bytes_per_sector: u32,
    _values: &EwfHeaderValues,
) -> String {
    // The EWF2 device information section is a serialized object string (UTF-16) that contains
    // device metadata. We write a minimal subset required for media geometry.
    format!("1\nmain\nts\tbp\tdt\tph\n{number_of_sectors}\t{bytes_per_sector}\tf\t1\n")
}

fn build_ewf2_case_data_string(
    chunk_count: u64,
    sectors_per_chunk: u32,
    error_granularity: u32,
    compression_method: u16,
    _values: &EwfHeaderValues,
) -> String {
    // Minimal EWF2 case data: chunk count and chunk geometry, plus error granularity and compression method.
    //
    // libewf’s case-data object string includes many more tags; we keep a small subset required for
    // `ewfinfo` and media geometry.
    format!("1\nmain\ntb\tcp\tsb\tgr\n{chunk_count}\t{compression_method}\t{sectors_per_chunk}\t{error_granularity}\n")
}

fn build_ewf2_sector_table_section_data(
    first_chunk_index: u64,
    entries: &[Ewf2TableEntry],
) -> Result<Vec<u8>> {
    let entries_len = u32::try_from(entries.len())
        .map_err(|_| Error::Invalid("sector table entry count overflow".to_string()))?;

    let mut out = Vec::with_capacity(
        EWF2_TABLE_HEADER_SIZE + (entries.len() * EWF2_TABLE_ENTRY_SIZE) + EWF2_TABLE_FOOTER_SIZE,
    );

    // Header (20 bytes) + 12 bytes alignment padding.
    let mut header = Vec::with_capacity(20);
    header.extend_from_slice(&first_chunk_index.to_le_bytes());
    header.extend_from_slice(&entries_len.to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes()); // unknown/padding
    let header_checksum = adler32_rfc1950(&header[..16]);
    header.extend_from_slice(&header_checksum.to_le_bytes());
    debug_assert_eq!(header.len(), 20);

    out.extend_from_slice(&header);
    out.extend(std::iter::repeat_n(0u8, 12));

    // Entries.
    let mut entries_bytes = Vec::with_capacity(entries.len() * EWF2_TABLE_ENTRY_SIZE);
    for e in entries {
        entries_bytes.extend_from_slice(&e.offset_raw);
        entries_bytes.extend_from_slice(&e.size.to_le_bytes());
        entries_bytes.extend_from_slice(&e.flags.to_le_bytes());
    }
    out.extend_from_slice(&entries_bytes);

    // Footer checksum (Adler32 of entries) + 12 bytes alignment padding.
    let footer_checksum = adler32_rfc1950(&entries_bytes);
    out.extend_from_slice(&footer_checksum.to_le_bytes());
    out.extend(std::iter::repeat_n(0u8, 12));

    Ok(out)
}

fn build_ewf2_md5_section_data(md5: &[u8; 16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(md5);
    let checksum = adler32_rfc1950(md5);
    out.extend_from_slice(&checksum.to_le_bytes());
    // Alignment padding: 12 bytes.
    out.extend(std::iter::repeat_n(0u8, 12));
    out
}

fn build_ewf2_sha1_section_data(sha1: &[u8; 20]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(sha1);
    let checksum = adler32_rfc1950(sha1);
    out.extend_from_slice(&checksum.to_le_bytes());
    // Alignment padding: 8 bytes.
    out.extend(std::iter::repeat_n(0u8, 8));
    out
}

fn ewf_error_to_io(err: Error) -> io::Error {
    match err {
        Error::Io(e) => e,
        other => io::Error::other(other.to_string()),
    }
}

impl std::io::Write for EwfWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        EwfWriter::write(self, buf).map_err(ewf_error_to_io)
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(f) = self.file.as_mut() {
            f.flush()?;
        }
        Ok(())
    }
}

impl std::io::Write for Ewf2Writer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ewf2Writer::write(self, buf).map_err(ewf_error_to_io)
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(f) = self.file.as_mut() {
            f.flush()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn test_writer_roundtrip_e01_single_segment() -> Result<()> {
        let start = Instant::now();
        let timeout = Duration::from_secs(10);
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("out.E01");

        let data = (0u8..=255).cycle().take(8192).collect::<Vec<u8>>();

        let mut opts = EwfWriterOptions::new(Ewf1Format::E01, data.len() as u64);
        opts.sectors_per_chunk = 1;
        opts.bytes_per_sector = 512;
        opts.segment_file_size = 10 * 1024 * 1024;

        let mut w = EwfWriter::create(&path, opts)?;
        let mut written = 0usize;
        while written < data.len() {
            if start.elapsed() > timeout {
                panic!("timeout: write loop exceeded {timeout:?}");
            }
            let n = w.write(&data[written..])?;
            assert!(n > 0, "writer.write made no progress");
            written += n;
        }
        w.finish()?;

        let r = crate::reader::EwfReader::open(&path)?;
        let mut out = vec![0u8; data.len()];
        r.read_exact_at(0, &mut out)?;
        assert_eq!(out, data);
        Ok(())
    }

    #[test]
    fn test_writer_roundtrip_e01_multi_segment() -> Result<()> {
        let start = Instant::now();
        let timeout = Duration::from_secs(10);
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("out.E01");

        let data = vec![0xABu8; 4096];
        let mut opts = EwfWriterOptions::new(Ewf1Format::E01, data.len() as u64);
        opts.sectors_per_chunk = 1;
        opts.bytes_per_sector = 512;
        // Force multiple segments by setting a tiny segment size.
        opts.segment_file_size = 2 * 1024;

        let mut w = EwfWriter::create(&path, opts)?;
        let mut written = 0usize;
        while written < data.len() {
            if start.elapsed() > timeout {
                panic!("timeout: write loop exceeded {timeout:?}");
            }
            let n = w.write(&data[written..])?;
            assert!(n > 0, "writer.write made no progress");
            written += n;
        }
        w.finish()?;

        // Open from the second segment path to exercise discovery.
        let r = crate::reader::EwfReader::open(dir.path().join("out.E02"))?;
        let mut out = vec![0u8; data.len()];
        r.read_exact_at(0, &mut out)?;
        assert_eq!(out, data);
        Ok(())
    }

    #[test]
    fn test_writer_roundtrip_s01_single_segment() -> Result<()> {
        let start = Instant::now();
        let timeout = Duration::from_secs(10);
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("out.s01");

        let data = (0u8..=255).cycle().take(4096).collect::<Vec<u8>>();
        let mut opts = EwfWriterOptions::new(Ewf1Format::S01, data.len() as u64);
        opts.sectors_per_chunk = 1;
        opts.bytes_per_sector = 512;
        opts.segment_file_size = 10 * 1024 * 1024;

        let mut w = EwfWriter::create(&path, opts)?;
        let mut written = 0usize;
        while written < data.len() {
            if start.elapsed() > timeout {
                panic!("timeout: write loop exceeded {timeout:?}");
            }
            let n = w.write(&data[written..])?;
            assert!(n > 0, "writer.write made no progress");
            written += n;
        }
        w.finish()?;

        let r = crate::reader::EwfReader::open(&path)?;
        let mut out = vec![0u8; data.len()];
        r.read_exact_at(0, &mut out)?;
        assert_eq!(out, data);
        Ok(())
    }

    #[test]
    fn test_writer_roundtrip_ex01_single_segment() -> Result<()> {
        let start = Instant::now();
        let timeout = Duration::from_secs(10);
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("out.Ex01");

        let data = (0u8..=255).cycle().take(8192).collect::<Vec<u8>>();

        let mut opts = Ewf2WriterOptions::new(data.len() as u64);
        opts.sectors_per_chunk = 1;
        opts.bytes_per_sector = 512;
        opts.segment_file_size = 10 * 1024 * 1024;
        opts.compression_method = Ewf2CompressionMethod::Zlib;

        let mut w = Ewf2Writer::create(&path, opts)?;
        let mut written = 0usize;
        while written < data.len() {
            if start.elapsed() > timeout {
                panic!("timeout: write loop exceeded {timeout:?}");
            }
            let n = w.write(&data[written..])?;
            assert!(n > 0, "writer.write made no progress");
            written += n;
        }
        w.finish()?;

        let r = crate::reader::EwfReader::open(&path)?;
        let mut out = vec![0u8; data.len()];
        r.read_exact_at(0, &mut out)?;
        assert_eq!(out, data);
        Ok(())
    }

    #[test]
    fn test_writer_roundtrip_ex01_multi_segment() -> Result<()> {
        let start = Instant::now();
        let timeout = Duration::from_secs(10);
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("out.Ex01");

        let data = vec![0xABu8; 4096];

        let mut opts = Ewf2WriterOptions::new(data.len() as u64);
        opts.sectors_per_chunk = 1;
        opts.bytes_per_sector = 512;
        // Force multiple segments by setting a tiny segment size.
        opts.segment_file_size = 2 * 1024;
        opts.compression_method = Ewf2CompressionMethod::Zlib;

        let mut w = Ewf2Writer::create(&path, opts)?;
        let mut written = 0usize;
        while written < data.len() {
            if start.elapsed() > timeout {
                panic!("timeout: write loop exceeded {timeout:?}");
            }
            let n = w.write(&data[written..])?;
            assert!(n > 0, "writer.write made no progress");
            written += n;
        }
        w.finish()?;

        // Open from the second segment path to exercise discovery.
        let r = crate::reader::EwfReader::open(dir.path().join("out.Ex02"))?;
        let mut out = vec![0u8; data.len()];
        r.read_exact_at(0, &mut out)?;
        assert_eq!(out, data);
        Ok(())
    }
}
