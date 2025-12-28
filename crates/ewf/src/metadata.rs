//! Spec-oriented metadata extracted from EWF images.
//!
//! This module is intentionally **format/spec** focused. It exposes structured metadata that can be
//! consumed by binaries (like `ewfinfo`) or other library users without coupling the `ewf` crate to
//! libewf’s CLI/reporting surface area.
//!
//! In particular:
//! - Types here model *what is in the image* (or what can be inferred from it).
//! - Formatting and presentation (labels, wrapping, date formatting, etc.) belongs to binaries.

use std::path::PathBuf;

use crate::{EwfCompression, EwfFileFormat, EwfFormat};

/// A contiguous run expressed in logical sectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectorRun {
    /// Start sector index (LBA).
    pub start_sector: u64,
    /// Number of sectors in the run.
    pub sector_count: u64,
}

/// High-level media type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaType {
    RemovableDisk,
    FixedDisk,
    OpticalDisk,
    SingleFiles,
    MemoryRam,
    Unknown,
}

/// A coarse compression “level” indicator used by some EWF1 variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionLevel {
    NoCompression,
    GoodFastCompression,
    BestCompression,
    Unknown,
    NotRecorded,
}

/// Header (acquiry) values extracted from EWF1 header sections.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeaderValues {
    pub case_number: Option<String>,
    pub evidence_number: Option<String>,
    pub description: Option<String>,
    pub examiner_name: Option<String>,
    pub notes: Option<String>,
    pub acquisition_datetime: Option<String>,
    pub system_datetime: Option<String>,
    pub acquisition_os: Option<String>,
    pub acquisition_software: Option<String>,
    pub acquisition_software_version: Option<String>,
    /// A password/hash value if present. Absence means “not set”.
    pub password: Option<String>,
}

/// Image-level digests (when present).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImageDigests {
    pub md5: Option<[u8; 16]>,
    pub sha1: Option<[u8; 20]>,
}

/// Metadata extracted from an EWF image set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageMetadata {
    pub format: EwfFormat,
    /// libewf-compatible file format classification.
    pub file_format: EwfFileFormat,
    pub segment_paths: Vec<PathBuf>,

    /// Segment file version (EWF2/EVF2 only).
    pub segment_file_version: Option<(u16, u16)>,

    pub sectors_per_chunk: u32,
    /// The number of sectors used as error granularity (0 if not recorded).
    pub error_granularity: u32,
    pub bytes_per_sector: u32,
    pub number_of_sectors: u64,
    pub media_size: u64,

    pub media_type: MediaType,
    pub is_physical: bool,

    pub compression_method: EwfCompression,
    pub compression_level: CompressionLevel,
    pub set_identifier: Option<[u8; 16]>,

    pub header_values: HeaderValues,
    pub digests: ImageDigests,

    pub sessions: Vec<SectorRun>,
    pub tracks: Vec<SectorRun>,
    pub acquisition_read_errors: Vec<SectorRun>,
}
