//! EWF1 `volume` / `disk` / `data` section parsing (metadata).
//!
//! This module is intentionally small and **format-focused**: it parses the raw bytes of the
//! “volume-like” section body into typed enums and values, without embedding display strings in the
//! parser itself.
//!
//! Reference material:
//! - `external/libewf/documentation/Expert Witness Compression Format (EWF).asciidoc`
//!   - “Volume section” (94-byte “EWF specification” variant; 1052-byte “EnCase/FTK” variant)
//!
//! ## Input format
//!
//! Callers must pass the **raw section body** bytes as stored in the EWF1 container (i.e. the
//! `data_range()` portion of an EWF1 section descriptor).
//!
//! The layout is a “volume-like” header used by multiple section types (`volume`, `disk`, and
//! sometimes `data`), with additional fields present in the EnCase/FTK “1052-byte volume” variant:
//!
//! - Offset `0x00` (`u8`): media type code
//! - Offset `0x08` (`u32` LE): sectors per chunk
//! - Offset `0x0c` (`u32` LE): bytes per sector
//! - Offset `0x10` (`u32` or `u64` LE): number of sectors
//!   - If the buffer is at least 24 bytes: interpret as `u64` at `0x10..0x18`
//!   - Otherwise: interpret as `u32` at `0x10..0x14`
//! - Offset `0x24` (`u8`): media flags (1052-byte variant; optional)
//! - Offset `0x34` (`u8`): compression level hint (1052-byte variant; optional)
//! - Offset `0x40..0x50` (`[u8; 16]`): set identifier (1052-byte variant; optional)
//!
//! Notes:
//! - This parser only models fields that are required for the `ewfinfo` report.
//! - Unknown codes are preserved via `Unknown(u8)` enum variants.

use std::fmt;

use crate::util::adler32_rfc1950;
use crate::{Error, Result};
use binrw::{BinRead as _, BinWrite as _, binrw};
use bitflags::bitflags;
use std::io::{Cursor, SeekFrom};

#[binrw]
#[brw(little)]
#[derive(Debug, Clone)]
struct RawEwf1VolumeLikeSectionBody {
    /// Byte 0: media type code (in the 1052-byte variant).
    ///
    /// In the 94-byte “spec” variant, this is part of a 4-byte reserved field that commonly holds
    /// `0x01 0x00 0x00 0x00`, which coincides with the “fixed disk” media type code.
    media_type_code: u8,
    #[brw(pad_after = 3)]
    _reserved0: (),

    _chunk_count: u32,
    sectors_per_chunk: u32,
    bytes_per_sector: u32,

    // EWF1 stores the sector count as either 32-bit (older variants) or 64-bit (newer ones).
    number_of_sectors_low: u32,
    #[br(try)]
    number_of_sectors_high: Option<u32>,

    // Fields below are specific to the 1052-byte EnCase/FTK/linen variant. We read them with
    // explicit offsets and tolerate missing data so this parser can operate on truncated inputs.
    #[br(try, seek_before = SeekFrom::Start(36))]
    media_flags_raw: Option<u8>,
    #[br(try, seek_before = SeekFrom::Start(52))]
    compression_level_raw: Option<u8>,
    #[br(try, seek_before = SeekFrom::Start(56))]
    error_granularity: Option<u32>,
    #[br(try, seek_before = SeekFrom::Start(64))]
    set_identifier_raw: Option<[u8; 16]>,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone)]
struct RawEwf1VolumeSectionE01_1052 {
    media_type_code: u8,
    #[brw(pad_after = 3)]
    _reserved0: (),
    chunk_count: u32,
    sectors_per_chunk: u32,
    bytes_per_sector: u32,
    number_of_sectors: u64,

    #[brw(pad_after = 12)]
    _reserved1: (),
    media_flags: u8,

    #[brw(pad_after = 15)]
    _reserved2: (),
    compression_level: u8,

    #[brw(pad_after = 3)]
    _reserved3: (),
    error_granularity: u32,

    #[brw(pad_after = 4)]
    _reserved4: (),
    #[brw(pad_after = 968)]
    set_identifier: [u8; 16],

    checksum: u32,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone)]
struct RawEwf1VolumeSectionS01_94 {
    reserved0_low: u8,
    #[brw(pad_after = 3)]
    _reserved0: (),
    chunk_count: u32,
    sectors_per_chunk: u32,
    bytes_per_sector: u32,
    number_of_sectors: u32,

    #[brw(pad_after = 65)]
    _reserved1: (),
    #[brw(magic = b"SMART")]
    _smart_signature: (),
    checksum: u32,
}

/// EWF1 media type code (byte 0 of the volume-like section body).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ewf1MediaType {
    RemovableDisk,
    FixedDisk,
    OpticalDisk,
    SingleFiles,
    MemoryRam,
    Unknown(u8),
}

impl Ewf1MediaType {
    pub(crate) fn from_code(code: u8) -> Self {
        match code {
            0x00 => Self::RemovableDisk,
            0x01 => Self::FixedDisk,
            0x03 => Self::OpticalDisk,
            0x0e => Self::SingleFiles,
            0x10 => Self::MemoryRam,
            other => Self::Unknown(other),
        }
    }
}

impl fmt::Display for Ewf1MediaType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Ewf1MediaType::RemovableDisk => "removable disk",
            Ewf1MediaType::FixedDisk => "fixed disk",
            Ewf1MediaType::OpticalDisk => "optical disk (CD/DVD/BD)",
            Ewf1MediaType::SingleFiles => "single files",
            Ewf1MediaType::MemoryRam => "memory (RAM)",
            Ewf1MediaType::Unknown(_) => "unknown",
        };
        f.write_str(s)
    }
}

bitflags! {
    /// EWF1 media flags byte (offset 36 in the 1052-byte variant).
    ///
    /// Unknown bits are preserved (see [`Ewf1MediaFlags::from_raw`]).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct Ewf1MediaFlags: u8 {
        /// libewf: `LIBEWF_MEDIA_FLAG_PHYSICAL`
        const PHYSICAL = 0x02;
    }
}

impl Ewf1MediaFlags {
    pub(crate) fn from_raw(raw: u8) -> Self {
        Self::from_bits_retain(raw)
    }

    pub(crate) fn is_physical(self) -> bool {
        self.contains(Self::PHYSICAL)
    }
}

/// Compression level hint byte (offset 52 in the 1052-byte variant).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ewf1VolumeCompressionLevel {
    NoCompression,
    GoodFastCompression,
    BestCompression,
    Unknown(u8),
    NotRecorded,
}

impl Ewf1VolumeCompressionLevel {
    pub(crate) fn from_optional_code(code: Option<u8>) -> Self {
        match code {
            Some(0x00) => Self::NoCompression,
            Some(0x01) => Self::GoodFastCompression,
            Some(0x02) => Self::BestCompression,
            Some(other) => Self::Unknown(other),
            None => Self::NotRecorded,
        }
    }
}

impl fmt::Display for Ewf1VolumeCompressionLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Ewf1VolumeCompressionLevel::NoCompression => "no compression",
            Ewf1VolumeCompressionLevel::GoodFastCompression => "good (fast) compression",
            Ewf1VolumeCompressionLevel::BestCompression => "best compression",
            Ewf1VolumeCompressionLevel::Unknown(_) | Ewf1VolumeCompressionLevel::NotRecorded => {
                "unknown compression"
            }
        };
        f.write_str(s)
    }
}

/// Parsed EWF1 volume-like section fields used by `ewfinfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ewf1VolumeInfo {
    pub(crate) sectors_per_chunk: u32,
    pub(crate) error_granularity: u32,
    pub(crate) bytes_per_sector: u32,
    pub(crate) number_of_sectors: u64,
    pub(crate) media_size: u64,
    pub(crate) compression_level: Ewf1VolumeCompressionLevel,
    pub(crate) set_identifier: Option<[u8; 16]>,
    pub(crate) media_type: Ewf1MediaType,
    pub(crate) is_physical: bool,
}

impl Ewf1VolumeInfo {
    /// Parse an EWF1 “volume-like” section **body**.
    ///
    /// The input must be the raw bytes of the `volume`/`disk`/`data` section body (not including
    /// the 76-byte section descriptor).
    pub(crate) fn parse_from_volume_like_section_body(data: &[u8]) -> Result<Self> {
        if data.len() < 20 {
            return Err(Error::Invalid(
                "short EWF1 volume-like section body".to_string(),
            ));
        }

        let raw = RawEwf1VolumeLikeSectionBody::read(&mut Cursor::new(data))
            .map_err(|e| Error::Invalid(format!("invalid EWF1 volume-like section body: {e}")))?;

        // The 1052-byte EnCase/FTK/linen variant stores `media_type` at byte 0.
        // The 94-byte “EWF specification” variant uses a 4-byte reserved field at offset 0 that
        // *contains* 0x01, which coincides with the “fixed disk” media type code. We keep that
        // behavior for compatibility.
        let media_type = Ewf1MediaType::from_code(raw.media_type_code);

        // NOTE: The `chunk_count` field exists at 0x04, but is currently unused by `ewfinfo`.
        // We still parse the geometry fields and sector count to compute media_size.
        let sectors_per_chunk = raw.sectors_per_chunk;
        let bytes_per_sector = raw.bytes_per_sector;

        if sectors_per_chunk == 0 || bytes_per_sector == 0 {
            return Err(Error::Invalid("invalid EWF1 volume parameters".to_string()));
        }

        // In EWF1 the sector count is 32-bit in older variants and 64-bit in newer ones.
        let number_of_sectors = if let Some(high) = raw.number_of_sectors_high {
            (u64::from(high) << 32) | u64::from(raw.number_of_sectors_low)
        } else {
            u64::from(raw.number_of_sectors_low)
        };

        let media_size = number_of_sectors
            .checked_mul(bytes_per_sector as u64)
            .ok_or_else(|| Error::Invalid("media size overflow".to_string()))?;

        let is_1052_variant = data.len() >= 1052;

        // Media flags live at offset 36 in the 1052-byte EnCase/FTK/linen volume variant.
        let media_flags = if is_1052_variant {
            raw.media_flags_raw.map(Ewf1MediaFlags::from_raw)
        } else {
            None
        };
        let is_physical = media_flags.map(|f| f.is_physical()).unwrap_or(false);

        // Sector error granularity lives at offset 56 in the 1052-byte EnCase/FTK/linen volume variant.
        let error_granularity = if is_1052_variant {
            raw.error_granularity.unwrap_or(0)
        } else {
            0
        };

        // Compression level at offset 52 for the 1052-byte variant.
        let compression_level = if is_1052_variant {
            Ewf1VolumeCompressionLevel::from_optional_code(raw.compression_level_raw)
        } else {
            Ewf1VolumeCompressionLevel::NotRecorded
        };

        // Set identifier is stored at [64..80] in the 1052-byte volume variant.
        let set_identifier = if is_1052_variant {
            raw.set_identifier_raw
                .and_then(|id| (id.iter().any(|&b| b != 0)).then_some(id))
        } else {
            None
        };

        Ok(Self {
            sectors_per_chunk,
            error_granularity,
            bytes_per_sector,
            number_of_sectors,
            media_size,
            compression_level,
            set_identifier,
            media_type,
            is_physical,
        })
    }
}

pub(crate) fn build_volume_section_e01_1052(
    chunk_count: u64,
    sectors_per_chunk: u32,
    error_granularity: u32,
    bytes_per_sector: u32,
    number_of_sectors: u64,
    compression_level: u8,
    set_identifier: [u8; 16],
) -> Vec<u8> {
    // FTK Imager / EnCase 1–7 / linen volume (1052 bytes) variant.
    //
    // See `external/libewf/documentation/Expert Witness Compression Format (EWF).asciidoc`:
    // “Volume section” → “FTK Imager, EnCase 1 to 7 and linen 5 to 7 (EWF-E01)”.
    let v = RawEwf1VolumeSectionE01_1052 {
        media_type_code: 0x01, // fixed media
        _reserved0: (),
        chunk_count: chunk_count as u32,
        sectors_per_chunk,
        bytes_per_sector,
        number_of_sectors,
        _reserved1: (),
        media_flags: 0x01, // “is an image file”
        _reserved2: (),
        compression_level,
        _reserved3: (),
        error_granularity,
        _reserved4: (),
        set_identifier,
        checksum: 0,
    };

    let mut out = vec![0u8; 1052];
    v.write(&mut Cursor::new(&mut out[..]))
        .expect("in-memory write cannot fail");
    let checksum = adler32_rfc1950(&out[..1048]).to_le_bytes();
    out[1048..1052].copy_from_slice(&checksum);
    out
}

pub(crate) fn build_volume_section_s01_94(
    chunk_count: u64,
    sectors_per_chunk: u32,
    bytes_per_sector: u32,
    number_of_sectors: u64,
) -> Vec<u8> {
    // EWF specification (94 bytes) variant used by SMART (EWF-S01).
    //
    // See `external/libewf/documentation/Expert Witness Compression Format (EWF).asciidoc`:
    // “Volume section” → “EWF specification” and “SMART (EWF-S01)”.
    let v = RawEwf1VolumeSectionS01_94 {
        reserved0_low: 0x01,
        _reserved0: (),
        chunk_count: chunk_count as u32,
        sectors_per_chunk,
        bytes_per_sector,
        number_of_sectors: number_of_sectors as u32,
        _reserved1: (),
        _smart_signature: (),
        checksum: 0,
    };

    let mut out = vec![0u8; 94];
    v.write(&mut Cursor::new(&mut out[..]))
        .expect("in-memory write cannot fail");
    let checksum = adler32_rfc1950(&out[..90]).to_le_bytes();
    out[90..94].copy_from_slice(&checksum);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_volume_like_section_body_64bit_sector_count() {
        let mut data = [0u8; 24];
        data[0] = 0x01; // fixed disk
        data[8..12].copy_from_slice(&64u32.to_le_bytes());
        data[12..16].copy_from_slice(&512u32.to_le_bytes());
        data[16..24].copy_from_slice(&2880u64.to_le_bytes());

        let v = Ewf1VolumeInfo::parse_from_volume_like_section_body(&data).unwrap();
        assert_eq!(v.sectors_per_chunk, 64);
        assert_eq!(v.error_granularity, 0);
        assert_eq!(v.bytes_per_sector, 512);
        assert_eq!(v.number_of_sectors, 2880);
        assert_eq!(v.media_size, 2880u64 * 512);
        assert_eq!(v.media_type.to_string(), "fixed disk");
        assert!(!v.is_physical);
        assert_eq!(v.compression_level.to_string(), "unknown compression");
        assert!(v.set_identifier.is_none());
    }

    #[test]
    fn test_parse_volume_like_section_body_32bit_sector_count() {
        let mut data = [0u8; 20];
        data[0] = 0x00; // removable disk
        data[8..12].copy_from_slice(&1u32.to_le_bytes());
        data[12..16].copy_from_slice(&512u32.to_le_bytes());
        data[16..20].copy_from_slice(&2880u32.to_le_bytes());

        let v = Ewf1VolumeInfo::parse_from_volume_like_section_body(&data).unwrap();
        assert_eq!(v.number_of_sectors, 2880);
        assert_eq!(v.media_type.to_string(), "removable disk");
    }

    #[test]
    fn test_parse_volume_like_section_body_variant_fields_flags_compression_set_id() {
        let mut data = vec![0u8; 1052];
        data[0] = 0x03; // optical disk
        data[8..12].copy_from_slice(&32u32.to_le_bytes());
        data[12..16].copy_from_slice(&2048u32.to_le_bytes());
        data[16..24].copy_from_slice(&10u64.to_le_bytes());
        data[36] = 0x02; // physical flag
        data[52] = 0x02; // best compression
        data[56..60].copy_from_slice(&7u32.to_le_bytes()); // error granularity

        let set_id: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        data[64..80].copy_from_slice(&set_id);

        let v = Ewf1VolumeInfo::parse_from_volume_like_section_body(&data).unwrap();
        assert_eq!(v.media_type.to_string(), "optical disk (CD/DVD/BD)");
        assert!(v.is_physical);
        assert_eq!(v.compression_level.to_string(), "best compression");
        assert_eq!(v.error_granularity, 7);
        assert_eq!(v.set_identifier, Some(set_id));
    }

    #[test]
    fn test_parse_volume_like_section_body_rejects_zero_geometry() {
        let mut data = [0u8; 24];
        data[8..12].copy_from_slice(&0u32.to_le_bytes());
        data[12..16].copy_from_slice(&512u32.to_le_bytes());
        data[16..24].copy_from_slice(&1u64.to_le_bytes());

        let err = Ewf1VolumeInfo::parse_from_volume_like_section_body(&data).unwrap_err();
        assert!(matches!(err, Error::Invalid(_)));
    }

    #[test]
    fn test_parse_volume_like_section_body_rejects_too_short() {
        let data = [0u8; 19];
        let err = Ewf1VolumeInfo::parse_from_volume_like_section_body(&data).unwrap_err();
        assert!(matches!(err, Error::Invalid(_)));
    }
}
