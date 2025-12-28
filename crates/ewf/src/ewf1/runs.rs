//! EWF1 run-list sections (`session`, `error2`).
//!
//! These sections encode lists of sector runs:
//! - `session`: optical media session boundaries (start sectors).
//! - `error2`: acquisition read error sector ranges.
//!
//! References:
//! - `external/libewf/documentation/Expert Witness Compression Format (EWF).asciidoc`
//! - libewf implementation:
//!   - `external/libewf/libewf/libewf_session_section.c`
//!   - `external/libewf/libewf/libewf_error2_section.c`

use crate::metadata::SectorRun;
use crate::{Error, Result};
use binrw::{BinRead as _, binrw};
use std::io::Cursor;

#[binrw]
#[brw(little)]
#[derive(Debug, Clone)]
struct RawEwf1SessionSection {
    count: u32,
    #[brw(pad_after = 32)]
    _header_padding: (),
    #[br(count = count)]
    entries: Vec<RawEwf1SessionEntry>,
    checksum: u32,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone)]
struct RawEwf1SessionEntry {
    _unknown0: u32,
    start_sector: u32,
    #[brw(pad_after = 24)]
    _reserved: (),
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone)]
struct RawEwf1Error2Section {
    count: u32,
    #[brw(pad_after = 516)]
    _header_padding: (),
    #[br(count = count)]
    entries: Vec<RawEwf1Error2Entry>,
    checksum: u32,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone)]
struct RawEwf1Error2Entry {
    start_sector: u32,
    sector_count: u32,
}

/// EWF1 `session` section parser.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Ewf1SessionSection<'a> {
    data: &'a [u8],
}

impl<'a> Ewf1SessionSection<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Parse session runs.
    ///
    /// The section stores a list of session start sectors; the run length is derived from the next
    /// start (or from `total_sectors` for the last run).
    pub(crate) fn runs(self, total_sectors: u64) -> Result<Vec<SectorRun>> {
        let raw = RawEwf1SessionSection::read(&mut Cursor::new(self.data))
            .map_err(|e| Error::Invalid(format!("invalid EWF1 session section: {e}")))?;

        let mut starts: Vec<u64> = Vec::with_capacity(raw.entries.len());
        for e in raw.entries {
            starts.push(u64::from(e.start_sector));
        }

        let mut runs: Vec<SectorRun> = Vec::with_capacity(starts.len());
        for (i, start) in starts.iter().copied().enumerate() {
            let sector_count = if let Some(next) = starts.get(i + 1).copied() {
                next.saturating_sub(start)
            } else {
                total_sectors.saturating_sub(start)
            };
            runs.push(SectorRun {
                start_sector: start,
                sector_count,
            });
        }
        Ok(runs)
    }
}

/// EWF1 `error2` section parser.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Ewf1Error2Section<'a> {
    data: &'a [u8],
}

impl<'a> Ewf1Error2Section<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub(crate) fn runs(self) -> Result<Vec<SectorRun>> {
        let raw = RawEwf1Error2Section::read(&mut Cursor::new(self.data))
            .map_err(|e| Error::Invalid(format!("invalid EWF1 error2 section: {e}")))?;

        Ok(raw
            .entries
            .into_iter()
            .map(|e| SectorRun {
                start_sector: u64::from(e.start_sector),
                sector_count: u64::from(e.sector_count),
            })
            .collect())
    }
}
