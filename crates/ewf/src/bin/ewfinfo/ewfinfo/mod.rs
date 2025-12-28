//! `ewfinfo`-style reporting for **image** (disk) EWF sets.
//!
//! This module provides a Rust-native, strongly-typed “report + rendering” API intended to back an
//! `ewfinfo`-compatible CLI. The CLI is expected to be responsible for argument parsing (clap),
//! selecting which sections to print (e.g. `-i`/`-m`/`-e`), and for **logical evidence** outputs
//! (`-F`/`-H`/`-B`). The `ewf` library only exposes spec-oriented metadata extraction; this module
//! owns the *image metadata* report model and renderers.
//!
//! ## Compatibility notes
//!
//! - The section structure and formatting are based on libewf’s `ewfinfo` implementation, but the
//!   data model here is not a 1:1 port of libewf’s `info_handle_t`. Instead, the library exposes
//!   stable Rust types that the application can map its CLI options into.
//! - DFXML output is **schema-aligned** (DFXML Working Group) and therefore intentionally differs
//!   from libewf’s historic “DFXML” output (which uses an `ewfobjects` root).
//! - Any unsupported surface area must return an explicit [`EwfInfoError::Unsupported`] with a
//!   clear `TODO:` marker rather than silently degrading behavior.
//!
//! ## References
//!
//! - `external/libewf/ewftools/info_handle.h`
//! - `external/libewf/ewftools/info_handle.c`
//! - `external/libewf/ewftools/ewfinfo.c`
//! - `external/libewf/manuals/ewfinfo.1`
//! - `external/refs/repos/dfxml-working-group__dfxml_schema.commit`
//! - `crates/dfxml/schema/dfxml.xsd`
//!
//! ## Where it is used
//!
//! The `ewfinfo` binary wires this module up in `crates/ewf/src/bin/ewfinfo/cli.rs`.

mod print_dfxml;
mod print_text;

use std::fmt;

/// Error type for `ewfinfo` report building and printing.
///
/// This error is intended for **library** usage, and uses `thiserror` for structured errors.
#[derive(Debug, thiserror::Error)]
pub enum EwfInfoError {
    /// The underlying EWF reader returned an error.
    #[error(transparent)]
    EwF(#[from] ewf::Error),

    /// The operation is not supported yet.
    ///
    /// This variant is intentionally used for explicit, user-visible `TODO:` gaps when porting
    /// libewf behavior.
    #[error("unsupported: {0}")]
    #[allow(dead_code)]
    Unsupported(String),

    /// The report data is internally inconsistent (should generally be treated as a bug).
    #[error("invalid ewfinfo report: {0}")]
    InvalidReport(String),
}

/// Result type used by this module.
pub type EwfInfoResult<T> = std::result::Result<T, EwfInfoError>;

/// Header codepage for decoding EWF1 `header` section strings.
///
/// libewf exposes this via `ewfinfo -A`; see `external/libewf/manuals/ewfinfo.1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HeaderCodepage {
    /// ASCII (libewf default).
    #[default]
    Ascii,
    Windows874,
    Windows932,
    Windows936,
    Windows949,
    Windows950,
    Windows1250,
    Windows1251,
    Windows1252,
    Windows1253,
    Windows1254,
    Windows1255,
    Windows1256,
    Windows1257,
    Windows1258,
}

/// Date formatting mode used when printing timestamps.
///
/// This corresponds to `ewfinfo -d` (`ctime`, `dm`, `md`, `iso8601`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EwfInfoDateFormat {
    /// libewf default.
    #[default]
    Ctime,
    /// Day/month (`dm`).
    DayMonth,
    /// Month/day (`md`).
    MonthDay,
    /// ISO-8601.
    Iso8601,
}

/// ANSI color mode for text output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EwfInfoColorMode {
    /// Never emit ANSI escape sequences.
    ///
    /// This is the default to keep unit tests and golden outputs deterministic.
    #[default]
    Never,
    /// Emit colors only when stdout is a terminal (and `NO_COLOR` is not set).
    Auto,
    /// Always emit colors (even when redirected).
    #[allow(dead_code)]
    Always,
}

/// Options that affect how an [`EwfInfoReport`] is printed (formatting).
#[derive(Debug, Clone, Default)]
pub struct EwfInfoPrintOptions {
    /// Date format (`ewfinfo -d`).
    pub date_format: EwfInfoDateFormat,

    /// Which logical section set to render (maps to libewf `ewfinfo`’s `-i`/`-m`/`-e` flags).
    pub sections: EwfInfoSections,

    /// ANSI color mode for text output.
    pub color: EwfInfoColorMode,
}

/// Selects which report sections to render.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EwfInfoSections {
    /// Render the full report (libewf `info_option == 'a'`).
    #[default]
    All,
    /// Render only acquisition/header values (libewf `info_option == 'i'`).
    AcquiryOnly,
    /// Render only media-related information (libewf `info_option == 'm'`).
    MediaOnly,
    /// Render only acquisition read errors (libewf `info_option == 'e'`).
    ErrorsOnly,
}

/// A typed `ewfinfo` report for image metadata.
///
/// The report is designed so that rendering can reproduce libewf `ewfinfo` output deterministically
/// (including section ordering).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EwfInfoReport {
    /// Image filenames (segment set) used in DFXML output.
    pub image_filenames: Vec<String>,

    /// Human-oriented acquisition/header values (aka “Acquiry information”).
    pub acquiry_information: Vec<InfoField>,

    /// EWF format information (“EWF information”).
    pub ewf_information: Vec<InfoField>,

    /// Media geometry/flags (“Media information”).
    pub media_information: Vec<InfoField>,

    /// Stored digest hashes (“Digest hash information”).
    pub digest_hash_information: Vec<InfoField>,

    /// Session runs (may be empty).
    pub sessions: Vec<ewf::metadata::SectorRun>,

    /// Track runs (may be empty).
    pub tracks: Vec<ewf::metadata::SectorRun>,

    /// Acquisition read error runs (may be empty).
    pub acquisition_read_errors: Vec<ewf::metadata::SectorRun>,

    /// Bytes per sector used when printing runs.
    pub bytes_per_sector: u32,
}

impl EwfInfoReport {
    /// Build a report from spec-oriented image metadata.
    pub fn from_image_metadata(meta: &ewf::metadata::ImageMetadata) -> EwfInfoResult<Self> {
        use ewf::metadata::{CompressionLevel, MediaType};
        use ewf::{EwfCompression, EwfFormat};

        let image_filenames: Vec<String> = meta
            .segment_paths
            .iter()
            .map(|p| p.display().to_string())
            .collect();

        let is_ewf1 = matches!(meta.format, EwfFormat::E01 | EwfFormat::S01);

        // Acquiry information is only available for EWF1 header sections.
        let mut acquiry_information: Vec<InfoField> = Vec::new();
        if is_ewf1 {
            push_string_field(
                &mut acquiry_information,
                "case_number",
                "Case number",
                meta.header_values.case_number.as_deref(),
            );
            push_string_field(
                &mut acquiry_information,
                "description",
                "Description",
                meta.header_values.description.as_deref(),
            );
            push_string_field(
                &mut acquiry_information,
                "examiner_name",
                "Examiner name",
                meta.header_values.examiner_name.as_deref(),
            );
            push_string_field(
                &mut acquiry_information,
                "evidence_number",
                "Evidence number",
                meta.header_values.evidence_number.as_deref(),
            );
            push_string_field(
                &mut acquiry_information,
                "notes",
                "Notes",
                meta.header_values.notes.as_deref(),
            );
            push_string_field(
                &mut acquiry_information,
                "acquiry_date",
                "Acquisition date",
                meta.header_values.acquisition_datetime.as_deref(),
            );
            push_string_field(
                &mut acquiry_information,
                "system_date",
                "System date",
                meta.header_values.system_datetime.as_deref(),
            );
            push_string_field(
                &mut acquiry_information,
                "acquiry_operating_system",
                "Operating system used",
                meta.header_values.acquisition_os.as_deref(),
            );
            push_string_field(
                &mut acquiry_information,
                "acquiry_software",
                "Software used",
                meta.header_values.acquisition_software.as_deref(),
            );
            push_string_field(
                &mut acquiry_information,
                "acquiry_software_version",
                "Software version used",
                meta.header_values.acquisition_software_version.as_deref(),
            );

            // Password is special in libewf; we store the raw value (empty means “not set”).
            acquiry_information.push(InfoField {
                identifier: "password",
                description: "Password",
                value: InfoValue::String(meta.header_values.password.clone().unwrap_or_default()),
            });
        }

        let file_format_str = meta.file_format.to_string();

        let compression_method_str = match meta.compression_method {
            EwfCompression::None => "none",
            EwfCompression::Zlib => "deflate",
            EwfCompression::Bzip2 => "bzip2",
            EwfCompression::Unknown(_) => "unknown",
        };

        let compression_level_str = match meta.compression_level {
            CompressionLevel::NoCompression => "no compression",
            CompressionLevel::GoodFastCompression => "good (fast) compression",
            CompressionLevel::BestCompression => "best compression",
            CompressionLevel::Unknown => "unknown compression",
            CompressionLevel::NotRecorded => "not recorded",
        };

        let mut ewf_information: Vec<InfoField> = Vec::new();
        ewf_information.push(InfoField {
            identifier: "file_format",
            description: "File format",
            value: InfoValue::String(file_format_str),
        });
        if let Some((maj, min)) = meta.segment_file_version {
            ewf_information.push(InfoField {
                identifier: "segment_file_version",
                description: "Segment file version",
                value: InfoValue::String(format!("{maj}.{min}")),
            });
        }
        ewf_information.push(InfoField {
            identifier: "sectors_per_chunk",
            description: "Sectors per chunk",
            value: InfoValue::U32(meta.sectors_per_chunk),
        });
        ewf_information.push(InfoField {
            identifier: "error_granularity",
            description: "Error granularity",
            value: InfoValue::U32(meta.error_granularity),
        });
        ewf_information.push(InfoField {
            identifier: "compression_method",
            description: "Compression method",
            value: InfoValue::String(compression_method_str.to_string()),
        });
        ewf_information.push(InfoField {
            identifier: "compression_level",
            description: "Compression level",
            value: InfoValue::String(compression_level_str.to_string()),
        });
        if let Some(set_id) = meta.set_identifier {
            ewf_information.push(InfoField {
                identifier: "set_identifier",
                description: "Set identifier",
                value: InfoValue::String(format_guid_le(&set_id)),
            });
        }

        let media_type_str = match meta.media_type {
            MediaType::RemovableDisk => "removable disk",
            MediaType::FixedDisk => "fixed disk",
            MediaType::OpticalDisk => "optical disk (CD/DVD/BD)",
            MediaType::SingleFiles => "single files",
            MediaType::MemoryRam => "memory (RAM)",
            MediaType::Unknown => "unknown",
        };

        let media_information: Vec<InfoField> = vec![
            InfoField {
                identifier: "media_type",
                description: "Media type",
                value: InfoValue::String(media_type_str.to_string()),
            },
            InfoField {
                identifier: "is_physical",
                description: "Is physical",
                value: InfoValue::Bool(meta.is_physical),
            },
            InfoField {
                identifier: "bytes_per_sector",
                description: "Bytes per sector",
                value: InfoValue::U32(meta.bytes_per_sector),
            },
            InfoField {
                identifier: "number_of_sectors",
                description: "Number of sectors",
                value: InfoValue::U64(meta.number_of_sectors),
            },
            InfoField {
                identifier: "media_size",
                description: "Media size",
                value: InfoValue::Size(meta.media_size),
            },
        ];

        let mut digest_hash_information: Vec<InfoField> = Vec::new();
        if let Some(md5) = meta.digests.md5 {
            digest_hash_information.push(InfoField {
                identifier: "md5",
                description: "MD5",
                value: InfoValue::String(hex_lower(&md5)),
            });
        }
        if let Some(sha1) = meta.digests.sha1 {
            digest_hash_information.push(InfoField {
                identifier: "sha1",
                description: "SHA1",
                value: InfoValue::String(hex_lower(&sha1)),
            });
        }

        Ok(EwfInfoReport {
            image_filenames,
            acquiry_information,
            ewf_information,
            media_information,
            digest_hash_information,
            sessions: meta.sessions.clone(),
            tracks: meta.tracks.clone(),
            acquisition_read_errors: meta.acquisition_read_errors.clone(),
            bytes_per_sector: meta.bytes_per_sector,
        })
    }

    /// Render the report as a human-friendly text report.
    ///
    /// Unlike the binary formats, the text output is not intended to be 1:1 compatible with
    /// libewf’s historical `ewfinfo` formatting.
    pub fn to_text(&self, options: &EwfInfoPrintOptions) -> EwfInfoResult<String> {
        print_text::render_text(self, options)
    }

    /// Render the report as schema-aligned DFXML (DFXML 2.0.0-beta.0).
    pub fn to_dfxml(&self, options: &EwfInfoPrintOptions) -> EwfInfoResult<String> {
        print_dfxml::render_dfxml(self, options)
    }
}

/// A single field/value printed inside a section.
///
/// The `identifier` is used for DFXML element naming (it matches libewf’s identifiers), while the
/// `description` is used for text output labels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfoField {
    /// DFXML identifier (e.g. `case_number`, `bytes_per_sector`).
    pub identifier: &'static str,
    /// Text label (e.g. `Case number`, `Bytes per sector`).
    pub description: &'static str,
    /// Field value (typed).
    pub value: InfoValue,
}

/// Field value variants needed to reproduce libewf formatting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InfoValue {
    /// Arbitrary string value.
    String(String),
    /// Unsigned 32-bit integer.
    U32(u32),
    /// Unsigned 64-bit integer.
    U64(u64),
    /// Size value in bytes (text output prints human-readable MiB + bytes).
    Size(u64),
    /// Boolean (“yes”/“no”).
    Bool(bool),
}

fn push_string_field(
    dst: &mut Vec<InfoField>,
    identifier: &'static str,
    description: &'static str,
    value: Option<&str>,
) {
    let Some(value) = value else {
        return;
    };
    if value.is_empty() {
        return;
    }
    dst.push(InfoField {
        identifier,
        description,
        value: InfoValue::String(value.to_string()),
    });
}

fn hex_lower(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(TABLE[(b >> 4) as usize] as char);
        out.push(TABLE[(b & 0x0f) as usize] as char);
    }
    out
}

fn format_guid_le(guid: &[u8; 16]) -> String {
    // Matches libewf’s little-endian GUID formatting used by `ewfinfo` for set identifiers.
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        guid[3],
        guid[2],
        guid[1],
        guid[0],
        guid[5],
        guid[4],
        guid[7],
        guid[6],
        guid[8],
        guid[9],
        guid[10],
        guid[11],
        guid[12],
        guid[13],
        guid[14],
        guid[15]
    )
}

fn ensure_bytes_per_sector(report: &EwfInfoReport) -> EwfInfoResult<u32> {
    if report.bytes_per_sector == 0 {
        return Err(EwfInfoError::InvalidReport(
            "bytes_per_sector must be non-zero".to_string(),
        ));
    }
    Ok(report.bytes_per_sector)
}

fn format_bool_yes_no(v: bool) -> &'static str {
    if v { "yes" } else { "no" }
}

fn format_size_mib(bytes: u64) -> String {
    // Mirrors libewf’s `byte_size_string_create(..., MEBIBYTE)` behavior: choose a MiB unit.
    // We keep it simple (no locale), and fall back to raw bytes where formatting is ambiguous.
    //
    // NOTE: This is intentionally deterministic; we do not attempt “smart” unit switching.
    let mib = 1024u64 * 1024u64;
    if bytes < mib {
        return format!("{bytes} bytes");
    }
    let value = (bytes as f64) / (mib as f64);
    // libewf prints e.g. "1.4 MiB" for 1474560. That is one decimal for non-integer values.
    let s = if (value - value.round()).abs() < f64::EPSILON {
        format!("{:.0} MiB", value)
    } else {
        format!("{:.1} MiB", value)
    };
    format!("{s} ({bytes} bytes)")
}

fn format_datetime_value(value: &str, fmt: EwfInfoDateFormat) -> String {
    // libewf supports multiple date formats for header values (`ewfinfo -d`).
    //
    // Empirically (via libewf’s `ewfinfo`), the input header values are commonly encoded as:
    //
    // - `YYYY-MM-DD HH:MM:SS`
    // - Unix epoch seconds (e.g. `1361530430`)
    //
    // and then rendered in one of the following formats:
    //
    // - `ctime`:   `Fri Feb 22 12:53:50 2013`
    // - `iso8601`: `2013-02-22T12:53:50`
    // - `dm`:      `22/02/2013 12:53:50`
    // - `md`:      `02/22/2013 12:53:50`
    //
    // We use `jiff`'s `strptime`/`strftime`-style routines to avoid hand-rolled parsing and to
    // correctly compute weekday names for `ctime`.
    //
    // If parsing fails, we fall back to the original string (no silent coercion).
    let value = value.trim();

    // 1) Common case: `YYYY-MM-DD HH:MM:SS`
    if let Ok(dt) = jiff::fmt::strtime::parse("%F %T", value).and_then(|tm| tm.to_datetime()) {
        return match fmt {
            EwfInfoDateFormat::Ctime => dt.strftime("%a %b %e %T %Y").to_string(),
            EwfInfoDateFormat::Iso8601 => dt.strftime("%FT%T").to_string(),
            EwfInfoDateFormat::DayMonth => dt.strftime("%d/%m/%Y %T").to_string(),
            EwfInfoDateFormat::MonthDay => dt.strftime("%m/%d/%Y %T").to_string(),
        };
    }

    // 2) Unix epoch seconds (`time_t` style). libewf renders these in the system time zone.
    // We accept an optional fractional component but ignore it for display (libewf prints seconds).
    let secs_str = value.split_once('.').map(|(s, _)| s).unwrap_or(value);
    if let Ok(secs) = secs_str.parse::<i64>() {
        let tz = jiff::tz::TimeZone::try_system().unwrap_or(jiff::tz::TimeZone::UTC);
        if let Ok(ts) = jiff::Timestamp::from_second(secs) {
            let dt = ts.to_zoned(tz).datetime();
            return match fmt {
                EwfInfoDateFormat::Ctime => dt.strftime("%a %b %e %T %Y").to_string(),
                EwfInfoDateFormat::Iso8601 => dt.strftime("%FT%T").to_string(),
                EwfInfoDateFormat::DayMonth => dt.strftime("%d/%m/%Y %T").to_string(),
                EwfInfoDateFormat::MonthDay => dt.strftime("%m/%d/%Y %T").to_string(),
            };
        }
    }

    value.to_string()
}

impl fmt::Display for HeaderCodepage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            HeaderCodepage::Ascii => "ascii",
            HeaderCodepage::Windows874 => "windows-874",
            HeaderCodepage::Windows932 => "windows-932",
            HeaderCodepage::Windows936 => "windows-936",
            HeaderCodepage::Windows949 => "windows-949",
            HeaderCodepage::Windows950 => "windows-950",
            HeaderCodepage::Windows1250 => "windows-1250",
            HeaderCodepage::Windows1251 => "windows-1251",
            HeaderCodepage::Windows1252 => "windows-1252",
            HeaderCodepage::Windows1253 => "windows-1253",
            HeaderCodepage::Windows1254 => "windows-1254",
            HeaderCodepage::Windows1255 => "windows-1255",
            HeaderCodepage::Windows1256 => "windows-1256",
            HeaderCodepage::Windows1257 => "windows-1257",
            HeaderCodepage::Windows1258 => "windows-1258",
        };
        f.write_str(s)
    }
}

impl fmt::Display for EwfInfoDateFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            EwfInfoDateFormat::Ctime => "ctime",
            EwfInfoDateFormat::DayMonth => "dm",
            EwfInfoDateFormat::MonthDay => "md",
            EwfInfoDateFormat::Iso8601 => "iso8601",
        };
        f.write_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_report(bytes_per_sector: u32) -> EwfInfoReport {
        EwfInfoReport {
            image_filenames: vec!["image.E01".to_string()],
            acquiry_information: vec![InfoField {
                identifier: "case_number",
                description: "Case number",
                value: InfoValue::String("1".to_string()),
            }],
            ewf_information: vec![InfoField {
                identifier: "sectors_per_chunk",
                description: "Sectors per chunk",
                value: InfoValue::U32(64),
            }],
            media_information: vec![
                InfoField {
                    identifier: "bytes_per_sector",
                    description: "Bytes per sector",
                    value: InfoValue::U32(bytes_per_sector),
                },
                InfoField {
                    identifier: "media_size",
                    description: "Media size",
                    value: InfoValue::Size(1_474_560),
                },
            ],
            digest_hash_information: vec![InfoField {
                identifier: "md5",
                description: "MD5",
                value: InfoValue::String("ae1ce8f5ac079d3ee93f97fe3792bda3".to_string()),
            }],
            sessions: vec![ewf::metadata::SectorRun {
                start_sector: 0,
                sector_count: 10,
            }],
            tracks: vec![],
            acquisition_read_errors: vec![ewf::metadata::SectorRun {
                start_sector: 100,
                sector_count: 0,
            }],
            bytes_per_sector,
        }
    }

    #[test]
    fn test_text_rendering_layout_and_sections() {
        let report = sample_report(512);
        let out = report.to_text(&EwfInfoPrintOptions::default()).unwrap();

        let expected = concat!(
            "Acquiry information\n",
            "───────────────────\n",
            "  Case number: 1\n",
            "\n",
            "EWF information\n",
            "───────────────\n",
            "  Sectors per chunk: 64\n",
            "\n",
            "Media information\n",
            "─────────────────\n",
            "  Bytes per sector: 512\n",
            "  Media size:       1.4 MiB (1474560 bytes)\n",
            "\n",
            "Digest hash information\n",
            "───────────────────────\n",
            "  MD5: ae1ce8f5ac079d3ee93f97fe3792bda3\n",
            "\n",
            "Sessions (1)\n",
            "────────────\n",
            "  - sectors 0..9 (10 sectors)\n",
            "\n",
            "Read errors during acquisition (1)\n",
            "──────────────────────────────────\n",
            "  - sectors 100..100 (0 sectors)\n",
            "\n",
        );

        assert_eq!(out, expected);
    }

    #[test]
    fn test_dfxml_rendering_emits_runs_and_escapes() {
        let mut report = sample_report(512);
        report.acquiry_information.push(InfoField {
            identifier: "acquiry_date",
            description: "Acquisition date",
            value: InfoValue::String("2020-01-01 & <test>".to_string()),
        });

        let out = report.to_dfxml(&EwfInfoPrintOptions::default()).unwrap();

        assert!(out.contains("<dfxml"));
        assert!(out.contains(dfxml::DFXML_NS));
        assert!(out.contains("<metadata>"));
        assert!(out.contains("<dc:type>Disk Image</dc:type>"));

        // Acquiry fields are mapped into Dublin Core for schema-aligned DFXML.
        assert!(out.contains("<dc:identifier>1</dc:identifier>"));
        assert!(out.contains("<dc:date>2020-01-01 &amp; &lt;test&gt;</dc:date>"));

        // Runs are printed in bytes.
        assert!(out.contains("img_offset=\"0\""));
        assert!(out.contains("len=\"5120\""));
        // sector_count=0 yields len=0; start sector 100 -> 100*512=51200
        assert!(out.contains("img_offset=\"51200\""));
        assert!(out.contains("len=\"0\""));
    }

    #[test]
    fn test_renderers_respect_section_filtering() {
        let report = sample_report(512);

        let acquiry_only = EwfInfoPrintOptions {
            sections: EwfInfoSections::AcquiryOnly,
            ..EwfInfoPrintOptions::default()
        };
        let out = report.to_text(&acquiry_only).unwrap();
        assert!(out.contains("Acquiry information\n"));
        assert!(!out.contains("EWF information\n"));
        assert!(!out.contains("Media information\n"));
        assert!(!out.contains("Read errors during acquisition"));

        let errors_only = EwfInfoPrintOptions {
            sections: EwfInfoSections::ErrorsOnly,
            ..EwfInfoPrintOptions::default()
        };
        let out = report.to_dfxml(&errors_only).unwrap();
        // Metadata is always present, but acquisition-only Dublin Core entries should be omitted.
        assert!(!out.contains("<dc:identifier>"));
        // Media-only image hash run should be omitted.
        assert!(!out.contains("type=\"image\""));
        // Error byte_runs should still render.
        assert!(out.contains("type=\"acquisition_read_error\""));
    }

    #[test]
    fn test_renderers_require_bytes_per_sector() {
        let report = sample_report(0);
        let err = report.to_text(&EwfInfoPrintOptions::default()).unwrap_err();
        assert!(matches!(err, EwfInfoError::InvalidReport(_)));
    }
}
