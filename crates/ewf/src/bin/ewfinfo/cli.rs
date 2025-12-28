//! clap-driven CLI parsing for the `ewfinfo` binary.
//!
//! This module is deliberately **binary-only**: it translates libewf-compatible command-line flags
//! into calls to the `ewf` crate. The `ewf` library provides spec-oriented metadata extraction,
//! while this binary owns the reporting/rendering layer and user-facing diagnostics.
//!
//! References:
//! - `external/libewf/ewftools/ewfinfo.c` (option parsing + modes)
//! - `external/libewf/manuals/ewfinfo.1` (flag documentation)

use std::io::Write as _;
use std::path::PathBuf;

use clap::{ArgAction, Parser, ValueEnum};
use miette::{Context as _, IntoDiagnostic as _, miette};

use ewf::EwfFormat;
use ewf::EwfReader;
use ewf::LefReader;

use crate::ewfinfo::{
    EwfInfoColorMode, EwfInfoDateFormat, EwfInfoPrintOptions, EwfInfoReport, EwfInfoSections,
    HeaderCodepage,
};
use crate::{bodyfile, logical};

/// Show meta data stored in EWF files.
#[derive(Debug, Parser)]
#[command(name = "ewfinfo", disable_version_flag = true)]
pub struct Cli {
    /// The codepage of the header section, options: ascii (default), windows-874, windows-932,
    /// windows-936, windows-949, windows-950, windows-1250, windows-1251, windows-1252,
    /// windows-1253, windows-1254, windows-1255, windows-1256, windows-1257 or windows-1258
    #[arg(short = 'A', value_enum, value_name = "codepage", default_value_t = HeaderCodepageArg::Ascii)]
    pub header_codepage: HeaderCodepageArg,

    /// Output logical files information as a bodyfile.
    #[arg(short = 'B', value_name = "bodyfile")]
    pub bodyfile: Option<PathBuf>,

    /// Show information about a specific file entry path.
    #[arg(short = 'F', value_name = "file_entry", conflicts_with = "hierarchy")]
    pub file_entry: Option<String>,

    /// The date format, options: ctime (default), dm (day/month), md (month/day), iso8601.
    #[arg(short = 'd', value_enum, value_name = "date_format", default_value_t = DateFormatArg::Ctime)]
    pub date_format: DateFormatArg,

    /// Only show EWF read error information.
    #[arg(short = 'e', action = ArgAction::SetTrue, conflicts_with_all = ["acquiry_only", "media_only"])]
    pub errors_only: bool,

    /// Shows the logical files hierarchy.
    #[arg(short = 'H', action = ArgAction::SetTrue)]
    pub hierarchy: bool,

    /// Only show EWF acquiry information.
    #[arg(short = 'i', action = ArgAction::SetTrue, conflicts_with_all = ["errors_only", "media_only"])]
    pub acquiry_only: bool,

    /// Only show EWF media information.
    #[arg(short = 'm', action = ArgAction::SetTrue, conflicts_with_all = ["errors_only", "acquiry_only"])]
    pub media_only: bool,

    /// Path segment separator, options: `/` (default), `\\`.
    #[arg(short = 's', value_enum, value_name = "separator", default_value_t = PathSeparator::Slash)]
    pub separator: PathSeparator,

    /// Specify the output format, options: text (default), dfxml.
    #[arg(short = 'f', value_enum, value_name = "format", default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,

    /// Verbose output to stderr.
    #[arg(short = 'v', action = ArgAction::SetTrue)]
    pub verbose: bool,

    /// Print version and exit.
    #[arg(short = 'V', long = "version", action = ArgAction::SetTrue)]
    pub version: bool,

    /// The first or the entire set of EWF segment files.
    #[arg(value_name = "ewf_files", required = true)]
    pub ewf_files: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Human-readable text output.
    #[value(name = "text")]
    Text,
    /// DFXML output (schema-aligned DFXML 2.0.0-beta.0; not yet implemented for logical-evidence modes).
    #[value(name = "dfxml")]
    Dfxml,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum PathSeparator {
    /// `/` (default).
    #[value(name = "/")]
    Slash,
    /// `\\` (Windows-style).
    #[value(name = "\\")]
    Backslash,
}

impl PathSeparator {
    pub fn as_char(self) -> char {
        match self {
            Self::Slash => '/',
            Self::Backslash => '\\',
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum HeaderCodepageArg {
    #[value(name = "ascii")]
    Ascii,
    #[value(name = "windows-874")]
    Windows874,
    #[value(name = "windows-932")]
    Windows932,
    #[value(name = "windows-936")]
    Windows936,
    #[value(name = "windows-949")]
    Windows949,
    #[value(name = "windows-950")]
    Windows950,
    #[value(name = "windows-1250")]
    Windows1250,
    #[value(name = "windows-1251")]
    Windows1251,
    #[value(name = "windows-1252")]
    Windows1252,
    #[value(name = "windows-1253")]
    Windows1253,
    #[value(name = "windows-1254")]
    Windows1254,
    #[value(name = "windows-1255")]
    Windows1255,
    #[value(name = "windows-1256")]
    Windows1256,
    #[value(name = "windows-1257")]
    Windows1257,
    #[value(name = "windows-1258")]
    Windows1258,
}

impl From<HeaderCodepageArg> for HeaderCodepage {
    fn from(value: HeaderCodepageArg) -> Self {
        match value {
            HeaderCodepageArg::Ascii => HeaderCodepage::Ascii,
            HeaderCodepageArg::Windows874 => HeaderCodepage::Windows874,
            HeaderCodepageArg::Windows932 => HeaderCodepage::Windows932,
            HeaderCodepageArg::Windows936 => HeaderCodepage::Windows936,
            HeaderCodepageArg::Windows949 => HeaderCodepage::Windows949,
            HeaderCodepageArg::Windows950 => HeaderCodepage::Windows950,
            HeaderCodepageArg::Windows1250 => HeaderCodepage::Windows1250,
            HeaderCodepageArg::Windows1251 => HeaderCodepage::Windows1251,
            HeaderCodepageArg::Windows1252 => HeaderCodepage::Windows1252,
            HeaderCodepageArg::Windows1253 => HeaderCodepage::Windows1253,
            HeaderCodepageArg::Windows1254 => HeaderCodepage::Windows1254,
            HeaderCodepageArg::Windows1255 => HeaderCodepage::Windows1255,
            HeaderCodepageArg::Windows1256 => HeaderCodepage::Windows1256,
            HeaderCodepageArg::Windows1257 => HeaderCodepage::Windows1257,
            HeaderCodepageArg::Windows1258 => HeaderCodepage::Windows1258,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum DateFormatArg {
    #[value(name = "ctime")]
    Ctime,
    #[value(name = "dm")]
    DayMonth,
    #[value(name = "md")]
    MonthDay,
    #[value(name = "iso8601")]
    Iso8601,
}

impl From<DateFormatArg> for EwfInfoDateFormat {
    fn from(value: DateFormatArg) -> Self {
        match value {
            DateFormatArg::Ctime => EwfInfoDateFormat::Ctime,
            DateFormatArg::DayMonth => EwfInfoDateFormat::DayMonth,
            DateFormatArg::MonthDay => EwfInfoDateFormat::MonthDay,
            DateFormatArg::Iso8601 => EwfInfoDateFormat::Iso8601,
        }
    }
}

impl Cli {
    pub fn run(self) -> miette::Result<()> {
        if self.version {
            println!("ewfinfo {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }

        let input = self
            .ewf_files
            .first()
            .ok_or_else(|| miette!("missing EWF input path"))?;

        // Open bodyfile early (libewf fails early if the path cannot be opened).
        let mut bodyfile_stream = if let Some(path) = &self.bodyfile {
            Some(
                std::fs::File::create(path)
                    .into_diagnostic()
                    .wrap_err_with(|| format!("unable to create bodyfile `{}`", path.display()))?,
            )
        } else {
            None
        };

        enum Mode<'a> {
            FileEntry(&'a str),
            Hierarchy,
            Image,
        }

        let mode = if let Some(query) = self.file_entry.as_deref() {
            Mode::FileEntry(query)
        } else if self.hierarchy {
            Mode::Hierarchy
        } else {
            Mode::Image
        };

        match mode {
            Mode::FileEntry(query) => {
                if self.format == OutputFormat::Dfxml {
                    // libewf supports DFXML for these modes too, but we keep this binary-only
                    // surface area small while wiring up image-mode parity.
                    return Err(miette!(
                        "dfxml output is not yet implemented for -F/-H/-B logical-evidence modes"
                    ));
                }

                // libewf prints a version header for text output in all modes.
                println!("ewfinfo {}", env!("CARGO_PKG_VERSION"));
                println!();

                // Logical evidence operations require LEF inputs (`.L01`/`.Lx01`).
                let lef = LefReader::open(input).map_err(|e| miette!("{e}"))?;
                let entry = logical::find_entry_by_path(lef.entries(), query)
                    .ok_or_else(|| miette!("file entry not found: `{query}`"))?;

                if let Some(stream) = bodyfile_stream.as_mut() {
                    stream
                        .write_all(
                            bodyfile::render_bodyfile_line(entry, self.separator.as_char())
                                .as_bytes(),
                        )
                        .into_diagnostic()
                        .wrap_err("unable to write bodyfile line")?;
                    stream
                        .flush()
                        .into_diagnostic()
                        .wrap_err("unable to flush bodyfile")?;
                    return Ok(());
                }

                print!(
                    "{}",
                    logical::render_file_entry_text(entry, self.separator.as_char())
                );
                Ok(())
            }
            Mode::Hierarchy => {
                if self.format == OutputFormat::Dfxml {
                    return Err(miette!(
                        "dfxml output is not yet implemented for -F/-H/-B logical-evidence modes"
                    ));
                }

                // libewf prints a version header for text output in all modes.
                println!("ewfinfo {}", env!("CARGO_PKG_VERSION"));
                println!();

                let lef = LefReader::open(input).map_err(|e| miette!("{e}"))?;

                if let Some(stream) = bodyfile_stream.as_mut() {
                    stream
                        .write_all(
                            bodyfile::render_bodyfile(lef.entries(), self.separator.as_char())
                                .as_bytes(),
                        )
                        .into_diagnostic()
                        .wrap_err("unable to write bodyfile")?;
                    stream
                        .flush()
                        .into_diagnostic()
                        .wrap_err("unable to flush bodyfile")?;
                    return Ok(());
                }

                print!(
                    "{}",
                    logical::render_hierarchy_text(lef.entries(), self.separator.as_char())
                );
                Ok(())
            }
            Mode::Image => {
                let sections = if self.acquiry_only {
                    EwfInfoSections::AcquiryOnly
                } else if self.media_only {
                    EwfInfoSections::MediaOnly
                } else if self.errors_only {
                    EwfInfoSections::ErrorsOnly
                } else {
                    EwfInfoSections::All
                };

                let print_options = EwfInfoPrintOptions {
                    date_format: self.date_format.into(),
                    sections,
                    color: EwfInfoColorMode::Auto,
                };

                let img = EwfReader::open(input).map_err(|e| miette!("{e}"))?;
                let header_codepage: HeaderCodepage = self.header_codepage.into();
                if matches!(img.format(), EwfFormat::E01 | EwfFormat::S01)
                    && header_codepage != HeaderCodepage::Ascii
                {
                    return Err(miette!(
                        "TODO: EWF1 header codepage `{}` decoding is not implemented yet",
                        header_codepage
                    ));
                }

                let meta = img.image_metadata().map_err(|e| miette!("{e}"))?;
                let report =
                    EwfInfoReport::from_image_metadata(&meta).map_err(|e| miette!("{e}"))?;

                match self.format {
                    OutputFormat::Text => {
                        // libewf prints a version header for text output.
                        println!("ewfinfo {}", env!("CARGO_PKG_VERSION"));
                        println!();
                        let text = report.to_text(&print_options).map_err(|e| miette!("{e}"))?;
                        print!("{text}");
                        Ok(())
                    }
                    OutputFormat::Dfxml => {
                        let xml = report
                            .to_dfxml(&print_options)
                            .map_err(|e| miette!("{e}"))?;
                        print!("{xml}");
                        Ok(())
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clap_parses_bodyfile_glued_short_opt() {
        let cli = Cli::try_parse_from(["ewfinfo", "-Bbodyfile", "-H", "case.L01"]).unwrap();
        assert_eq!(
            cli.bodyfile.as_deref(),
            Some(std::path::Path::new("bodyfile"))
        );
        assert!(cli.hierarchy);
    }

    #[test]
    fn test_clap_parses_separator_backslash() {
        let cli = Cli::try_parse_from(["ewfinfo", "-H", "-s", "\\", "case.L01"]).unwrap();
        assert_eq!(cli.separator, PathSeparator::Backslash);
    }

    #[test]
    fn test_clap_rejects_conflicting_info_flags() {
        let err = Cli::try_parse_from(["ewfinfo", "-e", "-i", "image.E01"]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("cannot be used with") || msg.contains("conflicts with"));
    }
}
