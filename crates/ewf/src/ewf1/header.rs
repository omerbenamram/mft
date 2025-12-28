//! EWF1 header parsing primitives (`header`, `header2`) and EWFX `xheader`.
//!
//! EWF1 stores human-oriented acquisition metadata in two places:
//!
//! - The **`header`** section: zlib-compressed ASCII text (EnCase-style) with CRLF line endings.
//! - The **`header2`** section: zlib-compressed UTF-16LE text (often EnCase 4–7), with categories.
//!
//! EWF-X (“EWFX”) adds:
//!
//! - The **`xheader`** section: zlib-compressed UTF-8 XML that contains the header values as XML
//!   elements (notably including *both* `acquiry_software` and `acquiry_software_version`).
//!
//! This module intentionally focuses on **spec-aligned extraction** into structured
//! [`crate::metadata::HeaderValues`]. Presentation/formatting (labels, date formatting) belongs to
//! binaries such as `ewfinfo`.
//!
//! References:
//! - `external/libewf/documentation/Expert Witness Compression Format (EWF).asciidoc`
//!   - “Header section”
//!   - “Header2 values”
//!   - “EWF-X” → “Xheader”
//! - libewf implementation:
//!   - `external/libewf/libewf/libewf_header_values.c`

use crate::metadata::HeaderValues;
use crate::{Error, Result};

/// A tag identifier used in EWF1 header strings.
///
/// This enum is used by both ASCII `header` and UTF-16LE `header2` parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ewf1HeaderTag {
    /// `a` — unique description / description.
    Description,
    /// `c` — case number.
    CaseNumber,
    /// `n` — evidence number.
    EvidenceNumber,
    /// `e` — examiner name.
    ExaminerName,
    /// `t` — notes.
    Notes,
    /// `av` — acquisition software **version** (e.g. EnCase version used to acquire media).
    AcquisitionSoftwareVersion,
    /// `ov` — acquisition platform/operating system.
    AcquisitionOperatingSystem,
    /// `m` — acquisition date/time string.
    AcquisitionDateTime,
    /// `u` — system date/time string.
    SystemDateTime,
    /// `p` — password hash (or `0` if not set).
    PasswordHash,
    /// `r` — compression level indicator (ASCII header only; not currently surfaced in metadata).
    CompressionLevel,
    /// `md` — media model (header2 only; not currently surfaced in metadata).
    Model,
    /// `sn` — serial number (header2 only; not currently surfaced in metadata).
    SerialNumber,
    /// Unknown/unsupported tag.
    Unknown,
}

impl Ewf1HeaderTag {
    /// Parse an EWF1 header tag string into a typed identifier.
    pub(crate) fn parse(tag: &str) -> Self {
        match tag {
            "a" => Self::Description,
            "c" => Self::CaseNumber,
            "n" => Self::EvidenceNumber,
            "e" => Self::ExaminerName,
            "t" => Self::Notes,
            "av" => Self::AcquisitionSoftwareVersion,
            "ov" => Self::AcquisitionOperatingSystem,
            "m" => Self::AcquisitionDateTime,
            "u" => Self::SystemDateTime,
            "p" => Self::PasswordHash,
            "r" => Self::CompressionLevel,
            "md" => Self::Model,
            "sn" => Self::SerialNumber,
            _ => Self::Unknown,
        }
    }

    fn apply(self, value: String, out: &mut HeaderValues) {
        match self {
            Self::Description => out.description = Some(value),
            Self::CaseNumber => out.case_number = Some(value),
            Self::EvidenceNumber => out.evidence_number = Some(value),
            Self::ExaminerName => out.examiner_name = Some(value),
            Self::Notes => out.notes = Some(value),
            Self::AcquisitionSoftwareVersion => out.acquisition_software_version = Some(value),
            Self::AcquisitionOperatingSystem => out.acquisition_os = Some(value),
            Self::AcquisitionDateTime => out.acquisition_datetime = Some(value),
            Self::SystemDateTime => out.system_datetime = Some(value),
            Self::PasswordHash => {
                // libewf uses the literal character '0' to indicate “not set”.
                if value != "0" {
                    out.password = Some(value);
                }
            }
            Self::CompressionLevel | Self::Model | Self::SerialNumber | Self::Unknown => {
                // Not surfaced in `HeaderValues` at the moment.
            }
        }
    }
}

/// Parser for an EWF1 `header` section (zlib-decompressed ASCII text).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Ewf1HeaderAscii<'a> {
    decompressed: &'a [u8],
}

impl<'a> Ewf1HeaderAscii<'a> {
    pub(crate) fn new(decompressed: &'a [u8]) -> Self {
        Self { decompressed }
    }

    pub(crate) fn parse_into(self, out: &mut HeaderValues) -> Result<()> {
        let s = String::from_utf8_lossy(self.decompressed);
        let mut lines = s.lines();

        let _category_count = lines
            .next()
            .ok_or_else(|| Error::Invalid("EWF1 header missing category count".to_string()))?;
        let _category = lines
            .next()
            .ok_or_else(|| Error::Invalid("EWF1 header missing category name".to_string()))?;

        let tags_line = lines
            .next()
            .ok_or_else(|| Error::Invalid("EWF1 header missing tags line".to_string()))?;
        let values_line = lines
            .next()
            .ok_or_else(|| Error::Invalid("EWF1 header missing values line".to_string()))?;

        let tags: Vec<&str> = tags_line.trim_end_matches('\r').split('\t').collect();
        let values: Vec<&str> = values_line.trim_end_matches('\r').split('\t').collect();

        if tags.len() != values.len() {
            return Err(Error::Invalid(
                "EWF1 header tags/values column count mismatch".to_string(),
            ));
        }

        for (t, v) in tags.into_iter().zip(values) {
            Ewf1HeaderTag::parse(t).apply(v.to_string(), out);
        }

        Ok(())
    }
}

/// Parser for an EWF1 `header2` section (zlib-decompressed UTF-16LE text).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Ewf1Header2Utf16Le<'a> {
    decompressed: &'a [u8],
}

impl<'a> Ewf1Header2Utf16Le<'a> {
    pub(crate) fn new(decompressed: &'a [u8]) -> Self {
        Self { decompressed }
    }

    pub(crate) fn parse_into(self, out: &mut HeaderValues) -> Result<()> {
        let mut bytes = self.decompressed;
        if bytes.len() >= 2 && bytes[0..2] == [0xff, 0xfe] {
            bytes = &bytes[2..];
        }
        if !bytes.len().is_multiple_of(2) {
            return Err(Error::Invalid(
                "EWF1 header2 UTF-16LE has odd byte length".to_string(),
            ));
        }
        let u16s: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes(c.try_into().expect("len=2")))
            .collect();
        let s = String::from_utf16_lossy(&u16s);

        let mut lines = s.lines();
        let _category_count = lines
            .next()
            .ok_or_else(|| Error::Invalid("EWF1 header2 missing category count".to_string()))?;
        let _category = lines
            .next()
            .ok_or_else(|| Error::Invalid("EWF1 header2 missing category name".to_string()))?;
        let tags_line = lines
            .next()
            .ok_or_else(|| Error::Invalid("EWF1 header2 missing tags line".to_string()))?;
        let values_line = lines
            .next()
            .ok_or_else(|| Error::Invalid("EWF1 header2 missing values line".to_string()))?;

        let tags: Vec<&str> = tags_line.trim_end_matches('\r').split('\t').collect();
        let values: Vec<&str> = values_line.trim_end_matches('\r').split('\t').collect();
        if tags.len() != values.len() {
            return Err(Error::Invalid(
                "EWF1 header2 tags/values column count mismatch".to_string(),
            ));
        }

        for (t, v) in tags.into_iter().zip(values) {
            Ewf1HeaderTag::parse(t).apply(v.to_string(), out);
        }

        Ok(())
    }
}

/// Parser for an EWFX `xheader` section (zlib-decompressed UTF-8 XML).
#[derive(Debug, Clone, Copy)]
pub(crate) struct EwfxXHeaderXml<'a> {
    decompressed: &'a [u8],
}

impl<'a> EwfxXHeaderXml<'a> {
    pub(crate) fn new(decompressed: &'a [u8]) -> Self {
        Self { decompressed }
    }

    pub(crate) fn parse_into(self, out: &mut HeaderValues) -> Result<()> {
        use quick_xml::Reader;
        use quick_xml::events::Event;
        use std::io::Cursor;

        let mut reader = Reader::from_reader(Cursor::new(self.decompressed));
        reader.config_mut().trim_text(true);

        let mut buf: Vec<u8> = Vec::new();
        let mut current_tag: Option<Vec<u8>> = None;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) => {
                    current_tag = Some(e.name().as_ref().to_vec());
                }
                Ok(Event::End(_)) => {
                    current_tag = None;
                }
                Ok(Event::Text(e)) => {
                    let Some(tag) = current_tag.as_deref() else {
                        buf.clear();
                        continue;
                    };

                    let decoded = e
                        .decode()
                        .map_err(|e| Error::Invalid(format!("invalid xheader XML: {e}")))?;
                    let text = quick_xml::escape::unescape(decoded.as_ref())
                        .map_err(|e| Error::Invalid(format!("invalid xheader XML: {e}")))?
                        .into_owned();

                    match tag {
                        b"case_number" => out.case_number = Some(text),
                        b"evidence_number" => out.evidence_number = Some(text),
                        b"description" => out.description = Some(text),
                        b"examiner_name" => out.examiner_name = Some(text),
                        b"notes" => out.notes = Some(text),
                        b"acquiry_date" => out.acquisition_datetime = Some(text),
                        b"system_date" => out.system_datetime = Some(text),
                        b"acquiry_operating_system" => out.acquisition_os = Some(text),
                        b"acquiry_software" => out.acquisition_software = Some(text),
                        b"acquiry_software_version" => {
                            out.acquisition_software_version = Some(text)
                        }
                        _ => {}
                    }
                }
                Ok(Event::Eof) => break,
                Ok(_) => {}
                Err(e) => return Err(Error::Invalid(format!("invalid xheader XML: {e}"))),
            }
            buf.clear();
        }

        Ok(())
    }
}

/// Normalizes EWF1 header values for libewf-compatible `ewfinfo` output.
///
/// Some tooling populates `acquiry_software` with the same value as
/// `acquiry_software_version`. libewf will only print a single “Software version used” line in
/// that case, so we drop the redundant “Software used” field.
pub(crate) fn normalize_header_values(values: &mut HeaderValues) {
    if values.acquisition_software.is_some()
        && values.acquisition_software == values.acquisition_software_version
    {
        values.acquisition_software = None;
    }
}
