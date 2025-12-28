use super::{
    EwfInfoPrintOptions, EwfInfoReport, EwfInfoResult, EwfInfoSections, InfoField, InfoValue,
    ensure_bytes_per_sector, format_datetime_value,
};

use dfxml::{
    BuildEnvironment, ByteRun, Creator, DfxmlDocument, DiskImageObject, DublinCoreElement,
    DublinCoreElementName, HashDigest, HashDigestType, Library, Source,
};

/// Render [`EwfInfoReport`] as schema-aligned DFXML (DFXML 2.0.0-beta.0).
///
/// Unlike libewf’s historic `ewfinfo -f dfxml` output (which uses an `ewfobjects` root), this
/// emits a schema-aligned `<dfxml>` document.
pub(super) fn render_dfxml(
    report: &EwfInfoReport,
    options: &EwfInfoPrintOptions,
) -> EwfInfoResult<String> {
    let bps = ensure_bytes_per_sector(report)? as u64;

    let want_acquiry = matches!(
        options.sections,
        EwfInfoSections::All | EwfInfoSections::AcquiryOnly
    );
    let want_media = matches!(
        options.sections,
        EwfInfoSections::All | EwfInfoSections::MediaOnly
    );
    let want_errors = matches!(
        options.sections,
        EwfInfoSections::All | EwfInfoSections::ErrorsOnly
    );

    let mut doc = DfxmlDocument::new();

    // Metadata is required by schema.
    doc.metadata.dublin_core.push(DublinCoreElement {
        name: DublinCoreElementName::Type,
        value: "Disk Image".to_string(),
    });

    if want_acquiry {
        if let Some(s) = get_string(&report.acquiry_information, "description") {
            doc.metadata.dublin_core.push(DublinCoreElement {
                name: DublinCoreElementName::Title,
                value: s.to_string(),
            });
        }
        if let Some(s) = get_string(&report.acquiry_information, "examiner_name") {
            doc.metadata.dublin_core.push(DublinCoreElement {
                name: DublinCoreElementName::Creator,
                value: s.to_string(),
            });
        }
        if let Some(s) = get_string(&report.acquiry_information, "case_number") {
            doc.metadata.dublin_core.push(DublinCoreElement {
                name: DublinCoreElementName::Identifier,
                value: s.to_string(),
            });
        }
        if let Some(s) = get_string(&report.acquiry_information, "evidence_number") {
            doc.metadata.dublin_core.push(DublinCoreElement {
                name: DublinCoreElementName::Identifier,
                value: s.to_string(),
            });
        }
        if let Some(s) = get_string(&report.acquiry_information, "notes") {
            doc.metadata.dublin_core.push(DublinCoreElement {
                name: DublinCoreElementName::Description,
                value: s.to_string(),
            });
        }
        if let Some(s) = get_string(&report.acquiry_information, "acquiry_date") {
            doc.metadata.dublin_core.push(DublinCoreElement {
                name: DublinCoreElementName::Date,
                value: format_datetime_value(s, options.date_format),
            });
        }
    }

    doc.creator = Some(Creator {
        program: Some("ewfinfo".to_string()),
        version: Some(env!("CARGO_PKG_VERSION").to_string()),
        build_environment: Some(BuildEnvironment {
            compiler: Some("rustc".to_string()),
            compilation_date: None,
            libraries: vec![Library {
                name: Some("ewf".to_string()),
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
            }],
        }),
        execution_environment: Some(dfxml::ExecutionEnvironment {
            os_sysname: Some(std::env::consts::OS.to_string()),
            arch: Some(std::env::consts::ARCH.to_string()),
        }),
    });

    if !report.image_filenames.is_empty() {
        doc.source = Some(Source {
            image_filenames: report.image_filenames.clone(),
        });
    }

    if want_media || want_errors {
        let mut dio = DiskImageObject {
            sector_size: Some(bps),
            byte_runs: Vec::new(),
        };

        if want_media {
            // Map image-level hashes to a single byte_run over the whole image (when possible).
            if let Some(media_size) = get_media_size_bytes(report) {
                let mut image_run = ByteRun {
                    img_offset: 0,
                    len: media_size,
                    kind: Some("image".to_string()),
                    hashdigests: Vec::new(),
                };
                for h in &report.digest_hash_information {
                    let InfoValue::String(s) = &h.value else {
                        continue;
                    };
                    let algorithm = match h.identifier {
                        "md5" => HashDigestType::Md5,
                        "sha1" => HashDigestType::Sha1,
                        _ => continue,
                    };
                    image_run.hashdigests.push(HashDigest {
                        algorithm,
                        value: s.clone(),
                    });
                }
                dio.byte_runs.push(image_run);
            }

            for r in &report.sessions {
                dio.byte_runs.push(ByteRun {
                    img_offset: r.start_sector.saturating_mul(bps),
                    len: r.sector_count.saturating_mul(bps),
                    kind: Some("session".to_string()),
                    hashdigests: Vec::new(),
                });
            }
            for r in &report.tracks {
                dio.byte_runs.push(ByteRun {
                    img_offset: r.start_sector.saturating_mul(bps),
                    len: r.sector_count.saturating_mul(bps),
                    kind: Some("track".to_string()),
                    hashdigests: Vec::new(),
                });
            }
        }

        if want_errors {
            for r in &report.acquisition_read_errors {
                dio.byte_runs.push(ByteRun {
                    img_offset: r.start_sector.saturating_mul(bps),
                    len: r.sector_count.saturating_mul(bps),
                    kind: Some("acquisition_read_error".to_string()),
                    hashdigests: Vec::new(),
                });
            }
        }

        doc.diskimageobjects.push(dio);
    }

    doc.to_xml_string()
        .map_err(|e| super::EwfInfoError::InvalidReport(format!("dfxml write failed: {e}")))
}

fn get_string<'a>(fields: &'a [InfoField], id: &str) -> Option<&'a str> {
    fields.iter().find_map(|f| {
        if f.identifier != id {
            return None;
        }
        match &f.value {
            InfoValue::String(s) if !s.is_empty() => Some(s.as_str()),
            _ => None,
        }
    })
}

fn get_media_size_bytes(report: &EwfInfoReport) -> Option<u64> {
    report.media_information.iter().find_map(|f| {
        if f.identifier != "media_size" {
            return None;
        }
        match f.value {
            InfoValue::Size(v) => Some(v),
            InfoValue::U64(v) => Some(v),
            InfoValue::U32(v) => Some(v as u64),
            _ => None,
        }
    })
}
