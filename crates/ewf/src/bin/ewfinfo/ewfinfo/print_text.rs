use super::{
    EwfInfoColorMode, EwfInfoPrintOptions, EwfInfoReport, EwfInfoResult, EwfInfoSections,
    InfoField, InfoValue, ensure_bytes_per_sector, format_bool_yes_no, format_datetime_value,
    format_size_mib,
};

use std::io::IsTerminal as _;

use textwrap::core::display_width;

/// Render [`EwfInfoReport`] as a human-friendly text report.
pub(super) fn render_text(
    report: &EwfInfoReport,
    options: &EwfInfoPrintOptions,
) -> EwfInfoResult<String> {
    let _bps = ensure_bytes_per_sector(report)?;
    let mut out = String::new();

    let use_color = color_enabled(options.color);
    let width = detect_width(options.color);

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

    // Section: Acquiry information
    if want_acquiry {
        push_heading(&mut out, "Acquiry information", use_color);
        if report.acquiry_information.is_empty() {
            out.push_str("  (no information found)\n\n");
        } else {
            let label_width = max_label_width(&report.acquiry_information).min(32);
            for f in &report.acquiry_information {
                let value = match (f.identifier, &f.value) {
                    ("password", InfoValue::String(s)) => {
                        if s.is_empty() {
                            "N/A".to_string()
                        } else {
                            format!("(hash: {s})")
                        }
                    }
                    ("acquiry_date", InfoValue::String(s))
                    | ("system_date", InfoValue::String(s)) => {
                        format_datetime_value(s, options.date_format)
                    }
                    (_, InfoValue::String(s)) => s.clone(),
                    (_, InfoValue::U32(v)) => v.to_string(),
                    (_, InfoValue::U64(v)) => v.to_string(),
                    (_, InfoValue::Size(v)) => format_size_mib(*v),
                    (_, InfoValue::Bool(v)) => format_bool_yes_no(*v).to_string(),
                };
                push_kv(
                    &mut out,
                    f.description,
                    &value,
                    label_width,
                    width,
                    use_color,
                );
            }
            out.push('\n');
        }
    }

    if want_media {
        // Section: EWF information
        push_heading(&mut out, "EWF information", use_color);
        let label_width = max_label_width(&report.ewf_information).min(32);
        for f in &report.ewf_information {
            let value = match &f.value {
                InfoValue::String(s) => s.clone(),
                InfoValue::U32(v) => v.to_string(),
                InfoValue::U64(v) => v.to_string(),
                InfoValue::Size(v) => format_size_mib(*v),
                InfoValue::Bool(v) => format_bool_yes_no(*v).to_string(),
            };
            push_kv(
                &mut out,
                f.description,
                &value,
                label_width,
                width,
                use_color,
            );
        }
        out.push('\n');

        // Section: Media information
        push_heading(&mut out, "Media information", use_color);
        let label_width = max_label_width(&report.media_information).min(32);
        for f in &report.media_information {
            let value = match &f.value {
                InfoValue::String(s) => s.clone(),
                InfoValue::U32(v) => v.to_string(),
                InfoValue::U64(v) => v.to_string(),
                InfoValue::Size(v) => format_size_mib(*v),
                InfoValue::Bool(v) => format_bool_yes_no(*v).to_string(),
            };
            push_kv(
                &mut out,
                f.description,
                &value,
                label_width,
                width,
                use_color,
            );
        }
        out.push('\n');

        // Section: Digest hash information (only if present).
        if !report.digest_hash_information.is_empty() {
            push_heading(&mut out, "Digest hash information", use_color);
            let label_width = max_label_width(&report.digest_hash_information).min(32);
            for f in &report.digest_hash_information {
                let value = match &f.value {
                    InfoValue::String(s) => s.clone(),
                    InfoValue::U32(v) => v.to_string(),
                    InfoValue::U64(v) => v.to_string(),
                    InfoValue::Size(v) => format_size_mib(*v),
                    InfoValue::Bool(v) => format_bool_yes_no(*v).to_string(),
                };
                push_kv(
                    &mut out,
                    f.description,
                    &value,
                    label_width,
                    width,
                    use_color,
                );
            }
            out.push('\n');
        }

        // Sessions / tracks: only print if present.
        push_runs(&mut out, "Sessions", &report.sessions, width, use_color);
        push_runs(&mut out, "Tracks", &report.tracks, width, use_color);
    }

    if want_errors && !report.acquisition_read_errors.is_empty() {
        push_runs(
            &mut out,
            "Read errors during acquisition",
            &report.acquisition_read_errors,
            width,
            use_color,
        );
    }

    Ok(out)
}

fn max_label_width(fields: &[InfoField]) -> usize {
    fields
        .iter()
        .map(|f| display_width(f.description))
        .max()
        .unwrap_or(0)
}

fn detect_width(color_mode: EwfInfoColorMode) -> usize {
    // Keep deterministic output in non-interactive contexts.
    if matches!(color_mode, EwfInfoColorMode::Always) || std::io::stdout().is_terminal() {
        if let Ok(cols) = std::env::var("COLUMNS")
            && let Ok(n) = cols.parse::<usize>()
            && (40..=240).contains(&n)
        {
            return n;
        }
        100
    } else {
        80
    }
}

fn color_enabled(mode: EwfInfoColorMode) -> bool {
    match mode {
        EwfInfoColorMode::Never => false,
        EwfInfoColorMode::Always => std::env::var_os("NO_COLOR").is_none(),
        EwfInfoColorMode::Auto => {
            std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
        }
    }
}

fn push_heading(out: &mut String, title: &str, color: bool) {
    if color {
        out.push_str("\x1b[1;36m");
        out.push_str(title);
        out.push_str("\x1b[0m\n");

        out.push_str("\x1b[2m");
        out.extend(std::iter::repeat_n('─', display_width(title)));
        out.push_str("\x1b[0m\n");
        return;
    }

    out.push_str(title);
    out.push('\n');
    out.extend(std::iter::repeat_n('─', display_width(title)));
    out.push('\n');
}

fn push_kv(
    out: &mut String,
    label: &str,
    value: &str,
    label_width: usize,
    width: usize,
    color: bool,
) {
    const INDENT: &str = "  ";

    let label_w = display_width(label);
    let value_start = label_width.saturating_add(2);
    let pad = value_start.saturating_sub(label_w.saturating_add(1)).max(1);

    let available = width
        .saturating_sub(display_width(INDENT))
        .saturating_sub(value_start)
        .max(1);

    let mut first_line = true;
    for (para_i, para) in value.split('\n').enumerate() {
        if para_i > 0 {
            // Preserve explicit newlines.
            out.push('\n');
        }

        let wrapped = textwrap::wrap(para, available);
        for line in wrapped {
            if first_line {
                out.push_str(INDENT);
                if color {
                    out.push_str("\x1b[2m");
                }
                out.push_str(label);
                out.push(':');
                out.extend(std::iter::repeat_n(' ', pad));
                if color {
                    out.push_str("\x1b[0m");
                }
                out.push_str(&line);
                out.push('\n');
                first_line = false;
            } else {
                out.push_str(INDENT);
                out.extend(std::iter::repeat_n(' ', value_start));
                out.push_str(&line);
                out.push('\n');
            }
        }
    }
}

fn push_runs(
    out: &mut String,
    title: &str,
    runs: &[ewf::metadata::SectorRun],
    width: usize,
    color: bool,
) {
    if runs.is_empty() {
        return;
    }

    let heading = format!("{title} ({})", runs.len());
    push_heading(out, &heading, color);

    const INDENT: &str = "  ";
    const BULLET: &str = "- ";
    let prefix = format!("{INDENT}{BULLET}");
    let prefix_w = display_width(&prefix);
    let available = width.saturating_sub(prefix_w).max(1);
    let subsequent = format!("{INDENT}  ");

    for r in runs {
        let mut last_sector = r.start_sector.saturating_add(r.sector_count);
        if r.sector_count != 0 {
            last_sector = last_sector.saturating_sub(1);
        }
        let msg = format!(
            "sectors {}..{} ({} sectors)",
            r.start_sector, last_sector, r.sector_count
        );
        let wrapped = textwrap::wrap(&msg, available);
        for (i, line) in wrapped.iter().enumerate() {
            if i == 0 {
                out.push_str(&prefix);
            } else {
                out.push_str(&subsequent);
            }
            out.push_str(line);
            out.push('\n');
        }
    }
    out.push('\n');
}
