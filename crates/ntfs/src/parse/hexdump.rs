/// Creates a compact hexdump around `pos` in `buf`.
///
/// `base_offset` is used for labeling offsets in the dump (useful when `buf` is a window into a
/// larger stream).
pub(crate) fn hexdump_around(
    buf: &[u8],
    base_offset: u64,
    pos: usize,
    lookbehind: usize,
    lookahead: usize,
) -> String {
    if buf.is_empty() {
        return "<empty buffer>".to_string();
    }

    let start = pos.saturating_sub(lookbehind);
    let end = (pos + lookahead).min(buf.len());

    // 16 bytes per line.
    let mut out = String::new();
    let mut i = start - (start % 16);
    while i < end {
        let line_start = i;
        let line_end = (i + 16).min(buf.len());

        // Offset.
        out.push_str(&format!(
            "0x{off:08x}  ",
            off = base_offset.saturating_add(line_start as u64)
        ));

        // Hex bytes.
        for b in buf[line_start..line_end]
            .iter()
            .copied()
            .map(Some)
            .chain(std::iter::repeat(None))
            .take(16)
        {
            match b {
                Some(b) => out.push_str(&format!("{b:02x} ")),
                None => out.push_str("   "),
            }
        }

        // ASCII.
        out.push(' ');
        for b in buf[line_start..line_end]
            .iter()
            .copied()
            .map(Some)
            .chain(std::iter::repeat(None))
            .take(16)
        {
            match b {
                Some(b) => {
                    let c = if b.is_ascii_graphic() || b == b' ' {
                        b as char
                    } else {
                        '.'
                    };
                    out.push(c);
                }
                None => out.push(' '),
            }
        }

        // Mark the cursor line/position.
        if pos >= line_start && pos < line_start + 16 {
            let caret_pos = 10 + 2 + (pos - line_start) * 3; // after "0x........  "
            out.push('\n');
            out.push_str(&" ".repeat(caret_pos));
            out.push('^');
        }

        out.push('\n');
        i += 16;
    }

    out
}
