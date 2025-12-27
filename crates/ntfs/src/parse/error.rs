use crate::parse::hexdump::hexdump_around;
use std::error::Error as StdError;
use std::fmt;

pub type Result<T> = std::result::Result<T, ParseError>;

/// A parsing error that captures the logical stream offset and a small hexdump window.
///
/// This is intentionally *not* an enum at the moment: in practice we want rich context (field
/// name + offset + bytes). Higher layers can categorize errors if/when needed.
#[derive(Debug)]
pub struct ParseError {
    offset: u64,
    field: &'static str,
    message: String,
    hexdump: String,
    source: Box<dyn StdError + Send + Sync + 'static>,
}

impl ParseError {
    pub fn new(
        offset: u64,
        field: &'static str,
        message: impl Into<String>,
        hexdump: impl Into<String>,
        source: Box<dyn StdError + Send + Sync + 'static>,
    ) -> Self {
        Self {
            offset,
            field,
            message: message.into(),
            hexdump: hexdump.into(),
            source,
        }
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    pub fn field(&self) -> &'static str {
        self.field
    }

    pub fn hexdump(&self) -> &str {
        &self.hexdump
    }

    pub(crate) fn capture_from_slice(
        buf: &[u8],
        base_offset: u64,
        pos: usize,
        field: &'static str,
        message: impl Into<String>,
        source: Box<dyn StdError + Send + Sync + 'static>,
    ) -> Self {
        let offset = base_offset.saturating_add(pos as u64);
        let hexdump = hexdump_around(buf, base_offset, pos, 96, 64);
        Self::new(offset, field, message, hexdump, source)
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Offset `0x{offset:08x} ({offset})` - failed to parse `{field}`\n\
             {message}\n\n\
             Source: {source}\n\n\
             Hexdump:\n{hexdump}",
            offset = self.offset,
            field = self.field,
            message = self.message,
            source = self.source,
            hexdump = self.hexdump
        )
    }
}

impl StdError for ParseError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(self.source.as_ref())
    }
}
