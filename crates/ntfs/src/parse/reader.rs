use crate::parse::error::{ParseError, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use std::io;

/// A small cursor over an in-memory buffer with offset-aware errors.
///
/// `base_offset` lets callers label errors with the original stream offset when `buf` is a slice
/// of a larger stream.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    base_offset: u64,
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            base_offset: 0,
            pos: 0,
        }
    }

    pub fn with_base_offset(buf: &'a [u8], base_offset: u64) -> Self {
        Self {
            buf,
            base_offset,
            pos: 0,
        }
    }

    pub fn base_offset(&self) -> u64 {
        self.base_offset
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn stream_offset(&self) -> u64 {
        self.base_offset.saturating_add(self.pos as u64)
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    pub fn seek(&mut self, field: &'static str, pos: usize) -> Result<()> {
        if pos > self.buf.len() {
            return Err(ParseError::capture_from_slice(
                self.buf,
                self.base_offset,
                self.pos,
                field,
                format!("seek out of bounds: pos={pos} len={}", self.buf.len()),
                Box::new(io::Error::from(io::ErrorKind::UnexpectedEof)),
            ));
        }
        self.pos = pos;
        Ok(())
    }

    pub fn skip(&mut self, field: &'static str, n: usize) -> Result<()> {
        let new_pos = self.pos.saturating_add(n);
        self.seek(field, new_pos)
    }

    pub fn take(&mut self, field: &'static str, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.buf.len() {
            return Err(ParseError::capture_from_slice(
                self.buf,
                self.base_offset,
                self.pos,
                field,
                format!(
                    "unexpected EOF: wanted {n} bytes, remaining {}",
                    self.remaining()
                ),
                Box::new(io::Error::from(io::ErrorKind::UnexpectedEof)),
            ));
        }
        let start = self.pos;
        let end = start + n;
        self.pos = end;
        Ok(&self.buf[start..end])
    }

    pub fn peek(&self, field: &'static str, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.buf.len() {
            return Err(ParseError::capture_from_slice(
                self.buf,
                self.base_offset,
                self.pos,
                field,
                format!(
                    "unexpected EOF: wanted {n} bytes, remaining {}",
                    self.remaining()
                ),
                Box::new(io::Error::from(io::ErrorKind::UnexpectedEof)),
            ));
        }
        Ok(&self.buf[self.pos..(self.pos + n)])
    }

    pub fn u8(&mut self, field: &'static str) -> Result<u8> {
        Ok(*self.take(field, 1)?.first().expect("len=1"))
    }

    pub fn u16_le(&mut self, field: &'static str) -> Result<u16> {
        let bytes = self.take(field, 2)?;
        (&mut &*bytes)
            .read_u16::<LittleEndian>()
            .map_err(|e| self.wrap_io(field, e))
    }

    pub fn u32_le(&mut self, field: &'static str) -> Result<u32> {
        let bytes = self.take(field, 4)?;
        (&mut &*bytes)
            .read_u32::<LittleEndian>()
            .map_err(|e| self.wrap_io(field, e))
    }

    pub fn u64_le(&mut self, field: &'static str) -> Result<u64> {
        let bytes = self.take(field, 8)?;
        (&mut &*bytes)
            .read_u64::<LittleEndian>()
            .map_err(|e| self.wrap_io(field, e))
    }

    fn wrap_io(&self, field: &'static str, e: io::Error) -> ParseError {
        ParseError::capture_from_slice(
            self.buf,
            self.base_offset,
            self.pos,
            field,
            "failed to decode integer",
            Box::new(e),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_and_seek() {
        let buf = [1_u8, 2, 3, 4, 5];
        let mut r = Reader::with_base_offset(&buf, 0x1000);

        assert_eq!(r.u8("a").unwrap(), 1);
        assert_eq!(r.position(), 1);
        assert_eq!(r.take("b", 2).unwrap(), &[2, 3]);
        assert_eq!(r.position(), 3);

        r.seek("rewind", 0).unwrap();
        assert_eq!(r.u16_le("u16").unwrap(), 0x0201);
    }

    #[test]
    fn oob_reports_offset() {
        let buf = [0_u8; 4];
        let mut r = Reader::with_base_offset(&buf, 0x2000);
        let err = r.u64_le("too_big").unwrap_err();
        assert_eq!(err.offset(), 0x2000);
        assert_eq!(err.field(), "too_big");
        assert!(err.hexdump().contains("0x00002000"));
    }
}
