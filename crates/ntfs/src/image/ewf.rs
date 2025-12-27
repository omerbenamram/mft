//! EWF random-access reader.
//!
//! This module provides `EwfImage`, an implementation of `ReadAt` backed by the standalone `ewf`
//! crate (extracted from this repository). This preserves the `ntfs::image::EwfImage` ergonomics
//! while delegating all EWF parsing/IO to `ewf`.

use crate::image::ReadAt;
use std::io;
use std::path::Path;

#[derive(Debug)]
pub struct EwfImage {
    inner: ewf::EwfReader,
}

impl EwfImage {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let inner = ewf::EwfReader::open(path).map_err(ewf_error_to_io)?;
        Ok(Self { inner })
    }

    /// Returns the logical EWF chunk size in bytes.
    pub fn chunk_size(&self) -> usize {
        self.inner.chunk_size()
    }

    /// Returns the number of chunks in the logical media.
    pub fn chunk_count(&self) -> u64 {
        self.inner.chunk_count()
    }
}

impl ReadAt for EwfImage {
    fn len(&self) -> u64 {
        self.inner.len()
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        self.inner
            .read_exact_at(offset, buf)
            .map_err(ewf_error_to_io)
    }
}

fn ewf_error_to_io(err: ewf::Error) -> io::Error {
    match err {
        ewf::Error::Io(e) => e,
        ewf::Error::Unsupported(msg) => io::Error::new(io::ErrorKind::Unsupported, msg),
        ewf::Error::Invalid(msg) | ewf::Error::Corrupt(msg) => {
            io::Error::new(io::ErrorKind::InvalidData, msg)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_and_read_minimal_e01() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("test.E01");

        let mut media = vec![0u8; 1024];
        media[..512].fill(b'A');
        media[512..].fill(b'B');

        let mut opts =
            ewf::writer::EwfWriterOptions::new(ewf::writer::Ewf1Format::E01, media.len() as u64);
        opts.bytes_per_sector = 512;
        opts.sectors_per_chunk = 1;
        opts.segment_file_size = 10 * 1024 * 1024;

        let mut w = ewf::EwfWriter::create(&path, opts).map_err(ewf_error_to_io)?;
        let mut written = 0usize;
        while written < media.len() {
            let n = w.write(&media[written..]).map_err(ewf_error_to_io)?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "writer made no progress",
                ));
            }
            written += n;
        }
        w.finish().map_err(ewf_error_to_io)?;

        let img = EwfImage::open(&path)?;
        assert_eq!(img.len(), 1024);
        assert_eq!(img.chunk_size(), 512);
        assert_eq!(img.chunk_count(), 2);

        let mut buf = vec![0u8; 1024];
        img.read_exact_at(0, &mut buf)?;
        assert_eq!(&buf[..512], &vec![b'A'; 512]);
        assert_eq!(&buf[512..], &vec![b'B'; 512]);

        Ok(())
    }
}
