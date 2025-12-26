use crate::image::ReadAt;
use std::fs::File;
use std::io;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::FileExt;
#[cfg(windows)]
use std::os::windows::fs::FileExt;

#[cfg(unix)]
fn file_read_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    file.read_at(buf, offset)
}

#[cfg(windows)]
fn file_read_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    file.seek_read(buf, offset)
}

#[derive(Debug)]
pub struct RawImage {
    file: File,
    len: u64,
}

impl RawImage {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        Ok(Self { file, len })
    }
}

impl ReadAt for RawImage {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_exact_at(&self, offset: u64, mut buf: &mut [u8]) -> io::Result<()> {
        if offset.saturating_add(buf.len() as u64) > self.len {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }

        let mut cur_offset = offset;
        while !buf.is_empty() {
            let read = file_read_at(&self.file, buf, cur_offset)?;
            if read == 0 {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            }
            cur_offset = cur_offset.saturating_add(read as u64);
            let tmp = buf;
            buf = &mut tmp[read..];
        }

        Ok(())
    }
}
