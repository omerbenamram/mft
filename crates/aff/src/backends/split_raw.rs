//! Split-raw backend (AFM payload).
//!
//! AFFLIB’s AFM container stores metadata in an AFF file (`.afm`) and stores the actual disk
//! bytes in one or more *raw* files whose extension is provided by the metadata segment
//! `raw_image_file_extension` (typically `"000"`).
//!
//! The payload may be split across multiple files by incrementing the **3-character extension**
//! (e.g. `.000`, `.001`, …, `.999`, `.A00`, …) using the same scheme as AFFLIBv3.

use forensic_image::ReadAt;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

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

fn io_eof() -> io::Error {
    io::Error::from(io::ErrorKind::UnexpectedEof)
}

#[derive(Debug)]
pub(crate) struct SplitRawImage {
    files: Vec<File>,
    /// Size of a “full” chunk file (the first file size) when split across multiple files.
    ///
    /// If the image is not split, this is `0` and `files.len() == 1`.
    maxsize: u64,
    image_size: u64,
}

impl SplitRawImage {
    pub(crate) fn open(first_path: impl AsRef<Path>) -> io::Result<Self> {
        let first_path = first_path.as_ref().to_path_buf();
        let mut files = Vec::new();

        let first = File::open(&first_path)?;
        let first_len = first.metadata()?.len();
        files.push(first);

        // Try to open additional files by incrementing the 3-char extension.
        let mut next_path = first_path.clone();
        let mut must_be_last = false;
        let mut maxsize = 0u64;
        let mut last_len = first_len;

        loop {
            if !increment_split_raw_extension(&mut next_path) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "split_raw: too many files (extension overflow)",
                ));
            }

            match File::open(&next_path) {
                Ok(f) => {
                    let len = f.metadata()?.len();
                    files.push(f);

                    if must_be_last {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "split_raw: found file after a short final segment",
                        ));
                    }

                    if maxsize == 0 {
                        // Second file exists: lock in the maxsize as the first file size.
                        maxsize = first_len;
                    }

                    if maxsize != 0 && len != maxsize {
                        // This file is smaller than the maxsize => must be the last file.
                        must_be_last = true;
                    }

                    last_len = len;
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    break;
                }
                Err(e) => return Err(e),
            }
        }

        let image_size = if maxsize == 0 {
            first_len
        } else {
            last_len + maxsize.saturating_mul(files.len().saturating_sub(1) as u64)
        };

        Ok(Self {
            files,
            maxsize,
            image_size,
        })
    }
}

impl ReadAt for SplitRawImage {
    fn len(&self) -> u64 {
        self.image_size
    }

    fn read_exact_at(&self, offset: u64, mut buf: &mut [u8]) -> io::Result<()> {
        if offset.saturating_add(buf.len() as u64) > self.len() {
            return Err(io_eof());
        }

        let mut cur = offset;
        while !buf.is_empty() {
            let (file_idx, file_off) = if self.maxsize == 0 {
                (0usize, cur)
            } else {
                let idx = (cur / self.maxsize) as usize;
                let off = cur % self.maxsize;
                (idx, off)
            };

            let file = self.files.get(file_idx).ok_or_else(|| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "missing split file")
            })?;

            let max_in_file = if self.maxsize == 0 {
                // Single file.
                buf.len() as u64
            } else {
                // Don't cross file boundary.
                (self.maxsize - file_off).min(buf.len() as u64)
            } as usize;

            let mut tmp = &mut buf[..max_in_file];
            let mut file_cursor = file_off;
            while !tmp.is_empty() {
                let n = file_read_at(file, tmp, file_cursor)?;
                if n == 0 {
                    return Err(io_eof());
                }
                file_cursor = file_cursor.saturating_add(n as u64);
                let t = tmp;
                tmp = &mut t[n..];
            }

            cur = cur.saturating_add(max_in_file as u64);
            let t = buf;
            buf = &mut t[max_in_file..];
        }

        Ok(())
    }
}

/// Increments the filename extension in-place according to AFFLIBv3 rules.
///
/// Returns `false` if the path does not have a 3-character extension (cannot be incremented).
fn increment_split_raw_extension(path: &mut PathBuf) -> bool {
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    if ext.len() != 3 {
        return false;
    }

    let mut bytes = [0u8; 3];
    bytes.copy_from_slice(ext.as_bytes());

    // Numeric case: 000..999 then A00.
    if bytes.iter().all(|b| b.is_ascii_digit()) {
        let num = ((bytes[0] - b'0') as u32) * 100
            + ((bytes[1] - b'0') as u32) * 10
            + (bytes[2] - b'0') as u32;
        let next = if num == 999 {
            *b"A00"
        } else {
            let n = (num + 1) % 1000;
            [
                b'0' + ((n / 100) as u8),
                b'0' + (((n / 10) % 10) as u8),
                b'0' + ((n % 10) as u8),
            ]
        };
        let next_ext = std::str::from_utf8(&next).unwrap();
        path.set_extension(next_ext);
        return true;
    }

    // Base36 case: uppercase for increment, preserve original case if first char was lowercase.
    let lower = bytes[0].is_ascii_lowercase();
    for b in &mut bytes {
        if b.is_ascii_alphabetic() {
            *b = b.to_ascii_uppercase();
        }
    }

    fn incval(ch: &mut u8) -> bool {
        match *ch {
            b'Z' => {
                *ch = b'0';
                true
            }
            b'9' => {
                *ch = b'A';
                false
            }
            _ => {
                *ch = (*ch).saturating_add(1);
                false
            }
        }
    }

    let carry2 = incval(&mut bytes[2]);
    let carry1 = carry2 && incval(&mut bytes[1]);
    let carry0 = carry1 && incval(&mut bytes[0]);
    if carry0 {
        // Too many files — AFFLIB would error; here we stop incrementing.
        return false;
    }

    if lower {
        for b in &mut bytes {
            if b.is_ascii_alphabetic() {
                *b = b.to_ascii_lowercase();
            }
        }
    }

    let next_ext = std::str::from_utf8(&bytes).unwrap();
    path.set_extension(next_ext);
    true
}

#[cfg(test)]
mod tests {
    use super::increment_split_raw_extension;
    use std::path::{Path, PathBuf};

    fn ext(path: &Path) -> String {
        path.extension().unwrap().to_string_lossy().to_string()
    }

    #[test]
    fn test_increment_numeric() {
        let mut p = PathBuf::from("image.000");
        assert!(increment_split_raw_extension(&mut p));
        assert_eq!(ext(&p), "001");

        let mut p = PathBuf::from("image.009");
        assert!(increment_split_raw_extension(&mut p));
        assert_eq!(ext(&p), "010");

        let mut p = PathBuf::from("image.999");
        assert!(increment_split_raw_extension(&mut p));
        assert_eq!(ext(&p), "A00");
    }

    #[test]
    fn test_increment_base36_uppercase() {
        let mut p = PathBuf::from("image.A00");
        assert!(increment_split_raw_extension(&mut p));
        assert_eq!(ext(&p), "A01");

        let mut p = PathBuf::from("image.A0Z");
        assert!(increment_split_raw_extension(&mut p));
        assert_eq!(ext(&p), "A10");

        let mut p = PathBuf::from("image.AZZ");
        assert!(increment_split_raw_extension(&mut p));
        assert_eq!(ext(&p), "B00");
    }

    #[test]
    fn test_increment_preserves_lowercase() {
        let mut p = PathBuf::from("image.a00");
        assert!(increment_split_raw_extension(&mut p));
        assert_eq!(ext(&p), "a01");

        let mut p = PathBuf::from("image.a0z");
        assert!(increment_split_raw_extension(&mut p));
        assert_eq!(ext(&p), "a10");
    }

    #[test]
    fn test_increment_requires_three_char_extension() {
        let mut p = PathBuf::from("image.raw");
        assert!(increment_split_raw_extension(&mut p));
        assert_eq!(ext(&p), "rax");

        let mut p = PathBuf::from("image.00");
        assert!(!increment_split_raw_extension(&mut p));
        assert_eq!(ext(&p), "00");
    }
}
