use crate::entry::MftEntry;
use crate::err::{self, Result};

use crate::{EntryHeader, ReadSeek};
use log::debug;
use snafu::ResultExt;

use std::fs::{self, File};
use std::io::{BufReader, Cursor, SeekFrom};
use std::path::Path;

pub struct MftParser<T: ReadSeek> {
    data: T,
    /// Entry size is present in the volume header, but this is not available to us.
    /// Instead this will be guessed by the entry size of the first entry.
    entry_size: u32,
    size: u64,
}

impl MftParser<BufReader<File>> {
    /// Instantiates an instance of the parser from a file path.
    /// Does not mutate the file contents in any way.
    pub fn from_path(filename: impl AsRef<Path>) -> Result<Self> {
        let f = filename.as_ref();

        let mft_fh = File::open(f).context(err::FailedToOpenFile { path: f.to_owned() })?;
        let size = fs::metadata(f)?.len();

        Self::from_read_seek(BufReader::with_capacity(4096, mft_fh), size)
    }
}

impl MftParser<Cursor<Vec<u8>>> {
    /// Instantiates an instance of the parser from a buffer containing a full MFT file.
    /// Useful for testing.
    pub fn from_buffer(buffer: Vec<u8>) -> Result<Self> {
        let size = buffer.len() as u64;
        let cursor = Cursor::new(buffer);

        Self::from_read_seek(cursor, size)
    }
}

impl<T: ReadSeek> MftParser<T> {
    pub fn from_read_seek(mut data: T, size: u64) -> Result<Self> {
        let first_entry = EntryHeader::from_reader(&mut data)?;
        data.seek(SeekFrom::Start(0))?;

        Ok(Self {
            data,
            entry_size: first_entry.total_entry_size,
            size,
        })
    }

    pub fn get_entry_count(&self) -> u64 {
        self.size / u64::from(self.entry_size)
    }

    pub fn iter_entries(&mut self) -> impl Iterator<Item = Result<MftEntry>> + '_ {
        let total_entries = self.get_entry_count();
        let mut count = 0;

        std::iter::from_fn(move || {
            if count == total_entries {
                None
            } else {
                // TODO: is this off by one?
                count += 1;
                debug!("Reading entry {}", count);

                if let Err(e) = self
                    .data
                    .seek(SeekFrom::Start(count * u64::from(self.entry_size)))
                    .eager_context(err::IoError)
                {
                    return Some(Err(e));
                };

                let mut entry_buffer = vec![0; self.entry_size as usize];

                if let Err(e) = self
                    .data
                    .read_exact(&mut entry_buffer)
                    .eager_context(err::IoError)
                {
                    return Some(Err(e));
                }

                Some(MftEntry::from_buffer(entry_buffer))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::MftParser;
    use std::path::PathBuf;

    // entrypoint for clion profiler.
    #[test]
    fn test_process_90_mft_entries() {
        let sample = PathBuf::from(file!())
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("samples")
            .join("MFT");

        let mut parser = MftParser::from_path(sample).unwrap();

        let mut count = 0;
        for record in parser.iter_entries().take(10000).filter_map(|a| a.ok()) {
            for attribute in record.iter_attributes() {
                count += 1;
            }
        }
    }
}
