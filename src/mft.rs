use crate::entry::MftEntry;
use crate::err::{self, Result};

use crate::{EntryHeader, ReadSeek};
use log::debug;
use snafu::ResultExt;

use crate::attribute::MftAttributeContent::AttrX30;

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, Cursor, SeekFrom};
use std::path::{Path, PathBuf};

pub struct MftParser<T: ReadSeek> {
    data: T,
    /// Entry size is present in the volume header, but this is not available to us.
    /// Instead this will be guessed by the entry size of the first entry.
    entry_size: u32,
    size: u64,
    entries_cache: HashMap<u64, PathBuf>,
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
        // We use the first entry to guess the entry size for all the other records.
        let first_entry = EntryHeader::from_reader(&mut data)?;
        data.seek(SeekFrom::Start(0))?;

        Ok(Self {
            data,
            entry_size: first_entry.total_entry_size,
            size,
            entries_cache: HashMap::new(),
        })
    }

    pub fn get_entry_count(&self) -> u64 {
        self.size / u64::from(self.entry_size)
    }

    /// Reads an entry from the MFT by entry number.
    pub fn get_entry(&mut self, entry_number: u64) -> Result<MftEntry> {
        debug!("Reading entry {}", entry_number);

        self.data
            .seek(SeekFrom::Start(entry_number * u64::from(self.entry_size)))?;
        let mut entry_buffer = vec![0; self.entry_size as usize];

        self.data.read_exact(&mut entry_buffer)?;

        Ok(MftEntry::from_buffer(entry_buffer)?)
    }

    /// Iterates over all the entries in the MFT.
    pub fn iter_entries(&mut self) -> impl Iterator<Item = Result<MftEntry>> + '_ {
        let total_entries = self.get_entry_count();
        let mut count = 0;

        std::iter::from_fn(move || {
            if count == total_entries {
                None
            } else {
                count += 1;
                Some(self.get_entry(count))
            }
        })
    }

    /// Gets the full path for an entry.
    /// Caches computations.
    pub fn get_full_path_for_entry(&mut self, entry: &MftEntry) -> Result<Option<PathBuf>> {
        let entry_id = entry.header.entry_reference.entry;

        for attribute in entry.iter_attributes().filter_map(|a| a.ok()) {
            if let AttrX30(filename_header) = attribute.data {
                let parent_entry_id = filename_header.parent.entry;

                if parent_entry_id > 0 {
                    // If i'm my own parent, I'm the root path.
                    if parent_entry_id == entry_id {
                        return Ok(Some(PathBuf::from(filename_header.name)));
                    }

                    let cached_entry = self.entries_cache.get(&parent_entry_id);

                    // If my parent path is known, then my path is parent's full path + my name.
                    // Else, retrieve and cache my parent's path.
                    if let Some(cached_parent_path) = cached_entry {
                        return Ok(Some(cached_parent_path.clone().join(filename_header.name)));
                    } else {
                        let path = match self.get_entry(parent_entry_id).ok() {
                            Some(parent) => match self.get_full_path_for_entry(&parent) {
                                Ok(Some(path)) => path,
                                _ => {
                                    return err::Any {
                                        detail: "Unexpected missing parent.\
                                         This is a bug, please report it at report at https://github.com/omerbenamram/mft/issues",
                                    }
                                    .fail()
                                }
                            },
                            // Parent is maybe corrupted or incomplete, use a sentinel instead.
                            None => PathBuf::from("[Unknown]"),
                        };

                        self.entries_cache.insert(parent_entry_id, path.clone());
                        return Ok(Some(path.join(filename_header.name)));
                    }
                } else {
                    let root = PathBuf::from(filename_header.name);

                    self.entries_cache
                        .insert(entry.header.entry_reference.entry, root.clone());
                    return Ok(Some(root));
                }
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use crate::tests::fixtures::mft_sample;
    use crate::{MftEntry, MftParser};

    // entrypoint for clion profiler.
    #[test]
    fn test_process_90_mft_entries() {
        let sample = mft_sample();

        let mut parser = MftParser::from_path(sample).unwrap();

        let mut count = 0;
        for record in parser.iter_entries().take(10000).filter_map(|a| a.ok()) {
            for _attribute in record.iter_attributes() {
                count += 1;
            }
        }
    }

    #[test]
    fn test_get_full_path() {
        let sample = mft_sample();
        let mut parser = MftParser::from_path(sample).unwrap();

        let mut paths = Vec::with_capacity(1000);
        let entries: Vec<MftEntry> = parser
            .iter_entries()
            .take(1000)
            .filter_map(Result::ok)
            .collect();

        for entry in entries {
            if let Some(path) = parser.get_full_path_for_entry(&entry).unwrap() {
                paths.push(path)
            }
        }

        assert_eq!(paths.len(), 988);
    }

    #[test]
    fn test_get_full_name() {
        let sample = mft_sample();
        let mut parser = MftParser::from_path(sample).unwrap();

        let e = parser.get_entry(5).unwrap();
        parser.get_full_path_for_entry(&e).unwrap();
    }
}
