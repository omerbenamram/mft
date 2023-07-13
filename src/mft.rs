use crate::entry::MftEntry;
use crate::err::{Error, Result};

use crate::EntryHeader;
use log::{debug, trace};

use lru::LruCache;
use std::fs::{self, File};
use std::io::{BufReader, Cursor, Read, Seek, SeekFrom};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

pub struct MftParser<T: Read + Seek> {
    data: T,
    /// Entry size is present in the volume header, but this is not available to us.
    /// Instead this will be guessed by the entry size of the first entry.
    entry_size: u32,
    size: u64,
    entries_cache: LruCache<u64, PathBuf>,
}

impl MftParser<BufReader<File>> {
    /// Instantiates an instance of the parser from a file path.
    /// Does not mutate the file contents in any way.
    pub fn from_path(filename: impl AsRef<Path>) -> Result<Self> {
        let f = filename.as_ref();

        let mft_fh = File::open(f).map_err(|e| Error::failed_to_open_file(f, e))?;
        let size = fs::metadata(f)?.len();

        Self::from_read_seek(BufReader::with_capacity(4096, mft_fh), Some(size))
    }
}

impl MftParser<Cursor<Vec<u8>>> {
    /// Instantiates an instance of the parser from a buffer containing a full MFT file.
    /// Useful for testing.
    pub fn from_buffer(buffer: Vec<u8>) -> Result<Self> {
        let size = buffer.len() as u64;
        let cursor = Cursor::new(buffer);

        Self::from_read_seek(cursor, Some(size))
    }
}

fn check_entry_size<T: Read + Seek>(data: &mut T, off: u64) -> Result<u32> {
    data.seek(SeekFrom::Start(off))?;
    if let Ok(header) = EntryHeader::from_reader(data, 0) {
        // Check that the entry size is nonzero and is consistent with
        // the length of the update sequence array. There should be one
        // element of the USA for each 512 bytes of entry, plus one extra
        // element for the update sequence number. The probability that
        // the entry size and USA size follow this rule when selected
        // randomly is vanishingly small (1/2^32), so this check should be
        // sufficient to ensure that we have a good entry size.
        if header.total_entry_size != 0 &&
           header.total_entry_size == (header.usa_size - 1) as u32 * 512
        {
            return Ok(header.total_entry_size);
        }
    }
    Err(Error::FailedToReadEntrySize{})
}

/// Search for a valid MFT FILE record to determine the FILE record size.
fn find_entry_size<T: Read + Seek>(data: &mut T, size: u64) -> Result<u32> {
    // Each valid FILE entry header contains the total size of its entry.
    // Every entry in the MFT is the same size, so we get the entry size
    // for this MFT from the first good FILE entry we can find. The stride
    // for the search is 1024; in the event that the entry size is 4096,
    // a stride of 1024 still works, due to 4096 being a multiple of 1024.
    //
    // Corrupt MFTs may have the first entries wiped/overwritten, and using
    // this method of determining the FILE record size may allow for recovery
    // of entries in such cases.
    (0..size)
        .step_by(1024)
        .find_map(|off| check_entry_size(data, off).ok())
        .ok_or(Error::FailedToReadEntrySize{})
}

impl<T: Read + Seek> MftParser<T> {
    pub fn from_read_seek(mut data: T, size: Option<u64>) -> Result<Self> {
        let size = match size {
            Some(sz) => sz,
            None => data.seek(SeekFrom::End(0))?,
        };

        let entry_size = find_entry_size(&mut data, size)?;
        data.seek(SeekFrom::Start(0))?;

        Ok(Self {
            data,
            entry_size,
            size,
            entries_cache: LruCache::new(NonZeroUsize::new(1000).expect("1000 > 0")),
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

        MftEntry::from_buffer(entry_buffer, entry_number)
    }

    /// Iterates over all the entries in the MFT.
    pub fn iter_entries(&mut self) -> impl Iterator<Item = Result<MftEntry>> + '_ {
        let total_entries = self.get_entry_count();

        (0..total_entries).map(move |i| self.get_entry(i))
    }

    fn inner_get_entry(&mut self, parent_entry_id: u64, entry_name: Option<&str>) -> PathBuf {
        let cached_entry = self.entries_cache.get(&parent_entry_id);

        // If my parent path is known, then my path is parent's full path + my name.
        // Else, retrieve and cache my parent's path.
        if let Some(cached_parent_path) = cached_entry {
            match entry_name {
                Some(name) => cached_parent_path.clone().join(name),
                None => cached_parent_path.clone(),
            }
        } else {
            let path = match self.get_entry(parent_entry_id).ok() {
                Some(parent) => match self.get_full_path_for_entry(&parent) {
                    Ok(Some(path)) if parent.is_dir() => path,
                    Ok(Some(_)) => PathBuf::from("[Unknown]"),
                    // I have a parent, which doesn't have a filename attribute.
                    // Default to root.
                    _ => PathBuf::new(),
                },
                // Parent is maybe corrupted or incomplete, use a sentinel instead.
                None => PathBuf::from("[Unknown]"),
            };

            self.entries_cache.put(parent_entry_id, path.clone());
            match entry_name {
                Some(name) => path.join(name),
                None => path,
            }
        }
    }

    /// Gets the full path for an entry.
    /// Caches computations.
    pub fn get_full_path_for_entry(&mut self, entry: &MftEntry) -> Result<Option<PathBuf>> {
        let entry_id = entry.header.record_number;
        match entry.find_best_name_attribute() {
            Some(filename_header) => {
                let parent_entry_id = filename_header.parent.entry;

                // MFT entry 5 is the root path.
                if parent_entry_id == 5 {
                    return Ok(Some(PathBuf::from(filename_header.name)));
                }

                if parent_entry_id == entry_id {
                    trace!(
                        "Found self-referential file path, for entry ID {}",
                        entry_id
                    );
                    return Ok(Some(PathBuf::from("[Orphaned]").join(filename_header.name)));
                }

                if parent_entry_id > 0 {
                    Ok(Some(self.inner_get_entry(
                        parent_entry_id,
                        Some(&filename_header.name),
                    )))
                } else {
                    trace!("Found orphaned entry ID {}", entry_id);

                    let orphan = PathBuf::from("[Orphaned]").join(filename_header.name);

                    self.entries_cache
                        .put(entry.header.record_number, orphan.clone());

                    Ok(Some(orphan))
                }
            }
            None => match entry.header.base_reference.entry {
                // I don't have a parent reference, and no X30 attribute. Though luck.
                0 => Ok(None),
                parent_entry_id => Ok(Some(self.inner_get_entry(parent_entry_id, None))),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::tests::fixtures::{mft_sample, mft_sample_name};
    use crate::{MftEntry, MftParser};

    use std::fs::File;
    use std::io::{BufReader, Seek, SeekFrom};

    use super::find_entry_size;

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

        assert!(count > 0)
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

    #[test]
    fn test_find_entry_size() {
        // The first header is zeroed. The second header has a corrupt
        // sequence array. The third header is valid.
        let f = File::open(mft_sample_name("third_header_good")).unwrap();
        let mut data = BufReader::new(f);
        let size = data.seek(SeekFrom::End(0)).unwrap();
        data.seek(SeekFrom::Start(0)).unwrap();
        assert_eq!(find_entry_size(&mut data, size).unwrap(), 1024);
    }
}
